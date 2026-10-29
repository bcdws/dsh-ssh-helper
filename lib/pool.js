/**
 * The SSH connection pool.
 *
 * One `Client` per host alias, kept warm with keepalive probes and reconnected
 * with exponential backoff. Sessions and SFTP transfers ride on
 * that shared transport; shell state is replayed per call so outputs never mix.
 *
 * @module dsh-ssh-pool/pool
 */
import { createRequire } from 'node:module';
import { createHash, randomBytes } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { basename } from 'node:path';
import { checkHostKey } from './knownhosts.js';
import { detectAgent } from './config.js';
import { redactText } from './redact.js';
import { normalizeHost } from './store.js';

// Load the CJS package through `require`, not an ESM default import: the DSH
// plugin loader's ESM interop exposes `Client` as a namespace object there, and
// `new Client()` then fails with "Client is not a constructor". `createRequire`
// sees the package's real CommonJS exports.
const require = createRequire(import.meta.url);
const ssh2 = require('ssh2');
const { Client } = ssh2;

/** The key's own file name — never its path, which the model has no use for. */
function basenameOf(file) {
  try {
    return basename(String(file));
  } catch {
    return null;
  }
}

const MAX_BACKOFF_MS = 30000;
const DEFAULT_MAX_OUTPUT_BYTES = 16000;

/** The effective per-stream output cap, defaulted so a missing option cannot disable it. */
function outputLimitOf(value) {
  return Number.isFinite(value) && value > 0 ? value : DEFAULT_MAX_OUTPUT_BYTES;
}

/** Whether the failure means the pooled transport is no longer usable. */
function isTransportGone(error) {
  const message = error instanceof Error ? error.message : String(error ?? '');
  return /not connected|no response from server|connection lost|ECONNRESET|EPIPE|socket hang up|channel open failure/i.test(message);
}

/** Tag a failure as safe to retry once on a fresh connection (nothing started remotely). */
function tagRetryable(error, retryable) {
  if (error !== null && typeof error === 'object') error.dshSshRetryable = retryable;
  return error;
}

/** Byte-capped text with an explicit omission marker. */
export function capText(text, maxBytes) {
  const source = String(text ?? '');
  const limit = outputLimitOf(maxBytes);
  const buffer = Buffer.from(source, 'utf8');
  if (buffer.length <= limit) return { text: source, truncated: false };
  const head = buffer.subarray(0, Math.floor(limit * 0.6)).toString('utf8');
  const tail = buffer.subarray(buffer.length - Math.floor(limit * 0.4)).toString('utf8');
  return {
    text: `${head}\n[... ${buffer.length - limit} bytes omitted; capped at ${limit} bytes per stream ...]\n${tail}`,
    truncated: true
  };
}

/** POSIX single-quote a string for a remote shell. */
export function shQuote(value) {
  return `'${String(value).replace(/'/g, "'\\''")}'`;
}

/**
 * One named SSH session: working directory and exported variables persist,
 * every call's output stays isolated.
 *
 * A long-lived shell shares one stdout stream with everything its commands
 * start, so a background process could write into the *next* command's result.
 * Instead each command runs in its own channel — its own process, its own
 * stdout/stderr, stdin closed immediately — while the session's cwd and
 * exported variables are stored in a 0600 state file on the host and replayed
 * before the next command. Output therefore cannot cross between calls, a
 * timeout kills only the command it belongs to, and the state even survives a
 * reconnect.
 */
class ShellSession {
  #host;
  #name;
  #queue = Promise.resolve();
  #disposed = false;

  constructor(host, name, key = name, ownerKey = 'host') {
    this.#host = host;
    this.#name = name;
    /** Map key, `owner::name`: one caller's session never collides with another's. */
    this.key = key;
    /** The DSH session that owns this session, or `host` for a non-session caller. */
    this.ownerKey = ownerKey;
    this.createdAt = Date.now();
    this.commands = 0;
    this.lastUsed = Date.now();
    /** Remote state file name, unique per host, owner and session name. */
    this.stateSuffix = `.dsh-ssh-${createHash('sha1').update(`${host.alias}\u0000${ownerKey}\u0000${name}`).digest('hex').slice(0, 16)}`;
  }

  get name() {
    return this.#name;
  }

  /** A session has no channel to lose: it stays usable for its whole life. */
  get alive() {
    return !this.#disposed;
  }

  /**
   * Shell expression for the state directory.
   *
   * Not /tmp: it is RAM-backed on most hosts, wiped on reboot, and world
   * writable. A private cache directory under $HOME survives reboots, is
   * readable only by the login user, and is easy to find and delete.
   */
  static stateDirShell() {
    return '${DSH_SSH_STATE_DIR:-${HOME:-/root}/.cache/dsh-ssh-sessions}';
  }

  /** Replay the saved state, run the command, then save the new state. */
  #script(command) {
    let terminator = `DSH_EOF_${randomBytes(8).toString('hex')}`;
    while (command.includes(terminator)) terminator = `DSH_EOF_${randomBytes(8).toString('hex')}`;
    const dir = ShellSession.stateDirShell();
    return [
      '__dsh_umask=$(umask)',
      'umask 077',
      `__dsh_dir="${dir}"`,
      'mkdir -p "$__dsh_dir" 2>/dev/null && chmod 700 "$__dsh_dir" 2>/dev/null',
      `__dsh_state="$__dsh_dir/${this.stateSuffix}"`,
      '[ -f "$__dsh_state" ] && . "$__dsh_state" 2>/dev/null',
      // The state file is the only thing that needs the private umask: restore
      // the login shell's own before running the command, or every file the
      // user's build/deploy creates would silently become 0600/0700.
      'umask "$__dsh_umask"',
      `eval "$(cat <<'${terminator}'`,
      command,
      terminator,
      ')"',
      '__dsh_rc=$?',
      // The directory is stored as a real `cd` line, not a bare path, so
      // sourcing the file restores it. Exported variables follow, except the
      // ones that look like credentials: a session must not persist secrets to
      // disk. A failed save must never fail the command.
      'umask 077',
      `{ printf 'cd "%s"\\n' "$PWD"; export -p | grep -Evi '(^|[ =])[A-Za-z0-9_]*(KEY|TOKEN|SECRET|PASS|CRED|AUTH)[A-Za-z0-9_]*='; } 2>/dev/null | head -c 65536 > "$__dsh_state" 2>/dev/null || true`,
      'umask "$__dsh_umask"',
      'exit $__dsh_rc'
    ].join('\n');
  }

  /** Run one command in this session, serialized against other calls on it. */
  run(command, options = {}) {
    // A connection loss disposes live sessions; a caller still holding this
    // object gets the host's replacement session instead of a dead one.
    if (this.#disposed) {
      const replacement = this.#host.session(this.#name, this.ownerKey);
      if (replacement !== this) return replacement.run(command, options);
      throw new Error(`ssh session "${this.#name}" was closed`);
    }
    const task = async () => {
      const { timeoutMs, maxOutputBytes, signal } = options;
      this.lastUsed = Date.now();
      this.commands += 1;
      const result = await this.#host.exec(this.#script(command), { timeoutMs, maxOutputBytes, signal });
      return {
        stdout: result.stdout,
        stderr: result.stderr,
        exitCode: result.exitCode,
        signal: result.signal ?? null,
        cwd: undefined,
        timedOut: result.timedOut === true,
        aborted: result.aborted === true,
        sessionEnded: false,
        endReason: result.aborted === true ? 'aborted' : result.timedOut === true ? 'timeout' : null
      };
    };
    const queued = this.#queue.then(task, task);
    // Keep the chain alive after a failure without dropping the rejection.
    this.#queue = queued.then(
      () => undefined,
      () => undefined
    );
    return queued;
  }

  /** Drop the session, and its remote state file when the host is reachable. */
  dispose() {
    if (this.#disposed) return;
    this.#disposed = true;
    this.#queue = this.#queue.then(
      () => undefined,
      () => undefined
    );
    if (this.#host.connected) {
      // Best effort: losing this file only means the next command starts from
      // the login shell's defaults again.
      void this.#host
        .exec(`rm -f "${ShellSession.stateDirShell()}/${this.stateSuffix}"`, { timeoutMs: 5000 })
        .catch(() => undefined);
    }
  }
}

/** One host alias: the pooled client, its sessions and counters. */
class HostConnection {
  #client;
  #connecting;
  #reconnectTimer;
  #disposed = false;
  #slots = 0;
  #work = 0;
  #waiters = [];
  #lostListeners = new Set();

  constructor(alias, spec, config, logger) {
    this.alias = alias;
    this.spec = spec;
    this.config = config;
    this.logger = logger;
    this.state = 'idle';
    this.connects = 0;
    this.reconnects = 0;
    this.failures = 0;
    this.connectedAt = undefined;
    this.lastUsed = undefined;
    this.lastError = undefined;
    this.hostKey = undefined;
    /** Reconnect after a drop only once the host has been used at least once. */
    this.keepWarm = false;
    this.sessions = new Map();
  }

  get connected() {
    return this.#client !== undefined;
  }

  /** Mark a non-exec operation (SFTP read/write/transfer) as in flight. */
  beginWork() {
    this.#work += 1;
    this.touch();
  }

  /** Mark a non-exec operation finished. */
  endWork() {
    this.#work = Math.max(0, this.#work - 1);
    this.touch();
  }

  /** Whether a command, transfer or session is using this connection. */
  get busy() {
    return this.#slots > 0 || this.#work > 0;
  }

  /** Connect if needed; concurrent callers share the one handshake. */
  async ensure() {
    if (this.#disposed) throw new Error(`ssh host "${this.alias}" is no longer available`);
    if (this.#client !== undefined) return this.#client;
    if (this.#connecting !== undefined) return await this.#connecting;
    this.#connecting = this.#connect().catch((error) => {
      // A failure before the handshake starts (an unreadable key, a bad path)
      // never reaches #connect's own fail(); record it here so the host does
      // not stay in "connecting" forever with no lastError.
      this.#markConnectFailure(error);
      throw error;
    });
    try {
      return await this.#connecting;
    } finally {
      this.#connecting = undefined;
    }
  }

  /** Record a setup failure that happened outside the handshake promise. */
  #markConnectFailure(error) {
    if (this.state !== 'connecting') return;
    this.failures += 1;
    this.state = 'down';
    const cause = error instanceof Error ? error.message : String(error);
    this.lastError = `ssh host "${this.alias}" (${this.spec.user}@${this.spec.host}:${this.spec.port}) failed: ${cause}`;
    this.#scheduleReconnect();
  }

  /** Open the transport: authenticate, verify the host key, start keepalive. */
  async #connect() {
    const spec = this.spec;
    this.state = 'connecting';
    const client = new Client();
    const hasKey = spec.identityFile !== undefined && existsSync(spec.identityFile);
    // Prefer the agent whenever one is available: a default identity file is
    // often passphrase-protected and already loaded there, and suppressing the
    // agent just because the file exists made those hosts unconnectable. When
    // the key is encrypted and no passphrase was configured, hand it to the
    // agent instead of passing an unreadable key to ssh2 (which parses it
    // before authentication and would fail the whole connection).
    const agent = spec.agent ?? detectAgent() ?? undefined;
    const keyBuffer = hasKey ? readFileSync(spec.identityFile) : undefined;
    let privateKey = keyBuffer;
    if (keyBuffer !== undefined && spec.passphrase === undefined && ssh2.utils.parseKey(keyBuffer) instanceof Error) {
      if (agent === undefined) {
        throw new Error(`identity file ${basenameOf(spec.identityFile)} is encrypted and no passphrase is configured; load it into ssh-agent or set hosts[].passphrase`);
      }
      privateKey = undefined;
    }
    const connectConfig = {
      host: spec.host,
      port: spec.port,
      username: spec.user,
      readyTimeout: this.config.connectTimeoutMs,
      keepaliveInterval: this.config.keepaliveIntervalMs,
      keepaliveCountMax: this.config.keepaliveCountMax,
      ...(agent === undefined ? {} : { agent }),
      ...(privateKey === undefined
        ? {}
        : {
            privateKey,
            ...(spec.passphrase === undefined ? {} : { passphrase: spec.passphrase })
          }),
      hostVerifier: (blob) => {
        if (this.config.hostKeyPolicy === 'off') return true;
        const verdict = checkHostKey({ blob, host: spec.host, port: spec.port, knownHostsPath: this.config.knownHostsPath });
        this.hostKey = verdict;
        if (verdict.status === 'match') return true;
        const message = `ssh host "${this.alias}" (${spec.user}@${spec.host}:${spec.port}) host key ${verdict.status}${verdict.detail === undefined ? '' : `: ${verdict.detail}`}`;
        if (verdict.status === 'unknown') {
          this.logger?.warn?.(`ssh-pool: ${message}; the host is not in known_hosts yet (hostKeyPolicy=${this.config.hostKeyPolicy})`);
          return true;
        }
        // A changed key is never "just a warning": that is the shape of a
        // man-in-the-middle, so warn mode still refuses it. Only a known_hosts
        // file the plugin cannot read may continue after the warning.
        if (this.config.hostKeyPolicy === 'strict' || verdict.status === 'mismatch') {
          this.lastError = message;
          this.logger?.warn?.(`ssh-pool: ${message}; refusing to connect (hostKeyPolicy=${this.config.hostKeyPolicy})`);
          return false;
        }
        this.logger?.warn?.(`ssh-pool: ${message}; continuing (hostKeyPolicy=warn)`);
        return true;
      }
    };
    return await new Promise((resolve, reject) => {
      let settled = false;
      const fail = (error) => {
        if (settled) return;
        settled = true;
        this.failures += 1;
        this.state = 'down';
        // Always name the host: a bare "Connection lost before handshake" tells
        // the caller nothing about which entry needs fixing.
        const cause = error instanceof Error ? error.message : String(error);
        const message = `ssh host "${this.alias}" (${spec.user}@${spec.host}:${spec.port}) failed: ${cause}`;
        this.lastError = message;
        try {
          client.end();
        } catch {
          /* already gone */
        }
        reject(new Error(message));
        this.#scheduleReconnect();
      };
      client.on('ready', () => {
        if (settled) return;
        settled = true;
        this.#client = client;
        this.state = 'ready';
        this.connects += 1;
        this.failures = 0;
        this.connectedAt = Date.now();
        this.lastUsed = Date.now();
        this.lastError = undefined;
        this.keepWarm = true;
        client.on('close', () => this.#onLost(client, 'the connection was closed'));
        client.on('end', () => this.#onLost(client, 'the connection ended'));
        client.on('error', (error) => {
          this.logger?.warn?.(`ssh-pool: ${this.alias}: ${error instanceof Error ? error.message : String(error)}`);
          this.#onLost(client, 'the connection failed');
        });
        this.logger?.info?.(`ssh-pool: ${this.alias}: connected to ${spec.user}@${spec.host}:${spec.port}`);
        resolve(client);
      });
      client.on('error', (error) => fail(error));
      client.on('close', () => {
        if (!settled) fail(new Error(`ssh host "${this.alias}" (${spec.user}@${spec.host}:${spec.port}) failed: connection closed before it was ready`));
      });
      try {
        client.connect(connectConfig);
      } catch (error) {
        fail(error);
      }
    });
  }

  /** Handle one transport drop exactly once, then retry in the background. */
  #onLost(client, reason) {
    if (this.#client !== client) return;
    this.#client = undefined;
    this.state = 'down';
    this.connectedAt = undefined;
    const message = `ssh host "${this.alias}" (${this.spec.user}@${this.spec.host}:${this.spec.port}) ${reason}`;
    this.lastError = message;
    for (const session of this.sessions.values()) session.dispose();
    this.sessions.clear();
    for (const listener of [...this.#lostListeners]) {
      try {
        listener(new Error(message));
      } catch {
        /* a listener must not break the pool */
      }
    }
    for (const waiter of this.#waiters.splice(0)) waiter();
    this.#scheduleReconnect();
  }

  /** Exponential backoff, capped; never spins forever on an unreachable host. */
  #scheduleReconnect() {
    if (this.#disposed || this.#reconnectTimer !== undefined) return;
    if (this.keepWarm !== true) return;
    const attempt = Math.min(this.reconnects + this.failures, 6);
    const delay = Math.min(500 * 2 ** Math.max(0, attempt - 1), MAX_BACKOFF_MS);
    this.#reconnectTimer = setTimeout(() => {
      this.#reconnectTimer = undefined;
      if (this.#disposed || this.#client !== undefined) return;
      // A host that never connected is probably misconfigured: stop retrying
      // and let the SSH assistant panel open it again to reset the counter.
      if (this.connects === 0 && this.failures >= 3) {
        this.logger?.warn?.(`ssh-pool: ${this.alias}: giving up after ${this.failures} attempts; open it from the SSH assistant panel to retry`);
        return;
      }
      void this.ensure().then(
        () => {
          this.reconnects += 1;
          this.logger?.info?.(`ssh-pool: ${this.alias}: reconnected`);
        },
        () => undefined
      );
    }, delay);
    if (typeof this.#reconnectTimer.unref === 'function') this.#reconnectTimer.unref();
  }

  /** Notify the operation in flight that the transport went away. */
  #registerLost(listener) {
    this.#lostListeners.add(listener);
    return () => this.#lostListeners.delete(listener);
  }

  /** Drop a client that is known to be dead so the next call reconnects. */
  #dropClient(reason) {
    const client = this.#client;
    this.#client = undefined;
    this.state = 'down';
    this.connectedAt = undefined;
    this.lastError = reason;
    try {
      client?.end();
    } catch {
      /* already gone */
    }
    this.#scheduleReconnect();
  }

  /** True when the error means the pooled client is stale; drops it and retries. */
  noteTransportGone(error) {
    if (!isTransportGone(error)) return false;
    this.#dropClient(error instanceof Error ? error.message : String(error));
    return true;
  }

  /** Take one of the host's channel slots; abort while waiting drops the wait. */
  async #acquire(signal) {
    if (signal?.aborted) throw new Error('tool call aborted');
    if (this.#slots < this.config.maxChannelsPerHost) {
      this.#slots += 1;
      return;
    }
    await new Promise((resolve, reject) => {
      const waiter = () => {
        signal?.removeEventListener('abort', onAbort);
        this.#slots += 1;
        resolve();
      };
      const onAbort = () => {
        const at = this.#waiters.indexOf(waiter);
        if (at >= 0) this.#waiters.splice(at, 1);
        reject(new Error('tool call aborted'));
      };
      this.#waiters.push(waiter);
      signal?.addEventListener('abort', onAbort, { once: true });
      if (signal?.aborted) onAbort();
    });
  }

  /** Give a slot back, handing it straight to the next waiter. */
  #release() {
    const next = this.#waiters.shift();
    if (next !== undefined) {
      next();
      return;
    }
    this.#slots = Math.max(0, this.#slots - 1);
  }

  /** Run a stateless command, retrying once when the transport was already gone. */
  async exec(command, options = {}) {
    try {
      return await this.#execAttempt(command, options);
    } catch (error) {
      if (options.retried === true || error?.dshSshRetryable !== true) throw error;
      const message = error instanceof Error ? error.message : String(error);
      this.logger?.warn?.(`ssh-pool: ${this.alias}: ${message}; reconnecting and retrying once`);
      this.#dropClient(message);
      return await this.#execAttempt(command, { ...options, retried: true });
    }
  }

  /**
   * Start a command detached and return at once.
   *
   * This is the root fix for the `nohup app &` class of problems: the plugin
   * writes the command to a private script, launches it with `setsid` (so it
   * survives the channel and the SSH session), sends its stdin to /dev/null
   * and both output streams to a log file the caller can read. Because the
   * child never holds the channel, the call returns immediately, nothing the
   * process prints can reach a later tool result, and the log lands somewhere
   * durable instead of /tmp.
   */
  async background(command, options = {}) {
    let terminator = `DSH_EOF_${randomBytes(8).toString('hex')}`;
    while (command.includes(terminator)) terminator = `DSH_EOF_${randomBytes(8).toString('hex')}`;
    const logDirShell = '${DSH_SSH_LOG_DIR:-${HOME:-/root}/.local/state/dsh-ssh/logs}';
    const stamp = new Date().toISOString().replace(/[:.]/g, '-').replace('T', '_').slice(0, 19);
    const safeAlias = String(this.alias).replace(/[^A-Za-z0-9._-]/g, '_');
    const defaultLog = `${logDirShell}/${safeAlias}-${stamp}-${randomBytes(3).toString('hex')}.log`;
    const logExpression =
      options.logPath === undefined || options.logPath === null || options.logPath === ''
        ? defaultLog
        : shQuote(options.logPath);
    const script = [
      '__dsh_umask=$(umask)',
      'umask 077',
      `__dsh_logdir="${logDirShell}"`,
      'mkdir -p "$__dsh_logdir" 2>/dev/null && chmod 700 "$__dsh_logdir" 2>/dev/null',
      `__dsh_log=${logExpression}`,
      'mkdir -p "$(dirname "$__dsh_log")" 2>/dev/null || true',
      // Create the log with 0600 before the child touches it, then hand the
      // login shell's own umask back to the detached process.
      '(umask 077; : >> "$__dsh_log") 2>/dev/null || true',
      `__dsh_script="$__dsh_logdir/.dsh-ssh-run-${randomBytes(6).toString('hex')}.sh"`,
      `cat > "$__dsh_script" <<'${terminator}'`,
      command,
      terminator,
      'chmod 700 "$__dsh_script" 2>/dev/null',
      options.cwd === undefined || options.cwd === null || options.cwd === ''
        ? 'true'
        : `cd ${shQuote(options.cwd)} 2>/dev/null || true`,
      'umask "$__dsh_umask"',
      'if command -v setsid >/dev/null 2>&1; then',
      '  setsid "${SHELL:-/bin/sh}" "$__dsh_script" >> "$__dsh_log" 2>&1 < /dev/null &',
      'else',
      '  nohup "${SHELL:-/bin/sh}" "$__dsh_script" >> "$__dsh_log" 2>&1 < /dev/null &',
      'fi',
      '__dsh_pid=$!',
      `printf 'pid=%s\\nlog=%s\\n' "$__dsh_pid" "$__dsh_log"`
    ].join('\n');
    const result = await this.exec(script, {
      timeoutMs: 15000,
      maxOutputBytes: 4000,
      signal: options.signal
    });
    const pidMatch = /^pid=(\d+)$/m.exec(result.stdout ?? '');
    const logMatch = /^log=(.+)$/m.exec(result.stdout ?? '');
    return {
      pid: pidMatch === null ? null : Number.parseInt(pidMatch[1], 10),
      logPath: logMatch === null ? null : logMatch[1].trim(),
      raw: result
    };
  }

  /** Run a stateless command on its own channel over the pooled connection. */
  async #execAttempt(command, { timeoutMs, maxOutputBytes, signal } = {}) {
    const outputLimit = outputLimitOf(maxOutputBytes);
    const client = await this.ensure();
    if (signal?.aborted) throw new Error('tool call aborted');
    await this.#acquire(signal);
    try {
      return await new Promise((resolve, reject) => {
        let stdout = '';
        let stderr = '';
        let settled = false;
        let timedOut = false;
        let aborted = false;
        let stream;
        let timer;
        let onAbort;
        let unregisterLost;
        const finish = (fn, value) => {
          if (settled) return;
          settled = true;
          if (timer !== undefined) clearTimeout(timer);
          if (onAbort !== undefined && signal !== undefined) signal.removeEventListener('abort', onAbort);
          unregisterLost?.();
          fn(value);
        };
        unregisterLost = this.#registerLost((error) => finish(reject, tagRetryable(error, stream === undefined)));
        const stop = (reason) => {
          timedOut = reason === 'timeout';
          aborted = reason === 'abort';
          // No channel yet: the timer/abort still has to settle the call, or a
          // server that never answers the channel-open request hangs forever.
          if (stream === undefined) {
            if (timedOut) {
              finish(resolve, { stdout, stderr, exitCode: null, signal: null, timedOut: true, aborted: false });
            } else {
              finish(reject, new Error('tool call aborted'));
            }
            return;
          }
          try {
            stream.signal('KILL');
          } catch {
            /* the channel may already be gone */
          }
          try {
            stream.close();
          } catch {
            /* ignore */
          }
        };
        try {
          client.exec(command, (error, channel) => {
            if (error) {
              // The channel never opened, so the command cannot have started.
              finish(reject, tagRetryable(error, true));
              return;
            }
            if (settled) {
              // The deadline or an abort already settled the call while the
              // channel-open request was in flight: never start the command.
              try {
                channel.close();
              } catch {
                /* already gone */
              }
              return;
            }
            stream = channel;
            channel.on('data', (chunk) => {
              stdout += chunk.toString('utf8');
              if (Buffer.byteLength(stdout, 'utf8') > outputLimit * 4) stdout = stdout.slice(-outputLimit * 2);
            });
            channel.stderr.on('data', (chunk) => {
              stderr += chunk.toString('utf8');
              if (Buffer.byteLength(stderr, 'utf8') > outputLimit * 4) stderr = stderr.slice(-outputLimit * 2);
            });
            channel.on('close', (code, signalName) => {
              this.lastUsed = Date.now();
              const exitCode = typeof code === 'number' ? code : null;
              finish(resolve, {
                stdout,
                stderr,
                exitCode,
                signal: signalName ?? null,
                timedOut,
                aborted
              });
            });
            channel.on('error', (streamError) => finish(reject, streamError));
            channel.end();
          });
        } catch (error) {
          // ssh2 throws synchronously when the client is no longer connected;
          // the channel never opened, so a retry on a fresh client is safe.
          finish(reject, tagRetryable(error, true));
        }
        // A synchronous failure already settled the call; do not leave a timer
        // or an abort listener behind.
        if (settled) return;
        if (timeoutMs > 0) {
          timer = setTimeout(() => stop('timeout'), timeoutMs);
          if (typeof timer.unref === 'function') timer.unref();
        }
        if (signal !== undefined) {
          if (signal.aborted) stop('abort');
          else {
            onAbort = () => stop('abort');
            signal.addEventListener('abort', onAbort, { once: true });
          }
        }
      });
    } finally {
      this.lastUsed = Date.now();
      this.#release();
    }
  }

  /**
   * The named persistent shell session for one caller, created on first use.
   *
   * Sessions are scoped by caller: two DSH sessions asking for `main` on the
   * same host get two different shells, so one session's `cd`/`export` can
   * never become another session's starting state. The TCP connection is still
   * shared, because a channel carries no shell state.
   */
  session(name, ownerKey = 'host') {
    const key = `${ownerKey}::${name}`;
    const existing = this.sessions.get(key);
    if (existing !== undefined && existing.alive) return existing;
    const created = new ShellSession(this, name, key, ownerKey);
    this.sessions.set(key, created);
    return created;
  }

  /** Record activity so an idle connection is not reaped while it is in use. */
  touch() {
    this.lastUsed = Date.now();
  }

  /** Close the live shell sessions belonging to one caller. */
  releaseSessions(ownerKey) {
    const closed = [];
    for (const [key, session] of [...this.sessions]) {
      if (session.ownerKey !== ownerKey) continue;
      session.dispose('the owning session released it');
      this.sessions.delete(key);
      closed.push(session.name);
    }
    return closed;
  }

  /** Whether any caller other than `ownerKey` still holds a shell here. */
  otherOwnersActive(ownerKey) {
    for (const session of this.sessions.values()) {
      if (session.ownerKey !== ownerKey && session.alive) return true;
    }
    return false;
  }

  /** Close this host's sessions and connection. */
  close(reason = 'closed by request', { keepWarm = false } = {}) {
    this.keepWarm = keepWarm;
    if (this.#reconnectTimer !== undefined) {
      clearTimeout(this.#reconnectTimer);
      this.#reconnectTimer = undefined;
    }
    for (const session of this.sessions.values()) session.dispose('the connection was closed');
    this.sessions.clear();
    const client = this.#client;
    this.#client = undefined;
    this.state = 'idle';
    this.connectedAt = undefined;
    this.lastError = reason;
    try {
      client?.end();
    } catch {
      /* already gone */
    }
  }

  dispose() {
    this.#disposed = true;
    this.close('plugin unloaded');
    for (const waiter of this.#waiters.splice(0)) waiter();
  }

  /** Plain-JSON status for the tools. */
  snapshot() {
    const now = Date.now();
    return {
      alias: this.alias,
      host: this.spec.host,
      port: this.spec.port,
      user: this.spec.user,
      keyName: this.spec.identityFile === undefined ? (this.spec.agent !== undefined ? `agent:${this.spec.agent}` : null) : basenameOf(this.spec.identityFile),
      source: this.spec.source,
      state: this.state,
      connected: this.connected,
      connectedSeconds: this.connectedAt === undefined ? 0 : Math.round((now - this.connectedAt) / 1000),
      idleSeconds: (this.lastUsed ?? this.connectedAt) === undefined ? null : Math.round((now - (this.lastUsed ?? this.connectedAt)) / 1000),
      connects: this.connects,
      reconnects: this.reconnects,
      failures: this.failures,
      /** Operations the agent asked for on this host since the plugin loaded. */
      commands: this.commands ?? 0,
      lastCommand: this.lastCommand ?? null,
      lastCommandSeconds: this.lastCommandAt === undefined ? null : Math.round((now - this.lastCommandAt) / 1000),
      sessions: [...this.sessions.values()].map((session) => ({
        name: session.name,
        owner: session.ownerKey,
        ownerShort: String(session.ownerKey).slice(0, 8),
        alive: session.alive,
        commands: session.commands,
        idleSeconds: Math.round((now - session.lastUsed) / 1000),
        ageSeconds: Math.round((now - session.createdAt) / 1000)
      })),
      hostKey: this.hostKey === undefined ? null : { status: this.hostKey.status, type: this.hostKey.keyType ?? null },
      lastError: this.lastError ?? null
    };
  }
}

/** The pool: host table, connections, and lifecycle. */
export class SshPool {
  #hosts = new Map();
  #connections = new Map();
  #idleTimer;
  #disposed = false;

  constructor({ hosts, config, logger, warnings = [], meta }) {
    this.config = config;
    this.logger = logger;
    this.warnings = [...warnings];
    /** Optional persistent metadata (remarks, permission grants, idle overrides). */
    this.meta = meta;
    for (const [alias, spec] of hosts) this.#hosts.set(alias, spec);
    // Ticking always, because the idle timeout can be changed from the UI and
    // each host may override it.
    this.#idleTimer = setInterval(() => this.#reapIdle(), 5000);
    if (typeof this.#idleTimer.unref === 'function') this.#idleTimer.unref();
  }

  /**
   * Per-host metadata: remark, hidden switch and idle override.
   *
   * A legacy metadata double (`caps`/`level`/`visible`, no `hidden`) is upgraded
   * by the store's own migration, so this seam and the state file can never
   * disagree.
   */
  hostMeta(alias) {
    const meta = normalizeHost(alias, this.meta?.host?.(alias));
    return {
      remark: meta.remark,
      hidden: meta.hidden,
      idleTimeoutMs: meta.idleTimeoutMs
    };
  }

  /**
   * Whether the agent-facing tools may touch this host.
   *
   * A hidden host stays fully managed in the SSH assistant (you can connect,
   * or unhide it), but the tools treat it exactly like an unknown host: no
   * listing, no command, no transfer.
   */
  hostVisible(alias) {
    return this.hostMeta(alias).hidden !== true;
  }

  /** The idle timeout that applies to one host right now (0 = never close). */
  idleTimeoutFor(alias) {
    const override = this.hostMeta(alias).idleTimeoutMs;
    if (override !== null) return override;
    const live = this.meta?.settings?.()?.idleTimeoutMs;
    return Number.isFinite(live) ? live : this.config.idleTimeoutMs;
  }

  /** Whether large log output should be routed to the tool-less side analyzer. */
  logAnalysis() {
    return this.meta?.settings?.()?.logAnalysis === true;
  }

  /** The live per-stream output budget the assistant setting controls. */
  outputLimit() {
    const live = this.meta?.settings?.()?.maxOutputBytes;
    return Number.isFinite(live) && live > 0 ? live : this.config.maxOutputBytes;
  }

  /**
   * The deadline policy for commands.
   *
   * The three numbers are constants by design (contract rev3): safety factor 3,
   * floor 5 s, ceiling 30 min. They are not settings — an old `state.json` or
   * plugin config that still carries `timeoutMultiplier` / `timeoutFloorMs` /
   * `timeoutCeilingMs` cannot move a deadline any more. Only the estimate used
   * for a command that matches no bucket still comes from `defaultTimeoutMs`.
   */
  timeoutPolicy() {
    const fallbackEstimateMs = Number(this.config.defaultTimeoutMs);
    return {
      multiplier: 3,
      floorMs: 5000,
      ceilingMs: 1800000,
      fallbackEstimateMs: Number.isFinite(fallbackEstimateMs) && fallbackEstimateMs > 0 ? fallbackEstimateMs : 30000
    };
  }

  /** The live deadline for one file transfer (large files get a longer one). */
  transferTimeout() {
    const live = this.meta?.settings?.()?.transferTimeoutMs;
    return Number.isFinite(live) && live > 0 ? live : this.config.transferTimeoutMs;
  }

  get aliases() {
    return [...this.#hosts.keys()];
  }

  has(alias) {
    return this.#hosts.has(alias);
  }

  spec(alias) {
    return this.#hosts.get(alias);
  }

  /** Resolve a host alias to its connection entry, creating it on first use. */
  connection(alias) {
    if (!this.#hosts.has(alias)) {
      const known = this.aliases;
      throw new Error(
        `unknown ssh host "${alias}"; known hosts: ${known.length > 0 ? known.join(', ') : '(none configured — check ~/.ssh/config or the plugin config)'}`
      );
    }
    let connection = this.#connections.get(alias);
    if (connection === undefined) {
      connection = new HostConnection(alias, this.#hosts.get(alias), this.config, this.logger);
      this.#connections.set(alias, connection);
    }
    return connection;
  }

  /** Every host connection created so far, for session bookkeeping. */
  connections() {
    return [...this.#connections.values()];
  }

  /** Aliases selected by `autoConnect` (`true`/`"*"` means every host). */
  autoConnectAliases() {
    const wanted = this.config.autoConnect;
    if (wanted.length === 1 && wanted[0] === '*') return this.aliases.filter((alias) => this.hostVisible(alias));
    return wanted.filter((alias) => this.#hosts.has(alias) && this.hostVisible(alias));
  }

  #reapIdle() {
    const now = Date.now();
    for (const connection of this.#connections.values()) {
      if (!connection.connected) continue;
      // Never reap a connection that is carrying a command, a transfer or a
      // session: the idle timeout is for idle connections.
      if (connection.busy) continue;
      const limit = this.idleTimeoutFor(connection.alias);
      if (!Number.isFinite(limit) || limit <= 0) continue;
      const lastUsed = connection.lastUsed ?? connection.connectedAt ?? now;
      if (now - lastUsed >= limit) {
        this.logger?.info?.(`ssh-pool: closing idle connection ${connection.alias} after ${Math.round((now - lastUsed) / 1000)}s`);
        connection.close('idle timeout');
      }
    }
  }

  /**
   * Release one caller's shell sessions on a host.
   *
   * The TCP connection is shared, so it closes only when no other caller still
   * holds a session: one session's cleanup must not tear the transport out
   * from under another.
   */
  releaseForOwner(alias, ownerKey) {
    const connection = this.connection(alias);
    const closed = connection.releaseSessions(ownerKey);
    const keptForOthers = connection.otherOwnersActive(ownerKey);
    if (!keptForOthers) connection.close('released by the calling session');
    return { alias, closedSessions: closed, keptForOthers };
  }

  /** Release one caller's sessions on every host, closing idle transports. */
  releaseAllForOwner(ownerKey) {
    return this.connections().map((connection) => this.releaseForOwner(connection.alias, ownerKey));
  }

  /**
   * Record one model-facing operation against its host: the per-host command
   * counter and last command the connection row shows.
   *
   * Called by the tool layer, so it only covers work an agent (or the panel)
   * actually asked for — internal session-state saves stay out of it.
   */
  recordActivity({ alias, detail = '' } = {}) {
    const text = redactText(String(detail ?? '')).replace(/\s+/g, ' ').trim().slice(0, 160);
    const connection = this.#connections.get(alias);
    if (connection === undefined) return;
    connection.commands = (connection.commands ?? 0) + 1;
    connection.lastCommandAt = Date.now();
    connection.lastCommand = text;
  }

  /** Status of every configured host, connected or not, with its stored metadata. */
  status() {
    return this.aliases.map((alias) => {
      const connection = this.#connections.get(alias);
      const base = connection !== undefined ? connection.snapshot() : this.#idleSnapshot(alias);
      const meta = this.hostMeta(alias);
      return {
        ...base,
        hidden: meta.hidden,
        remark: meta.remark,
        idleTimeoutMs: meta.idleTimeoutMs,
        effectiveIdleTimeoutMs: this.idleTimeoutFor(alias)
      };
    });
  }

  /** The status row of a host that has never been connected. */
  #idleSnapshot(alias) {
    const spec = this.#hosts.get(alias);
    return {
      alias,
      host: spec.host,
      port: spec.port,
      user: spec.user,
      keyName: spec.identityFile === undefined ? (spec.agent !== undefined ? `agent:${spec.agent}` : null) : basenameOf(spec.identityFile),
      source: spec.source,
      state: 'idle',
      connected: false,
      connectedSeconds: 0,
      idleSeconds: null,
      connects: 0,
      reconnects: 0,
      failures: 0,
      commands: 0,
      lastCommand: null,
      lastCommandSeconds: null,
      sessions: [],
      hostKey: null,
      lastError: null
    };
  }

  closeAll() {
    for (const connection of this.#connections.values()) connection.close('closed by request');
  }

  dispose() {
    if (this.#disposed) return;
    this.#disposed = true;
    if (this.#idleTimer !== undefined) clearInterval(this.#idleTimer);
    for (const connection of this.#connections.values()) connection.dispose();
    this.#connections.clear();
  }
}

export { HostConnection, ShellSession };

