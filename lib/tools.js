/**
 * The twelve model-facing tools over the pool.
 *
 * Every tool is a plain ToolDefinition object — the plugin resolves no Harness
 * package, so it keeps working across Harness upgrades that do not change the
 * registry contract.
 *
 * @module dsh-ssh-pool/tools
 */
import { transferFile } from './transfer.js';
import { deadlineFor } from './timeouts.js';
import { protectedWritePath } from './policy.js';
import { commandKind } from './diagnostics.js';
import { redactText } from './redact.js';
import { editRemoteFile, globRemote, grepRemote, readRemoteFile, writeRemoteFile } from './files.js';

const TEXT_OUTPUT = {
  type: 'object',
  properties: {
    text: { type: 'string' },
    truncated: { type: 'boolean' }
  },
  required: ['text', 'truncated'],
  additionalProperties: false
};

/** The side analyzer's result, or null when the raw output is returned. */
const ANALYSIS_SCHEMA = {
  oneOf: [
    {
      type: 'object',
      properties: {
        summary: { type: 'string' },
        model: { type: 'string' },
        inputBytes: { type: 'number' },
        analyzedBytes: { type: 'number' },
        inputLines: { type: 'number' },
        analyzedLines: { type: 'number' },
        truncated: { type: 'boolean' },
        source: { type: 'string' }
      },
      required: ['summary', 'model', 'inputBytes', 'analyzedBytes', 'inputLines', 'analyzedLines', 'truncated', 'source'],
      additionalProperties: false
    },
    { type: 'null' }
  ]
};

const ANALYSIS_NOTE = 'analyzed by a tool-less side model; no commands were executed. Raw output withheld by 日志旁路分析; pass analyze:false to get it';
const ANALYSIS_ERROR_SCHEMA = { oneOf: [{ type: 'string' }, { type: 'null' }] };
const formatBytes = (value) =>
  typeof value === 'number' && Number.isFinite(value) ? (value >= 1024 ? `${Math.round(value / 1024)} KB` : `${value} B`) : '?';
const coverageText = (analysis) =>
  `analyzed ${formatBytes(analysis.analyzedBytes)} / ${analysis.analyzedLines ?? '?'} lines of ${formatBytes(analysis.inputBytes)} / ${analysis.inputLines ?? '?'} lines${analysis.truncated ? ', truncated' : ''}`;

const STATUS_FIELDS = {
  alias: { type: 'string' },
  host: { type: 'string' },
  port: { type: 'number' },
  user: { type: 'string' },
  keyName: { oneOf: [{ type: 'string' }, { type: 'null' }] },
  source: { type: 'string' },
  state: { type: 'string' },
  connected: { type: 'boolean' },
  connectedSeconds: { type: 'number' },
  idleSeconds: { oneOf: [{ type: 'number' }, { type: 'null' }] },
  connects: { type: 'number' },
  reconnects: { type: 'number' },
  failures: { type: 'number' },
  sessions: { type: 'array', items: { type: 'object' } },
  hostKey: { oneOf: [{ type: 'object' }, { type: 'null' }] },
  lastError: { oneOf: [{ type: 'string' }, { type: 'null' }] },
  hidden: { type: 'boolean' },
  remark: { type: 'string' },
  idleTimeoutMs: { oneOf: [{ type: 'number' }, { type: 'null' }] },
  effectiveIdleTimeoutMs: { type: 'number' }
};

const STATUS_REQUIRED = ['alias', 'host', 'port', 'user', 'state', 'connected'];
const STATUS_SCHEMA = { type: 'object', properties: STATUS_FIELDS, required: STATUS_REQUIRED };

const HOSTS_SCHEMA = {
  type: 'object',
  properties: {
    hosts: { type: 'array', items: STATUS_SCHEMA },
    count: { type: 'number' },
    policyHint: { type: 'string' },
    warnings: { type: 'array', items: { type: 'string' } }
  },
  required: ['hosts', 'count'],
  additionalProperties: false
};

function text(value) {
  return [{ type: 'text', text: value }];
}

/** The calling DSH session's id: shell sessions are scoped to it. */
function ownerOf(exec) {
  const id = exec?.agent?.id;
  return typeof id === 'string' && id.length > 0 ? id : 'local';
}

/** One-line-per-host rendering for `ssh_hosts`. */
function renderHosts(value) {
  if (value.hosts.length === 0) return 'No SSH hosts are configured. Check ~/.ssh/config or the plugin `hosts` config.';
  const lines = value.hosts.map((host) => {
    const key = host.keyName === null || host.keyName === undefined ? 'agent/default' : host.keyName;
    const parts = [
      `${host.alias} → ${host.user}@${host.host}:${host.port}`,
      `[${host.state}]`,
      `key=${key}`,
      `connects=${host.connects}`,
      host.idleSeconds === null ? 'never used' : `idle=${host.idleSeconds}s`
    ];
    if (host.connected) parts.push(`up=${host.connectedSeconds}s`);
    if (host.reconnects > 0) parts.push(`reconnects=${host.reconnects}`);
    if (Array.isArray(host.sessions) && host.sessions.length > 0) {
      parts.push(`sessions=${host.sessions.map((session) => `${session.name}@${session.ownerShort ?? session.owner}`).join(',')}`);
    }
    if (typeof host.remark === 'string' && host.remark.length > 0) parts.push(`note=${host.remark}`);
    if (host.lastError !== null && host.lastError !== undefined && !host.connected) parts.push(`last error: ${host.lastError}`);
    return `- ${parts.join(' ')}`;
  });
  const hints = typeof value.policyHint === 'string' && value.policyHint.length > 0 ? `\n[policy] ${value.policyHint}` : '';
  const warnings = value.warnings.length > 0 ? `\n[warnings] ${value.warnings.join('; ')}` : '';
  return `${lines.join('\n')}${hints}${warnings}`;
}

/** The bash-tool result shape: body first, then one marker per line. */
function renderRun(value, args) {
  const stdout = value.stdout.text;
  const stderr = value.stderr.text;
  let body = value.mode === 'background' ? '' : stdout;
  if (value.mode === 'background') {
    body = `[started detached] pid=${value.pid ?? '?'}\n[log] ${value.logPath ?? '(unknown)'}`;
  } else if (stderr.length > 0) {
    if (body.length > 0 && !body.endsWith('\n')) body += '\n';
    body += `[stderr]\n${stderr}`;
  }
  if (body.length === 0) body = '(no output)';
  if (value.analysis !== null && value.analysis !== undefined) {
    body = `[side analysis · ${value.analysis.model} · no tools · ${coverageText(value.analysis)}]\n${value.analysis.summary}\n[${ANALYSIS_NOTE}]`;
  }
  const markers = [];
  // Prefer the resolved session name; fall back to the call's own argument,
  // which is what the presented value carries back for a boolean `true`.
  const requested = args?.session;
  const sessionName =
    requested === true || requested === 'true'
      ? 'main'
      : typeof value.session === 'string' && value.session.length > 0 && value.session !== 'true'
        ? value.session
        : typeof requested === 'string' && requested.length > 0 && requested !== 'false'
          ? requested
          : null;
  if (value.mode === 'session' && sessionName !== null) {
    markers.push(`[session: ${sessionName}${value.cwd === null ? '' : `, cwd: ${value.cwd}`}]`);
  }
  if (value.timedOut) {
    const estimate = typeof value.estimateMs === 'number' ? `; the estimate was ${value.estimateMs}ms × ${value.multiplier ?? '?'}` : '';
    markers.push(`[timed out after ${value.timeoutMs}ms; the remote command was killed${estimate}]`);
  }
  if (value.sessionEnded) {
    markers.push(`[session ended: ${value.endReason ?? 'closed'}; working directory and exported variables were lost — the next call starts a fresh session]`);
  }
  if (value.aborted) markers.push('[tool call aborted]');
  else if (value.signal !== null) markers.push(`[killed by signal: ${value.signal}]`);
  else if (value.exitCode !== null && value.exitCode !== 0) markers.push(`[exit code: ${value.exitCode}]`);
  if (value.mode === 'background') {
    markers.push(`[the process keeps running; follow it with: tail -n <lines> ${value.logPath ?? '<log>'}]`);
  }
  if (typeof value.hint === 'string' && value.hint.length > 0) markers.push(`[hint] ${value.hint}`);
  if (typeof value.analysisError === 'string' && value.analysisError.length > 0) {
    markers.push(`[旁路分析不可用: ${value.analysisError}]`);
  }
  return markers.length === 0 ? body : `${body.endsWith('\n') ? body : `${body}\n`}${markers.join('\n')}`;
}

/** Outer schema shared by the run result, stateless and session alike. */
const RUN_SCHEMA = {
  type: 'object',
  properties: {
    host: { type: 'string' },
    mode: { type: 'string' },
    session: { oneOf: [{ type: 'string' }, { type: 'null' }] },
    exitCode: { oneOf: [{ type: 'number' }, { type: 'null' }] },
    signal: { oneOf: [{ type: 'string' }, { type: 'null' }] },
    timedOut: { type: 'boolean' },
    aborted: { type: 'boolean' },
    sessionEnded: { type: 'boolean' },
    endReason: { oneOf: [{ type: 'string' }, { type: 'null' }] },
    timeoutMs: { type: 'number' },
    estimateMs: { oneOf: [{ type: 'number' }, { type: 'null' }] },
    multiplier: { oneOf: [{ type: 'number' }, { type: 'null' }] },
    deadlineSource: { oneOf: [{ type: 'string' }, { type: 'null' }] },
    stdout: TEXT_OUTPUT,
    stderr: TEXT_OUTPUT,
    cwd: { oneOf: [{ type: 'string' }, { type: 'null' }] },
    durationMs: { type: 'number' },
    handshakeMs: { type: 'number' },
    reused: { type: 'boolean' },
    pid: { oneOf: [{ type: 'number' }, { type: 'null' }] },
    logPath: { oneOf: [{ type: 'string' }, { type: 'null' }] },
    hint: { oneOf: [{ type: 'string' }, { type: 'null' }] },
    analysis: ANALYSIS_SCHEMA,
    analysisError: ANALYSIS_ERROR_SCHEMA
  },
  required: ['host', 'mode', 'timedOut', 'aborted', 'sessionEnded', 'timeoutMs', 'stdout', 'stderr', 'durationMs', 'handshakeMs', 'reused', 'analysis', 'analysisError'],
  additionalProperties: false
};

/** Cap one stream to the configured byte budget. */
/** cap() plus secret redaction, preserving the { text, truncated } shape. */
function safeCap(value, maxOutputBytes) {
  // Redact BEFORE capping: capping first can cut a secret in half and leave the
  // head fragment behind in the transcript. Non-strings (undefined/null) must
  // not become the literal "undefined".
  const raw = typeof value === 'string' ? value : value === null || value === undefined ? '' : String(value);
  return cap(redactText(raw), maxOutputBytes);
}

function cap(text, maxOutputBytes) {
  const size = Buffer.byteLength(text, 'utf8');
  if (size <= maxOutputBytes) return { text, truncated: false };
  const buffer = Buffer.from(text, 'utf8');
  const head = buffer.subarray(0, Math.floor(maxOutputBytes * 0.6)).toString('utf8');
  const tail = buffer.subarray(buffer.length - Math.floor(maxOutputBytes * 0.4)).toString('utf8');
  return {
    text: `${head}\n[... ${size - maxOutputBytes} bytes omitted; capped at ${maxOutputBytes} bytes per stream ...]\n${tail}`,
    truncated: true
  };
}

/** Connect if needed and report what the connection cost. */
async function ensureTimed(connection) {
  if (connection.connected) return 0;
  const started = Date.now();
  await connection.ensure();
  return Date.now() - started;
}

/**
 * Compile one author-facing parameter map into the object-rooted JSON Schema
 * the registry hands to the model.
 *
 * A definition passed to a raw `ctx.tools.register` is forwarded verbatim,
 * unlike `defineTool`, which compiles the author-facing map itself. A bare
 * property map therefore reaches the provider as a schema without `type`, and
 * a strict provider rejects the whole request ("schema must be a JSON Schema
 * of 'type: \"object\"', got 'type: null'"). The per-property `required: true`
 * shorthand moves into the top-level `required` list.
 */
function parameterSchema(properties) {
  const required = [];
  const compiled = {};
  for (const [name, schema] of Object.entries(properties)) {
    if (schema.required === true) {
      required.push(name);
      const rest = { ...schema };
      delete rest.required;
      compiled[name] = rest;
    } else {
      compiled[name] = schema;
    }
  }
  return {
    type: 'object',
    properties: compiled,
    ...(required.length === 0 ? {} : { required })
  };
}

/**
 * Build every tool definition bound to one pool.
 * @param pool - the live pool.
 * @param config - the normalized plugin config.
 * @returns the tool definitions, ready for `ctx.tools.register`.
 */
const resultBytes = (value) => {
  let bytes = 0;
  const add = (text) => {
    if (typeof text === 'string') bytes += Buffer.byteLength(text, 'utf8');
  };
  add(value?.stdout?.text);
  add(value?.stderr?.text);
  add(value?.content);
  if (Array.isArray(value?.matches)) for (const match of value.matches) add(match?.text);
  return bytes;
};

const resultAnalysis = (value) => {
  if (value === null || typeof value !== 'object') return null;
  if (!Object.prototype.hasOwnProperty.call(value, 'analysis') && !Object.prototype.hasOwnProperty.call(value, 'analysisError')) return null;
  if (typeof value.analysisError === 'string' && value.analysisError.length > 0) {
    if (value.analysisError.includes('正忙')) return 'busy';
    if (value.analysisError.includes('没有返回摘要')) return 'empty';
    return 'error';
  }
  return value.analysis === null ? 'skipped' : 'success';
};

const resultFailure = (value) => {
  if (value?.timedOut === true) return { outcome: 'timeout', reason: 'timeout' };
  if (value?.aborted === true) return { outcome: 'aborted', reason: 'aborted' };
  return { outcome: 'ok', reason: null };
};

const thrownFailure = (error) => {
  const message = error instanceof Error ? error.message : String(error ?? '');
  if (/\[ssh-pool policy\]/.test(message)) return { outcome: 'denied', reason: 'policy' };
  if (/timed out|timeout/i.test(message)) return { outcome: 'timeout', reason: 'timeout' };
  if (/abort|cancel/i.test(message)) return { outcome: 'aborted', reason: 'aborted' };
  if (/unknown\s+(?:ssh\s+)?host|required|invalid|not found|missing/i.test(message)) return { outcome: 'error', reason: 'invalid' };
  if (/connect|handshake|authentication|host key|ssh/i.test(message)) return { outcome: 'error', reason: 'connection' };
  return { outcome: 'error', reason: 'other' };
};

export function createTools(pool, config, extras = {}) {
  const policy = extras.policy;

  /**
   * Resolve a host the agent-facing tools may use.
   *
   * A host switched off in the SSH assistant reads exactly like an unknown
   * host, so a session can neither list it nor reach it — and learns nothing
   * from the error.
   */
  const visibleHost = (alias) => {
    if (typeof alias !== 'string' || alias.length === 0) throw new Error('host is required');
    if (!pool.has(alias) || pool.hostVisible(alias) === false) {
      const known = pool.aliases.filter((candidate) => pool.hostVisible(candidate));
      throw new Error(`unknown ssh host "${alias}"; known hosts: ${known.length > 0 ? known.join(', ') : '(none available)'}`);
    }
    return pool.connection(alias);
  };

  /** The hosts the agent may see, in table order. */
  const visibleStatus = () => pool.status().filter((entry) => pool.hostVisible(entry.alias));

  /** The live per-stream output budget (the SSH assistant can change it). */
  const outputLimit = () => (typeof pool.outputLimit === 'function' ? pool.outputLimit() : config.maxOutputBytes);

  /**
   * The live deadline policy: estimate × multiplier, clamped. Command deadlines
   * are derived per command, never a fixed number.
   */
  const timeoutPolicy = () =>
    typeof pool.timeoutPolicy === 'function'
      ? pool.timeoutPolicy()
      : {
          multiplier: 3,
          floorMs: 5000,
          ceilingMs: 1800000,
          fallbackEstimateMs: config.defaultTimeoutMs ?? 30000
        };

  /** The live transfer deadline; a transfer is cancelled rather than left hanging. */
  const transferTimeout = () =>
    typeof pool.transferTimeout === 'function' ? pool.transferTimeout() : (Number(config.transferTimeoutMs) > 0 ? config.transferTimeoutMs : 600000);

  /* ── optional side analysis ─────────────────────────────────────────────── */
  const ANALYZE_MIN_BYTES = 4096;
  /** Paths whose content is a log rather than a config file. */
  const LOG_PATH = /(?:^|\/)(?:var\/log\/|.*\.log(?:\.\d+)?(?:\.gz)?$|.*\.journal$|journal|syslog|dmesg)/i;
  /** Commands whose output is normally a log, not a one-line state probe. */
  const LOG_COMMAND = /\b(?:journalctl|dmesg|tail|head|zcat|zgrep|grep|awk|sed|cat)\b/i;
  const diagnostics = extras.diagnostics;
  const analyzerRun =
    typeof extras.analyzer === 'function'
      ? extras.analyzer
      : typeof extras.analyzer?.run === 'function'
        ? extras.analyzer.run.bind(extras.analyzer)
        : null;
  const analysisOn = () => (typeof pool.logAnalysis === 'function' ? pool.logAnalysis() === true : false);
  const runAnalysis = async ({ tool, target, text, signal, sessionId }) => {
    if (analyzerRun === null || typeof text !== 'string' || text.length === 0) return { error: '旁路分析未配置' };
    try {
      const result = await analyzerRun({ tool, target, text, signal, sessionId, bytes: Buffer.byteLength(text, 'utf8') });
      if (result !== null && typeof result === 'object' && typeof result.summary === 'string') return result;
      if (result !== null && typeof result === 'object' && typeof result.error === 'string') return { error: result.error };
      return { error: '旁路分析没有返回结果' };
    } catch (error) {
      return { error: error instanceof Error ? error.message : String(error) };
    }
  };
  /** `analyze:true` forces, `analyze:false` vetoes, omitted follows the panel switch. */
  const shouldAnalyze = (flag, heuristic, bytes) => {
    if (flag === false) return false;
    const forced = flag === true;
    const enabled = forced || (analysisOn() && heuristic);
    return enabled && bytes >= (forced ? 1 : ANALYZE_MIN_BYTES);
  };
  const sshHosts = {
    name: 'ssh_hosts',
    description:
      'List the SSH hosts this plugin can operate: alias, user@host:port, identity file, live connection state, sessions and the last error. Hosts come from the OpenSSH client config (~/.ssh/config, with forge entries such as github.com and gitee.com excluded) plus the plugin \'hosts\' config. Read-only; the first call to a host connects automatically, and the SSH assistant panel can open or close connections.',
    parameters: {
      host: {
        type: 'string',
        description: 'Optional host alias to report in detail. Omit to list every host.'
      }
    },
    output: {
      schema: HOSTS_SCHEMA,
      render: (_args, value) => text(renderHosts(value))
    },
    isConcurrencySafe: () => true,
    async execute(args) {
      const wanted = typeof args?.host === 'string' && args.host.length > 0 ? args.host : undefined;
      if (wanted !== undefined && (!pool.has(wanted) || pool.hostVisible(wanted) === false)) {
        const known = pool.aliases.filter((candidate) => pool.hostVisible(candidate));
        throw new Error(`unknown ssh host "${wanted}"; known hosts: ${known.join(', ') || '(none available)'}`);
      }
      const hosts = visibleStatus().filter((entry) => wanted === undefined || entry.alias === wanted);
      return {
        hosts,
        count: hosts.length,
        policyHint: typeof policy?.hints === 'function' ? policy.hints() : '',
        warnings: wanted === undefined ? pool.warnings : []
      };
    }
  };

  const sshRun = {
    name: 'ssh_run',
    description: `Run a shell command on a configured SSH host over this plugin's pooled connection, so repeated calls to the same host skip the SSH handshake. Without "session" each call runs in a fresh remote shell. With "session" the working directory and exported variables carry over to later calls with the same name, but every call still runs in its own process, so each result contains only that command's output. Output is capped per stream at ${outputLimit()} bytes by default and the SSH assistant adjusts that; for more, redirect to a remote file and read it with ssh_transfer, or filter remotely with grep/head/tail. Every command runs under a deadline derived from an estimate of its run time (expectedMs when you give one, otherwise inferred from the command) times a safety factor, so nothing waits forever: give expectedMs for slow work and omit it for quick commands. Read the [exit code: N] marker; a non-zero exit is reported, not failed. A small guard refuses only commands that would make the machine unbootable; the plugin policy guard lists them, and ssh_hosts includes the hints.`,
    parameters: {
      host: {
        type: 'string',
        required: true,
        description: 'Host alias from ~/.ssh/config or the plugin config; ssh_hosts lists them.'
      },
      command: {
        type: 'string',
        required: true,
        description: 'The shell command to run on the remote host.'
      },
      session: {
        oneOf: [{ type: 'string' }, { type: 'boolean' }],
        description:
          'Run in a named session: a string names it (sessions are per host), true uses the default session "main". Working directory and exported variables carry over to later calls in the same session; each call still runs in its own process, so outputs never mix. Omit for a fresh shell per call.'
      },
      cwd: {
        type: 'string',
        description: 'Working directory for this command. In session mode it also becomes the session directory for later calls.'
      },
      analyze: {
        type: 'boolean',
        description:
          'Route a large log-like result to the tool-less side analyzer and return only its summary. true forces it, false returns raw output; omit to follow the SSH assistant\'s 日志旁路分析 switch.'
      },
      expectedMs: {
        type: 'number',
        description:
          'Your estimate of how long the command should take, in milliseconds. The deadline is derived from it: estimate × a constant safety factor of 3, clamped between a floor of 5 s and a ceiling of 30 min. Say how long you expect a build, deploy, backup or service restart to take instead of relying on a fixed timeout. Omit it for quick commands: the estimate only decides how long a hung command may sit before its channel is killed, so inflating it delays the failure instead of speeding anything up.'
      },
      timeoutMs: {
        type: 'number',
        description:
          'Explicit deadline in milliseconds; it overrides the derived value verbatim (no multiplier applied). Omit it to let the plugin derive the deadline from expectedMs, or from the command\'s own shape when you gave no estimate. Nothing ever waits forever.'
      },
      background: {
        type: 'boolean',
        description:
          'Start the command detached and return immediately instead of waiting for it: the plugin launches it with setsid (fallback nohup), sends stdin to /dev/null, appends both output streams to a log file, and reports the PID and log path. Use this for daemons, servers and long tasks — do NOT append "&" yourself, because an unredirected background process keeps the channel open and the call would wait for it.'
      },
      logPath: {
        type: 'string',
        description:
          'Log file for background mode (appended to). Default: ~/.local/state/dsh-ssh/logs/<host>-<timestamp>.log — never /tmp; pass /var/log/<app>/<app>.log for a system service.'
      }
    },
    output: {
      schema: RUN_SCHEMA,
      render: (args, value) => text(renderRun(value, args))
    },
    isConcurrencySafe: () => true,
    presentCall(args) {
      const session = typeof args?.session === 'string' ? args.session : args?.session === true ? 'main' : undefined;
      return {
        card: 'terminal',
        title: `ssh ${args?.host ?? '?'}: ${args?.command ?? ''}`,
        ...session === undefined ? {} : { description: `session ${session}` },
        ...typeof args?.cwd === 'string' ? { cwd: args.cwd } : {}
      };
    },
    async execute(args, exec) {
      const host = args?.host;
      const command = args?.command;
      if (typeof host !== 'string' || host.length === 0) throw new Error('host is required');
      if (typeof command !== 'string' || command.trim().length === 0) throw new Error('command is required');
      // Deadlines are derived, never fixed: an estimate (the caller's, or one
      // inferred from the command's shape) times a safety factor, clamped. An
      // explicit timeoutMs wins and is used verbatim.
      const policy = timeoutPolicy();
      const derived = deadlineFor({ command, expectedMs: args?.expectedMs, ...policy });
      const requestedTimeout = Number(args?.timeoutMs);
      const explicitTimeout =
        Number.isFinite(requestedTimeout) && requestedTimeout > 0
          ? Math.min(Math.round(requestedTimeout), policy.ceilingMs)
          : null;
      const timeoutMs = explicitTimeout ?? derived.timeoutMs;
      const deadline = explicitTimeout === null ? derived : { estimateMs: explicitTimeout, multiplier: 1, timeoutMs: explicitTimeout, source: 'timeoutMs' };
      const connection = visibleHost(host);
      const started = Date.now();
      const handshakeMs = await ensureTimed(connection);
      // Report every run in the assistant's activity trail: a stateless call
      // leaves no session behind, and the panel must still show that it ran.
      const done = (value) => {
        if (typeof pool.recordActivity === 'function') {
          pool.recordActivity({
            alias: host,
            kind: value.mode === 'background' ? 'background' : 'run',
            detail: command,
            durationMs: value.durationMs,
            exitCode: value.exitCode,
            timedOut: value.timedOut,
            owner: ownerOf(exec)
          });
        }
        return value;
      };
      // `cd … && { … }` keeps a failed cd from running the command and never
      // calls `exit`, which would tear the persistent session down.
      const wrap = (text) =>
        typeof args?.cwd === 'string' && args.cwd.length > 0 ? `cd ${shQuote(args.cwd)} && {\n${text}\n}` : text;
      // The Harness may hand a boolean parameter through as the string
      // "true"/"false", so both spellings mean "the default session".
      const requested = args?.session;
      const wantsDefaultSession = requested === true || requested === 'true';
      const wantsSession = wantsDefaultSession || (typeof requested === 'string' && requested.length > 0 && requested !== 'false');
      const sessionName = wantsDefaultSession ? 'main' : typeof requested === 'string' ? requested : null;
      const analyzeRun = async (stdout, stderr) => {
        const text = [stdout, stderr].filter((part) => typeof part === 'string' && part.length > 0).join('\n');
        const bytes = Buffer.byteLength(text, 'utf8');
        const wanted = shouldAnalyze(args?.analyze, LOG_COMMAND.test(command), bytes);
        if (!wanted) return { wanted: false, analysis: null, analysisError: null };
        const result = await runAnalysis({ tool: 'ssh_run', target: command, text, signal: exec?.signal, sessionId: exec?.agent?.id });
        return result.error === undefined
          ? { wanted: true, analysis: result, analysisError: null }
          : { wanted: true, analysis: null, analysisError: result.error };
      };
      // Background mode: the plugin owns detaching, logging and the PID, so the
      // call returns at once and nothing can leak into a later result.
      if (args?.background === true || args?.background === 'true') {
        const started2 = await connection.background(command, {
          cwd: typeof args?.cwd === 'string' && args.cwd.length > 0 ? args.cwd : undefined,
          logPath: typeof args?.logPath === 'string' && args.logPath.length > 0 ? args.logPath : undefined,
          signal: exec?.signal
        });
        return done({
          host,
          mode: 'background',
          session: null,
          exitCode: null,
          signal: null,
          timedOut: false,
          aborted: false,
          sessionEnded: false,
          endReason: null,
          timeoutMs: 15000,
          estimateMs: null,
          multiplier: null,
          deadlineSource: 'background launcher',
          stdout: safeCap(started2.raw.stdout, outputLimit()),
          stderr: safeCap(started2.raw.stderr, outputLimit()),
          cwd: null,
          durationMs: Date.now() - started,
          handshakeMs,
          reused: handshakeMs === 0,
          pid: started2.pid,
          logPath: started2.logPath,
          hint: started2.pid === null ? 'the process may not have started; check the log path and the command' : null,
          analysis: null,
          analysisError: null
        });
      }
      // A trailing "&" without background mode is the classic mistake: the
      // child keeps the channel open, so the call waits for it to exit.
      const backgroundHint = /&\s*$/.test(command.trim())
        ? '命令以 & 结尾但没有用 background:true；若后台进程未重定向输出，本次调用会一直等它退出或超时。要立刻返回并保留日志，请用 background:true（可配 logPath）。'
        : null;
      if (wantsSession) {
        const name = sessionName ?? 'main';
        const session = connection.session(name, ownerOf(exec));
        const result = await session.run(wrap(command), {
          timeoutMs,
          maxOutputBytes: outputLimit(),
          signal: exec?.signal
        });
        const { wanted: analysisWanted, analysis, analysisError } = await analyzeRun(result.stdout, result.stderr);
        return done({
          host,
          mode: 'session',
          session: name,
          exitCode: result.exitCode,
          signal: result.signal ?? null,
          timedOut: result.timedOut,
          aborted: result.aborted === true,
          sessionEnded: result.sessionEnded === true,
          endReason: result.endReason ?? null,
          timeoutMs,
          estimateMs: deadline.estimateMs,
          multiplier: deadline.multiplier,
          deadlineSource: deadline.source,
          stdout: analysis === null ? safeCap(result.stdout, analysisWanted ? Math.min(outputLimit(), 4096) : outputLimit()) : { text: '', truncated: false },
          stderr: analysis === null ? safeCap(result.stderr, analysisWanted ? Math.min(outputLimit(), 4096) : outputLimit()) : { text: '', truncated: false },
          cwd: result.cwd ?? null,
          durationMs: Date.now() - started,
          handshakeMs,
          reused: handshakeMs === 0,
          pid: null,
          logPath: null,
          hint: analysisError ?? backgroundHint,
          analysis,
          analysisError
        });
      }
      const result = await connection.exec(wrap(command), {
        timeoutMs,
        maxOutputBytes: outputLimit(),
        signal: exec?.signal
      });
      const { wanted: analysisWanted, analysis, analysisError } = await analyzeRun(result.stdout, result.stderr);
      return done({
        host,
        mode: 'exec',
        session: null,
        exitCode: result.exitCode,
        signal: result.signal ?? null,
        timedOut: result.timedOut,
        aborted: result.aborted === true,
        sessionEnded: false,
        endReason: null,
        timeoutMs,
        estimateMs: deadline.estimateMs,
        multiplier: deadline.multiplier,
        deadlineSource: deadline.source,
        stdout: analysis === null ? safeCap(result.stdout, analysisWanted ? Math.min(outputLimit(), 4096) : outputLimit()) : { text: '', truncated: false },
        stderr: analysis === null ? safeCap(result.stderr, analysisWanted ? Math.min(outputLimit(), 4096) : outputLimit()) : { text: '', truncated: false },
        cwd: null,
        durationMs: Date.now() - started,
        handshakeMs,
        reused: handshakeMs === 0,
        pid: null,
        logPath: null,
        hint: analysisError ?? backgroundHint,
        analysis,
        analysisError
      });
    }
  };

  /* ── remote file tools ──────────────────────────────────────────────────── */

  const fileTimeout = () => (typeof pool.transferTimeout === 'function' ? pool.transferTimeout() : 600000);
  /** Refuse the few write targets the shell guard would also refuse. */
  const guardWritePath = (path) => {
    const blocked = protectedWritePath(path);
    if (blocked === null) return;
    throw new Error(`[ssh-pool policy] ${blocked.title}：${path}\n${blocked.reason}\n建议: ${blocked.suggestion}`);
  };

  const sshRead = {
    name: 'ssh_read',
    description:
      'Read a text file on the host over SFTP (no shell, binary exact) and return its sha256. Pass that sha256 back to ssh_edit so an edit cannot overwrite a change made after this read. Use offset/limit to read a line window instead of the whole file.',
    parameters: {
      host: { type: 'string', required: true, description: 'Host alias; ssh_hosts lists them.' },
      path: { type: 'string', required: true, description: 'Absolute POSIX path (or relative to the login directory).' },
      offset: { type: 'number', description: 'First line to return (1-based, default 1).' },
      limit: { type: 'number', description: 'How many lines to return (default 200, max 2000).' },
      analyze: {
        type: 'boolean',
        description:
          'Route a large log file to the tool-less side analyzer and return only its summary. true forces it, false returns raw content; omit to follow the 日志旁路分析 switch. Config files are not analyzed automatically.'
      }
    },
    output: {
      schema: {
        type: 'object',
        properties: {
          host: { type: 'string' },
          path: { type: 'string' },
          sha256: { type: 'string' },
          size: { type: 'number' },
          totalLines: { type: 'number' },
          offset: { type: 'number' },
          limit: { type: 'number' },
          lines: { type: 'number' },
          content: { type: 'string' },
          truncated: { type: 'boolean' },
          mtimeMs: { oneOf: [{ type: 'number' }, { type: 'null' }] },
          analysis: ANALYSIS_SCHEMA,
          analysisError: ANALYSIS_ERROR_SCHEMA
        },
        required: ['host', 'path', 'sha256', 'size', 'totalLines', 'offset', 'limit', 'lines', 'content', 'truncated', 'mtimeMs', 'analysis', 'analysisError'],
        additionalProperties: false
      },
      render: (args, value) => {
        if (value.analysis !== null) {
          return text(`[${value.path} · sha256 ${value.sha256} · side analysis ${value.analysis.model} · no tools · ${coverageText(value.analysis)}]\n${value.analysis.summary}\n[${ANALYSIS_NOTE}]`);
        }
        const failed = typeof value.analysisError === 'string' && value.analysisError.length > 0 ? `\n[旁路分析不可用: ${value.analysisError}]` : '';
        return text(`[${value.path} · sha256 ${value.sha256} · lines ${value.offset}-${value.offset + value.lines - 1}/${value.totalLines}${value.truncated ? ' (more)' : ''}]\n${value.content}${failed}`);
      }
    },
    isConcurrencySafe: () => true,
    async execute(args, exec) {
      const host = args?.host;
      if (typeof host !== 'string' || host.length === 0) throw new Error('host is required');
      if (typeof args?.path !== 'string' || args.path.length === 0) throw new Error('path is required');
      const connection = visibleHost(host);
      const value = await readRemoteFile(connection, { path: args.path, offset: args?.offset, limit: Math.min(2000, Number(args?.limit) || 200), timeoutMs: fileTimeout() });
      // A config file is exactly where a token or a private key lives.
      const wanted = shouldAnalyze(args?.analyze, LOG_PATH.test(args.path), Buffer.byteLength(value.content, 'utf8'));
      const result = wanted ? await runAnalysis({ tool: 'ssh_read', target: args.path, text: value.content, signal: exec?.signal, sessionId: exec?.agent?.id }) : null;
      const analysis = result !== null && result.error === undefined ? result : null;
      const analysisError = result?.error ?? null;
      // If the side call was attempted and failed, show a bounded preview rather
      // than dumping the whole log back into the main context.
      const capped = safeCap(value.content, wanted && analysis === null ? Math.min(outputLimit(), 4096) : outputLimit());
      return {
        host,
        ...value,
        content: analysis === null ? capped.text : '',
        truncated: analysis === null ? (wanted ? true : value.truncated || capped.truncated) : value.truncated,
        analysis,
        analysisError
      };
    }
  };

  const sshWrite = {
    name: 'ssh_write',
    description:
      'Write a text file on the host over SFTP: the content goes to a temp file in the same directory and is renamed over the target, so a failed write never leaves a half-written file. Keeps a dated backup by default. Writes to block devices and /boot, /proc or /sys are refused; ordinary configuration files are allowed. For whole new files; to change an existing file prefer ssh_edit (which refuses to clobber a concurrent edit).',
    parameters: {
      host: { type: 'string', required: true, description: 'Host alias.' },
      path: { type: 'string', required: true, description: 'Absolute POSIX path to write.' },
      content: { type: 'string', required: true, description: 'Full file content (UTF-8).' },
      backup: { type: 'boolean', description: 'Keep <path>.bak.<YYYY-MM-DD> when the file already exists (default true).' }
    },
    output: {
      schema: {
        type: 'object',
        properties: {
          host: { type: 'string' },
          path: { type: 'string' },
          bytes: { type: 'number' },
          sha256: { type: 'string' },
          backup: { oneOf: [{ type: 'string' }, { type: 'null' }] },
          mode: { oneOf: [{ type: 'number' }, { type: 'null' }] },
          created: { type: 'boolean' }
        },
        required: ['host', 'path', 'bytes', 'sha256', 'backup', 'mode', 'created'],
        additionalProperties: false
      },
      render: (args, value) => text(`${value.created ? 'created' : 'rewrote'} ${value.path} (${value.bytes} bytes, mode ${typeof value.mode === 'number' ? `0${value.mode.toString(8).padStart(3, '0')}` : 'default'}, sha256 ${value.sha256.slice(0, 12)}${value.backup === null ? '' : `, backup ${value.backup}`})`)
    },
    isConcurrencySafe: () => false,
    async execute(args) {
      const host = args?.host;
      if (typeof host !== 'string' || host.length === 0) throw new Error('host is required');
      if (typeof args?.path !== 'string' || args.path.length === 0) throw new Error('path is required');
      if (typeof args?.content !== 'string') throw new Error('content is required');
      guardWritePath(args.path);
      const connection = visibleHost(host);
      const value = await writeRemoteFile(connection, { path: args.path, content: args.content, backup: args?.backup !== false, timeoutMs: fileTimeout() });
      return { host, ...value };
    }
  };

  const sshEdit = {
    name: 'ssh_edit',
    description:
      'Edit a text file on the host: ssh_read gives you a sha256; pass it here with the exact oldString and the newString. The edit re-reads the file, refuses with stale-edit if the sha256 no longer matches (nothing is written), and refuses when oldString appears more than once unless replaceAll is true. Writes atomically and keeps a dated backup.',
    parameters: {
      host: { type: 'string', required: true, description: 'Host alias.' },
      path: { type: 'string', required: true, description: 'Absolute POSIX path of the file to edit.' },
      sha256: { type: 'string', description: 'The sha256 returned by ssh_read for this file (required; validated before anything is written).' },
      oldString: { type: 'string', description: 'Exact text to replace; must appear exactly once unless replaceAll is true.' },
      newString: { type: 'string', description: 'Replacement text.' },
      old_string: { type: 'string', description: 'Alias of oldString (the local edit tool spells it this way).' },
      new_string: { type: 'string', description: 'Alias of newString.' },
      replaceAll: { type: 'boolean', description: 'Replace every occurrence (default false: a multiple match is refused).' },
      backup: { type: 'boolean', description: 'Keep <path>.bak.<YYYY-MM-DD> (default true).' }
    },
    output: {
      schema: {
        type: 'object',
        properties: {
          host: { type: 'string' },
          path: { type: 'string' },
          replacements: { type: 'number' },
          previousSha256: { type: 'string' },
          sha256: { type: 'string' },
          bytes: { type: 'number' },
          backup: { oneOf: [{ type: 'string' }, { type: 'null' }] },
          mode: { oneOf: [{ type: 'number' }, { type: 'null' }] },
          mtimeMs: { oneOf: [{ type: 'number' }, { type: 'null' }] }
        },
        required: ['host', 'path', 'replacements', 'previousSha256', 'sha256', 'bytes', 'backup', 'mode', 'mtimeMs'],
        additionalProperties: false
      },
      render: (args, value) => text(`${value.path}: ${value.replacements} replacement(s), sha256 ${value.previousSha256.slice(0, 12)} → ${value.sha256} (pass this full sha256 to the next ssh_edit), mode ${typeof value.mode === 'number' ? `0${value.mode.toString(8).padStart(3, '0')}` : 'default'} kept${value.backup === null ? '' : ` (backup ${value.backup})`}`)
    },
    isConcurrencySafe: () => false,
    async execute(args) {
      const host = args?.host;
      if (typeof host !== 'string' || host.length === 0) throw new Error('host is required');
      if (typeof args?.path !== 'string' || args.path.length === 0) throw new Error('path is required');
      guardWritePath(args.path);
      const oldString = typeof args?.oldString === 'string' ? args.oldString : args?.old_string;
      const newString = typeof args?.newString === 'string' ? args.newString : args?.new_string;
      if (typeof oldString !== 'string' || oldString.length === 0) {
        throw new Error('oldString is required (old_string is accepted too): the exact text to replace, as returned by ssh_read');
      }
      if (typeof newString !== 'string') throw new Error('newString is required (new_string is accepted too)');
      const connection = visibleHost(host);
      const value = await editRemoteFile(connection, {
        path: args.path,
        sha256: args.sha256,
        oldString,
        newString,
        replaceAll: args?.replaceAll === true || args?.replace_all === true,
        backup: args?.backup !== false,
        timeoutMs: fileTimeout()
      });
      return { host, ...value };
    }
  };

  const sshGlob = {
    name: 'ssh_glob',
    description:
      'List files on the host whose path or basename matches a glob (for example "**/*.conf" or "*.log"), starting from a directory. Walks over SFTP, skipping .git and node_modules, with a depth and entry cap. Read-only.',
    parameters: {
      host: { type: 'string', required: true, description: 'Host alias.' },
      pattern: { type: 'string', required: true, description: 'Glob pattern; `*` stays in one segment, `**` spans directories.' },
      cwd: { type: 'string', description: 'Directory to start from (default the login directory ".").' },
      maxEntries: { type: 'number', description: 'Maximum entries to return (default 200).' },
      maxDepth: { type: 'number', description: 'Maximum directory depth (default 6).' }
    },
    output: {
      schema: {
        type: 'object',
        properties: {
          host: { type: 'string' },
          pattern: { type: 'string' },
          cwd: { type: 'string' },
          entries: {
            type: 'array',
            items: {
              type: 'object',
              properties: { path: { type: 'string' }, size: { oneOf: [{ type: 'number' }, { type: 'null' }] }, mtimeMs: { oneOf: [{ type: 'number' }, { type: 'null' }] } },
              required: ['path', 'size', 'mtimeMs'],
              additionalProperties: false
            }
          },
          scanned: { type: 'number' },
          truncated: { type: 'boolean' }
        },
        required: ['host', 'pattern', 'cwd', 'entries', 'scanned', 'truncated'],
        additionalProperties: false
      },
      render: (args, value) =>
        text(
          value.entries.length === 0
            ? `no files match ${value.pattern} under ${value.cwd} (scanned ${value.scanned})`
            : `${value.entries.length} match(es) for ${value.pattern} under ${value.cwd}${value.truncated ? ' (capped)' : ''}:\n${value.entries.map((entry) => entry.path).join('\n')}`
        )
    },
    isConcurrencySafe: () => true,
    async execute(args) {
      const host = args?.host;
      if (typeof host !== 'string' || host.length === 0) throw new Error('host is required');
      if (typeof args?.pattern !== 'string' || args.pattern.length === 0) throw new Error('pattern is required');
      const connection = visibleHost(host);
      const value = await globRemote(connection, {
        pattern: args.pattern,
        cwd: typeof args?.cwd === 'string' && args.cwd.length > 0 ? args.cwd : '.',
        maxEntries: Math.min(2000, Number(args?.maxEntries) || 200),
        maxDepth: Math.min(20, Number(args?.maxDepth) || 6),
        timeoutMs: fileTimeout()
      });
      return { host, ...value };
    }
  };

  const sshGrep = {
    name: 'ssh_grep',
    description:
      'Search file contents on the host with the host\'s own grep (read-only, no install needed): bounded by matches per file, excluded .git/node_modules/.cache, a deadline and an output cap. Give a directory and optionally an --include glob such as "*.log".',
    parameters: {
      host: { type: 'string', required: true, description: 'Host alias.' },
      pattern: { type: 'string', required: true, description: 'Regular expression (grep -E syntax).' },
      path: { type: 'string', description: 'File or directory to search (default ".").' },
      include: { type: 'string', description: 'Only search files matching this glob, e.g. "*.conf".' },
      maxMatches: { type: 'number', description: 'Maximum matches to return (default 50).' },
      ignoreCase: { type: 'boolean', description: 'Case-insensitive search.' },
      analyze: {
        type: 'boolean',
        description:
          'Route the matches to the tool-less side analyzer and return only its summary. true forces it, false returns raw matches; omit to follow the 日志旁路分析 switch.'
      }
    },
    output: {
      schema: {
        type: 'object',
        properties: {
          host: { type: 'string' },
          pattern: { type: 'string' },
          path: { type: 'string' },
          matches: {
            type: 'array',
            items: {
              type: 'object',
              properties: { file: { type: 'string' }, line: { type: 'number' }, text: { type: 'string' } },
              required: ['file', 'line', 'text'],
              additionalProperties: false
            }
          },
          scannedFiles: { type: 'number' },
          truncated: { type: 'boolean' },
          exitCode: { oneOf: [{ type: 'number' }, { type: 'null' }] },
          timedOut: { type: 'boolean' },
          analysis: ANALYSIS_SCHEMA,
          analysisError: ANALYSIS_ERROR_SCHEMA
        },
        required: ['host', 'pattern', 'path', 'matches', 'scannedFiles', 'truncated', 'exitCode', 'timedOut', 'analysis', 'analysisError'],
        additionalProperties: false
      },
      render: (args, value) => {
        if (value.analysis !== null) {
          return text(`[${value.path} · side analysis ${value.analysis.model} · no tools · ${coverageText(value.analysis)}]\n${value.analysis.summary}\n[${ANALYSIS_NOTE}]`);
        }
        const body =
          value.matches.length === 0
            ? `no match for /${value.pattern}/ under ${value.path}`
            : `${value.matches.length} match(es) for /${value.pattern}/${value.truncated ? ' (capped)' : ''}:\n${value.matches.map((match) => `${match.file}:${match.line}: ${match.text}`).join('\n')}`;
        const failed = typeof value.analysisError === 'string' && value.analysisError.length > 0 ? `\n[旁路分析不可用: ${value.analysisError}]` : '';
        return text(`${body}${failed}`);
      }
    },
    isConcurrencySafe: () => true,
    async execute(args, exec) {
      const host = args?.host;
      if (typeof host !== 'string' || host.length === 0) throw new Error('host is required');
      if (typeof args?.pattern !== 'string' || args.pattern.length === 0) throw new Error('pattern is required');
      const connection = visibleHost(host);
      const value = await grepRemote(connection, {
        pattern: args.pattern,
        path: typeof args?.path === 'string' && args.path.length > 0 ? args.path : '.',
        include: typeof args?.include === 'string' && args.include.length > 0 ? args.include : undefined,
        maxMatches: Number(args?.maxMatches) || 50,
        ignoreCase: args?.ignoreCase === true,
        timeoutMs: Math.min(fileTimeout(), 60000)
      });
      // Subscription URLs and tokens show up in matched lines.
      const matches = value.matches.map((match) => ({ ...match, text: redactText(match.text) }));
      const raw = matches.map((match) => `${match.file}:${match.line}: ${match.text}`).join('\n');
      const wanted = shouldAnalyze(args?.analyze, true, Buffer.byteLength(raw, 'utf8'));
      const result = wanted ? await runAnalysis({ tool: 'ssh_grep', target: `${args.path ?? '.'} /${args.pattern}/`, text: raw, signal: exec?.signal, sessionId: exec?.agent?.id }) : null;
      const analysis = result !== null && result.error === undefined ? result : null;
      const analysisError = result?.error ?? null;
      // On failure keep only the first 20 matches; the caller can pass
      // analyze:false to get the rest rather than filling the main context.
      return {
        host,
        ...value,
        matches: analysis === null ? (wanted ? matches.slice(0, 20) : matches) : [],
        truncated: analysis === null && wanted ? true : value.truncated,
        analysis,
        analysisError
      };
    }
  };

  /* ── health checks ──────────────────────────────────────────────────────── */

  /** Fixed, bounded, read-only command sets for the questions an operator asks
   *  most: "is it healthy", "is the disk full", "what is listening", and so
   *  on. Nothing here scans the whole filesystem. */
  const CHECK_SCOPES = {
    health: [
      'echo "== uptime =="; uptime',
      'echo "== memory =="; free -m 2>/dev/null | head -3',
      'echo "== disk =="; df -h / /var 2>/dev/null | head -5',
      'echo "== cpu =="; nproc',
      'echo "== systemd =="; systemctl is-system-running 2>/dev/null || true'
    ].join('; '),
    disk: [
      'echo "== df =="; df -h 2>/dev/null | head -12',
      'echo "== heavy dirs =="; du -sh /var/log /var/tmp /tmp /root 2>/dev/null || true',
      'echo "== inodes =="; df -i / 2>/dev/null | head -3'
    ].join('; '),
    services: [
      'echo "== failed =="; systemctl list-units --type=service --state=failed --no-pager --no-legend 2>/dev/null | head -20',
      'echo "== active =="; for unit in sshd ssh nginx; do printf "%s: %s\\n" "$unit" "$(systemctl is-active "$unit" 2>/dev/null)"; done'
    ].join('; '),
    ports: 'echo "== listening =="; ss -lntp 2>/dev/null | head -40',
    logins: [
      'echo "== who =="; who 2>/dev/null',
      'echo "== last =="; last -n 20 2>/dev/null | head -20'
    ].join('; '),
    cert: 'echo "== certificates =="; for f in /etc/nginx/ssl/*.pem /etc/letsencrypt/live/*/fullchain.pem; do [ -f "$f" ] && openssl x509 -in "$f" -noout -subject -enddate 2>/dev/null && echo "  ($f)"; done | head -20',
    // Where the disk actually went: journald usage, its retention config, and the
    // biggest log files. All bounded (du/journalctl --disk-usage/find -size).
    logs: [
      'echo "== journald usage =="; journalctl --disk-usage 2>/dev/null',
      'echo "== journald config =="; grep -RhE "^(SystemMaxUse|RuntimeMaxUse|SystemKeepFree|MaxRetentionSec)=" /etc/systemd/journald.conf /etc/systemd/journald.conf.d/ 2>/dev/null | head -10',
      'echo "== log dirs =="; du -sh /var/log /var/log/journal 2>/dev/null',
      'echo "== files over 50M =="; find /var/log -maxdepth 2 -type f -size +50M -printf "%s %p\\n" 2>/dev/null | sort -rn | head -10',
      'echo "== rotated files =="; ls -1t /var/log/*.gz /var/log/*.[0-9] 2>/dev/null | head -10'
    ].join('; '),
    // Mode and ownership, the thing that silently breaks a script after an edit.
    permissions: [
      'echo "== common paths =="; for p in /etc /var/log /usr/local/bin /usr/local/sbin /opt /srv; do [ -e "$p" ] && stat -c "%a %U:%G %n" "$p"; done 2>/dev/null',
      'echo "== recently changed in /etc =="; find /etc -maxdepth 2 -type f -newermt "-7 days" -printf "%TY-%Tm-%Td %m %U:%G %p\\n" 2>/dev/null | head -15',
      'echo "== executables in /usr/local/bin =="; ls -l /usr/local/bin 2>/dev/null | head -15'
    ].join('; ')
  };

  /** One-line, human-readable reading of the check output. */
  const summarise = (scope, stdout) => {
    const notes = [];
    const text = String(stdout ?? '');
    const disk = /(\d+)%\s+\/var|(\d+)%\s+\/$/m.exec(text);
    if (scope === 'health' || scope === 'disk') {
      const pcts = [...text.matchAll(/(\d+)%/g)].map((match) => Number(match[1])).filter((value) => value >= 0 && value <= 100);
      if (pcts.length > 0) {
        const worst = Math.max(...pcts);
        notes.push(`磁盘最高占用 ${worst}%${worst >= 90 ? '（告警）' : worst >= 75 ? '（偏高）' : '（正常）'}`);
      }
      const load = /load average:\s*([\d.]+)/.exec(text);
      if (load !== null) notes.push(`负载 ${load[1]}`);
      const mem = /Mem:\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\d+)/.exec(text);
      if (mem !== null) notes.push(`可用内存 ${mem[1]} MB`);
    }
    if (scope === 'services') {
      // systemctl prefixes failed rows with a bullet: `● unit.service loaded
      // failed failed …`, so an anchored `^\S+\.service` count misses every
      // one of them and reported "no failed services" while systemd said
      // degraded. Count the actual unit rows instead.
      const failed = text.split('\n').filter((line) => /\.service\b/.test(line) && /\bfailed\b/.test(line)).length;
      notes.push(failed === 0 ? '没有失败的服务' : `${failed} 个服务处于 failed`);
      const inactive = [...text.matchAll(/^(\w+):\s*(\S+)/gm)].filter((match) => match[2] !== 'active').map((match) => match[1]);
      if (inactive.length > 0) notes.push(`未运行：${inactive.join(', ')}`);
    }
    if (scope === 'ports') {
      const lines = text.split('\n').filter((line) => line.includes('LISTEN'));
      notes.push(`监听端口 ${lines.length} 个`);
    }
    if (scope === 'logins') {
      const count = text.split('\n').filter((line) => line.trim().length > 0 && !line.startsWith('==') && !line.startsWith('wtmp')).length;
      notes.push(`登录记录 ${count} 条`);
    }
    if (scope === 'cert') {
      const dates = [...text.matchAll(/notAfter=(.+)/g)].map((match) => match[1].trim());
      notes.push(dates.length === 0 ? '没找到证书（可用 path 指定）' : `证书到期：${dates.join(' / ')}`);
    }
    if (scope === 'logs') {
      const journald = /Archived and active journals take up ([\d.]+[KMG]?B)/.exec(text) ?? /([\d.]+[KMG]?B)/.exec(text);
      if (journald !== null) notes.push(`journald 占用 ${journald[1]}`);
      const dirs = [...text.matchAll(/^([\d.]+[KMGT])\s+(\/var\/log\S*)/gm)].map((match) => `${match[2]} ${match[1]}`);
      if (dirs.length > 0) notes.push(`日志目录：${dirs.join('、')}`);
      const big = text.split('\n').filter((line) => /^\d+\s+\/var\/log/.test(line)).length;
      if (big > 0) notes.push(`超过 50M 的日志 ${big} 个`);
      const retention = [...text.matchAll(/^(SystemMaxUse|MaxRetentionSec)=(.+)$/gm)].map((match) => `${match[1]}=${match[2]}`);
      notes.push(retention.length === 0 ? '未配置 journald 保留上限（建议 SystemMaxUse=64M + MaxRetentionSec=7day）' : `保留配置：${retention.join(', ')}`);
    }
    if (scope === 'permissions') {
      const executables = text.split('\n').filter((line) => /^-rwx/.test(line));
      notes.push(`含执行位的条目 ${executables.length} 条`);
      const lines = text.split('\n').filter((line) => /^\d{3,4}\s+\S+:\S+\s+\//.test(line));
      if (lines.length > 0) notes.push(lines.slice(0, 4).join('；'));
    }
    return notes.join(' · ');
  };

  const sshCheck = {
    name: 'ssh_check',
    description:
      'Answer "is this machine healthy" without hand-writing commands: runs one fixed, bounded, read-only check set and returns a one-line reading plus the raw output. Scopes: health (uptime, memory, disk, cpu, systemd), disk (df, heavy directories, inodes), services (failed units, sshd/nginx state), ports (listening sockets), logins (who, last), cert (certificate expiry), logs (journald usage and retention config, the biggest log files, rotated files), permissions (mode/ownership of common paths and what changed recently).',
    parameters: {
      host: { type: 'string', required: true, description: 'Host alias.' },
      scope: { type: 'string', enum: ['health', 'disk', 'services', 'ports', 'logins', 'cert', 'logs', 'permissions'], description: 'Which check set to run (default health).' },
      service: { type: 'string', description: 'With scope=services: also show this unit\'s status (e.g. nginx).' },
      path: { type: 'string', description: 'With scope=cert: check this certificate file instead of the default locations.' }
    },
    output: {
      schema: {
        type: 'object',
        properties: {
          host: { type: 'string' },
          scope: { type: 'string' },
          summary: { type: 'string' },
          output: { type: 'string' },
          exitCode: { oneOf: [{ type: 'number' }, { type: 'null' }] },
          durationMs: { type: 'number' }
        },
        required: ['host', 'scope', 'summary', 'output', 'exitCode', 'durationMs'],
        additionalProperties: false
      },
      render: (args, value) => text(`[${value.host} · ${value.scope}] ${value.summary}\n\n${value.output}`)
    },
    isConcurrencySafe: () => true,
    async execute(args) {
      const host = args?.host;
      if (typeof host !== 'string' || host.length === 0) throw new Error('host is required');
      const scope = ['health', 'disk', 'services', 'ports', 'logins', 'cert', 'logs', 'permissions'].includes(args?.scope) ? args.scope : 'health';
      const connection = visibleHost(host);
      const parts = [CHECK_SCOPES[scope]];
      if (scope === 'services' && typeof args?.service === 'string' && args.service.length > 0) {
        parts.push(`printf '== %s ==\\n' ${shQuote(args.service)}; systemctl status ${shQuote(args.service)} --no-pager -l 2>/dev/null | head -20`);
      }
      if (scope === 'permissions' && typeof args?.path === 'string' && args.path.length > 0) {
        parts.push(`stat -c '%a %U:%G %n' ${shQuote(args.path)} 2>/dev/null || printf 'not readable: %s\\n' ${shQuote(args.path)}`);
      }
      if (scope === 'cert' && typeof args?.path === 'string' && args.path.length > 0) {
        parts.push(`openssl x509 -in ${shQuote(args.path)} -noout -subject -enddate 2>/dev/null || printf 'not a readable certificate: %s\\n' ${shQuote(args.path)}`);
      }
      const started = Date.now();
      const result = await connection.exec(parts.join('; '), {
        timeoutMs: 60000,
        maxOutputBytes: outputLimit()
      });
      const output = safeCap(result.stdout ?? '', outputLimit()).text;
      pool.recordActivity?.({ alias: host, kind: 'check', detail: `ssh_check ${scope}` });
      return {
        host,
        scope,
        summary: redactText(summarise(scope, result.stdout ?? '')),
        output,
        exitCode: typeof result.exitCode === 'number' ? result.exitCode : null,
        durationMs: Date.now() - started
      };
    }
  };

  const sshTransfer = {
    name: 'ssh_transfer',
    description:
      'Upload or download one file over SFTP on the host\'s existing pooled connection (binary exact, no second handshake). Local paths are on this machine and are read or written exactly as given; remote paths are POSIX paths on the SSH host. Parent directories are created by default. A transfer always runs under a deadline and is cancelled when it expires, so a stalled link cannot block the call forever.',
    parameters: {
      direction: {
        type: 'string',
        enum: ['upload', 'download'],
        required: true,
        description: '"upload" copies localPath to remotePath; "download" copies remotePath to localPath.'
      },
      host: { type: 'string', required: true, description: 'Host alias; ssh_hosts lists them.' },
      localPath: { type: 'string', required: true, description: 'Absolute path on this machine.' },
      remotePath: { type: 'string', required: true, description: 'Path on the SSH host (POSIX form, e.g. /root/app.tar.gz).' },
      createDirs: {
        type: 'boolean',
        description: 'Create missing parent directories at the destination (default true).'
      },
      timeoutMs: {
        type: 'number',
        description: `Deadline in milliseconds, defaulting to the assistant's transfer timeout (${transferTimeout()} ms). A transfer that outlives it is cancelled rather than left running.`
      }
    },
    output: {
      schema: {
        type: 'object',
        properties: {
          direction: { type: 'string' },
          host: { type: 'string' },
          localPath: { type: 'string' },
          remotePath: { type: 'string' },
          bytes: { type: 'number' },
          durationMs: { type: 'number' },
          bytesPerSecond: { type: 'number' }
        },
        required: ['direction', 'host', 'localPath', 'remotePath', 'bytes', 'durationMs', 'bytesPerSecond'],
        additionalProperties: false
      },
      render: (_args, value) =>
        text(
          `${value.direction === 'upload' ? 'uploaded' : 'downloaded'} ${value.bytes} bytes in ${value.durationMs}ms (${value.bytesPerSecond} B/s)\n${value.localPath} ${value.direction === 'upload' ? '→' : '←'} ${value.host}:${value.remotePath}`
        )
    },
    isConcurrencySafe: () => true,
    async execute(args, exec) {
      const direction = args?.direction;
      if (direction !== 'upload' && direction !== 'download') throw new Error('direction must be "upload" or "download"');
      if (typeof args?.host !== 'string' || args.host.length === 0) throw new Error('host is required');
      if (typeof args?.localPath !== 'string' || args.localPath.length === 0) throw new Error('localPath is required');
      if (typeof args?.remotePath !== 'string' || args.remotePath.length === 0) throw new Error('remotePath is required');
      visibleHost(args.host);
      if (direction === 'upload') guardWritePath(args.remotePath);
      const transferStarted = Date.now();
      const transferred = await transferFile(pool, {
        host: args.host,
        direction,
        localPath: args.localPath,
        remotePath: args.remotePath,
        createDirs: args.createDirs !== false,
        // A transfer always has a deadline: 0 no longer means "wait forever".
        timeoutMs: Number.isFinite(Number(args.timeoutMs)) && Number(args.timeoutMs) > 0 ? Number(args.timeoutMs) : transferTimeout(),
        signal: exec?.signal
      });
      if (typeof pool.recordActivity === 'function') {
        pool.recordActivity({
          alias: args.host,
          kind: 'transfer',
          detail: `${direction} ${args.localPath} → ${args.remotePath}`,
          durationMs: Date.now() - transferStarted,
          owner: ownerOf(exec)
        });
      }
      return transferred;
    }
  };

  const tools = [sshHosts, sshRun, sshCheck, sshTransfer, sshRead, sshWrite, sshEdit, sshGlob, sshGrep].map((tool) => ({
    ...tool,
    parameters: parameterSchema(tool.parameters)
  }));
  if (diagnostics === undefined) return tools;
  return tools.map((tool) => ({
    ...tool,
    async execute(args, exec) {
      const started = Date.now();
      try {
        const value = await tool.execute(args, exec);
        const failure = resultFailure(value);
        diagnostics.record({
          tool: tool.name,
          host: typeof args?.host === 'string' ? args.host : value?.host ?? null,
          commandKind: tool.name === 'ssh_run' && typeof args?.command === 'string' ? commandKind(args.command) : null,
          outcome: failure.outcome,
          reason: failure.reason,
          durationMs: Date.now() - started,
          bytes: resultBytes(value),
          reused: typeof value?.reused === 'boolean' ? value.reused : null,
          analysis: resultAnalysis(value)
        });
        return value;
      } catch (error) {
        const failure = thrownFailure(error);
        diagnostics.record({
          tool: tool.name,
          host: typeof args?.host === 'string' ? args.host : null,
          commandKind: tool.name === 'ssh_run' && typeof args?.command === 'string' ? commandKind(args.command) : null,
          outcome: failure.outcome,
          reason: failure.reason,
          durationMs: Date.now() - started,
          bytes: 0,
          reused: null,
          analysis: null
        });
        throw error;
      }
    }
  }));
}

function shQuote(value) {
  return `'${String(value).replace(/'/g, `'\\''`)}'`;
}
