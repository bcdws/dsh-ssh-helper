/**
 * The three model-facing tools over the pool: list hosts, run a command, move a file.
 *
 * The agent already knows the shell, so reading, searching and editing files
 * go through `ssh_run`; the pool and the guard are what this module adds.
 *
 * Every tool is a plain `{ name, description, parameters, output, execute }`
 * object with no Harness import, so any host can mount it: DSH registers them
 * directly, another adapter (e.g. an MCP server) maps them to its own protocol.
 *
 * Host-neutral contract:
 *  - `execute(args, call)` takes the neutral call context from
 *    `call-context.js` (`{ callerId, signal }`); each adapter translates its own
 *    execution shape before calling.
 *  - The machine-destruction policy is enforced inside `execute`, so mounting
 *    the tools anywhere keeps the guard; a refusal throws `PolicyDeniedError`.
 *
 * @module dsh-ssh-pool/tools
 */
import { transferFile } from './transfer.js';
import { deadlineFor } from './timeouts.js';
import { assertCommandAllowed, assertWritePathAllowed, createPolicy, homeFor } from './policy.js';
import { callContext, LOCAL_CALLER } from './call-context.js';
import { commandKind } from './diagnostics.js';
import { annotateError } from './errors.js';
import { homedir, hostname, release, type as osType } from 'node:os';
import { redactText } from './redact.js';
import { unknownHostMessage } from './alias-suggest.js';

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
        source: { type: 'string' },
        // True when no model was reachable and the summary is the local
        // deterministic digest (signature counts, timeline, tail lines).
        local: { type: 'boolean' }
      },
      required: ['summary', 'model', 'inputBytes', 'analyzedBytes', 'inputLines', 'analyzedLines', 'truncated', 'source'],
      additionalProperties: false
    },
    { type: 'null' }
  ]
};

const ANALYSIS_NOTE = 'analyzed by a tool-less side model; no commands were executed. Raw output withheld by 日志旁路分析; pass analyze:false to get it';
const LOCAL_NOTE = 'deterministic local digest; no model was called and no log text left this machine. Raw output withheld by 日志旁路分析; pass analyze:false to get it';
const ANALYSIS_ERROR_SCHEMA = { oneOf: [{ type: 'string' }, { type: 'null' }] };
const formatBytes = (value) =>
  typeof value === 'number' && Number.isFinite(value) ? (value >= 1024 ? `${Math.round(value / 1024)} KB` : `${value} B`) : '?';
const coverageText = (analysis) =>
  `analyzed ${formatBytes(analysis.analyzedBytes)} / ${analysis.analyzedLines ?? '?'} lines of ${formatBytes(analysis.inputBytes)} / ${analysis.inputLines ?? '?'} lines${analysis.truncated ? ', truncated' : ''}`;
/** A local digest must never be presented as model analysis. */
const analysisHeader = (analysis) =>
  analysis?.local === true ? '本地规则摘要（无模型）' : `side analysis · ${analysis.model} · no tools`;
const analysisFooter = (analysis) => (analysis?.local === true ? LOCAL_NOTE : ANALYSIS_NOTE);

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
  handshakeTimeouts: { type: 'number' },
  retryPaused: { type: 'boolean' },
  sessions: { type: 'array', items: { type: 'object' } },
  hostKey: { oneOf: [{ type: 'object' }, { type: 'null' }] },
  lastError: { oneOf: [{ type: 'string' }, { type: 'null' }] },
  hidden: { type: 'boolean' },
  remark: { type: 'string' },
  lastCommandAgeSeconds: { oneOf: [{ type: 'number' }, { type: 'null' }] },
  callFailures: { type: 'number' },
  lastFailure: {
    oneOf: [
      {
        type: 'object',
        properties: { tool: { type: 'string' }, code: { type: 'string' }, message: { type: 'string' }, ageSeconds: { type: 'number' } },
        required: ['tool', 'code', 'message', 'ageSeconds']
      },
      { type: 'null' }
    ]
  },
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
    warnings: { type: 'array', items: { type: 'string' } },
    local: {
      type: 'object',
      properties: {
        hostname: { type: 'string' },
        platform: { type: 'string' },
        os: { type: 'string' },
        cwd: { type: 'string' },
        home: { type: 'string' },
        pid: { type: 'number' },
        uptimeSeconds: { type: 'number' }
      }
    }
  },
  required: ['hosts', 'count'],
  additionalProperties: false
};

function text(value) {
  return [{ type: 'text', text: value }];
}

/** `[policy]` in a repeat `ssh_hosts` result when the caller already has the full text. */
const POLICY_REPEAT = 'unchanged; the full text is in the server instructions and in your first ssh_hosts result, and comes again after a refusal.';

/**
 * Optional `notices` on every host-scoped result: the host's [note].
 * Absent when there is none.
 */
const NOTICES_SCHEMA = { type: 'array', items: { type: 'string' } };

/** Add `notices` to an object output schema (the schemas forbid unknown keys). */
function withNoticesSchema(schema) {
  if (schema?.type !== 'object' || schema.properties === undefined) return schema;
  return { ...schema, properties: { notices: NOTICES_SCHEMA, ...schema.properties } };
}

/** Where this server process runs: localPath and "it just started" both depend on it. */
function localInfo() {
  return {
    hostname: hostname(),
    platform: process.platform,
    os: `${osType()} ${release()}`,
    cwd: process.cwd(),
    home: homedir(),
    pid: process.pid,
    uptimeSeconds: Math.round(process.uptime())
  };
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
    if (host.retryPaused === true) parts.push(`retry=paused(${host.handshakeTimeouts ?? '?'})`);
    if (Array.isArray(host.sessions) && host.sessions.length > 0) {
      parts.push(`sessions=${host.sessions.map((session) => `${session.name}@${session.ownerShort ?? session.owner}`).join(',')}`);
    }
    if (typeof host.remark === 'string' && host.remark.length > 0) parts.push(`note=${host.remark}`);
    if (host.lastError !== null && host.lastError !== undefined && !host.connected) parts.push(`last error: ${host.lastError}`);
    if (host.lastFailure !== null && host.lastFailure !== undefined) {
      parts.push(`last failed call: ${host.lastFailure.tool} [${host.lastFailure.code}] ${host.lastFailure.ageSeconds}s ago (${host.callFailures} failed calls)`);
    }
    return `- ${parts.join(' ')}`;
  });
  const hints = typeof value.policyHint === 'string' && value.policyHint.length > 0 ? `\n[policy] ${value.policyHint}` : '';
  const warnings = value.warnings.length > 0 ? `\n[warnings] ${value.warnings.join('; ')}` : '';
  const local =
    value.local === undefined
      ? ''
      : `\n[local] this server runs on ${value.local.hostname} (${value.local.os}, ${value.local.platform}); ssh_transfer localPath is resolved there, cwd ${value.local.cwd}; up ${value.local.uptimeSeconds}s`;
  return `${lines.join('\n')}${hints}${warnings}${local}`;
}

/** The bash-tool result shape: body first, then one marker per line. */
function renderRun(value, args) {
  const stdout = value.stdout.text;
  const stderr = value.stderr.text;
  let body = value.mode === 'background' ? '' : stdout;
  if (value.mode === 'background') {
    body = `[started detached] pid=${value.pid ?? '?'}\n[log] ${value.logPath ?? '(unknown)'}\n[script] ${value.scriptPath ?? '(unknown)'}`;
  } else if (stderr.length > 0) {
    if (body.length > 0 && !body.endsWith('\n')) body += '\n';
    body += `[stderr]\n${stderr}`;
  }
  if (body.length === 0) body = '(no output)';
  if (value.analysis !== null && value.analysis !== undefined) {
    body = `[${analysisHeader(value.analysis)} · ${coverageText(value.analysis)}]\n${value.analysis.summary}\n[${analysisFooter(value.analysis)}]`;
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
  if (value.detached === true) markers.push('[still running on the host — answered at the per-call cap; not killed]');
  else if (value.aborted) markers.push('[tool call aborted]');
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
    detached: { type: 'boolean' },
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
    scriptPath: { oneOf: [{ type: 'string' }, { type: 'null' }] },
    hint: { oneOf: [{ type: 'string' }, { type: 'null' }] },
    analysis: ANALYSIS_SCHEMA,
    analysisError: ANALYSIS_ERROR_SCHEMA
  },
  required: ['host', 'mode', 'timedOut', 'aborted', 'sessionEnded', 'timeoutMs', 'stdout', 'stderr', 'durationMs', 'handshakeMs', 'reused', 'analysis', 'analysisError'],
  additionalProperties: false
};

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

const CODE_OUTCOMES = {
  policy_denied: { outcome: 'denied', reason: 'policy' },
  exec_timeout: { outcome: 'timeout', reason: 'timeout' },
  connect_timeout: { outcome: 'timeout', reason: 'connection' },
  cancelled: { outcome: 'aborted', reason: 'aborted' },
  unknown_host: { outcome: 'error', reason: 'invalid' },
  invalid_argument: { outcome: 'error', reason: 'invalid' },
  local_path: { outcome: 'error', reason: 'invalid' },
  connection_refused: { outcome: 'error', reason: 'connection' },
  closed_before_handshake: { outcome: 'error', reason: 'connection' },
  host_unreachable: { outcome: 'error', reason: 'connection' },
  auth_failed: { outcome: 'error', reason: 'connection' },
  key_unusable: { outcome: 'error', reason: 'connection' },
  host_key_mismatch: { outcome: 'error', reason: 'connection' },
  transport_lost: { outcome: 'error', reason: 'connection' }
};

const thrownFailure = (error) => {
  if (typeof error?.failureCode === 'string' && CODE_OUTCOMES[error.failureCode] !== undefined) return CODE_OUTCOMES[error.failureCode];
  const message = error instanceof Error ? error.message : String(error ?? '');
  if (error?.code === 'POLICY_DENY' || /\[ssh-pool policy\]/.test(message)) return { outcome: 'denied', reason: 'policy' };
  if (/timed out|timeout/i.test(message)) return { outcome: 'timeout', reason: 'timeout' };
  if (/abort|cancel/i.test(message)) return { outcome: 'aborted', reason: 'aborted' };
  if (/unknown\s+(?:ssh\s+)?host|required|invalid|not found|missing/i.test(message)) return { outcome: 'error', reason: 'invalid' };
  if (/connect|handshake|authentication|host key|ssh/i.test(message)) return { outcome: 'error', reason: 'connection' };
  return { outcome: 'error', reason: 'other' };
};

/**
 * What the command guard can know about the shell an `ssh_run` call will use:
 * the login's home and the named session (looked up, never created) with its
 * working directory and exported variables. A fresh shell's directory is left
 * unknown, so a bare relative target is not judged. Shared by the tool and
 * the DSH pre-dispatch guard, so both judge one command alike.
 */
export function runShellContext(connection, args, callerId) {
  const home = homeFor(connection?.spec?.user);
  const background = args?.background === true || args?.background === 'true';
  const requested = args?.session;
  const wantsDefault = requested === true || requested === 'true';
  const wantsSession = wantsDefault || (typeof requested === 'string' && requested.length > 0 && requested !== 'false');
  const name = typeof requested === 'string' && !wantsDefault ? requested : 'main';
  const session = wantsSession && !background ? connection?.peekSession?.(name, callerId) : undefined;
  return { home, cwd: typeof session?.cwd === 'string' ? session.cwd : null, env: session?.variables ?? {} };
}

/**
 * Build every tool definition bound to one pool.
 * @param pool - the live pool.
 * @param config - the normalized plugin config.
 * @param extras - optional `{ policy, analyzer, diagnostics, policyOncePerCaller }`;
 *   `policy` defaults to `createPolicy()`, `analyzer` is `{ run, status }` or a
 *   bare `run` function (see `analysis.js`). `policyOncePerCaller` (MCP, whose
 *   `initialize` instructions already carry the policy) gives the full
 *   `[policy]` text in a caller's first `ssh_hosts` result and again after a
 *   refusal, and a one-line pointer otherwise.
 * @returns the tool definitions. Each `execute(args, call)` expects the neutral
 *   call context; the DSH adapter in `index.js` translates its execution first.
 */
export function createTools(pool, config, extras = {}) {
  // The guard is not optional: a caller that passes no policy still gets the
  // default one, so no adapter can mount the tools without it.
  const policy = extras.policy ?? createPolicy();

  /** Callers that already got the full policy text and were not refused since. */
  const policyShown = extras.policyOncePerCaller === true ? new Set() : null;
  const policyHintFor = (callerId) => {
    const full = typeof policy?.hints === 'function' ? policy.hints() : '';
    if (policyShown === null || full.length === 0) return full;
    if (policyShown.has(callerId)) return POLICY_REPEAT;
    policyShown.add(callerId);
    return full;
  };

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
      throw new Error(unknownHostMessage(alias, known));
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
      // No real caller id: let the analyzer pick its own stable session name.
      const routed = sessionId === LOCAL_CALLER ? undefined : sessionId;
      const result = await analyzerRun({ tool, target, text, signal, sessionId: routed, bytes: Buffer.byteLength(text, 'utf8') });
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
      'List the SSH hosts this plugin can operate: alias, user@host:port, the user\'s note about the host (also shown as [note] on every call against it), key, connection state, sessions, the last connection error and the last failed call with its error code. Also shows the [policy] guard hints and where this server runs (hostname, OS, cwd), which is where ssh_transfer resolves localPath. Hosts come from ~/.ssh/config (forge entries such as github.com excluded) plus the plugin hosts config. Read-only; a host connects on its first call.',
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
    async execute(args, call) {
      const wanted = typeof args?.host === 'string' && args.host.length > 0 ? args.host : undefined;
      if (wanted !== undefined && (!pool.has(wanted) || pool.hostVisible(wanted) === false)) {
        const known = pool.aliases.filter((candidate) => pool.hostVisible(candidate));
        throw new Error(unknownHostMessage(wanted, known));
      }
      const hosts = visibleStatus().filter((entry) => wanted === undefined || entry.alias === wanted);
      return {
        hosts,
        count: hosts.length,
        policyHint: policyHintFor(call.callerId),
        warnings: wanted === undefined ? pool.warnings : [],
        local: localInfo()
      };
    }
  };

  const sshRun = {
    name: 'ssh_run',
    description: `Run a shell command on a host over its pooled SSH connection (no new handshake per call). Without "session" every call gets a fresh shell; with "session", the working directory and exported variables carry over. Output is capped per stream: filter on the host (grep -m, tail -n, sed -n) instead of dumping files. Give expectedMs for slow work; the deadline is derived from it. A non-zero exit is reported as [exit code: N]. On an idle host the first call opens the SSH connection first (1–3 s, not counted against the deadline). Failures end with an [error: <code>] line; if your client timed out, the command may still have run — check ssh_hosts before repeating anything that changes state. Do not fall back to local ssh. A guard refuses only what would scrap the machine ([policy] in ssh_hosts).`,
    parameters: {
      host: {
        type: 'string',
        required: true,
        description: 'Host alias; ssh_hosts lists them.'
      },
      command: {
        type: 'string',
        required: true,
        description: 'Shell command to run on the host.'
      },
      session: {
        oneOf: [{ type: 'string' }, { type: 'boolean' }],
        description: 'Session name (per host) that keeps cwd and exported variables across calls; true means "main". Omit for a fresh shell per call.'
      },
      analyze: {
        type: 'boolean',
        description: 'true: return only a tool-less side summary of a large log-like result; false: always raw. Omit to follow the 日志旁路分析 switch.'
      },
      expectedMs: {
        type: 'number',
        description: 'Your run-time estimate in ms; the deadline is estimate × 3, clamped to 5 s–30 min. Give it for builds, deploys, backups and restarts; omit it for quick commands (inflating it only delays the failure of a hung command).'
      },
      background: {
        type: 'boolean',
        description: 'Start detached and return at once with pid, logPath and scriptPath; use it for daemons and long tasks instead of appending "&". The log and a `.dsh-ssh-run-<hash>.sh` script holding the command stay in ~/.local/state/dsh-ssh/logs on the host.'
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
        ...session === undefined ? {} : { description: `session ${session}` }
      };
    },
    async execute(args, call) {
      const host = args?.host;
      const command = args?.command;
      if (typeof host !== 'string' || host.length === 0) throw new Error('host is required');
      if (typeof command !== 'string' || command.trim().length === 0) throw new Error('command is required');
      // Deadlines are derived, never fixed: an estimate (the caller's, or one
      // inferred from the command's shape) times a safety factor, clamped.
      const deadline = deadlineFor({ command, expectedMs: args?.expectedMs, ...timeoutPolicy() });
      const timeoutMs = deadline.timeoutMs;
      const connection = visibleHost(host);
      // The Harness may hand a boolean parameter through as the string
      // "true"/"false", so both spellings mean "the default session".
      const background = args?.background === true || args?.background === 'true';
      const requested = args?.session;
      const wantsDefaultSession = requested === true || requested === 'true';
      const wantsSession = wantsDefaultSession || (typeof requested === 'string' && requested.length > 0 && requested !== 'false');
      const sessionName = wantsDefaultSession ? 'main' : typeof requested === 'string' ? requested : null;
      // Before any transport work: a refused command never opens a channel.
      // Relative targets and $VARs resolve against what the shell will have.
      assertCommandAllowed(policy, { host, command, ...runShellContext(connection, args, call.callerId) });
      const started = Date.now();
      const handshakeMs = await ensureTimed(connection);
      // The per-call cap (maxCallMs) bounds how long the agent waits, connect
      // included, so it gets an answer before its client gives up. It never
      // kills: the command keeps running under its own deadline, and how it
      // ended lands on the host (lastCommand, lastFailure) for ssh_hosts.
      const capMs = Number(config.maxCallMs) > 0 ? Number(config.maxCallMs) : 0;
      const capRemaining = capMs > 0 ? Math.max(1000, capMs - (Date.now() - started)) : Infinity;
      const detachAfterMs = capRemaining < timeoutMs ? capRemaining : undefined;
      const runTimeoutMs = timeoutMs;
      const runSource = deadline.source;
      const onDetachedEnd = (outcome) => {
        const seconds = Math.round((Date.now() - started) / 1000);
        if (typeof pool.recordActivity === 'function') {
          const ending = outcome?.error ? 'connection lost' : outcome?.timedOut ? 'killed at its deadline' : `exit ${outcome?.exitCode ?? '?'}`;
          pool.recordActivity({ alias: host, kind: 'run', detail: `${command} [finished after cap: ${ending}, ${seconds}s]`, owner: call.callerId });
        }
        if (outcome?.timedOut === true) {
          pool.noteCallFailure?.(host, { tool: 'ssh_run', code: 'exec_timeout', message: `ran past the per-call cap, then hit its deadline (${timeoutMs}ms) and was killed` });
        } else if (outcome?.error) {
          pool.noteCallFailure?.(host, { tool: 'ssh_run', code: 'transport_lost', message: 'ran past the per-call cap; the connection dropped before it finished' });
        } else if (outcome?.exitCode !== 0) {
          pool.noteCallFailure?.(host, { tool: 'ssh_run', code: 'error', message: `ran past the per-call cap and exited with ${outcome?.exitCode ?? 'no code'}` });
        }
      };
      const capHint = (result) =>
        result.detached === true
          ? `still running: answered at this server's per-call cap (maxCallMs=${capMs}) so the client does not give up; the command was NOT killed and keeps running up to its own deadline (${timeoutMs}ms). Do not rerun it — call ssh_hosts later: lastCommand shows how it finished, lastFailure if it failed. Use background:true for long work next time.`
          : null;
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
            owner: call.callerId
          });
        }
        return value;
      };
      const analyzeRun = async (stdout, stderr) => {
        const text = [stdout, stderr].filter((part) => typeof part === 'string' && part.length > 0).join('\n');
        const bytes = Buffer.byteLength(text, 'utf8');
        const wanted = shouldAnalyze(args?.analyze, LOG_COMMAND.test(command), bytes);
        if (!wanted) return { wanted: false, analysis: null, analysisError: null };
        const result = await runAnalysis({ tool: 'ssh_run', target: command, text, signal: call.signal, sessionId: call.callerId });
        return result.error === undefined
          ? { wanted: true, analysis: result, analysisError: null }
          : { wanted: true, analysis: null, analysisError: result.error };
      };
      // Background mode: the plugin owns detaching, logging and the PID, so the
      // call returns at once and nothing can leak into a later result.
      if (background) {
        const started2 = await connection.background(command, { signal: call.signal });
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
          scriptPath: started2.scriptPath ?? null,
          hint: started2.pid === null ? 'the process may not have started; check the log path and the command' : null,
          analysis: null,
          analysisError: null
        });
      }
      // A trailing "&" without background mode is the classic mistake: the
      // child keeps the channel open, so the call waits for it to exit.
      const backgroundHint = /&\s*$/.test(command.trim())
        ? '命令以 & 结尾但没有用 background:true；若后台进程未重定向输出，本次调用会一直等它退出或超时。要立刻返回并保留日志，请用 background:true。'
        : null;
      if (wantsSession) {
        const name = sessionName ?? 'main';
        const session = connection.session(name, call.callerId);
        const result = await session.run(command, {
          timeoutMs: runTimeoutMs,
          maxOutputBytes: outputLimit(),
          signal: call.signal,
          detachAfterMs,
          onDetachedEnd,
          onOutput: call.onOutput
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
          detached: result.detached === true,
          sessionEnded: result.sessionEnded === true,
          endReason: result.endReason ?? null,
          timeoutMs: runTimeoutMs,
          estimateMs: deadline.estimateMs,
          multiplier: deadline.multiplier,
          deadlineSource: runSource,
          stdout: analysis === null ? safeCap(result.stdout, analysisWanted ? Math.min(outputLimit(), 4096) : outputLimit()) : { text: '', truncated: false },
          stderr: analysis === null ? safeCap(result.stderr, analysisWanted ? Math.min(outputLimit(), 4096) : outputLimit()) : { text: '', truncated: false },
          cwd: result.cwd ?? null,
          durationMs: Date.now() - started,
          handshakeMs,
          reused: handshakeMs === 0,
          pid: null,
          logPath: null,
          scriptPath: null,
          hint: capHint(result) ?? analysisError ?? backgroundHint,
          analysis,
          analysisError
        });
      }
      const result = await connection.exec(command, {
        timeoutMs: runTimeoutMs,
        maxOutputBytes: outputLimit(),
        signal: call.signal,
        detachAfterMs,
        onDetachedEnd,
        onOutput: call.onOutput
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
        detached: result.detached === true,
        sessionEnded: false,
        endReason: null,
        timeoutMs: runTimeoutMs,
        estimateMs: deadline.estimateMs,
        multiplier: deadline.multiplier,
        deadlineSource: runSource,
        stdout: analysis === null ? safeCap(result.stdout, analysisWanted ? Math.min(outputLimit(), 4096) : outputLimit()) : { text: '', truncated: false },
        stderr: analysis === null ? safeCap(result.stderr, analysisWanted ? Math.min(outputLimit(), 4096) : outputLimit()) : { text: '', truncated: false },
        cwd: null,
        durationMs: Date.now() - started,
        handshakeMs,
        reused: handshakeMs === 0,
        pid: null,
        logPath: null,
        scriptPath: null,
        hint: capHint(result) ?? analysisError ?? backgroundHint,
        analysis,
        analysisError
      });
    }
  };

  /** Refuse the few write targets the shell guard would also refuse. */
  const guardWritePath = (host, path) => assertWritePathAllowed({ host, path });

  const sshTransfer = {
    name: 'ssh_transfer',
    description:
      'Upload or download one file over SFTP on the host\'s pooled connection (binary exact, no second handshake). localPath is on the machine running this server (ssh_hosts → [local]), used exactly as given; remotePath is a POSIX path on the host. Parent directories are created by default. A transfer is cancelled at its deadline, so a stalled link cannot hang the call.',
    parameters: {
      direction: {
        type: 'string',
        enum: ['upload', 'download'],
        required: true,
        description: '"upload" copies localPath to remotePath; "download" copies remotePath to localPath.'
      },
      host: { type: 'string', required: true, description: 'Host alias; ssh_hosts lists them.' },
      localPath: { type: 'string', required: true, description: 'Absolute path on the machine running this server, not necessarily the agent\'s.' },
      remotePath: { type: 'string', required: true, description: 'Path on the SSH host (POSIX form, e.g. /root/app.tar.gz).' },
      createDirs: {
        type: 'boolean',
        description: 'Create missing parent directories at the destination (default true).'
      },
      timeoutMs: {
        type: 'number',
        description: 'Deadline in ms (default: the SSH assistant\'s transfer timeout). A transfer that outlives it is cancelled.'
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
    async execute(args, call) {
      const direction = args?.direction;
      if (direction !== 'upload' && direction !== 'download') throw new Error('direction must be "upload" or "download"');
      if (typeof args?.host !== 'string' || args.host.length === 0) throw new Error('host is required');
      if (typeof args?.localPath !== 'string' || args.localPath.length === 0) throw new Error('localPath is required');
      if (typeof args?.remotePath !== 'string' || args.remotePath.length === 0) throw new Error('remotePath is required');
      visibleHost(args.host);
      if (direction === 'upload') guardWritePath(args.host, args.remotePath);
      const transferStarted = Date.now();
      const transferred = await transferFile(pool, {
        host: args.host,
        direction,
        localPath: args.localPath,
        remotePath: args.remotePath,
        createDirs: args.createDirs !== false,
        // A transfer always has a deadline: 0 no longer means "wait forever".
        timeoutMs: Number.isFinite(Number(args.timeoutMs)) && Number(args.timeoutMs) > 0 ? Number(args.timeoutMs) : transferTimeout(),
        signal: call.signal
      });
      if (typeof pool.recordActivity === 'function') {
        pool.recordActivity({
          alias: args.host,
          kind: 'transfer',
          detail: `${direction} ${args.localPath} → ${args.remotePath}`,
          durationMs: Date.now() - transferStarted,
          owner: call.callerId
        });
      }
      return transferred;
    }
  };

  /** The `[note]` line for one host-scoped call. */
  const hostNotices = (host) => {
    const lines = [];
    const remark = typeof pool.hostMeta === 'function' ? pool.hostMeta(host)?.remark : '';
    if (typeof remark === 'string' && remark.trim().length > 0) lines.push(`[note] ${host}: ${remark.replace(/\s+/g, ' ').trim()}`);
    return lines;
  };

  const tools = [sshHosts, sshRun, sshTransfer].map((tool) => ({
    ...tool,
    parameters: parameterSchema(tool.parameters),
    // Normalize whatever the adapter passed, so a missing or partial context
    // still yields a valid `{ callerId, signal }`.
    execute: async (args, input) => {
      const host = typeof args?.host === 'string' && args.host.length > 0 ? args.host : null;
      const call = callContext(input);
      try {
        const raw = await tool.execute(args, call);
        const notices = host !== null && tool.name !== 'ssh_hosts' ? hostNotices(host) : [];
        // First key, so a client that dumps the value shows the note first.
        const value = notices.length > 0 && raw !== null && typeof raw === 'object' && !Array.isArray(raw) ? { notices, ...raw } : raw;
        if (host !== null && value?.timedOut === true) {
          pool.noteCallFailure?.(host, { tool: tool.name, code: 'exec_timeout', message: `deadline ${value.timeoutMs}ms reached; the remote command was killed` });
        } else if (host !== null && value?.aborted === true) {
          pool.noteCallFailure?.(host, { tool: tool.name, code: 'cancelled', message: 'cancelled by the caller before the command finished' });
        }
        return value;
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error ?? '');
        const annotated = annotateError(error);
        // A refusal points the agent at ssh_hosts for the rules: give it the full text there.
        if (annotated.failureCode === 'policy_denied') policyShown?.delete(call.callerId);
        // An unknown (or hidden) alias is never recorded: it must not leave a
        // trace on a hidden host that the agent could later read.
        if (host !== null && annotated.failureCode !== 'unknown_host') {
          pool.noteCallFailure?.(host, { tool: tool.name, code: annotated.failureCode, message });
        }
        throw annotated;
      }
    },
    // Every host-scoped result carries the host's own note, so a remark like
    // "生产主库，先确认" reaches the agent even when it never calls ssh_hosts.
    // It goes into the text *and* the value (`notices`): MCP clients that read
    // `structuredContent` never see the text content.
    ...(tool.name !== 'ssh_hosts' && typeof tool.output?.render === 'function'
      ? {
          output: {
            ...tool.output,
            schema: withNoticesSchema(tool.output.schema),
            render: (args, value) => {
              const content = tool.output.render(args, value);
              const host = typeof args?.host === 'string' ? args.host : null;
              if (host === null || !Array.isArray(content) || content[0]?.type !== 'text') return content;
              const lines = Array.isArray(value?.notices) ? value.notices : hostNotices(host);
              if (lines.length === 0) return content;
              return [{ ...content[0], text: `${lines.join('\n')}\n${content[0].text}` }, ...content.slice(1)];
            }
          }
        }
      : {})
  }));
  if (diagnostics === undefined) return tools;
  return tools.map((tool) => ({
    ...tool,
    async execute(args, call) {
      const started = Date.now();
      try {
        const value = await tool.execute(args, call);
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
