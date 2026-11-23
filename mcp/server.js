/**
 * A dependency-free MCP server core over the host-neutral SSH tools.
 *
 * This file knows the protocol, not the transport: `createMcpSession` takes a
 * `send(message)` callback and exposes `receive(message)`, so the same session
 * runs over stdio (`mcp/stdio.js`) or, later, an HTTP transport.
 *
 * Mapping from the plugin's tool objects:
 *  - `parameters` (already JSON Schema)  → `inputSchema`
 *  - `output.schema`                     → `outputSchema` (protocol ≥ 2025-06-18),
 *    with `required` relaxed to match the lean value below
 *  - `output.render(args, value)`        → text `content`
 *  - the returned value                  → `structuredContent` (≥ 2025-06-18),
 *    lean: null/false fields and pure diagnostics are left out
 *  - a thrown error                      → `isError: true`, with its failure
 *    code (`lib/errors.js`) under `_meta["dsh-ssh-helper/error"]`; a policy
 *    refusal also carries the rule fields there.
 *
 * The command policy needs nothing here: the tools enforce it themselves.
 *
 * @module dsh-ssh-helper/mcp/server
 */
import { posix } from 'node:path';
import { callContext } from '../lib/call-context.js';
import { redactText } from '../lib/redact.js';

/** Newest first; the first entry is offered when the client asks for an unknown one. */
export const SUPPORTED_PROTOCOL_VERSIONS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];

/** Protocol versions that know `outputSchema` / `structuredContent`. */
const STRUCTURED_SINCE = '2025-06-18';
/** Protocol versions that know tool `annotations`. */
const ANNOTATIONS_SINCE = '2025-03-26';

export const ERROR_META_KEY = 'dsh-ssh-helper/error';

const PARSE_ERROR = -32700;
const INVALID_REQUEST = -32600;
const METHOD_NOT_FOUND = -32601;
const INVALID_PARAMS = -32602;
const INTERNAL_ERROR = -32603;

/**
 * Behaviour hints a client can turn into its own approval prompts. They are
 * hints, not enforcement; the command policy is the enforcement.
 */
export const TOOL_ANNOTATIONS = {
  ssh_hosts: { title: 'List SSH hosts', readOnlyHint: true, openWorldHint: false },
  ssh_run: { title: 'Run remote command', readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  ssh_transfer: { title: 'Transfer file', readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true }
};

const atLeast = (version, since) => typeof version === 'string' && version >= since;

/** Copy of `object` without the keys `skip(key, value)` picks. */
const omit = (object, skip) => Object.fromEntries(Object.entries(object).filter(([key, child]) => !skip(key, child)));

/** Host counters that say nothing while they are zero. */
const ZERO_QUIET = new Set(['connectedSeconds', 'connects', 'reconnects', 'failures', 'handshakeTimeouts', 'commands', 'callFailures']);

/**
 * Diagnostics `structuredContent` leaves out; the text content never shows
 * them either. Some clients hand only `structuredContent` to the model, so
 * every field costs tokens on every call. `optional` lists the top-level keys
 * `trim` may remove that the tool's schema requires (the advertised schema
 * stops requiring them).
 */
const STRUCTURED_TRIM = {
  ssh_run: {
    optional: ['handshakeMs', 'reused', 'stderr'],
    trim: (value) =>
      omit(
        value,
        (key, child) =>
          key === 'handshakeMs' ||
          key === 'reused' ||
          // How the deadline was derived only matters once it was hit.
          (value.timedOut !== true && (key === 'estimateMs' || key === 'multiplier' || key === 'deadlineSource')) ||
          (key === 'stderr' && child?.text === '')
      )
  },
  ssh_hosts: {
    optional: [],
    trim: (value) => ({
      ...value,
      hosts: (value.hosts ?? []).map((host) =>
        omit(
          host,
          (key, child) =>
            (ZERO_QUIET.has(key) && child === 0) ||
            (key === 'remark' && child === '') ||
            (key === 'sessions' && Array.isArray(child) && child.length === 0) ||
            key === 'effectiveIdleTimeoutMs' ||
            key === 'lastCommandSeconds'
        )
      )
    })
  }
};

/** A schema whose value may be null or false, i.e. one the lean value can omit. */
function omittable(schema) {
  if (schema === null || typeof schema !== 'object') return false;
  const types = Array.isArray(schema.type) ? schema.type : [schema.type];
  if (types.includes('null') || types.includes('boolean')) return true;
  return [schema.oneOf, schema.anyOf].some((list) => Array.isArray(list) && list.some(omittable));
}

/** The output schema with `required` relaxed to what a lean value always carries. */
function leanSchema(schema, optional = []) {
  if (schema === null || typeof schema !== 'object' || Array.isArray(schema)) return schema;
  const lean = { ...schema };
  if (schema.properties !== undefined) {
    lean.properties = Object.fromEntries(Object.entries(schema.properties).map(([key, child]) => [key, leanSchema(child)]));
    if (Array.isArray(schema.required)) {
      const required = schema.required.filter((key) => !optional.includes(key) && !omittable(schema.properties[key]));
      if (required.length > 0) lean.required = required;
      else delete lean.required;
    }
  }
  if (schema.items !== undefined) lean.items = leanSchema(schema.items);
  for (const key of ['oneOf', 'anyOf']) if (Array.isArray(schema[key])) lean[key] = schema[key].map((child) => leanSchema(child));
  return lean;
}

/** Drop null and false fields at every depth (array entries are kept). */
function leanValue(value) {
  if (Array.isArray(value)) return value.map(leanValue);
  if (value === null || typeof value !== 'object') return value;
  const lean = {};
  for (const [key, child] of Object.entries(value)) {
    if (child === null || child === false || child === undefined) continue;
    lean[key] = leanValue(child);
  }
  return lean;
}

const outputSchemas = new WeakMap();
/** The advertised (lean) output schema of a tool, built once per tool object. */
function outputSchemaOf(tool) {
  if (tool.output?.schema?.type !== 'object') return undefined;
  if (!outputSchemas.has(tool)) outputSchemas.set(tool, leanSchema(tool.output.schema, STRUCTURED_TRIM[tool.name]?.optional ?? []));
  return outputSchemas.get(tool);
}

/** The `structuredContent` for one result: lean, and without the tool's diagnostics. */
function structuredValue(tool, value) {
  const trim = STRUCTURED_TRIM[tool.name]?.trim;
  return leanValue(trim === undefined ? value : trim(value));
}

/** The `tools/list` entry for one plugin tool. */
export function toMcpTool(tool, protocolVersion = SUPPORTED_PROTOCOL_VERSIONS[0]) {
  const annotations = TOOL_ANNOTATIONS[tool.name];
  const entry = {
    name: tool.name,
    description: tool.description,
    inputSchema: tool.parameters?.type === 'object' ? tool.parameters : { type: 'object', properties: {} }
  };
  if (annotations !== undefined && atLeast(protocolVersion, ANNOTATIONS_SINCE)) {
    entry.title = annotations.title;
    entry.annotations = annotations;
  }
  const outputSchema = atLeast(protocolVersion, STRUCTURED_SINCE) ? outputSchemaOf(tool) : undefined;
  if (outputSchema !== undefined) entry.outputSchema = outputSchema;
  return entry;
}

/** The `tools/call` result for a value the tool returned. */
export function toMcpResult(tool, args, value, protocolVersion = SUPPORTED_PROTOCOL_VERSIONS[0]) {
  let content;
  try {
    content = typeof tool.output?.render === 'function' ? tool.output.render(args, value) : undefined;
  } catch {
    content = undefined;
  }
  if (!Array.isArray(content) || content.length === 0) content = [{ type: 'text', text: JSON.stringify(value, null, 2) }];
  const result = { content, isError: false };
  if (atLeast(protocolVersion, STRUCTURED_SINCE) && tool.output?.schema?.type === 'object' && value !== null && typeof value === 'object' && !Array.isArray(value)) {
    result.structuredContent = structuredValue(tool, value);
  }
  return result;
}

/** Longest output line a progress message quotes. */
const PROGRESS_LINE_MAX = 160;
/** ANSI escape sequences and control characters a progress line drops. */
const CONTROL_TEXT = /\x1b\[[0-?]*[ -/]*[@-~]|[\x00-\x08\x0b-\x1f\x7f]/g;

/**
 * Follow one call's live output and keep its latest non-empty line: redacted,
 * stripped of escape codes, clipped. `\r` counts as a line break, so a
 * progress bar shows its current state.
 */
function outputTail() {
  const buffers = { stdout: '', stderr: '' };
  let latest = 'stdout';
  const lastLine = (text) => {
    const lines = text.split(/\r\n|\r|\n/);
    for (let index = lines.length - 1; index >= 0; index -= 1) {
      const clean = lines[index].replace(CONTROL_TEXT, '').trim();
      if (clean.length === 0) continue;
      const safe = redactText(clean);
      return safe.length > PROGRESS_LINE_MAX ? `${safe.slice(0, PROGRESS_LINE_MAX - 1)}…` : safe;
    }
    return '';
  };
  return {
    feed: (stream, text) => {
      const key = stream === 'stderr' ? 'stderr' : 'stdout';
      buffers[key] = (buffers[key] + text).slice(-4096);
      latest = key;
    },
    line: () => lastLine(buffers[latest]) || lastLine(buffers[latest === 'stdout' ? 'stderr' : 'stdout'])
  };
}

/**
 * Calls that are not concurrency-safe (file writes and edits) queue per target
 * file, so a slow write on one host never holds up an edit elsewhere.
 */
function exclusiveKey(args) {
  return typeof args.host === 'string' && typeof args.path === 'string' ? `${args.host}\0${posix.normalize(args.path)}` : '';
}

/**
 * The `tools/call` result for a thrown error. Errors are reported to the model
 * (`isError`), not as JSON-RPC failures, so it can read and react to them.
 */
export function toMcpError(error) {
  const message = error instanceof Error ? error.message : String(error ?? 'tool failed');
  const result = { content: [{ type: 'text', text: message }], isError: true };
  if (error?.code === 'POLICY_DENY') {
    result._meta = {
      [ERROR_META_KEY]: {
        code: error.code,
        failureCode: 'policy_denied',
        rule: error.rule,
        title: error.title,
        reason: error.reason,
        suggestion: error.suggestion,
        matches: error.matches,
        host: error.host,
        target: error.target,
        ...(error.path === undefined ? {} : { path: error.path })
      }
    };
  } else if (typeof error?.failureCode === 'string') {
    result._meta = { [ERROR_META_KEY]: { failureCode: error.failureCode, hint: error.failureHint ?? null, retryable: error.retryable === true } };
  }
  return result;
}

/**
 * One MCP connection.
 *
 * @param input
 * @param input.tools - the plugin tool objects (`createTools(...)`).
 * @param input.send - writes one JSON-RPC message object to the peer.
 * @param input.serverInfo - `{ name, version }`.
 * @param input.instructions - optional usage notes returned by `initialize`.
 * @param input.beforeCall - optional hook run before every `tools/call`
 *   (e.g. re-reading ~/.ssh/config).
 * @param input.onInitialize - optional `({ clientInfo, protocolVersion })`
 *   hook, run once the client has introduced itself.
 * @param input.logger - optional `{ info, warn }`; never stdout.
 * @param input.requestTimeoutMs - deadline for server → client requests.
 * @param input.progressIntervalMs - how often a long `tools/call` that carries
 *   a `progressToken` gets a `notifications/progress` heartbeat.
 */
export function createMcpSession({ tools, send, serverInfo, instructions, beforeCall, onInitialize, logger, requestTimeoutMs = 120_000, progressIntervalMs = 10_000 }) {
  const byName = new Map(tools.map((tool) => [tool.name, tool]));
  const inflight = new Map();
  const pending = new Map();
  let nextId = 1;
  let closed = false;
  let protocolVersion = SUPPORTED_PROTOCOL_VERSIONS[0];
  let clientInfo = null;
  let clientCapabilities = {};
  let initialized = false;
  // Calls that are not concurrency-safe (file writes/edits) run one at a time
  // per target file: key (see `exclusiveKey`) → the tail of that file's queue.
  const exclusive = new Map();

  const reply = (id, result) => send({ jsonrpc: '2.0', id, result });
  const fail = (id, code, message, data) => send({ jsonrpc: '2.0', id, error: { code, message, ...(data === undefined ? {} : { data }) } });

  const callerId = () => `mcp:${typeof clientInfo?.name === 'string' && clientInfo.name.length > 0 ? clientInfo.name : 'client'}`;

  const initialize = (params) => {
    const requested = params?.protocolVersion;
    protocolVersion = SUPPORTED_PROTOCOL_VERSIONS.includes(requested) ? requested : SUPPORTED_PROTOCOL_VERSIONS[0];
    clientInfo = params?.clientInfo ?? null;
    clientCapabilities = params?.capabilities !== null && typeof params?.capabilities === 'object' ? params.capabilities : {};
    try {
      onInitialize?.({ clientInfo, protocolVersion });
    } catch (error) {
      logger?.warn?.(`ssh-pool mcp: onInitialize failed: ${error instanceof Error ? error.message : String(error)}`);
    }
    return {
      protocolVersion,
      capabilities: { tools: { listChanged: false } },
      serverInfo,
      ...(typeof instructions === 'string' && instructions.length > 0 ? { instructions } : {})
    };
  };

  const callTool = async (id, params) => {
    const name = params?.name;
    const tool = typeof name === 'string' ? byName.get(name) : undefined;
    if (tool === undefined) {
      fail(id, INVALID_PARAMS, `Unknown tool: ${String(name)}`);
      return;
    }
    const args = params?.arguments ?? {};
    if (args === null || typeof args !== 'object' || Array.isArray(args)) {
      fail(id, INVALID_PARAMS, 'tool arguments must be an object');
      return;
    }
    const controller = new AbortController();
    inflight.set(id, controller);
    // A client that sent a progressToken may reset its own timeout on each
    // progress notification (MCP allows it), so a slow command is not given up
    // on mid-run, and a client that shows the message sees the latest output
    // line. The message never names the host: the call may target one the
    // agent cannot see.
    const progressToken = params?._meta?.progressToken;
    let heartbeat = null;
    let tail = null;
    if ((typeof progressToken === 'string' || typeof progressToken === 'number') && progressIntervalMs > 0) {
      const began = Date.now();
      let beats = 0;
      tail = outputTail();
      heartbeat = setInterval(() => {
        if (closed || controller.signal.aborted) return;
        beats += 1;
        const seconds = Math.round((Date.now() - began) / 1000);
        const line = tail.line();
        send({ jsonrpc: '2.0', method: 'notifications/progress', params: { progressToken, progress: beats, message: `${tool.name}: still running (${seconds}s)${line === '' ? '' : ` · ${line}`}` } });
      }, progressIntervalMs);
      heartbeat.unref?.();
    }
    const run = async () => {
      try {
        await beforeCall?.(tool.name, args);
      } catch (error) {
        logger?.warn?.(`ssh-pool mcp: beforeCall failed: ${error instanceof Error ? error.message : String(error)}`);
      }
      const value = await tool.execute(args, callContext({ callerId: callerId(), signal: controller.signal, onOutput: tail?.feed }));
      return toMcpResult(tool, args, value, protocolVersion);
    };
    let result;
    try {
      const safe = typeof tool.isConcurrencySafe === 'function' ? tool.isConcurrencySafe(args) !== false : true;
      if (safe) {
        result = await run();
      } else {
        const key = exclusiveKey(args);
        const turn = (exclusive.get(key) ?? Promise.resolve()).then(run);
        const settled = turn.catch(() => {});
        exclusive.set(key, settled);
        // The last call in a file's queue removes the queue when it is done.
        settled.then(() => {
          if (exclusive.get(key) === settled) exclusive.delete(key);
        });
        result = await turn;
      }
    } catch (error) {
      result = toMcpError(error);
    } finally {
      if (heartbeat !== null) clearInterval(heartbeat);
      inflight.delete(id);
    }
    // A cancelled request gets no response (the client has already moved on).
    if (!controller.signal.aborted && !closed) reply(id, result);
  };

  const handleRequest = async (message) => {
    const { id, method, params } = message;
    switch (method) {
      case 'initialize':
        reply(id, initialize(params));
        return;
      case 'ping':
        reply(id, {});
        return;
      case 'tools/list':
        reply(id, { tools: tools.map((tool) => toMcpTool(tool, protocolVersion)) });
        return;
      case 'tools/call':
        await callTool(id, params);
        return;
      default:
        fail(id, METHOD_NOT_FOUND, `Method not found: ${String(method)}`);
    }
  };

  const handleNotification = (message) => {
    if (message.method === 'notifications/initialized') {
      initialized = true;
      return;
    }
    if (message.method === 'notifications/cancelled') {
      const controller = inflight.get(message.params?.requestId);
      controller?.abort(new Error(typeof message.params?.reason === 'string' ? message.params.reason : 'cancelled by client'));
    }
    // Every other notification is informational for this server.
  };

  const handleResponse = (message) => {
    const waiter = pending.get(message.id);
    if (waiter === undefined) return;
    pending.delete(message.id);
    waiter.settle(message);
  };

  /** Handle one incoming JSON-RPC message (object) or a batch (array). */
  const receive = async (message) => {
    if (closed) return;
    if (Array.isArray(message)) {
      await Promise.all(message.map((entry) => receive(entry)));
      return;
    }
    if (message === null || typeof message !== 'object' || message.jsonrpc !== '2.0') {
      fail(message?.id ?? null, INVALID_REQUEST, 'expected a JSON-RPC 2.0 message');
      return;
    }
    const hasId = message.id !== undefined && message.id !== null;
    try {
      if (typeof message.method === 'string') {
        if (hasId) await handleRequest(message);
        else handleNotification(message);
      } else if (hasId && ('result' in message || 'error' in message)) {
        handleResponse(message);
      } else {
        fail(message.id ?? null, INVALID_REQUEST, 'message has neither a method nor a result');
      }
    } catch (error) {
      logger?.warn?.(`ssh-pool mcp: ${error instanceof Error ? error.message : String(error)}`);
      if (hasId && typeof message.method === 'string') fail(message.id, INTERNAL_ERROR, error instanceof Error ? error.message : String(error));
    }
  };

  /** Send a request to the client (e.g. `sampling/createMessage`) and await its result. */
  const request = (method, params, { signal, timeoutMs = requestTimeoutMs } = {}) =>
    new Promise((resolve, reject) => {
      if (closed) {
        reject(new Error('MCP session closed'));
        return;
      }
      const id = `s${nextId++}`;
      const cleanup = () => {
        clearTimeout(timer);
        signal?.removeEventListener('abort', onAbort);
      };
      const onAbort = () => {
        if (!pending.delete(id)) return;
        cleanup();
        send({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: id, reason: 'cancelled by server' } });
        reject(signal.reason instanceof Error ? signal.reason : new Error('request cancelled'));
      };
      const timer = setTimeout(() => {
        if (!pending.delete(id)) return;
        cleanup();
        send({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: id, reason: 'timed out' } });
        reject(new Error(`${method} timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      if (signal?.aborted) {
        clearTimeout(timer);
        reject(new Error('request cancelled'));
        return;
      }
      signal?.addEventListener('abort', onAbort, { once: true });
      pending.set(id, {
        settle: (message) => {
          cleanup();
          if (message.error !== undefined) reject(new Error(`${method} failed: ${message.error?.message ?? 'error'}${message.error?.code === undefined ? '' : ` (${message.error.code})`}`));
          else resolve(message.result);
        }
      });
      send({ jsonrpc: '2.0', id, method, params });
    });

  /** Abort every running call and fail every outstanding server request. */
  const close = () => {
    if (closed) return;
    closed = true;
    for (const controller of inflight.values()) controller.abort(new Error('MCP session closed'));
    inflight.clear();
    for (const waiter of pending.values()) waiter.settle({ error: { message: 'MCP session closed' } });
    pending.clear();
  };

  return {
    receive,
    request,
    close,
    /** A malformed line from the transport: answer with a parse error. */
    parseError: (detail) => fail(null, PARSE_ERROR, `Parse error${detail ? `: ${detail}` : ''}`),
    /** Whether the client declared a capability (e.g. `sampling`). */
    supports: (capability) => clientCapabilities?.[capability] !== undefined && clientCapabilities?.[capability] !== null,
    get protocolVersion() {
      return protocolVersion;
    },
    get clientInfo() {
      return clientInfo;
    },
    get initialized() {
      return initialized;
    },
    get callerId() {
      return callerId();
    }
  };
}
