/**
 * A dependency-free MCP server core over the host-neutral SSH tools.
 *
 * This file knows the protocol, not the transport: `createMcpSession` takes a
 * `send(message)` callback and exposes `receive(message)`, so the same session
 * runs over stdio (`mcp/stdio.js`) or, later, an HTTP transport.
 *
 * Mapping from the plugin's tool objects:
 *  - `parameters` (already JSON Schema)  → `inputSchema`
 *  - `output.schema`                     → `outputSchema` (protocol ≥ 2025-06-18)
 *  - `output.render(args, value)`        → text `content`
 *  - the returned value                  → `structuredContent` (≥ 2025-06-18)
 *  - a thrown error                      → `isError: true`; a policy refusal also
 *    carries its fields under `_meta["dsh-ssh-helper/error"]`.
 *
 * The command policy needs nothing here: the tools enforce it themselves.
 *
 * @module dsh-ssh-helper/mcp/server
 */
import { callContext } from '../lib/call-context.js';

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
  ssh_read: { title: 'Read remote file', readOnlyHint: true, openWorldHint: true },
  ssh_glob: { title: 'Find remote files', readOnlyHint: true, openWorldHint: true },
  ssh_grep: { title: 'Search remote files', readOnlyHint: true, openWorldHint: true },
  ssh_write: { title: 'Write remote file', readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
  ssh_edit: { title: 'Edit remote file', readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
  ssh_transfer: { title: 'Transfer file', readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true }
};

const atLeast = (version, since) => typeof version === 'string' && version >= since;

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
  if (atLeast(protocolVersion, STRUCTURED_SINCE) && tool.output?.schema?.type === 'object') entry.outputSchema = tool.output.schema;
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
  if (atLeast(protocolVersion, STRUCTURED_SINCE) && tool.output?.schema?.type === 'object' && value !== null && typeof value === 'object') {
    result.structuredContent = value;
  }
  return result;
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
 * @param input.logger - optional `{ info, warn }`; never stdout.
 * @param input.requestTimeoutMs - deadline for server → client requests.
 */
export function createMcpSession({ tools, send, serverInfo, instructions, beforeCall, logger, requestTimeoutMs = 120_000 }) {
  const byName = new Map(tools.map((tool) => [tool.name, tool]));
  const inflight = new Map();
  const pending = new Map();
  let nextId = 1;
  let closed = false;
  let protocolVersion = SUPPORTED_PROTOCOL_VERSIONS[0];
  let clientInfo = null;
  let clientCapabilities = {};
  let initialized = false;
  // Tools that are not concurrency-safe (file writes/edits) run one at a time.
  let exclusive = Promise.resolve();

  const reply = (id, result) => send({ jsonrpc: '2.0', id, result });
  const fail = (id, code, message, data) => send({ jsonrpc: '2.0', id, error: { code, message, ...(data === undefined ? {} : { data }) } });

  const callerId = () => `mcp:${typeof clientInfo?.name === 'string' && clientInfo.name.length > 0 ? clientInfo.name : 'client'}`;

  const initialize = (params) => {
    const requested = params?.protocolVersion;
    protocolVersion = SUPPORTED_PROTOCOL_VERSIONS.includes(requested) ? requested : SUPPORTED_PROTOCOL_VERSIONS[0];
    clientInfo = params?.clientInfo ?? null;
    clientCapabilities = params?.capabilities !== null && typeof params?.capabilities === 'object' ? params.capabilities : {};
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
    const run = async () => {
      try {
        await beforeCall?.(tool.name, args);
      } catch (error) {
        logger?.warn?.(`ssh-pool mcp: beforeCall failed: ${error instanceof Error ? error.message : String(error)}`);
      }
      const value = await tool.execute(args, callContext({ callerId: callerId(), signal: controller.signal }));
      return toMcpResult(tool, args, value, protocolVersion);
    };
    let result;
    try {
      const safe = typeof tool.isConcurrencySafe === 'function' ? tool.isConcurrencySafe(args) !== false : true;
      if (safe) {
        result = await run();
      } else {
        const turn = exclusive.then(run);
        exclusive = turn.catch(() => {});
        result = await turn;
      }
    } catch (error) {
      result = toMcpError(error);
    } finally {
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
