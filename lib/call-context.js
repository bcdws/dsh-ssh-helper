/**
 * The host-neutral call context every tool receives as its second argument.
 *
 * A tool needs exactly two things from whoever invoked it:
 *  - `callerId`: who is calling. Persistent shell sessions are keyed by it, so
 *    two callers on the same host never share `cd` or exported variables while
 *    still sharing the pooled transport.
 *  - `signal`: an optional AbortSignal that cancels the remote work.
 *
 * Each host adapter builds this from its own execution shape (DSH passes
 * `{ agent: { id }, signal }`; an MCP server would use its session id), so the
 * tools never read a host-specific field.
 *
 * @module dsh-ssh-helper/call-context
 */

/** Caller id used when the host supplies none (a single local user). */
export const LOCAL_CALLER = 'local';

/**
 * Normalize a call context.
 * @param {{ callerId?: unknown, signal?: unknown }} [input]
 * @returns {{ callerId: string, signal: AbortSignal | undefined }}
 */
export function callContext(input = {}) {
  const source = input !== null && typeof input === 'object' ? input : {};
  const callerId = typeof source.callerId === 'string' && source.callerId.length > 0 ? source.callerId : LOCAL_CALLER;
  const signal = isAbortSignal(source.signal) ? source.signal : undefined;
  return Object.freeze({ callerId, signal });
}

/** Translate a DSH tool execution into the neutral call context. */
export function fromDshExecution(execution) {
  return callContext({ callerId: execution?.agent?.id, signal: execution?.signal });
}

function isAbortSignal(value) {
  return value !== null && typeof value === 'object' && typeof value.aborted === 'boolean' && typeof value.addEventListener === 'function';
}
