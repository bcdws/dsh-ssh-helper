/**
 * Small, bounded diagnostics buffer for the SSH tools.
 *
 * This is not an audit log: it never stores commands, paths, stdout, stderr,
 * file contents or provider payloads. Each entry is a fixed-shape event with
 * only a host alias, the tool name, an outcome/reason enum, duration, output
 * byte count, connection reuse and side-analysis status. The buffer is
 * in-memory only and reset when the plugin reloads; the panel exposes a
 * snapshot read-only through `/ssh-pool/state`.
 *
 * @module dsh-ssh-helper/diagnostics
 */

const MAX_EVENTS = 50;
const SLOW_MS = 30_000;
const OUTCOMES = new Set(['ok', 'error', 'denied', 'timeout', 'aborted']);
const ANALYSIS_STATUSES = new Set(['success', 'empty', 'busy', 'error', 'skipped']);
const REASONS = new Set([
  'policy',
  'timeout',
  'aborted',
  'invalid',
  'connection',
  'analysis',
  'other'
]);

const compact = (value, max = 40) =>
  typeof value === 'string' && value.length > 0 ? value.slice(0, max) : null;

const WRAPPERS = new Set([
  'sudo',
  'doas',
  'nice',
  'ionice',
  'nohup',
  'time',
  'command',
  'builtin',
  'exec',
  'env',
  'stdbuf',
  'setsid',
  'chrt',
  'taskset',
  'timeout'
]);

/**
 * First executable of a shell command, for low-sensitivity correlation.
 *
 * Only the command word is returned (for example `du`, `journalctl`, `apt`);
 * arguments, paths, redirections and output are never stored. A wrapper such
 * as `sudo`/`timeout` is skipped when its shape is simple; anything that cannot
 * be classified becomes null rather than leaking more text.
 */
export function commandKind(command) {
  if (typeof command !== 'string' || command.trim().length === 0) return null;
  const tokens = command.trim().split(/\s+/);
  for (let index = 0; index < tokens.length; index += 1) {
    const raw = tokens[index].replace(/^[('"]+/, '').replace(/[)'";&|]+$/, '');
    if (raw.length === 0 || raw === '&&' || raw === '||' || raw === ';') continue;
    const base = raw.split('/').pop() ?? '';
    if (WRAPPERS.has(base)) {
      // Skip a wrapper's options and, for timeout/nice, its numeric operand.
      while (index + 1 < tokens.length && /^(?:-{1,2}|[0-9])/.test(tokens[index + 1])) index += 1;
      continue;
    }
    if (/^[A-Za-z0-9._+-]{1,40}$/.test(base)) return base.toLowerCase();
    return null;
  }
  return null;
}

/** Create one process-local diagnostics buffer. */
export function createDiagnostics() {
  const events = [];
  const counters = {
    toolCalls: 0,
    failures: 0,
    policyDenials: 0,
    timeouts: 0,
    slowCalls: 0,
    analyses: { success: 0, empty: 0, busy: 0, error: 0, skipped: 0 }
  };

  const record = (event = {}) => {
    const entry = {
      at: Date.now(),
      tool: compact(event.tool, 40) ?? 'unknown',
      host: compact(event.host, 80),
      commandKind: compact(event.commandKind, 40),
      outcome: OUTCOMES.has(event.outcome) ? event.outcome : 'error',
      reason: REASONS.has(event.reason) ? event.reason : null,
      durationMs: Number.isFinite(event.durationMs) ? Math.max(0, Math.round(event.durationMs)) : 0,
      bytes: Number.isFinite(event.bytes) ? Math.max(0, Math.round(event.bytes)) : 0,
      reused: event.reused === true ? true : event.reused === false ? false : null,
      analysis: ANALYSIS_STATUSES.has(event.analysis) ? event.analysis : null,
      slow: Number.isFinite(event.durationMs) ? Math.max(0, Math.round(event.durationMs)) >= SLOW_MS : false
    };
    events.push(entry);
    if (events.length > MAX_EVENTS) events.shift();

    counters.toolCalls += 1;
    if (entry.outcome !== 'ok') counters.failures += 1;
    if (entry.outcome === 'denied') counters.policyDenials += 1;
    if (entry.outcome === 'timeout') counters.timeouts += 1;
    if (entry.slow) counters.slowCalls += 1;
    if (entry.analysis !== null) counters.analyses[entry.analysis] += 1;
  };

  const snapshot = () => ({
    counters: { ...counters, analyses: { ...counters.analyses } },
    events: events.map((event) => ({ ...event }))
  });

  return { record, snapshot };
}
