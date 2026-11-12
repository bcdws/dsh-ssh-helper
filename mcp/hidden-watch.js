/**
 * Close a server's live connection a little while after the panel hides its
 * host.
 *
 * The DSH panel does this for its own pool inside the `meta` route; an MCP
 * server only sees the state file change, so it diffs the hidden set on every
 * change. Only a transition to hidden counts, so a host the agent already
 * could not reach, or an unhide, leaves the connection alone. The grace period
 * lets a command already in flight finish; showing the host again cancels it.
 *
 * @module dsh-ssh-helper/mcp/hidden-watch
 */
import { HIDDEN_CLOSE_DELAY_MS, scheduleHiddenConnectionClose } from '../lib/assistant-api.js';

/**
 * @param input - `{ pool, meta, logger, delayMs }`; `meta` is a state view with
 *   `refresh()` and `host(alias)`.
 * @returns `check()` — run it on a timer; returns the aliases whose close was
 *   newly scheduled.
 */
export function createHiddenWatcher({ pool, meta, logger, delayMs = HIDDEN_CLOSE_DELAY_MS }) {
  const hiddenNow = () => new Set(pool.aliases.filter((alias) => meta.host(alias).hidden === true));
  let hidden = hiddenNow();
  /** alias → cancel function for a close still inside its grace period. */
  const pending = new Map();
  const cancel = (alias) => {
    pending.get(alias)?.();
    pending.delete(alias);
  };
  return () => {
    if (!meta.refresh()) return [];
    const next = hiddenNow();
    const scheduled = [];
    for (const connection of pool.connections()) {
      const alias = connection.alias;
      if (!next.has(alias) || hidden.has(alias)) continue;
      cancel(alias);
      pending.set(
        alias,
        scheduleHiddenConnectionClose(connection, () => meta.host(alias).hidden === true, { delayMs, reason: 'hidden in the MCP panel' })
      );
      logger?.info?.(`${alias} hidden in the panel; will close its live connection in ${Math.round(delayMs / 1000)}s`);
      scheduled.push(alias);
    }
    // Showing the host again before the deadline keeps the connection.
    for (const alias of [...pending.keys()]) if (!next.has(alias)) cancel(alias);
    hidden = next;
    return scheduled;
  };
}
