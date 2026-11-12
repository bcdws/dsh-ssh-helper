/**
 * Close a server's live connection when the panel hides its host.
 *
 * The DSH panel does this for its own pool inside the `meta` route; an MCP
 * server only sees the state file change, so it diffs the hidden set on every
 * change. Only a transition to hidden counts, so a host the agent already
 * could not reach, or an unhide, leaves the connection alone.
 *
 * @module dsh-ssh-helper/mcp/hidden-watch
 */
import { closeHiddenConnection } from '../lib/assistant-api.js';

/**
 * @param input - `{ pool, meta, logger }`; `meta` is a state view with
 *   `refresh()` and `host(alias)`.
 * @returns `check()` — run it on a timer; returns the newly hidden aliases.
 */
export function createHiddenWatcher({ pool, meta, logger }) {
  const hiddenNow = () => new Set(pool.aliases.filter((alias) => meta.host(alias).hidden === true));
  let hidden = hiddenNow();
  return () => {
    if (!meta.refresh()) return [];
    const next = hiddenNow();
    const closed = [];
    for (const connection of pool.connections()) {
      const alias = connection.alias;
      if (!next.has(alias) || hidden.has(alias)) continue;
      closeHiddenConnection(connection, () => meta.host(alias).hidden === true, 'hidden in the MCP panel');
      logger?.info?.(`${alias} hidden in the panel; closed its live connection`);
      closed.push(alias);
    }
    hidden = next;
    return closed;
  };
}
