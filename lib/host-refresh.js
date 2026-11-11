/**
 * Re-read the host table from OpenSSH config into a live pool.
 *
 * Shared by every host adapter: the DSH panel calls it on each state read, the
 * MCP server before each tool call, so a host or key added locally appears
 * without restarting anything.
 *
 * @module dsh-ssh-helper/host-refresh
 */
import { buildHostTable } from './config.js';

/**
 * @param input - `{ pool, config, logger }`; `config` is a normalized config.
 * @returns `refresh()` → `{ added, changed, removed, skipped? }`.
 */
export function createHostRefresher({ pool, config, logger }) {
  return () => {
    const next = buildHostTable(config);
    // A missing or unreadable config is treated as "keep what we have": a
    // transient read failure must never silently remove every host.
    const unreadable = next.warnings.some((warning) => warning.startsWith('cannot read') || warning.startsWith('ssh config not found'));
    if (unreadable && pool.aliases.length > 0) {
      pool.warnings = [...next.warnings];
      return { added: [], changed: [], removed: [], skipped: true };
    }
    const diff = pool.refreshHosts(next.hosts, next.warnings);
    if (diff.added.length > 0 || diff.changed.length > 0 || diff.removed.length > 0) {
      logger?.info?.(
        `ssh-pool: host table refreshed (added=${diff.added.length}, changed=${diff.changed.length}, removed=${diff.removed.length})`
      );
    }
    return diff;
  };
}
