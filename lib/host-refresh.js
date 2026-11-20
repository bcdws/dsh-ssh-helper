/**
 * Re-read the host table from OpenSSH config into a live pool.
 *
 * Shared by every host adapter: the panels call it on each state read, and
 * both adapters run it (through {@link createChangeRefresher}) before each tool
 * call, so a host or key added or renamed locally appears without restarting
 * anything.
 *
 * @module dsh-ssh-helper/host-refresh
 */
import { statSync } from 'node:fs';
import { buildHostTable } from './config.js';

/**
 * Wrap a refresher so it re-reads only when the OpenSSH config changed (mtime
 * or size) since the last check — cheap enough to run before every tool call.
 * The first check only records the baseline: the host table was just built
 * from that same file. A refresh failure is logged, never thrown, so a broken
 * edit cannot make a tool call fail.
 *
 * @param input - `{ config, refresh, logger }`; `config` is a normalized config.
 * @returns `refreshIfChanged()` → the refresh diff, or `undefined` when nothing changed.
 */
export function createChangeRefresher({ config, refresh, logger }) {
  let seen = null;
  const check = () => {
    if (!config.useSshConfig) return undefined;
    let stamp;
    try {
      const stat = statSync(config.sshConfigPath);
      stamp = `${stat.mtimeMs}:${stat.size}`;
    } catch {
      return undefined;
    }
    if (seen === null || stamp === seen) {
      seen = stamp;
      return undefined;
    }
    seen = stamp;
    try {
      return refresh();
    } catch (error) {
      logger?.warn?.(`ssh-pool: host refresh failed: ${error instanceof Error ? error.message : String(error)}`);
      return undefined;
    }
  };
  check();
  return check;
}

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
