/**
 * A read-only view of the SSH assistant state (`$DSH_HOME/ssh-pool/state.json`).
 *
 * The DSH panel owns that file. An MCP process only reads it, so a host hidden
 * in the panel is hidden from every agent too, and two processes never
 * overwrite each other's edits. The file is re-read when its mtime changes
 * (checked at most once per `minIntervalMs`), so a running MCP server follows
 * the panel without a restart.
 *
 * @module dsh-ssh-helper/mcp/state-view
 */
import { statSync } from 'node:fs';
import { MetadataStore, defaultStatePath } from '../lib/store.js';

/**
 * @param input - `{ filePath?, defaults?, minIntervalMs? }`; `defaults` is the
 *   same `{ settings }` seed `MetadataStore` takes.
 * @returns `{ host(alias), settings(), filePath }` — the shape `SshPool` reads.
 */
export function createStateView({ filePath = defaultStatePath(), defaults = {}, minIntervalMs = 1000 } = {}) {
  const mtimeOf = () => {
    try {
      return statSync(filePath).mtimeMs;
    } catch {
      return null;
    }
  };
  let store = new MetadataStore({ filePath, defaults });
  let mtime = mtimeOf();
  let checkedAt = Date.now();

  const current = () => {
    const now = Date.now();
    if (now - checkedAt >= minIntervalMs) {
      checkedAt = now;
      const next = mtimeOf();
      if (next !== mtime) {
        mtime = next;
        store = new MetadataStore({ filePath, defaults });
      }
    }
    return store;
  };

  return {
    filePath,
    host: (alias) => current().host(alias),
    settings: () => current().settings()
  };
}
