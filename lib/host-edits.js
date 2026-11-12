/**
 * The panel's host edits: rename a key file, rename a Host alias, or both in
 * one atomic step. Each edits the user's `~/.ssh/config` (with a backup),
 * moves the panel metadata with the alias, and rebuilds the pool's host table.
 *
 * Shared by the DSH panel and the MCP panel; only hosts that come from
 * OpenSSH config can be edited (plugin-config hosts live in the bundle config).
 *
 * @module dsh-ssh-helper/host-edits
 */
import { renameIdentityFile } from './keyfile.js';
import { renameHostAlias } from './hostalias.js';
import { editHostIdentity } from './edit-host.js';

/**
 * @param input - `{ pool, store, config, refreshHosts, logger }`; `store` needs
 *   `renameHost(old, new)`, `config` is a normalized config.
 * @returns `{ renameKey, renameHost, editHost }`, the callbacks `createAssistantApi` takes.
 */
export function createHostEditors({ pool, store, config, refreshHosts, logger }) {
  const editableSpec = (alias, where) => {
    const spec = pool.spec(alias);
    if (spec === undefined) throw new Error(`unknown host "${alias}"`);
    if (spec.source !== 'ssh-config') {
      throw new Error(`this host comes from plugin config, not ~/.ssh/config; ${where} in the bundle config instead`);
    }
    return spec;
  };

  /** Rename the actual key file and every IdentityFile pointing at it. */
  const renameKey = ({ alias, keyName }) => {
    const spec = editableSpec(alias, 'rename its IdentityFile');
    const result = renameIdentityFile({ configPath: config.sshConfigPath, identityFile: spec.identityFile, newName: keyName });
    refreshHosts();
    logger?.info?.(`ssh-pool: renamed key ${result.oldName} -> ${result.newName} for ${alias}`);
    return result;
  };

  const renameHost = ({ alias, newAlias }) => {
    editableSpec(alias, 'rename it');
    const result = renameHostAlias({ configPath: config.sshConfigPath, oldAlias: alias, newAlias });
    store.renameHost(alias, result.newAlias);
    refreshHosts();
    logger?.info?.(`ssh-pool: renamed host ${result.oldAlias} -> ${result.newAlias}`);
    return result;
  };

  /** Atomic combined edit used by the single dialog. */
  const editHost = ({ alias, newAlias, keyName }) => {
    const spec = editableSpec(alias, 'edit it');
    const result = editHostIdentity({
      configPath: config.sshConfigPath,
      oldAlias: alias,
      newAlias,
      oldKeyPath: spec.identityFile,
      newKeyName: keyName
    });
    if (result.aliasChanged) store.renameHost(alias, result.newAlias);
    refreshHosts();
    logger?.info?.(
      `ssh-pool: edited ${alias}${result.aliasChanged ? ` -> ${result.newAlias}` : ''}${result.keyChanged ? `; key ${result.oldKeyName} -> ${result.newKeyName}` : ''}`
    );
    return result;
  };

  return { renameKey, renameHost, editHost };
}
