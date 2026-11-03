/**
 * Atomic Host alias + identity-file rename.
 *
 * Both edits are prepared against one config text, the key file is renamed,
 * and the config is written once. A config-write failure restores the renamed
 * key files, so the dialog's two fields either both apply or neither does.
 *
 * @module dsh-ssh-helper/edit-host
 */
import { copyFileSync, existsSync, lstatSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { homedir } from 'node:os';
import { rewriteHostAliases } from './hostalias.js';
import { rewriteIdentityPaths } from './keyfile.js';

const SAFE_KEY = /^[A-Za-z0-9._-]{1,100}$/;

function fail(message) {
  throw new Error(message);
}

function checkRegular(path, label) {
  let stat;
  try {
    stat = lstatSync(path);
  } catch {
    fail(`${label} not found: ${path}`);
  }
  if (stat.isSymbolicLink()) fail(`${label} is a symlink; refusing to rename it: ${path}`);
  if (!stat.isFile()) fail(`${label} is not a regular file: ${path}`);
  return stat;
}

/**
 * Apply an optional Host alias change and an optional key-file change.
 *
 * @param input - `{ configPath, oldAlias, newAlias?, oldKeyPath?, newKeyName?, home? }`.
 * @returns facts without key material.
 */
export function editHostIdentity({ configPath, oldAlias, newAlias, oldKeyPath, newKeyName, home = homedir() }) {
  if (typeof configPath !== 'string' || configPath.length === 0) fail('ssh config path is missing');
  if (typeof oldAlias !== 'string' || oldAlias.length === 0) fail('current host alias is required');
  const aliasChanged = typeof newAlias === 'string' && newAlias.trim().length > 0 && newAlias.trim() !== oldAlias;
  const keyChanged = typeof newKeyName === 'string' && newKeyName.trim().length > 0;
  if (!aliasChanged && !keyChanged) return { changed: false, aliasChanged: false, keyChanged: false, references: 0 };

  let text;
  try {
    text = readFileSync(configPath, 'utf8');
  } catch (error) {
    fail(`cannot read ssh config: ${error instanceof Error ? error.message : String(error)}`);
  }

  if (aliasChanged) {
    const host = rewriteHostAliases(text, oldAlias, newAlias.trim());
    text = host.text;
  }

  let key = null;
  if (keyChanged) {
    if (typeof oldKeyPath !== 'string' || oldKeyPath.length === 0) fail('host has no identityFile to rename');
    const name = newKeyName.trim();
    if (!SAFE_KEY.test(name) || name === '.' || name === '..' || name.endsWith('.pub')) {
      fail('key name may only contain letters, digits, dot, underscore and hyphen');
    }
    const oldPath = isAbsolute(oldKeyPath) ? resolve(oldKeyPath) : resolve(home, oldKeyPath);
    const newPath = join(dirname(oldPath), name);
    if (oldPath !== newPath) {
      if (/^\s*Include\b/im.test(text)) {
        fail('ssh config uses Include; rename the key in the included file explicitly');
      }
      checkRegular(oldPath, 'identity file');
      if (existsSync(newPath)) fail(`target already exists: ${basename(newPath)}`);
      const oldPublic = `${oldPath}.pub`;
      const newPublic = `${newPath}.pub`;
      const hasPublic = existsSync(oldPublic);
      if (hasPublic) {
        checkRegular(oldPublic, 'public key');
        if (existsSync(newPublic)) fail(`target already exists: ${basename(newPublic)}`);
      }
      const rewritten = rewriteIdentityPaths(text, oldPath, newPath, home);
      if (rewritten.references === 0) fail(`no IdentityFile points to ${basename(oldPath)}; refusing a partial rename`);
      text = rewritten.text;
      key = { oldPath, newPath, oldPublic, newPublic, hasPublic, newName: name };
    }
  }

  const configStat = statSync(configPath);
  const backup = `${configPath}.bak.${new Date().toISOString().replace(/[:.]/g, '-')}`;
  try {
    copyFileSync(configPath, backup);
  } catch (error) {
    fail(`cannot back up ssh config: ${error instanceof Error ? error.message : String(error)}`);
  }

  const renamed = [];
  try {
    if (key !== null) {
      renameSync(key.oldPath, key.newPath);
      renamed.push([key.oldPath, key.newPath]);
      if (key.hasPublic) {
        renameSync(key.oldPublic, key.newPublic);
        renamed.push([key.oldPublic, key.newPublic]);
      }
    }
    const temp = join(dirname(configPath), `.${basename(configPath)}.dsh-tmp-${process.pid}-${Date.now()}`);
    try {
      writeFileSync(temp, text, { mode: configStat.mode & 0o7777 });
      renameSync(temp, configPath);
    } catch (error) {
      try {
        rmSync(temp, { force: true });
      } catch {
        /* best effort */
      }
      throw error;
    }
  } catch (error) {
    for (const [from, to] of renamed.reverse()) {
      try {
        renameSync(to, from);
      } catch {
        /* best effort; original error is more useful */
      }
    }
    fail(`edit failed: ${error instanceof Error ? error.message : String(error)}`);
  }

  return {
    changed: true,
    aliasChanged,
    keyChanged: key !== null,
    oldAlias,
    newAlias: aliasChanged ? newAlias.trim() : oldAlias,
    oldKeyName: key === null ? null : basename(key.oldPath),
    newKeyName: key === null ? null : key.newName,
    references: key === null ? 0 : 1,
    backup: basename(backup)
  };
}
