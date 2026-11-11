/**
 * Rename a local SSH identity file and update every matching IdentityFile in
 * the OpenSSH config.
 *
 * This is deliberately a small, conservative transaction:
 *  - only a basename may be supplied (the directory never moves);
 *  - symlinks and existing targets are refused;
 *  - the config is backed up before anything changes;
 *  - the key (and optional .pub) are renamed first, then the config is written
 *    atomically; a config write failure restores both filenames.
 *
 * It does not read key material.
 *
 * @module dsh-ssh-helper/keyfile
 */
import { copyFileSync, existsSync, lstatSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { homedir } from 'node:os';
import { expandPath } from './config.js';

const SAFE_NAME = /^[A-Za-z0-9._-]{1,100}$/;

function fail(message) {
  throw new Error(message);
}

/** Split one IdentityFile value into value text and an inline comment. */
function splitValueComment(raw) {
  let quote = '';
  let escaped = false;
  for (let index = 0; index < raw.length; index += 1) {
    const char = raw[index];
    if (quote !== '') {
      if (escaped) escaped = false;
      else if (char === '\\') escaped = true;
      else if (char === quote) quote = '';
      continue;
    }
    if (char === '"' || char === "'") {
      quote = char;
      continue;
    }
    if (char === '#' && (index === 0 || /\s/.test(raw[index - 1]))) {
      return { value: raw.slice(0, index), comment: raw.slice(index) };
    }
  }
  return { value: raw, comment: '' };
}

function unquote(value) {
  const text = String(value).trim();
  if (text.length >= 2 && ((text.startsWith('"') && text.endsWith('"')) || (text.startsWith("'") && text.endsWith("'")))) {
    return text.slice(1, -1);
  }
  return text;
}

/**
 * Render a path as ssh_config wants it: quoted when it holds anything the
 * tokenizer treats specially, and with every backslash doubled so a Windows
 * path survives the config's own escape handling.
 */
export function quoteConfigValue(path) {
  return /[\s#"'\\]/.test(path) ? `"${path.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"` : path;
}

function resolvedPath(value, home) {
  const expanded = expandPath(value, home);
  return isAbsolute(expanded) ? resolve(expanded) : resolve(home, expanded);
}

/** Rewrite every IdentityFile that resolves to `oldPath`. */
export function rewriteIdentityPaths(text, oldPath, newPath, home) {
  let references = 0;
  const lines = text.split(/(?<=\n)/);
  const next = lines.map((line) => {
    const eol = line.endsWith('\r\n') ? '\r\n' : line.endsWith('\n') ? '\n' : '';
    const body = eol === '' ? line : line.slice(0, -eol.length);
    const match = /^(\s*IdentityFile)(\s*=\s*|\s+)(.*)$/i.exec(body);
    if (match === null) return line;
    const { value, comment } = splitValueComment(match[3]);
    if (resolvedPath(unquote(value), home) !== oldPath) return line;
    references += 1;
    const suffix = comment.length > 0 ? ` ${comment}` : '';
    return `${match[1]}${match[2]}${quoteConfigValue(newPath)}${suffix}${eol}`;
  }).join('');
  return { text: next, references };
}

function safeLstat(path, label) {
  let stat;
  try {
    stat = lstatSync(path);
  } catch {
    fail(`${label} not found: ${path}`);
  }
  if (stat.isSymbolicLink()) fail(`${label} is a symlink; refusing to rename it: ${path}`);
  return stat;
}

/**
 * Rename one identity file and update the config references.
 *
 * @param input - `{ configPath, identityFile, newName, home? }`.
 * @returns a small fact object; never includes key material.
 */
export function renameIdentityFile({ configPath, identityFile, newName, home = homedir() }) {
  if (typeof configPath !== 'string' || configPath.length === 0) fail('ssh config path is missing');
  if (typeof identityFile !== 'string' || identityFile.length === 0) fail('host has no identityFile to rename');
  if (typeof newName !== 'string' || newName.length === 0) fail('new key name is required');
  const name = newName.trim();
  if (!SAFE_NAME.test(name) || name === '.' || name === '..' || name.endsWith('.pub')) {
    fail('key name may only contain letters, digits, dot, underscore and hyphen');
  }
  const oldPath = isAbsolute(identityFile) ? resolve(identityFile) : resolve(home, identityFile);
  const newPath = join(dirname(oldPath), name);
  if (oldPath === newPath) return { changed: false, oldName: basename(oldPath), newName: name, references: 0 };

  const oldStat = safeLstat(oldPath, 'identity file');
  if (!oldStat.isFile()) fail(`identity file is not a regular file: ${oldPath}`);
  if (existsSync(newPath)) fail(`target already exists: ${basename(newPath)}`);
  const oldPublic = `${oldPath}.pub`;
  const newPublic = `${newPath}.pub`;
  const hasPublic = existsSync(oldPublic);
  if (hasPublic) {
    const publicStat = safeLstat(oldPublic, 'public key');
    if (!publicStat.isFile()) fail(`public key is not a regular file: ${oldPublic}`);
    if (existsSync(newPublic)) fail(`target already exists: ${basename(newPublic)}`);
  }

  let configText;
  try {
    configText = readFileSync(configPath, 'utf8');
  } catch (error) {
    fail(`cannot read ssh config: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (/^\s*Include\b/im.test(configText)) {
    fail('ssh config uses Include; rename the key in the included file explicitly');
  }
  const oldHome = home;
  const rewritten = rewriteIdentityPaths(configText, oldPath, newPath, oldHome);
  if (rewritten.references === 0) {
    fail(`no IdentityFile in ${configPath} points to ${basename(oldPath)}; refusing a partial rename`);
  }

  const configStat = statSync(configPath);
  const backupPath = `${configPath}.bak.${new Date().toISOString().replace(/[:.]/g, '-')}`;
  try {
    copyFileSync(configPath, backupPath);
  } catch (error) {
    fail(`cannot back up ssh config: ${error instanceof Error ? error.message : String(error)}`);
  }

  const renamed = [];
  try {
    renameSync(oldPath, newPath);
    renamed.push([oldPath, newPath]);
    if (hasPublic) {
      renameSync(oldPublic, newPublic);
      renamed.push([oldPublic, newPublic]);
    }
    const temp = `${configPath}.dsh-tmp-${process.pid}-${Date.now()}`;
    try {
      writeFileSync(temp, rewritten.text, { mode: configStat.mode & 0o7777 });
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
        /* best effort; the original error is more useful */
      }
    }
    fail(`key rename failed: ${error instanceof Error ? error.message : String(error)}`);
  }

  return {
    changed: true,
    oldName: basename(oldPath),
    newName: name,
    publicRenamed: hasPublic,
    references: rewritten.references,
    backup: basename(backupPath)
  };
}
