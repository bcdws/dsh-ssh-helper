/**
 * Rename an OpenSSH `Host` alias without touching the key or host address.
 *
 * Only the exact alias token in `Host` lines is changed; comments, options and
 * other aliases stay as they are. The config is backed up before the write and
 * replaced atomically.
 *
 * @module dsh-ssh-helper/hostalias
 */
import { copyFileSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';

const SAFE_ALIAS = /^[A-Za-z0-9._-]{1,100}$/;

function fail(message) {
  throw new Error(message);
}

/** Split a Host-line value from its inline comment. */
function splitComment(raw) {
  let quote = '';
  for (let index = 0; index < raw.length; index += 1) {
    const char = raw[index];
    if (quote !== '') {
      if (char === quote && raw[index - 1] !== '\\') quote = '';
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

/** Every exact Host pattern in the document (used only for collision checks). */
function hostTokens(text) {
  const tokens = new Set();
  for (const line of String(text).split(/\r?\n/)) {
    const match = /^\s*Host\s+(.*)$/i.exec(line);
    if (match === null) continue;
    const { value } = splitComment(match[1]);
    for (const token of value.trim().split(/\s+/)) if (token.length > 0) tokens.add(token);
  }
  return tokens;
}

/**
 * Pure Host-line rewrite: validate and change every exact alias token.
 * The caller owns the file read/write so the same transformed text can be
 * combined with an IdentityFile rewrite in one transaction.
 */
export function rewriteHostAliases(text, oldAlias, newAlias) {
  if (typeof oldAlias !== 'string' || oldAlias.length === 0) fail('current host alias is required');
  if (typeof newAlias !== 'string' || newAlias.length === 0) fail('new host alias is required');
  const next = newAlias.trim();
  if (!SAFE_ALIAS.test(next)) fail('host alias may only contain letters, digits, dot, underscore and hyphen');
  if (next === oldAlias) return { text, references: 0, newAlias: next };
  if (/^\s*Include\b/im.test(text)) {
    fail('ssh config uses Include; rename the alias in the included file explicitly');
  }
  if (hostTokens(text).has(next)) fail(`host alias already exists: ${next}`);
  const escaped = oldAlias.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const jumpReference = new RegExp(`(?:^|[,\\s@=])${escaped}(?:[,\\s:]|$)`);
  for (const line of String(text).split(/\r?\n/)) {
    const match = /^\s*(ProxyJump|ProxyCommand)\s+(.*)$/i.exec(line);
    if (match === null) continue;
    const { value } = splitComment(match[2]);
    if (jumpReference.test(value)) fail(`host alias is referenced by ${match[1]}; update that reference first`);
  }

  let references = 0;
  const lines = String(text).split(/(?<=\n)/);
  const rewritten = lines.map((line) => {
    const eol = line.endsWith('\r\n') ? '\r\n' : line.endsWith('\n') ? '\n' : '';
    const body = eol === '' ? line : line.slice(0, -eol.length);
    const match = /^(\s*Host)(\s+)(.*)$/i.exec(body);
    if (match === null) return line;
    const { value, comment } = splitComment(match[3]);
    const tokens = value.trim().split(/\s+/).filter(Boolean);
    let hit = false;
    const replaced = tokens.map((token) => {
      if (token !== oldAlias) return token;
      hit = true;
      return next;
    });
    if (!hit) return line;
    references += 1;
    return `${match[1]}${match[2]}${replaced.join(' ')}${comment.length > 0 ? ` ${comment}` : ''}${eol}`;
  }).join('');
  if (references === 0) fail(`no Host alias named "${oldAlias}"`);
  return { text: rewritten, references, newAlias: next };
}

/**
 * Rename one exact Host alias.
 *
 * @param input - `{ configPath, oldAlias, newAlias }`.
 * @returns `{ oldAlias, newAlias, references, backup }`.
 */
export function renameHostAlias({ configPath, oldAlias, newAlias }) {
  if (typeof configPath !== 'string' || configPath.length === 0) fail('ssh config path is missing');
  if (typeof oldAlias !== 'string' || oldAlias.length === 0) fail('current host alias is required');
  if (typeof newAlias !== 'string' || newAlias.length === 0) fail('new host alias is required');
  if (newAlias.trim() === oldAlias) return { oldAlias, newAlias: oldAlias, references: 0, changed: false };
  let text;
  try {
    text = readFileSync(configPath, 'utf8');
  } catch (error) {
    fail(`cannot read ssh config: ${error instanceof Error ? error.message : String(error)}`);
  }
  const rewritten = rewriteHostAliases(text, oldAlias, newAlias);
  const configStat = statSync(configPath);
  const backup = `${configPath}.bak.${new Date().toISOString().replace(/[:.]/g, '-')}`;
  try {
    copyFileSync(configPath, backup);
  } catch (error) {
    fail(`cannot back up ssh config: ${error instanceof Error ? error.message : String(error)}`);
  }

  const temp = join(dirname(configPath), `.${basename(configPath)}.dsh-tmp-${process.pid}-${Date.now()}`);
  try {
    writeFileSync(temp, rewritten.text, { mode: configStat.mode & 0o7777 });
    renameSync(temp, configPath);
  } catch (error) {
    try {
      rmSync(temp, { force: true });
    } catch {
      /* best effort */
    }
    fail(`host rename failed: ${error instanceof Error ? error.message : String(error)}`);
  }

  return { oldAlias, newAlias: rewritten.newAlias, references: rewritten.references, changed: true, backup: basename(backup) };
}
