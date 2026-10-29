/**
 * `known_hosts` verification for pooled connections.
 *
 * ssh2 hands the raw host key blob to `hostVerifier`; this module compares it
 * with the OpenSSH `known_hosts` file, supporting both plain and hashed
 * (`|1|salt|hash`) entries. Policy is decided by the caller: `strict` refuses
 * an unknown or changed key, `warn` records the finding and connects anyway,
 * `off` skips the check.
 *
 * @module dsh-ssh-pool/knownhosts
 */
import { createHmac } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';

/** The key type stored as the first field of an SSH host key blob. */
export function keyTypeOf(blob) {
  if (!Buffer.isBuffer(blob) || blob.length < 5) return undefined;
  const length = blob.readUInt32BE(0);
  if (length <= 0 || length > blob.length - 4) return undefined;
  return blob.subarray(4, 4 + length).toString('utf8');
}

/** Host keys relevant to one `host:port`, keyed by `host`/`[host]:port` form. */
function hostNames(host, port) {
  return port === 22 ? [host] : [`[${host}]:${port}`, host];
}

/** Match one `known_hosts` entry against a host name, hashed entries included. */
function entryMatchesHost(entry, host) {
  if (!entry.startsWith('|1|')) {
    // Plain entries may carry a negation marker and comma-separated names.
    return entry.split(',').some((name) => (name.startsWith('!') ? false : name === host));
  }
  const parts = entry.split('|');
  if (parts.length < 4) return false;
  const salt = Buffer.from(parts[2], 'base64');
  const expected = parts[3];
  const candidate = createHmac('sha1', salt).update(host).digest('base64').replace(/=+$/, '');
  return candidate === expected;
}

/**
 * Check one host key against `known_hosts`.
 * @param input - the key blob, host, port, and the known_hosts path.
 * @returns `match`, `mismatch` (the host is known but with a different key), `unknown`, or `unreadable`.
 */
export function checkHostKey({ blob, host, port, knownHostsPath }) {
  const keyType = keyTypeOf(blob);
  if (keyType === undefined) return { status: 'unknown', detail: 'host key blob could not be parsed' };
  const encoded = blob.toString('base64');
  if (!knownHostsPath || !existsSync(knownHostsPath)) {
    return { status: 'unreadable', detail: `no known_hosts file at ${knownHostsPath ?? '(unset)'}` };
  }
  let text;
  try {
    text = readFileSync(knownHostsPath, 'utf8');
  } catch (error) {
    return { status: 'unreadable', detail: error instanceof Error ? error.message : String(error) };
  }
  const names = hostNames(host, port);
  let sawHost = false;
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed.length === 0 || trimmed.startsWith('#')) continue;
    // `@cert-authority` / `@revoked` markers are not modeled.
    if (trimmed.startsWith('@')) continue;
    const [nameField, entryType, entryKey] = trimmed.split(/\s+/);
    if (!nameField || !entryType || !entryKey) continue;
    if (!names.some((name) => entryMatchesHost(nameField, name))) continue;
    sawHost = true;
    if (entryType === keyType && entryKey === encoded) return { status: 'match', keyType };
  }
  if (sawHost) return { status: 'mismatch', keyType };
  return { status: 'unknown', keyType };
}
