/**
 * Remote file operations over the pooled connection's SFTP session.
 *
 * Everything here rides on the existing client: no extra software on the host,
 * no shell quoting, binary exact. Two guarantees matter for an agent editing
 * files it did not create:
 *
 * - every read returns a `sha256`, and every edit must present it back; the
 *   edit re-reads the file and refuses with `stale-edit` if it changed;
 * - writes go to a temp file in the same directory and are renamed over the
 *   target, so a failed write cannot leave a half-written file behind.
 *
 * @module dsh-ssh-helper/files
 */
import { createHash, randomBytes } from 'node:crypto';
import { openSftp } from './sftp.js';

/** sha256 of a buffer, hex. */
export function sha256Of(buffer) {
  return createHash('sha256').update(buffer).digest('hex');
}

/** Convert a glob (`*`, `**`, `?`) into an anchored RegExp. */
export function globToRegExp(pattern) {
  let out = '';
  const text = String(pattern ?? '');
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (char === '*') {
      if (text[index + 1] === '*') {
        // `**/` matches zero or more path segments.
        if (text[index + 2] === '/') {
          out += '(?:[^/]+/)*';
          index += 2;
        } else {
          out += '.*';
          index += 1;
        }
      } else {
        out += '[^/]*';
      }
      continue;
    }
    if (char === '?') {
      out += '[^/]';
      continue;
    }
    out += char.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`^${out}$`);
}

/** True when `path` matches the glob; a bare pattern also matches any basename. */
export function matchesGlob(path, pattern) {
  const text = String(pattern ?? '');
  const target = String(path ?? '');
  if (globToRegExp(text).test(target)) return true;
  if (!text.includes('/')) return globToRegExp(text).test(target.split('/').pop() ?? '');
  return false;
}

/**
 * Locate the unique occurrence of `oldString`.
 * @returns `{ start, count }` — `count` is how many times it appears.
 */
export function findUnique(content, oldString) {
  if (oldString.length === 0) return { start: -1, count: 0 };
  let count = 0;
  let start = -1;
  let from = 0;
  for (;;) {
    const at = content.indexOf(oldString, from);
    if (at < 0) break;
    count += 1;
    if (start < 0) start = at;
    from = at + oldString.length;
  }
  return { start, count };
}

/** Settle a promise or reject after `timeoutMs`, cancelling the SFTP session. */
function bounded(sftp, promise, timeoutMs, what, signal) {
  const races = [promise];
  let timer;
  let onAbort;
  if (timeoutMs > 0) {
    races.push(new Promise((_, reject) => {
      timer = setTimeout(() => {
        try {
          sftp.end();
        } catch {
          /* already gone */
        }
        reject(new Error(`${what} timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      if (typeof timer.unref === 'function') timer.unref();
    }));
  }
  if (signal !== undefined) {
    races.push(new Promise((_, reject) => {
      onAbort = () => {
        try {
          sftp.end();
        } catch {
          /* already gone */
        }
        reject(new Error(`${what} aborted`));
      };
      if (signal.aborted) onAbort();
      else signal.addEventListener('abort', onAbort, { once: true });
    }));
  }
  return Promise.race(races).finally(() => {
    if (timer !== undefined) clearTimeout(timer);
    if (onAbort !== undefined) signal.removeEventListener('abort', onAbort);
  });
}

/** Open an SFTP session on a pooled connection and always close it. */
async function withSftp(connection, timeoutMs, what, work, signal) {
  connection.beginWork?.();
  try {
    const client = await connection.ensure();
    const sftp = await openSftp(client, { timeoutMs, what, signal });
    try {
      return await bounded(sftp, work(sftp), timeoutMs, what, signal);
    } finally {
      try {
        sftp.end();
      } catch {
        /* already closed */
      }
    }
  } finally {
    connection.endWork?.();
  }
}

const sftpCall = (sftp, method, ...args) =>
  new Promise((resolve, reject) => {
    sftp[method](...args, (error, value) => (error ? reject(error) : resolve(value)));
  });

const sftpStat = async (sftp, path) => {
  try {
    return await sftpCall(sftp, 'stat', path);
  } catch {
    return undefined;
  }
};

const sftpRead = async (sftp, path) => {
  const handle = await new Promise((resolve, reject) => {
    sftp.open(path, 'r', (error, opened) => (error ? reject(error) : resolve(opened)));
  });
  try {
    const stats = await sftpCall(sftp, 'fstat', handle);
    if (stats.isDirectory()) throw new Error(`"${path}" is a directory`);
    const chunks = [];
    let position = 0;
    for (;;) {
      // ssh2's read callback is (err, bytesRead, buffer): using the second
      // argument as the buffer read a number and looped forever.
      const { bytesRead, buffer } = await new Promise((resolve, reject) => {
        sftp.read(handle, Buffer.alloc(64 * 1024), 0, 64 * 1024, position, (error, read, chunk) =>
          error ? reject(error) : resolve({ bytesRead: read ?? 0, buffer: chunk })
        );
      });
      if (!bytesRead || bytesRead <= 0) break;
      chunks.push(buffer.subarray(0, bytesRead));
      position += bytesRead;
      if (position > 8 * 1024 * 1024) throw new Error(`"${path}" is larger than 8 MB; read a slice or use ssh_transfer`);
    }
    return { buffer: Buffer.concat(chunks), stats };
  } finally {
    try {
      sftp.close(handle, () => undefined);
    } catch {
      /* already closed */
    }
  }
};

const sftpWrite = (sftp, path, buffer) =>
  new Promise((resolve, reject) => {
    sftp.writeFile(path, buffer, (error) => (error ? reject(error) : resolve()));
  });

/**
 * Move the temp file over the target.
 *
 * Some SFTP servers refuse a plain `rename` when the destination already exists,
 * so prefer OpenSSH's atomic `posix-rename@openssh.com` extension and fall back
 * to unlink-then-rename where the extension is missing.
 */
const atomicReplace = async (sftp, temp, path) => {
  if (typeof sftp.ext_openssh_rename === 'function') {
    try {
      await sftpCall(sftp, 'ext_openssh_rename', temp, path);
      return;
    } catch {
      /* extension not supported by the server: fall through */
    }
  }
  try {
    await sftpCall(sftp, 'unlink', path);
  } catch {
    /* the target does not exist yet */
  }
  await sftpCall(sftp, 'rename', temp, path);
};

/** Read a text file: content, line window, and the sha256 an edit must present. */
export async function readRemoteFile(connection, { path, offset = 1, limit = 200, timeoutMs = 60000, signal }) {
  return await withSftp(connection, timeoutMs, 'read', async (sftp) => {
    const { buffer, stats } = await sftpRead(sftp, path);
    const text = buffer.toString('utf8');
    const all = text.split('\n');
    const total = all.length;
    const from = Math.max(1, Math.round(Number(offset) || 1));
    const count = Math.max(1, Math.round(Number(limit) || 200));
    const slice = all.slice(from - 1, from - 1 + count);
    return {
      path,
      sha256: sha256Of(buffer),
      size: buffer.length,
      totalLines: total,
      offset: from,
      limit: count,
      lines: slice.length,
      content: slice.join('\n'),
      truncated: from - 1 + count < total,
      mtimeMs: typeof stats.mtime === 'number' ? stats.mtime * 1000 : null
    };
  }, signal);
}

/** Write a text file atomically, optionally keeping a dated backup. */
export async function writeRemoteFile(connection, { path, content, backup = true, timeoutMs = 60000, signal }) {
  return await withSftp(connection, timeoutMs, 'write', async (sftp) => {
    const buffer = Buffer.from(String(content ?? ''), 'utf8');
    const existing = await sftpStat(sftp, path);
    // The rename replaces the file wholesale, so its mode has to be carried over:
    // a fresh temp file would otherwise drop an executable bit (0755 → 0644) and
    // silently break scripts that later get executed.
    const mode = existing === undefined ? null : existing.mode & 0o7777;
    let backupPath = null;
    if (existing !== undefined && backup === true) {
      const current = await sftpRead(sftp, path);
      backupPath = `${path}.bak.${new Date().toISOString().slice(0, 10)}`;
      await sftpWrite(sftp, backupPath, current.buffer);
      if (mode !== null) await sftpCall(sftp, 'chmod', backupPath, mode);
    }
    const temp = `${path}.dsh-tmp-${randomBytes(4).toString('hex')}`;
    try {
      await sftpWrite(sftp, temp, buffer);
      if (mode !== null) await sftpCall(sftp, 'chmod', temp, mode);
      await atomicReplace(sftp, temp, path);
    } catch (error) {
      try {
        await sftpCall(sftp, 'unlink', temp);
      } catch {
        /* nothing to clean up */
      }
      throw error;
    }
    return { path, bytes: buffer.length, sha256: sha256Of(buffer), backup: backupPath, created: existing === undefined, mode };
  }, signal);
}

/**
 * Replace text in a file only when the caller's sha256 still matches.
 *
 * `oldString` must appear exactly once unless `replaceAll` is set: a blind
 * replace is how an agent silently rewrites unrelated code.
 */
export async function editRemoteFile(connection, { path, sha256, oldString, newString, replaceAll = false, backup = true, timeoutMs = 60000, signal }) {
  return await withSftp(connection, timeoutMs, 'edit', async (sftp) => {
    const { buffer, stats } = await sftpRead(sftp, path);
    const current = sha256Of(buffer);
    if (typeof sha256 !== 'string' || sha256.length === 0) {
      throw new Error(`ssh_edit needs the sha256 returned by ssh_read for "${path}"; re-read the file first (current sha256: ${current})`);
    }
    // A short prefix is accepted (the model often copies the 12-character
    // display form); anything shorter than 8 cannot identify a file safely.
    const expected = sha256.trim().toLowerCase();
    const matches = expected.length >= 8 ? current.startsWith(expected) : current === expected;
    if (!matches) {
      const shown = current.startsWith(expected.slice(0, 8)) ? 24 : 12;
      const error = new Error(
        `stale-edit: "${path}" changed since it was read (expected ${expected.slice(0, shown)}, found ${current.slice(0, shown)}); nothing was written — read it again`
      );
      error.rule = 'stale-edit';
      throw error;
    }
    const text = buffer.toString('utf8');
    const found = findUnique(text, String(oldString ?? ''));
    if (found.count === 0) throw new Error(`oldString not found in "${path}" (sha256 still ${current.slice(0, 12)})`);
    if (found.count > 1 && replaceAll !== true) {
      throw new Error(`oldString appears ${found.count} times in "${path}"; make it unique or pass replaceAll: true (nothing was written)`);
    }
    const next = replaceAll === true ? text.split(oldString).join(String(newString ?? '')) : text.slice(0, found.start) + String(newString ?? '') + text.slice(found.start + oldString.length);
    const nextBuffer = Buffer.from(next, 'utf8');
    // Carry the mode over: the temp file plus rename would otherwise strip an
    // executable bit (0755 → 0644) and break the very script being edited.
    const mode = typeof stats.mode === 'number' ? stats.mode & 0o7777 : null;
    let backupPath = null;
    if (backup === true) {
      backupPath = `${path}.bak.${new Date().toISOString().slice(0, 10)}`;
      await sftpWrite(sftp, backupPath, buffer);
      if (mode !== null) await sftpCall(sftp, 'chmod', backupPath, mode);
    }
    const temp = `${path}.dsh-tmp-${randomBytes(4).toString('hex')}`;
    try {
      await sftpWrite(sftp, temp, nextBuffer);
      if (mode !== null) await sftpCall(sftp, 'chmod', temp, mode);
      await atomicReplace(sftp, temp, path);
    } catch (error) {
      try {
        await sftpCall(sftp, 'unlink', temp);
      } catch {
        /* nothing to clean up */
      }
      throw error;
    }
    return {
      path,
      replacements: found.count,
      previousSha256: current,
      sha256: sha256Of(nextBuffer),
      bytes: nextBuffer.length,
      backup: backupPath,
      mode,
      mtimeMs: typeof stats.mtime === 'number' ? stats.mtime * 1000 : null
    };
  }, signal);
}

/** List files under `cwd` whose path or basename matches the glob. */
export async function globRemote(connection, { pattern, cwd = '.', maxEntries = 200, maxDepth = 6, timeoutMs = 60000, signal }) {  return await withSftp(connection, timeoutMs, 'glob', async (sftp) => {
    const root = String(cwd ?? '.');
    const found = [];
    let scanned = 0;
    let truncated = false;
    const walk = async (dir, depth) => {
      if (truncated || depth > maxDepth) return;
      let entries;
      try {
        entries = await sftpCall(sftp, 'readdir', dir);
      } catch {
        return;
      }
      for (const entry of entries) {
        if (truncated) return;
        if (entry.filename === '.' || entry.filename === '..') continue;
        const child = `${dir.replace(/\/$/, '')}/${entry.filename}`;
        const attrs = entry.attrs ?? {};
        const isDirectory = typeof attrs.isDirectory === 'function' ? attrs.isDirectory() : (attrs.mode ?? 0) & 0o040000;
        if (isDirectory) {
          if (entry.filename === '.git' || entry.filename === 'node_modules') continue;
          await walk(child, depth + 1);
          continue;
        }
        scanned += 1;
        const relative = child.startsWith(`${root}/`) ? child.slice(root.length + 1) : child;
        if (!matchesGlob(relative, pattern) && !matchesGlob(child, pattern)) continue;
        found.push({ path: child, size: attrs.size ?? null, mtimeMs: typeof attrs.mtime === 'number' ? attrs.mtime * 1000 : null });
        if (found.length >= maxEntries) {
          truncated = true;
          return;
        }
      }
    };
    await walk(root, 0);
    return { pattern, cwd: root, entries: found, scanned, truncated };
  }, signal);
}

/** POSIX single-quote a string for the remote shell. */
function quote(value) {
  return `'${String(value).replace(/'/g, "'\\''")}'`;
}

/**
 * Bounded content search.
 *
 * Runs the host's own `grep` (present on every Linux, no install needed) with
 * hard bounds: matches per file, excluded heavy directories, a deadline, and an
 * output cap. Read-only by construction — it never writes anything.
 */
export async function grepRemote(connection, { pattern, path = '.', include, maxMatches = 50, ignoreCase = false, timeoutMs = 60000, signal }) {
  const limit = Math.max(1, Math.min(1000, Math.round(Number(maxMatches) || 50)));
  const parts = [
    'grep',
    '-rn',
    '--binary-files=without-match',
    '--exclude-dir=.git',
    '--exclude-dir=node_modules',
    '--exclude-dir=.cache',
    `-m ${limit}`
  ];
  if (ignoreCase === true) parts.push('-i');
  if (typeof include === 'string' && include.length > 0) parts.push(`--include=${quote(include)}`);
  parts.push('-e', quote(String(pattern)), quote(String(path ?? '.')));
  const command = parts.join(' ');
  const result = await connection.exec(command, { timeoutMs, maxOutputBytes: 256 * 1024, signal });
  const matches = [];
  let truncated = false;
  let scannedFiles = 0;
  const seen = new Set();
  for (const line of String(result.stdout ?? '').split('\n')) {
    if (line.length === 0) continue;
    const first = line.indexOf(':');
    if (first < 0) continue;
    const second = line.indexOf(':', first + 1);
    if (second < 0) continue;
    const file = line.slice(0, first);
    const lineNumber = Number.parseInt(line.slice(first + 1, second), 10);
    if (!Number.isFinite(lineNumber)) continue;
    seen.add(file);
    if (matches.length >= limit) {
      truncated = true;
      break;
    }
    matches.push({ file, line: lineNumber, text: line.slice(second + 1) });
  }
  scannedFiles = seen.size;
  return { pattern, path: String(path ?? '.'), matches, scannedFiles, truncated, exitCode: result.exitCode, timedOut: result.timedOut === true };
}
