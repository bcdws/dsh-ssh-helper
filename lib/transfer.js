/**
 * SFTP transfers over a host's pooled connection.
 *
 * Both directions reuse the live connection, so a transfer never pays a second
 * handshake, and SFTP is binary exact — no base64 round trip.
 *
 * @module dsh-ssh-pool/transfer
 */
import { existsSync, mkdirSync, statSync } from 'node:fs';
import { dirname } from 'node:path';
import { posix } from 'node:path';

/** Promisify `sftp.mkdir(path, cb)`, treating "already exists" as success. */
function makeRemoteDir(sftp, path) {
  return new Promise((resolve, reject) => {
    sftp.mkdir(path, (error) => {
      if (error === undefined || error === null || error.code === 4 /* SSH_FX_FAILURE: exists */) {
        resolve();
        return;
      }
      reject(error);
    });
  });
}

/** Create every missing directory of a remote POSIX path. */
async function ensureRemoteDir(sftp, remotePath) {
  const target = posix.dirname(remotePath);
  if (target === '.' || target === '/' || target === '') return;
  const segments = target.split('/').filter((segment) => segment.length > 0);
  let current = target.startsWith('/') ? '' : '.';
  for (const segment of segments) {
    current = current === '' ? `/${segment}` : `${current}/${segment}`;
    await makeRemoteDir(sftp, current);
  }
}

/**
 * Move one file between this machine and a host.
 * @param input - pool, host alias, direction, paths, and call options.
 * @returns transfer facts for the tool result.
 */
export async function transferFile(pool, { host, direction, localPath, remotePath, createDirs = true, timeoutMs = 0, signal }) {
  const connection = pool.connection(host);
  const started = Date.now();
  connection.beginWork?.();
  try {
    const client = await connection.ensure();
    const sftp = await new Promise((resolve, reject) => {
      client.sftp((error, session) => (error ? reject(error) : resolve(session)));
    });
    let timer;
    let onAbort;
    let failCancelled;
    // A cancellation must settle the await below: closing the SFTP session alone
    // leaves a stalled fastPut/fastGet callback pending, which is exactly the
    // "waits forever" case a deadline is supposed to prevent.
    const cancelled = new Promise((_, reject) => {
      failCancelled = reject;
    });
    cancelled.catch(() => undefined);
    const stop = (message) => {
      try {
        sftp.end();
      } catch {
        /* already closed */
      }
      failCancelled(new Error(message));
    };
    try {
      if (timeoutMs > 0) {
        timer = setTimeout(() => stop(`transfer timed out after ${timeoutMs}ms; the transfer was cancelled`), timeoutMs);
        if (typeof timer.unref === 'function') timer.unref();
      }
      if (signal !== undefined) {
        if (signal.aborted) throw new Error('tool call aborted');
        onAbort = () => stop('tool call aborted');
        signal.addEventListener('abort', onAbort, { once: true });
      }
      const work = (async () => {
        if (direction === 'upload') {
          if (!existsSync(localPath)) throw new Error(`local file not found: ${localPath}`);
          const size = statSync(localPath).size;
          if (createDirs) await ensureRemoteDir(sftp, remotePath);
          await new Promise((resolve, reject) => {
            sftp.fastPut(localPath, remotePath, (error) => (error ? reject(error) : resolve()));
          });
          return {
            direction,
            host,
            localPath,
            remotePath,
            bytes: size,
            durationMs: Date.now() - started,
            bytesPerSecond: Math.round(size / Math.max(0.001, (Date.now() - started) / 1000))
          };
        }
        if (createDirs) {
          const localDir = dirname(localPath);
          if (localDir.length > 0 && !existsSync(localDir)) mkdirSync(localDir, { recursive: true });
        }
        await new Promise((resolve, reject) => {
          sftp.fastGet(remotePath, localPath, (error) => (error ? reject(error) : resolve()));
        });
        const size = statSync(localPath).size;
        return {
          direction,
          host,
          localPath,
          remotePath,
          bytes: size,
          durationMs: Date.now() - started,
          bytesPerSecond: Math.round(size / Math.max(0.001, (Date.now() - started) / 1000))
        };
      })();
      // Whichever settles first wins; the loser is ignored (its handlers are
      // attached here, so a late rejection cannot surface as unhandled).
      work.catch(() => undefined);
      return await Promise.race([work, cancelled]);
    } finally {
      if (timer !== undefined) clearTimeout(timer);
      if (onAbort !== undefined && signal !== undefined) signal.removeEventListener('abort', onAbort);
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
