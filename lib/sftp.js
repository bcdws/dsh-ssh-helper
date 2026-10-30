/**
 * SFTP session opening with a deadline.
 *
 * `client.sftp()` is an async callback: if the remote side accepts the
 * transport but never answers the SFTP subsystem request, the callback never
 * fires. Everything after this point already has a deadline; this helper
 * closes that gap so a hung session becomes a normal error instead of a stuck
 * tool call.
 *
 * @module dsh-ssh-helper/sftp
 */

export const SFTP_OPEN_TIMEOUT_MS = 15000;

/**
 * Open one SFTP session.
 *
 * @param client - an ssh2 client.
 * @param options - `{ timeoutMs, what, signal }`.
 * @returns the SFTP session, or rejects on error/timeout/abort.
 */
export function openSftp(client, { timeoutMs = SFTP_OPEN_TIMEOUT_MS, what = 'SFTP', signal } = {}) {
  const limit = Number.isFinite(timeoutMs) && timeoutMs > 0 ? Math.min(timeoutMs, SFTP_OPEN_TIMEOUT_MS) : SFTP_OPEN_TIMEOUT_MS;
  return new Promise((resolve, reject) => {
    let settled = false;
    let timer;
    const cleanup = () => {
      if (timer !== undefined) clearTimeout(timer);
      if (signal !== undefined) signal.removeEventListener('abort', onAbort);
    };
    const fail = (error) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(error);
    };
    const succeed = (session) => {
      if (settled) {
        // The timeout/abort already won; close the late session instead of
        // leaking it to a caller that has stopped waiting.
        try {
          session?.end();
        } catch {
          /* already closed */
        }
        return;
      }
      settled = true;
      cleanup();
      resolve(session);
    };
    const onAbort = () => fail(new Error(`${what} aborted`));
    if (signal?.aborted) {
      fail(new Error(`${what} aborted`));
      return;
    }
    signal?.addEventListener('abort', onAbort, { once: true });
    timer = setTimeout(() => fail(new Error(`${what} SFTP open timed out after ${limit}ms`)), limit);
    if (typeof timer.unref === 'function') timer.unref();
    try {
      client.sftp((error, session) => (error ? fail(error) : succeed(session)));
    } catch (error) {
      fail(error);
    }
  });
}
