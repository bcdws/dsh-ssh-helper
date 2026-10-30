/**
 * Reconnect backoff and handshake-timeout policy.
 *
 * A host that keeps timing out during the SSH handshake is usually not going
 * to recover by retrying every few seconds. Back off exponentially, and after
 * a bounded number of consecutive handshake timeouts stop the background
 * timer; the panel or a user-initiated SSH call can still retry explicitly.
 *
 * @module dsh-ssh-helper/backoff
 */

export const MAX_HANDSHAKE_TIMEOUTS = 6;
export const BASE_RECONNECT_DELAY_MS = 1000;
export const MAX_RECONNECT_DELAY_MS = 300000;

/** Delay before the next attempt, growing 1s, 2s, 4s, ... up to 5 minutes. */
export function reconnectDelayMs(attempt) {
  const step = Number.isFinite(attempt) ? Math.max(1, Math.floor(attempt)) : 1;
  return Math.min(BASE_RECONNECT_DELAY_MS * 2 ** (step - 1), MAX_RECONNECT_DELAY_MS);
}

/** True only for an SSH handshake timeout, not auth/refused/command timeouts. */
export function isHandshakeTimeout(error) {
  const message = error instanceof Error ? error.message : String(error ?? '');
  return /timed out while waiting for handshake|handshake.*timed out|handshake timeout/i.test(message);
}

/** Whether background auto-reconnect should stop after this many timeouts. */
export function shouldPauseRetry(handshakeTimeouts) {
  return Number.isFinite(handshakeTimeouts) && handshakeTimeouts >= MAX_HANDSHAKE_TIMEOUTS;
}
