/** Reconnect backoff and handshake-timeout classification. */
import { MAX_HANDSHAKE_TIMEOUTS, isHandshakeTimeout, reconnectDelayMs, shouldPauseRetry } from '../lib/backoff.js';

let pass = 0;
const failures = [];
const check = (name, ok, detail) => (ok ? (pass += 1) : failures.push(`${name}: ${detail}`));

check('delay-sequence', [1, 2, 3, 4, 5, 6].map(reconnectDelayMs).join(',') === '1000,2000,4000,8000,16000,32000', [1, 2, 3, 4, 5, 6].map(reconnectDelayMs).join(','));
check('delay-cap', reconnectDelayMs(20) === 300000, String(reconnectDelayMs(20)));
check('delay-invalid', reconnectDelayMs(undefined) === 1000 && reconnectDelayMs(-2) === 1000, `${reconnectDelayMs(undefined)} / ${reconnectDelayMs(-2)}`);
check('handshake-timeout', isHandshakeTimeout(new Error('Timed out while waiting for handshake')) === true, 'exact handshake timeout');
check('handshake-timeout-text', isHandshakeTimeout('ssh: handshake timed out') === true, 'handshake text');
check('not-auth-timeout', isHandshakeTimeout(new Error('All configured authentication methods failed')) === false, 'auth must not pause');
check('not-refused', isHandshakeTimeout(new Error('connect ECONNREFUSED 127.0.0.1:22')) === false, 'refused must not pause');
check('not-command-timeout', isHandshakeTimeout(new Error('command timed out after 15s')) === false, 'command timeout must not pause');
check('pause-threshold', shouldPauseRetry(MAX_HANDSHAKE_TIMEOUTS - 1) === false && shouldPauseRetry(MAX_HANDSHAKE_TIMEOUTS) === true, `${MAX_HANDSHAKE_TIMEOUTS}`);

console.log(`${pass}/${pass + failures.length} passed`);
for (const failure of failures) console.log(`FAIL ${failure}`);
process.exit(failures.length === 0 ? 0 : 2);
