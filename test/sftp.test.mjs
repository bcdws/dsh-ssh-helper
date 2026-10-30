/** SFTP open must settle even when the remote side never answers. */
import { EventEmitter } from 'node:events';
import { openSftp } from '../lib/sftp.js';

const keepAlive = setTimeout(() => {}, 1000);
let pass = 0;
const failures = [];
const check = (name, ok, detail) => (ok ? (pass += 1) : failures.push(`${name}: ${detail}`));

const never = { sftp: () => {} };
const started = Date.now();
const timedOut = await openSftp(never, { timeoutMs: 30, what: 'write' }).then(
  () => '',
  (error) => (error instanceof Error ? error.message : String(error))
);
check('open-timeout', /write SFTP open timed out/.test(timedOut) && Date.now() - started < 500, `${timedOut} ${Date.now() - started}`);

let lateCallback;
let lateSession;
const late = { sftp: (callback) => { lateCallback = callback; } };
const lateResult = await openSftp(late, { timeoutMs: 20, what: 'read' }).then(
  () => '',
  (error) => (error instanceof Error ? error.message : String(error))
);
lateSession = { ended: false, end() { this.ended = true; } };
lateCallback(null, lateSession);
check('late-session-closed', lateSession.ended === true, JSON.stringify(lateSession));

const controller = new AbortController();
const aborted = { sftp: () => {} };
const abortPromise = openSftp(aborted, { timeoutMs: 1000, what: 'edit', signal: controller.signal });
controller.abort();
const abortMessage = await abortPromise.then(
  () => '',
  (error) => (error instanceof Error ? error.message : String(error))
);
check('open-abort', /edit aborted/.test(abortMessage), abortMessage);

const session = { end() {} };
const ok = { sftp: (callback) => callback(null, session) };
const opened = await openSftp(ok, { timeoutMs: 100, what: 'glob' });
check('open-success', opened === session, String(opened));

console.log(`${pass}/${pass + failures.length} passed`);
for (const failure of failures) console.log(`FAIL ${failure}`);
clearTimeout(keepAlive);
process.exit(failures.length === 0 ? 0 : 2);
