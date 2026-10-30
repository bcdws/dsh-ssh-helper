/**
 * Pool mechanics that are easy to regress without a real host: a deadline that
 * fires while the channel is still opening, an abort that races the channel
 * slot, a setup failure before the handshake, and the session script's umask
 * handoff.
 *
 * Every case uses a fake client; nothing here opens a socket.
 */
import { EventEmitter } from 'node:events';
import { HostConnection, ShellSession } from '../lib/pool.js';

const spec = { alias: 'h', host: '127.0.0.1', port: 22, user: 'root', source: 'config' };
const config = { connectTimeoutMs: 100, keepaliveIntervalMs: 0, keepaliveCountMax: 1, hostKeyPolicy: 'off', maxChannelsPerHost: 1 };
const logger = { warn: () => {}, info: () => {} };
const makeConnection = () => new HostConnection('h', spec, config, logger);

/** A channel double: stderr emitter plus the methods #execAttempt touches. */
function channelFor(command) {
  const channel = new EventEmitter();
  channel.stderr = new EventEmitter();
  channel.end = () => {};
  channel.signal = () => {};
  channel.close = () => {};
  return channel;
}

const connections = [];
const connectionWith = (exec) => {
  const connection = makeConnection();
  connections.push(connection);
  connection.ensure = async () => ({ exec });
  return connection;
};

let pass = 0;
const failures = [];
const check = (name, ok, detail) => (ok ? (pass += 1) : failures.push(`${name}: ${detail}`));

// 1. A timeout while the channel-open request is still pending must settle the
//    call instead of hanging forever (the timer used to only close a channel
//    that did not exist yet).
const neverOpens = connectionWith((_command, _callback) => {
  /* the server never answers the channel-open request */
});
const started = Date.now();
// The pool unrefs its deadline timer; keep this test process alive so the
// deadline can fire and settle the call.
const keepAlive = setTimeout(() => {}, 500);
const timedOut = await neverOpens.exec('sleep 10', { timeoutMs: 40 });
clearTimeout(keepAlive);
check('channel-open-timeout-settles', timedOut.timedOut === true && Date.now() - started < 1000, JSON.stringify(timedOut));

// 2. Aborting a call that is waiting for a channel slot must remove it from the
//    queue: the command must never reach the remote side after the abort.
const seen = [];
let firstChannel;
const queued = connectionWith((command, callback) => {
  seen.push(command);
  if (command === 'first-hold') {
    firstChannel = channelFor(command);
    setImmediate(() => callback(null, firstChannel));
    return;
  }
  const channel = channelFor(command);
  setImmediate(() => callback(null, channel));
  setImmediate(() => channel.emit('close', 0));
});
const first = queued.exec('first-hold');
await new Promise((resolve) => setTimeout(resolve, 10));
const controller = new AbortController();
const second = queued.exec('second-should-not-run', { signal: controller.signal });
await new Promise((resolve) => setTimeout(resolve, 10));
controller.abort();
// Release the slot the first call holds; the aborted waiter must already be gone.
firstChannel.emit('close', 0);
const [secondError] = await Promise.all([
  second.then(
    () => '',
    (error) => (error instanceof Error ? error.message : String(error))
  ),
  first.then(() => undefined, () => undefined)
]);
check('aborted-queue-rejects', /aborted/.test(secondError), secondError);
check('aborted-queue-not-run', !seen.includes('second-should-not-run'), JSON.stringify(seen));

// 3. A setup failure before the handshake (an unreadable identity file) records
//    the failure and leaves the state 'down', never 'connecting' forever.
const broken = new HostConnection('h', { ...spec, identityFile: '/tmp' }, config, logger);
connections.push(broken);
const brokenError = await broken.ensure().then(
  () => '',
  (error) => (error instanceof Error ? error.message : String(error))
);
check('setup-failure-rejects', /EISDIR|illegal operation|failed/.test(brokenError), brokenError);
check('setup-failure-state', broken.state === 'down' && typeof broken.lastError === 'string' && broken.failures === 1, JSON.stringify({ state: broken.state, lastError: broken.lastError, failures: broken.failures }));

// 4. The session script keeps the private umask only around its own state file
//    and restores the login shell's umask before running the user's command.
const scripts = [];
const fakeHost = {
  connected: true,
  exec: async (command) => {
    scripts.push(command);
    return { stdout: '', stderr: '', exitCode: 0, timedOut: false, signal: null, aborted: false };
  },
  session: () => ({ run: async () => ({}) })
};
const session = new ShellSession(fakeHost, 'main');
await session.run('touch build/output');
const script = scripts[0] ?? '';
const commandAt = script.indexOf('eval "');
const restoreBefore = script.lastIndexOf('umask "$__dsh_umask"', commandAt);
check('session-umask-captured', script.startsWith('__dsh_umask=$(umask)\n'), script.slice(0, 60));
check('session-umask-restored-before-command', commandAt > 0 && restoreBefore > 0, script.slice(0, 400));
check('session-umask-reapplied-for-state', script.indexOf('umask 077', commandAt) > commandAt, script.slice(-400));

// 4b. Host status exposes the reconnect pause state.
const pausedSnapshot = makeConnection();
connections.push(pausedSnapshot);
check('snapshot-retry-fields', pausedSnapshot.snapshot().retryPaused === false && pausedSnapshot.snapshot().handshakeTimeouts === 0, JSON.stringify(pausedSnapshot.snapshot()));

// 5. The busy flag used by the idle reaper.
const busy = makeConnection();
connections.push(busy);
check('not-busy-initially', busy.busy === false, String(busy.busy));
busy.beginWork();
check('busy-while-work', busy.busy === true, String(busy.busy));
busy.endWork();
check('idle-after-work', busy.busy === false, String(busy.busy));

for (const connection of connections) connection.dispose();
console.log(`${pass}/${pass + failures.length} passed`);
for (const failure of failures) console.log(`FAIL ${failure}`);
process.exit(failures.length === 0 ? 0 : 2);
