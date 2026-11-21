/**
 * Pool mechanics that are easy to regress without a real host: a deadline that
 * fires while the channel is still opening, an abort that races the channel
 * slot, a setup failure before the handshake, and the session script's umask
 * handoff.
 *
 * Every case uses a fake client; nothing here opens a socket.
 */
import { EventEmitter } from 'node:events';
import { HostConnection, ShellSession, SshPool, killSessionScript } from '../lib/pool.js';

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
/** Every exec carries a PID-marker line first; fakes see only the caller's command. */
const userCommand = (command) => (command.startsWith("printf '\\036DSH") ? command.slice(command.indexOf('\n') + 1) : command);
const connectionWith = (exec) => {
  const connection = makeConnection();
  connections.push(connection);
  connection.ensure = async () => ({ exec: (command, callback) => exec(userCommand(command), callback) });
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

// 4. Session state lives in the plugin's memory: the script reports it behind
//    a random marker on stderr, the pool strips it, and the next command gets
//    it back on stdin (never in the script, which is the remote shell's argv).
{
  const calls = [];
  let reply = () => ({});
  const fakeHost = {
    connected: true,
    exec: async (command, options) => {
      calls.push({ command, options });
      return { stdout: '', stderr: '', exitCode: 0, timedOut: false, signal: null, aborted: false, ...reply(options) };
    },
    session: () => ({ run: async () => ({}) })
  };
  const session = new ShellSession(fakeHost, 'main');
  reply = () => ({ trailer: "/srv/it's here\nexport FOO='bar'\n" });
  const first = await session.run('cd /srv && export FOO=bar');
  const [one] = calls;
  check('state-first-no-replay', one.options.stdin === '' && !one.command.includes('eval "$(cat)"'), one.command.slice(0, 200));
  check('state-marker-random', /^\n\x1eDSH_STATE_[0-9a-f]{16}\n$/.test(one.options.trailerMarker) && one.command.includes(`'${one.options.trailerMarker.slice(-17, -1)}'`), JSON.stringify(one.options.trailerMarker));
  check('state-no-host-files', !/umask 077|dsh-ssh-sessions|\brm\b|\bfind\b|> "\$/.test(one.command.replace('cd /srv && export FOO=bar', '')), one.command);
  check('state-command-without-fd9', one.command.includes(')" 9>&-'), one.command);
  check('state-cwd-returned', first.cwd === "/srv/it's here" && session.cwd === "/srv/it's here", String(first.cwd));

  reply = () => ({});
  await session.run('make');
  const two = calls[1];
  check('state-replay-on-stdin', two.options.stdin === `export FOO='bar'\n\ncd '/srv/it'\\''s here'\n` && two.command.includes('eval "$(cat)" 2>/dev/null'), JSON.stringify(two.options.stdin));
  check('state-replay-not-in-script', !two.command.includes("FOO='bar'") && !two.command.includes('/srv/it'), two.command);
  check('state-kept-without-trailer', session.cwd === "/srv/it's here", String(session.cwd));
  check('state-new-marker-per-call', two.options.trailerMarker !== one.options.trailerMarker, 'marker reused');

  // A detached run that ends after a newer run must not overwrite newer state.
  let lateEnd;
  reply = (options) => {
    lateEnd = options.onDetachedEnd;
    return { detached: true };
  };
  await session.run('long-build', { detachAfterMs: 10, onDetachedEnd: () => {} });
  reply = () => ({ trailer: '/newer\n' });
  await session.run('cd /newer');
  lateEnd({ exitCode: 0, stdout: '', stderr: '', trailer: '/older\n' });
  check('state-late-detached-ignored', session.cwd === '/newer', String(session.cwd));
  reply = () => ({ trailer: 'garbage\n' });
  await session.run('true');
  check('state-garbage-ignored', session.cwd === '/newer', String(session.cwd));

  // The plugin deletes nothing on the host by itself: closing a session sends no command.
  const sent = calls.length;
  session.dispose();
  check('session-dispose-sends-nothing', calls.length === sent, JSON.stringify(calls.slice(sent)));
}

// 4a. End to end through a real local shell standing in for the remote one:
//     marker stripping, stdin replay, cwd/env carry-over, credential filter,
//     and a background child that must not hold the channel open via fd 9.
{
  const { spawn } = await import('node:child_process');
  const { mkdtempSync, rmSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const work = mkdtempSync(join(tmpdir(), 'dsh-session-'));
  const localClient = {
    exec(command, callback) {
      const child = spawn('sh', ['-c', command], { stdio: ['pipe', 'pipe', 'pipe'] });
      const channel = new EventEmitter();
      channel.stderr = new EventEmitter();
      // Re-chunk stderr one byte at a time so a marker split across chunks is covered.
      child.stdout.on('data', (data) => channel.emit('data', data));
      child.stderr.on('data', (data) => {
        for (const byte of data) channel.stderr.emit('data', Buffer.from([byte]));
      });
      child.on('close', (code, name) => channel.emit('close', code, name));
      channel.end = (data) => child.stdin.end(data);
      channel.signal = () => child.kill('SIGKILL');
      channel.close = () => child.kill('SIGKILL');
      callback(undefined, channel);
    }
  };
  const local = new HostConnection('h', spec, { ...config, maxChannelsPerHost: 2 }, logger);
  connections.push(local);
  local.ensure = async () => localClient;
  const shell = local.session('main', 'owner-a');
  const opts = { timeoutMs: 10000, maxOutputBytes: 200 };
  const a = await shell.run(`mkdir -p '${work}/sub dir' && cd '${work}/sub dir' && export DSH_T_VAR=alpha DSH_T_TOKEN=secret && echo to-err >&2 && echo out`, opts);
  check('local-stderr-clean', a.stderr === 'to-err\n' && a.stdout === 'out\n', JSON.stringify({ stderr: a.stderr, stdout: a.stdout }));
  check('local-cwd', a.cwd === `${work}/sub dir`, String(a.cwd));
  const b = await shell.run('pwd; echo "var=$DSH_T_VAR tok=${DSH_T_TOKEN:-unset}"; exec 2>/dev/null; cd /', opts);
  check('local-carry-over', b.stdout === `${work}/sub dir\nvar=alpha tok=unset\n`, JSON.stringify(b.stdout));
  check('local-state-despite-stderr-redirect', b.cwd === '/', String(b.cwd));
  const other = local.session('main', 'owner-b');
  const c = await other.run('echo "var=${DSH_T_VAR:-unset}"', opts);
  check('local-owner-isolated', c.stdout === 'var=unset\n', JSON.stringify(c.stdout));
  const big = await shell.run('i=0; while [ $i -lt 400 ]; do echo noise-line-$i >&2; i=$((i+1)); done; cd /tmp', opts);
  check('local-state-survives-output-cap', big.cwd === '/tmp' && !big.stderr.includes('DSH_STATE'), String(big.cwd));
  const began = Date.now();
  const bg = await shell.run('sleep 3 >/dev/null 2>&1 & echo started', opts);
  check('local-background-does-not-hold', bg.stdout === 'started\n' && Date.now() - began < 2000, `${Date.now() - began}ms`);
  const code = await shell.run('(exit 42)', opts);
  check('local-exit-code', code.exitCode === 42 && code.cwd === '/tmp', JSON.stringify({ exitCode: code.exitCode, cwd: code.cwd }));
  rmSync(work, { recursive: true, force: true });
}

// 4a-2. background(): the returned log path is real and the call leaves the
//       script for the caller to remove, never pretending to have cleaned up.
{
  const { spawn } = await import('node:child_process');
  const { mkdtempSync, rmSync, existsSync, readdirSync, readFileSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const work = mkdtempSync(join(tmpdir(), 'dsh-bg-'));
  const logDir = join(work, 'logs');
  const localClient = {
    exec(command, callback) {
      const child = spawn('sh', ['-c', command], { stdio: ['pipe', 'pipe', 'pipe'] });
      const channel = new EventEmitter();
      channel.stderr = new EventEmitter();
      child.stdout.on('data', (data) => channel.emit('data', data));
      child.stderr.on('data', (data) => channel.stderr.emit('data', data));
      child.on('close', (code, name) => channel.emit('close', code, name));
      channel.end = (data) => child.stdin.end(data);
      channel.signal = () => child.kill('SIGKILL');
      channel.close = () => child.kill('SIGKILL');
      callback(undefined, channel);
    }
  };
  const local = new HostConnection('h', spec, config, logger);
  connections.push(local);
  local.ensure = async () => localClient;
  // Point the default log directory at the temp tree through the documented
  // environment override, so the test never touches the real home directory.
  const previousLogDir = process.env.DSH_SSH_LOG_DIR;
  process.env.DSH_SSH_LOG_DIR = logDir;
  try {
    const started = await local.background('echo bg-hello; sleep 0.2; echo bg-bye', {});
    await new Promise((resolve) => setTimeout(resolve, 800));
    check('background-pid', typeof started.pid === 'number' && started.pid > 0, String(started.pid));
    check('background-log-path-returned', typeof started.logPath === 'string' && started.logPath.startsWith(logDir), String(started.logPath));
    check('background-log-written', existsSync(started.logPath) && readFileSync(started.logPath, 'utf8').includes('bg-bye'), 'log missing its output');
    // The script stays behind on purpose: it cannot reliably delete itself,
    // so the caller removes it by path. This test pins that contract.
    const scripts = readdirSync(logDir).filter((name) => /^\.dsh-ssh-run-[0-9a-f]+\.sh$/.test(name));
    check('background-script-left-for-caller', scripts.length === 1, JSON.stringify(readdirSync(logDir)));
    // An explicit logPath is honoured.
    const explicit = join(work, 'explicit.log');
    const second = await local.background('echo explicit-line', { logPath: explicit });
    await new Promise((resolve) => setTimeout(resolve, 800));
    check('background-explicit-log', second.logPath === explicit && existsSync(explicit) && readFileSync(explicit, 'utf8').includes('explicit-line'), String(second.logPath));
  } finally {
    if (previousLogDir === undefined) delete process.env.DSH_SSH_LOG_DIR;
    else process.env.DSH_SSH_LOG_DIR = previousLogDir;
    rmSync(work, { recursive: true, force: true });
  }
}

// 4a-3. background() refuses a log path the file tools would also refuse.
{
  const local = new HostConnection('h', spec, config, logger);
  connections.push(local);
  local.ensure = async () => {
    throw new Error('the guard must run before any connection');
  };
  let refused = null;
  try {
    await local.background('echo x', { logPath: '/boot/grub/grub.cfg' });
  } catch (error) {
    refused = error;
  }
  check('background-refuses-boot-log', refused !== null && refused.code === 'POLICY_DENY' && refused.rule === 'danger.write-system', String(refused?.message ?? 'allowed'));
  let deviceRefused = null;
  try {
    await local.background('echo x', { logPath: '/dev/sda' });
  } catch (error) {
    deviceRefused = error;
  }
  check('background-refuses-device-log', deviceRefused !== null && deviceRefused.rule === 'danger.write-device', String(deviceRefused?.message ?? 'allowed'));
  // The plugin's own default directory is ordinary work.
  let defaultOk = null;
  try {
    await local.background('echo x', { logPath: '/root/.local/state/dsh-ssh/logs/app.log' });
  } catch (error) {
    defaultOk = error;
  }
  check('background-allows-default-dir', defaultOk === null || !/policy/.test(String(defaultOk.message)), String(defaultOk?.message ?? ''));
}

// 4b. Host status exposes the reconnect pause state.
const pausedSnapshot = makeConnection();
connections.push(pausedSnapshot);
check('snapshot-retry-fields', pausedSnapshot.snapshot().retryPaused === false && pausedSnapshot.snapshot().handshakeTimeouts === 0, JSON.stringify(pausedSnapshot.snapshot()));

// 4c. Refreshing the host table adds/changes/removes aliases and invalidates
//     a changed host's connection.
const refreshPool = new SshPool({
  hosts: new Map([['h', { ...spec }]]),
  config,
  logger,
  warnings: []
});
const oldConnection = refreshPool.connection('h');
const refreshed = refreshPool.refreshHosts(
  new Map([
    ['h', { ...spec, identityFile: '/tmp/new-key' }],
    ['h2', { ...spec, alias: 'h2' }]
  ]),
  []
);
check('refresh-adds-and-changes', refreshed.added.join(',') === 'h2' && refreshed.changed.join(',') === 'h' && refreshPool.has('h2'), JSON.stringify(refreshed));
check('refresh-invalidates-changed-connection', refreshPool.connection('h') !== oldConnection, 'connection should be recreated');
const removed = refreshPool.refreshHosts(new Map([['h2', { ...spec, alias: 'h2' }]]), []);
check('refresh-removes', removed.removed.join(',') === 'h' && !refreshPool.has('h'), JSON.stringify(removed));
refreshPool.dispose();

// 5. The busy flag used by the idle reaper.
const busy = makeConnection();
connections.push(busy);
check('not-busy-initially', busy.busy === false, String(busy.busy));
busy.beginWork();
check('busy-while-work', busy.busy === true, String(busy.busy));
busy.endWork();
check('idle-after-work', busy.busy === false, String(busy.busy));

// 6. Deadline: the PID marker is stripped from stderr, the whole remote
//    session is killed from a second channel, and the caller is answered
//    within the grace period even though this channel never closes.
{
  const sent = [];
  let main;
  const raw = makeConnection();
  connections.push(raw);
  raw.ensure = async () => ({
    exec: (command, callback) => {
      sent.push(command);
      const channel = channelFor(command);
      if (sent.length === 1) {
        main = channel;
        setImmediate(() => {
          callback(null, channel);
          channel.stderr.emit('data', Buffer.from('\x1eDSH 4242 98765\nreal warning\n'));
        });
      } else {
        setImmediate(() => {
          callback(null, channel);
          channel.emit('close', 0);
        });
      }
    }
  });
  const begun = Date.now();
  const keep = setTimeout(() => {}, 4000);
  const result = await raw.exec('sleep 60', { timeoutMs: 50 });
  clearTimeout(keep);
  const waited = Date.now() - begun;
  check('marker-prefixed', sent[0].startsWith("printf '\\036DSH") && sent[0].endsWith('\nsleep 60'), JSON.stringify(sent[0]));
  check('marker-stripped', result.stderr === 'real warning\n', JSON.stringify(result.stderr));
  check('kill-sent', sent.length === 2 && sent[1] === killSessionScript(4242, '98765'), JSON.stringify(sent[1]));
  check('deadline-answers-in-grace', result.timedOut === true && waited < 3000 && waited >= 50, `waited ${waited}ms`);
  check('slot-held-until-close', raw.busy === true, 'slot released before the channel closed');
  main.emit('close', null, 'KILL');
  check('slot-released-on-close', raw.busy === false, 'slot still held after close');
}

// 7. Kill script: kills group and session, but only when the PID still is the
//    recorded process; a non-numeric start time disables the check, never injects.
{
  const script = killSessionScript(4242, '98765');
  check('kill-script-guard', script.includes("s='98765'") && script.includes('|| exit 0') && script.includes('kill -KILL -- "-$p"') && script.includes('pkill -KILL -s "$p"'), script);
  check('kill-script-no-injection', killSessionScript(4242, "1'; rm -rf /; '").includes("s=''"), killSessionScript(4242, "1'; rm -rf /; '"));
}

// 8. Detach (the per-call cap): answer early with the output so far, keep the
//    channel and its slot, and report the real end later — no kill.
{
  const sent = [];
  let main;
  const raw = makeConnection();
  connections.push(raw);
  raw.ensure = async () => ({
    exec: (command, callback) => {
      sent.push(command);
      main = channelFor(command);
      setImmediate(() => {
        callback(null, main);
        main.emit('data', Buffer.from('step 1\n'));
      });
    }
  });
  let ended = null;
  const keep = setTimeout(() => {}, 1000);
  const early = await raw.exec('make all', { timeoutMs: 60000, detachAfterMs: 40, onDetachedEnd: (outcome) => (ended = outcome) });
  clearTimeout(keep);
  check('detach-answers-early', early.detached === true && early.stdout === 'step 1\n' && early.timedOut === false, JSON.stringify(early));
  check('detach-no-kill', sent.length === 1, JSON.stringify(sent));
  check('detach-keeps-slot', raw.busy === true, 'slot released while the command still runs');
  main.emit('data', Buffer.from('step 2\n'));
  main.emit('close', 0);
  check('detach-late-end', ended?.exitCode === 0 && ended.stdout === 'step 1\nstep 2\n' && raw.busy === false, JSON.stringify(ended));
}

for (const connection of connections) connection.dispose();
console.log(`${pass}/${pass + failures.length} passed`);
for (const failure of failures) console.log(`FAIL ${failure}`);
process.exit(failures.length === 0 ? 0 : 2);
