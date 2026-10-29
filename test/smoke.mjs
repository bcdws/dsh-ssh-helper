/**
 * Smoke test for the SSH pool against one real host.
 *
 * Every command is read-only; the only remote writes are files under /tmp
 * (and the session state file), both removed before the suite ends.
 */
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SshPool } from '../lib/pool.js';
import { createTools } from '../lib/tools.js';
import { transferFile } from '../lib/transfer.js';
import { liveHost } from './live-host.mjs';

const { config, alias: HOST, spec, hosts } = liveHost();
const results = [];
const record = (name, ok, detail) => {
  results.push({ name, ok, detail });
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}: ${JSON.stringify(detail)}`);
};
const ms = (start) => Date.now() - start;

const table = new Map([[HOST, hosts.get(HOST)]]);
console.log('host spec:', JSON.stringify(spec));

const pool = new SshPool({ hosts: table, config, logger: { warn: (...a) => console.log('[warn]', ...a), info: (...a) => console.log('[info]', ...a) } });

try {
  // 1. Cold connect + first command.
  const cold = Date.now();
  const first = await pool.connection(HOST).exec('whoami; uname -s; echo $DSH_SMOKE_OK', { timeoutMs: 20000, maxOutputBytes: 10000 });
  const coldMs = ms(cold);
  record('cold-exec', first.exitCode === 0 && first.stdout.includes('root'), { coldMs, stdout: first.stdout.trim() });

  // 2. Reused connection: five calls, each must skip the handshake.
  const reusedTimings = [];
  let allReused = true;
  for (let i = 0; i < 5; i += 1) {
    const t = Date.now();
    const r = await pool.connection(HOST).exec('echo reuse-ok', { timeoutMs: 20000, maxOutputBytes: 10000 });
    reusedTimings.push(ms(t));
    if (r.exitCode !== 0 || !r.stdout.includes('reuse-ok')) allReused = false;
  }
  record('reused-exec', allReused, {
    timings: reusedTimings,
    medianMs: reusedTimings.slice().sort((a, b) => a - b)[2],
    coldMs,
    speedup: Number((coldMs / reusedTimings.slice().sort((a, b) => a - b)[2]).toFixed(1))
  });

  // 3. Persistent sessions: cwd and env survive; sessions are independent.
  const session = pool.connection(HOST).session('smoke');
  const step1 = await session.run('cd /tmp && export DSH_SMOKE_VAR=alpha && export DSH_SMOKE_TOKEN=super-secret && pwd', { timeoutMs: 20000, maxOutputBytes: 10000 });
  const step2 = await session.run('pwd; echo "var=$DSH_SMOKE_VAR"', { timeoutMs: 20000, maxOutputBytes: 10000 });
  const other = await pool.connection(HOST).session('other');
  const step3 = await other.run('pwd; echo "var=${DSH_SMOKE_VAR:-unset}"', { timeoutMs: 20000, maxOutputBytes: 10000 });
  record(
    'session-state',
    step1.stdout.includes('/tmp') && step2.stdout.includes('/tmp') && step2.stdout.includes('var=alpha') && step3.stdout.includes('unset'),
    { step1: step1.stdout.trim(), step2: step2.stdout.trim(), step3: step3.stdout.trim(), cwd: step2.cwd }
  );

  // 3b. The state file must live in a private cache dir (never /tmp) and must
  //     not persist credential-looking variables.
  const probe = await pool.connection(HOST).exec(
    'cd ~ && { ' +
      'echo "dir=$(ls -d .cache/dsh-ssh-sessions 2>/dev/null || echo missing)"; ' +
      'echo "files=$(ls -A .cache/dsh-ssh-sessions 2>/dev/null | wc -l)"; ' +
      'echo "mode=$(stat -c %a .cache/dsh-ssh-sessions 2>/dev/null || echo none)"; ' +
      'echo "has-cd=$(grep -l \'^cd "\' .cache/dsh-ssh-sessions/.[!.]* 2>/dev/null | wc -l)"; ' +
      'echo "secret-hits=$(grep -rl DSH_SMOKE_TOKEN .cache/dsh-ssh-sessions/ 2>/dev/null | wc -l)"; ' +
      'echo "tmp-files=$(ls -d /tmp/.dsh-ssh-* 2>/dev/null | wc -l)"; }',
    { timeoutMs: 20000, maxOutputBytes: 10000 }
  );
  const field = (name) => {
    const line = (probe.stdout ?? '').split('\n').find((entry) => entry.startsWith(`${name}=`));
    return line === undefined ? 'MISSING' : line.slice(name.length + 1).trim();
  };
  record(
    'session-state-location',
    field('dir') === '.cache/dsh-ssh-sessions' && Number(field('files')) >= 1 && field('mode') === '700' && Number(field('has-cd')) >= 1 && field('secret-hits') === '0' && field('tmp-files') === '0',
    { dir: field('dir'), files: field('files'), mode: field('mode'), hasCd: field('has-cd'), secretHits: field('secret-hits'), tmpFiles: field('tmp-files') }
  );

  // 4. Exit-code propagation and stderr separation (subshell keeps the session alive).
  const failing = await session.run('echo to-stderr >&2; (exit 42)', { timeoutMs: 20000, maxOutputBytes: 10000 });
  const statelessFail = await pool.connection(HOST).exec('echo stateless-stderr >&2; exit 7', { timeoutMs: 20000, maxOutputBytes: 10000 });
  record(
    'exit-code',
    failing.exitCode === 42 && failing.stderr.includes('to-stderr') && statelessFail.exitCode === 7 && statelessFail.stderr.includes('stateless-stderr'),
    { sessionExit: failing.exitCode, sessionStderr: failing.stderr.trim(), execExit: statelessFail.exitCode, execStderr: statelessFail.stderr.trim() }
  );

  // 4b. `exit N` in a command ends only that command's process: the exit code
  //     comes back, the output is kept, and the session's saved state survives.
  const killing = await session.run('echo before-exit; exit 3', { timeoutMs: 20000, maxOutputBytes: 10000 });
  const revived = await session.run('echo revived; pwd', { timeoutMs: 20000, maxOutputBytes: 10000 });
  record(
    'session-exit-code',
    killing.exitCode === 3 && killing.stdout.includes('before-exit') && killing.sessionEnded !== true && revived.stdout.includes('revived') && revived.stdout.includes('/tmp'),
    { exit: killing.exitCode, killingStdout: killing.stdout.trim(), revived: revived.stdout.trim() }
  );

  // 4c. A failed cwd guard must not run the command nor kill the session.
  const badCwd = await session.run(`cd '/nope-does-not-exist' && {\necho should-not-run\n}`, { timeoutMs: 20000, maxOutputBytes: 10000 });
  const afterBadCwd = await session.run('echo still-alive; pwd', { timeoutMs: 20000, maxOutputBytes: 10000 });
  record(
    'cwd-guard',
    badCwd.exitCode === 1 && !badCwd.stdout.includes('should-not-run') && afterBadCwd.stdout.includes('still-alive'),
    { badExit: badCwd.exitCode, badStdout: badCwd.stdout.trim(), after: afterBadCwd.stdout.trim() }
  );

  // 4d. A session timeout returns the partial output, kills only that command,
  //     and leaves the session's saved state untouched.
  const timedOut = await session.run('echo partial-output; sleep 30', { timeoutMs: 2500, maxOutputBytes: 10000 });
  const afterTimeout = await session.run('echo session-recovered; pwd', { timeoutMs: 20000, maxOutputBytes: 10000 });
  record(
    'session-timeout',
    timedOut.timedOut === true && timedOut.stdout.includes('partial-output') && afterTimeout.stdout.includes('session-recovered') && afterTimeout.stdout.includes('/tmp'),
    { timedOut: timedOut.timedOut, partial: timedOut.stdout.trim(), recovered: afterTimeout.stdout.trim() }
  );

  // 4f. No cross-talk: a background writer started in a session must never
  //     appear in a later command's result, and vice versa.
  const noise = await session.run('(while true; do echo bg-noise; sleep 0.05; done) & echo noise-started', { timeoutMs: 20000, maxOutputBytes: 10000 });
  await new Promise((resolve) => setTimeout(resolve, 400));
  const clean = await session.run('echo clean-output; echo clean-stderr >&2', { timeoutMs: 20000, maxOutputBytes: 10000 });
  record(
    'session-no-crosstalk',
    noise.stdout.includes('noise-started') && clean.stdout.includes('clean-output') && !clean.stdout.includes('bg-noise') && !clean.stderr.includes('bg-noise'),
    { noiseStarted: noise.stdout.includes('noise-started'), cleanStdout: clean.stdout.trim().slice(0, 200), leaked: clean.stdout.includes('bg-noise') }
  );

  // 4e. Session isolation: two owners asking for the same session name get
  //     separate shells, so one DSH session's state cannot leak into another.
  const ownerA = pool.connection(HOST).session('iso', 'session-A');
  const ownerB = pool.connection(HOST).session('iso', 'session-B');
  const movedA = await ownerA.run('cd /tmp && pwd', { timeoutMs: 20000, maxOutputBytes: 10000 });
  const stateB = await ownerB.run('pwd', { timeoutMs: 20000, maxOutputBytes: 10000 });
  const againA = await ownerA.run('pwd', { timeoutMs: 20000, maxOutputBytes: 10000 });
  const released = pool.releaseForOwner(HOST, 'session-A');
  const afterRelease = await ownerB.run('echo b-still-there', { timeoutMs: 20000, maxOutputBytes: 10000 });
  record(
    'session-isolation',
    ownerA !== ownerB && movedA.stdout.includes('/tmp') && stateB.stdout.trim() === '/root' && againA.stdout.includes('/tmp') && released.closedSessions.length === 1 && afterRelease.stdout.includes('b-still-there'),
    { ownerA: movedA.stdout.trim(), ownerB: stateB.stdout.trim(), againA: againA.stdout.trim(), released, afterRelease: afterRelease.stdout.trim() }
  );

  // 5. SFTP round trip with a checksum comparison.
  const local = mkdtempSync(join(tmpdir(), 'dsh-smoke-'));
  const payload = `hello-from-smoke ${new Date().toISOString()}\n${'x'.repeat(4096)}\n`;
  const upPath = join(local, 'upload.txt');
  writeFileSync(upPath, payload);
  const remotePath = `/tmp/dsh-smoke-${Date.now()}.txt`;
  const up = await transferFile(pool, { host: HOST, direction: 'upload', localPath: upPath, remotePath });
  const downPath = join(local, 'download.txt');
  const down = await transferFile(pool, { host: HOST, direction: 'download', localPath: downPath, remotePath });
  const same = createHash('sha256').update(readFileSync(upPath)).digest('hex') === createHash('sha256').update(readFileSync(downPath)).digest('hex');
  const remoteCheck = await pool.connection(HOST).exec(`sha256sum ${remotePath}`, { timeoutMs: 20000, maxOutputBytes: 10000 });
  record('sftp-roundtrip', same && up.bytes === down.bytes, { up, down, same, remoteSha: remoteCheck.stdout.trim().split(/\s+/)[0] });
  await pool.connection(HOST).exec(`rm -f ${remotePath}`, { timeoutMs: 20000, maxOutputBytes: 10000 });
  rmSync(local, { recursive: true, force: true });

  // 6. A transfer deadline is enforced: an abusively short timeout cancels the
  //    transfer instead of leaving it pending (0 must not mean "wait forever").
  const bigLocal = mkdtempSync(join(tmpdir(), 'dsh-smoke-big-'));
  const bigPath = join(bigLocal, 'big.bin');
  writeFileSync(bigPath, Buffer.alloc(8 * 1024 * 1024, 7));
  const deadlineStart = Date.now();
  let deadlineMessage = '';
  let deadlineCancelled = false;
  try {
    await transferFile(pool, { host: HOST, direction: 'upload', localPath: bigPath, remotePath: '/tmp/dsh-smoke-big.bin', timeoutMs: 5 });
  } catch (error) {
    deadlineCancelled = true;
    deadlineMessage = error instanceof Error ? error.message : String(error);
  }
  const deadlineMs = Date.now() - deadlineStart;
  record('transfer-deadline', deadlineCancelled && /timed out/i.test(deadlineMessage) && deadlineMs < 15000, { ms: deadlineMs, message: deadlineMessage });
  await pool.connection(HOST).exec('rm -f /tmp/dsh-smoke-big.bin', { timeoutMs: 20000, maxOutputBytes: 2000 });
  rmSync(bigLocal, { recursive: true, force: true });

  // 6b. Background mode: returns at once with a PID and a log file; nothing the
  //     detached process prints reaches this call or any later one.
  const q = (value) => `'${String(value).replace(/'/g, "'\\''")}'`;
  const bgStart = Date.now();
  const bg = await pool.connection(HOST).background('for i in $(seq 1 6); do echo bg-line-$i; sleep 0.2; done', {});
  const bgMs = Date.now() - bgStart;
  await new Promise((resolve) => setTimeout(resolve, 1500));
  const bgLog = await pool.connection(HOST).exec(`tail -n 20 ${q(bg.logPath ?? '')}`, { timeoutMs: 20000, maxOutputBytes: 10000 });
  const bgAfter = await pool.connection(HOST).exec('echo clean-after-bg', { timeoutMs: 20000, maxOutputBytes: 10000 });
  record(
    'background-mode',
    bgMs < 5000 && typeof bg.pid === 'number' && typeof bg.logPath === 'string' && bg.logPath.length > 0 && bgLog.stdout.includes('bg-line-6') && !bgLog.stdout.includes('clean-after-bg') && bgAfter.stdout.trim() === 'clean-after-bg',
    { ms: bgMs, pid: bg.pid, logPath: bg.logPath, lastLines: bgLog.stdout.trim().split('\n').slice(-2), after: bgAfter.stdout.trim() }
  );
  await pool.connection(HOST).exec(`rm -f ${q(bg.logPath ?? '')}`, { timeoutMs: 10000, maxOutputBytes: 2000 }).catch(() => {});

  // 7. Unknown host fails fast and clearly.
  const unknownStart = Date.now();
  let unknownMessage = '';
  try {
    await pool.connection('does-not-exist').exec('true', { timeoutMs: 5000, maxOutputBytes: 1000 });
  } catch (error) {
    unknownMessage = error instanceof Error ? error.message : String(error);
  }
  record('unknown-host', unknownMessage.includes('unknown ssh host'), { ms: ms(unknownStart), message: unknownMessage });

  // 8. Explicit close, then transparent reconnect.
  pool.connection(HOST).close('smoke close');
  const reconnectStart = Date.now();
  const back = await pool.connection(HOST).exec('echo back-online', { timeoutMs: 20000, maxOutputBytes: 10000 });
  const snapshot = pool.connection(HOST).snapshot();
  record('reconnect', back.exitCode === 0 && back.stdout.includes('back-online'), {
    ms: ms(reconnectStart),
    connects: snapshot.connects,
    hostKey: snapshot.hostKey
  });

  // 9. Tool definitions resolve and their renderers produce model-facing text.
  const tools = createTools(pool, config);
  const names = tools.map((tool) => tool.name);
  const hostsValue = await tools[0].execute({});
  const runTool = tools[2];
  const runValue = await runTool.execute({ host: HOST, command: 'echo tool-path-ok' }, { signal: new AbortController().signal });
  const rendered = runTool.output.render({}, runValue)[0].text;
  record('tools', names.length === 5 && rendered.includes('tool-path-ok'), {
    names,
    hostsRendered: tools[0].output.render({}, hostsValue)[0].text.split('\n')[0],
    runRendered: rendered.trim()
  });
} catch (error) {
  console.log('FAIL uncaught:', error instanceof Error ? error.stack ?? error.message : String(error));
} finally {
  pool.dispose();
  const failed = results.filter((item) => !item.ok);
  console.log(`\nsummary: ${results.length - failed.length}/${results.length} passed`);
  process.exit(failed.length === 0 ? 0 : 2);
}
