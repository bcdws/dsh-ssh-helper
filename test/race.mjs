/**
 * Targeted reproduction of the transport-gone race: destroy the TCP socket
 * underneath a live pooled client and immediately issue the next command,
 * before ssh2 has emitted its own close event.
 */
import { SshPool } from '../lib/pool.js';
import { liveHost } from './live-host.mjs';

const { config, alias: HOST, hosts } = liveHost();
const pool = new SshPool({
  hosts: new Map([[HOST, hosts.get(HOST)]]),
  config,
  logger: { warn: (...args) => console.log('[warn]', ...args), info: () => {} }
});
const conn = pool.connection(HOST);
let failures = 0;

const warm = await conn.exec('echo warm', { timeoutMs: 20000, maxOutputBytes: 4096 });
console.log('warm exec:', warm.exitCode, JSON.stringify(warm.stdout.trim()), '| state', conn.snapshot().state, '| connects', conn.snapshot().connects);

for (let round = 1; round <= 3; round += 1) {
  const client = await conn.ensure();
  const sock = client._sock;
  const before = conn.snapshot();
  const started = Date.now();
  sock.destroy();
  try {
    const result = await conn.exec('echo after-drop', { timeoutMs: 20000, maxOutputBytes: 4096 });
    const snapshot = conn.snapshot();
    const ok = result.exitCode === 0 && result.stdout.includes('after-drop');
    if (!ok) failures += 1;
    console.log(
      `round ${round}: ${ok ? 'PASS' : 'FAIL'} stdout=${JSON.stringify(result.stdout.trim())} ms=${Date.now() - started} state=${snapshot.state} connects=${snapshot.connects} reconnects=${snapshot.reconnects} (before: connects=${before.connects})`
    );
  } catch (error) {
    failures += 1;
    console.log(`round ${round}: FAIL ${error instanceof Error ? error.message : String(error)} ms=${Date.now() - started}`);
  }
  await new Promise((resolve) => setTimeout(resolve, 1500));
}

// The session path must survive the same race.
const session = conn.session('race');
const sWarm = await session.run('cd /tmp && echo s-warm', { timeoutMs: 20000, maxOutputBytes: 4096 });
const client = await conn.ensure();
client._sock.destroy();
const started = Date.now();
let sessionRace = 'unknown';
try {
  const dropped = await session.run('pwd; echo s-after-drop', { timeoutMs: 20000, maxOutputBytes: 4096 });
  sessionRace = dropped.stdout.includes('s-after-drop') ? 'silently re-ran' : `unexpected: ${JSON.stringify(dropped.stdout)}`;
} catch (error) {
  // An honest, actionable failure is the intended outcome: the command may
  // have been interrupted, so the caller re-runs it.
  const message = error instanceof Error ? error.message : String(error);
  sessionRace = /may not have completed.*re-run it/.test(message) ? 'honest failure' : `unhelpful: ${message}`;
}
const recovery = await session.run('pwd; echo recovered', { timeoutMs: 20000, maxOutputBytes: 4096 });
// Sessions now run through the same exec path as every other command, so a
// drop before the channel opened is retried once (nothing had started
// remotely); anything later surfaces as the honest, actionable failure.
const sessionOutcome = sessionRace === 'honest failure' || sessionRace === 'silently re-ran';
const recoveryOk = recovery.stdout.includes('recovered') && recovery.stdout.trim().startsWith('/tmp');
if (!sessionOutcome || !recoveryOk) failures += 1;
console.log(`session race: ${sessionRace} ms=${Date.now() - started} | stale session self-heals: ${recoveryOk} stdout=${JSON.stringify(recovery.stdout.trim())}`);

console.log('s-warm was:', JSON.stringify(sWarm.stdout.trim()));
console.log(failures === 0 ? '\nrace summary: all rounds recovered' : `\nrace summary: ${failures} failure(s)`);
pool.dispose();
process.exit(failures === 0 ? 0 : 2);
