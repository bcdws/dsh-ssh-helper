/** Error context, host identity in failures, and the output memory guard. */
import { SshPool } from '../lib/pool.js';
import { liveHost } from './live-host.mjs';

const { config, alias: HOST, spec } = liveHost();
const real = { ...spec, alias: HOST };
const table = new Map([
  ['bad-dns', { ...real, alias: 'bad-dns', host: 'ssh-helper.invalid' }],
  ['bad-local', { ...real, alias: 'bad-local', host: '127.0.0.1', port: 9 }],
  [HOST, real]
]);
const pool = new SshPool({ hosts: table, config, logger: { warn: () => {} } });
let failures = 0;

for (const alias of ['bad-dns', 'bad-local']) {
  const started = Date.now();
  try {
    await pool.connection(alias).exec('true', { timeoutMs: 12000, maxOutputBytes: 4096 });
    failures += 1;
    console.log(`FAIL ${alias}: expected a failure`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const named = message.includes(alias) && message.includes(':');
    if (!named) failures += 1;
    console.log(`${named ? 'PASS' : 'FAIL'} ${alias} (${Date.now() - started}ms): ${message}`);
  }
}

// No maxOutputBytes at all: the pool's memory guard must still bound the buffer
// (the model-facing byte cap with its omission notice is applied by the tool).
const huge = await pool.connection(HOST).exec('seq 1 200000', { timeoutMs: 60000 });
const stdoutBytes = Buffer.byteLength(huge.stdout, 'utf8');
const capped = stdoutBytes < 900000;
if (!capped) failures += 1;
console.log(`${capped ? 'PASS' : 'FAIL'} default output guard: stdoutBytes=${stdoutBytes} exitCode=${huge.exitCode} (unbounded would be >1.2MB)`);

const snapshot = pool.connection('bad-dns').snapshot();
console.log(`bad-dns lastError: ${snapshot.lastError}`);
console.log(failures === 0 ? '\nerrors summary: ok' : `\nerrors summary: ${failures} failure(s)`);
pool.dispose();
process.exit(failures === 0 ? 0 : 2);
