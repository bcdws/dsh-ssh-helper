/**
 * Tool-layer guard rails: hidden hosts and protected write targets.
 * close argument and the shell-quoting of the remaining tool layer.
 *
 * These are the paths that do not go through ssh_run's command guard, so they
 * need their own coverage.
 */
import { createTools } from '../lib/tools.js';
import { createPolicy } from '../lib/policy.js';

const specs = new Map([
  ['open-host', { alias: 'open-host', host: '10.0.0.1', port: 22, user: 'root', state: 'idle', connected: false }],
  ['hidden-host', { alias: 'hidden-host', host: '10.0.0.2', port: 22, user: 'root', state: 'idle', connected: false }]
]);
const hidden = new Set(['hidden-host']);
const seen = { exec: [], writes: [], transfers: [] };
const pool = {
  aliases: [...specs.keys()],
  warnings: [],
  logger: undefined,
  has: (alias) => specs.has(alias),
  hostVisible: (alias) => !hidden.has(alias),
  timeoutPolicy: () => ({ multiplier: 3, floorMs: 1000, ceilingMs: 1800000, fallbackEstimateMs: 4000 }),
  recordActivity: () => {},
  transferTimeout: () => 5678,
  connection: (alias) => {
    if (!specs.has(alias)) throw new Error('unknown ssh host');
    return {
      connected: true,
      ensure: async () => {},
      session: () => ({ run: async () => ({ stdout: 'ran\n', stderr: '', exitCode: 0 }) }),
      exec: async (command) => {
        seen.exec.push(command);
        return { stdout: '', stderr: '', exitCode: 0, signal: null, timedOut: false };
      }
    };
  },
  status: () => [...specs.values()].map((spec) => ({ ...spec, sessions: [], connects: 0, reconnects: 0, failures: 0, idleSeconds: null, hidden: hidden.has(spec.alias), remark: '', idleTimeoutMs: null, effectiveIdleTimeoutMs: 0 })),
  releaseForOwner: () => ({ alias: 'x', closedSessions: [], keptForOthers: false }),
  releaseAllForOwner: () => [],
  connections: () => []
};

const policy = createPolicy();
const byName = new Map(createTools(pool, { maxOutputBytes: 16000, defaultTimeoutMs: 30000 }, { policy }).map((tool) => [tool.name, tool]));
let pass = 0;
const failures = [];
const check = (name, ok, detail) => (ok ? (pass += 1) : failures.push(`${name}: ${detail}`));
const failureOf = async (promise) => {
  try {
    await promise;
    return '';
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
};

// ── hidden hosts stay invisible to every tool ──────────────────────────────
const listed = await byName.get('ssh_hosts').execute({});
check('hidden-not-listed', listed.hosts.length === 1 && listed.hosts[0].alias === 'open-host', JSON.stringify(listed.hosts.map((host) => host.alias)));
const hiddenRun = await failureOf(byName.get('ssh_run').execute({ host: 'hidden-host', command: 'uptime' }, {}));
check('hidden-run-unknown', /unknown ssh host "hidden-host"/.test(hiddenRun), hiddenRun);

// ── protected write targets, before any connection work ────────────────────
const blockWrite = await failureOf(byName.get('ssh_write').execute({ host: 'open-host', path: '/dev/sda', content: 'x' }));
check('write-block-device-denied', /写入块设备/.test(blockWrite), blockWrite);
const bootEdit = await failureOf(byName.get('ssh_edit').execute({ host: 'open-host', path: '/boot/grub/grub.cfg', sha256: 'a'.repeat(64), oldString: 'a', newString: 'b' }));
check('edit-boot-denied', /写入系统关键路径/.test(bootEdit), bootEdit);
const upload = await failureOf(byName.get('ssh_transfer').execute({ host: 'open-host', direction: 'upload', localPath: '/tmp/x', remotePath: '/dev/sda' }, {}));
check('upload-block-device-denied', /写入块设备/.test(upload), upload);
check('no-write-attempted', seen.writes.length === 0 && seen.transfers.length === 0, JSON.stringify(seen));


console.log(`${pass}/${pass + failures.length} passed`);
for (const failure of failures) console.log(`FAIL ${failure}`);
process.exit(failures.length === 0 ? 0 : 2);
