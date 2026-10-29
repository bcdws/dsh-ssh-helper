/**
 * Tool-layer host visibility: a connection switched off in the assistant must
 * read exactly like an unknown host — no listing, no command, no transfer, no
 * hidden-host filtering — while the panel's own pool view stays complete.
 */
import { createTools } from '../lib/tools.js';

const specs = new Map([
  ['open-host', { alias: 'open-host', host: '10.0.0.1', port: 22, user: 'root', keyName: 'open_rsa', state: 'idle', connected: false }],
  ['hidden-host', { alias: 'hidden-host', host: '10.0.0.2', port: 22, user: 'root', keyName: 'hidden_rsa', state: 'idle', connected: false }]
]);
const hidden = new Set(['hidden-host']);
/** Every exec/transfer call records the deadline it was given. */
const seen = { execTimeouts: [], transferTimeouts: [], activities: [] };
const pool = {
  aliases: [...specs.keys()],
  warnings: [],
  logger: undefined,
  has: (alias) => specs.has(alias),
  hostVisible: (alias) => !hidden.has(alias),
  // Live deadline policy (the assistant settings), distinct from the config.
  timeoutPolicy: () => ({ multiplier: 2.5, floorMs: 1000, ceilingMs: 3600000, fallbackEstimateMs: 4000 }),
  // The panel's activity trail: every model-facing operation lands here.
  recordActivity: (entry) => seen.activities.push(entry),
  transferTimeout: () => 5678,
  connection: (alias) => {
    if (!specs.has(alias)) throw new Error('unknown ssh host');
    return {
      connected: true,
      ensure: async () => {},
      session: () => ({ run: async () => ({ stdout: 'ran\n', stderr: '', exitCode: 0, cwd: '/root' }) }),
      exec: async (_command, options = {}) => {
        seen.execTimeouts.push(options.timeoutMs);
        return { stdout: 'ran\n', stderr: '', exitCode: 0, signal: null, timedOut: false };
      }
    };
  },
  status: () => [...specs.values()].map((spec) => ({ ...spec, sessions: [], connects: 0, reconnects: 0, failures: 0, idleSeconds: null, hidden: hidden.has(spec.alias), remark: '', idleTimeoutMs: null, effectiveIdleTimeoutMs: 0 })),
  releaseForOwner: () => ({ alias: 'x', closedSessions: [], keptForOthers: false }),
  releaseAllForOwner: () => [],
  connections: () => []
};

const tools = createTools(pool, { maxOutputBytes: 200000, defaultTimeoutMs: 60000 }, {});
const byName = new Map(tools.map((tool) => [tool.name, tool]));
let pass = 0;
const failures = [];
const check = (name, ok, detail) => (ok ? (pass += 1) : failures.push(`${name}: ${detail}`));
const expectDenied = async (name, promise) => {
  try {
    await promise;
    check(name, false, 'resolved instead of denying a hidden host');
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    check(name, /unknown ssh host "hidden-host"/.test(message) && !/hidden/i.test(message.replace(/unknown ssh host "hidden-host"/, '')), message);
  }
};

// The visible host still works end to end.
const listed = await byName.get('ssh_hosts').execute({});
check('listed-visible-only', listed.hosts.length === 1 && listed.hosts[0].alias === 'open-host', JSON.stringify(listed.hosts.map((host) => host.alias)));
check('hidden-flag-exposed', listed.hosts[0].hidden === false, JSON.stringify(listed.hosts[0]));
const ran = await byName.get('ssh_run').execute({ host: 'open-host', command: 'echo hi' }, {});
check('visible-run-works', ran.exitCode === 0 && ran.stdout.text.includes('ran'), JSON.stringify(ran));
// Deadlines are derived per command: estimate × multiplier from the live policy.
check('derived-deadline', seen.execTimeouts.at(-1) === 12500, `timeoutMs=${seen.execTimeouts.at(-1)}`);
check(
  'deadline-reported',
  ran.estimateMs === 5000 && ran.multiplier === 2.5 && ran.timeoutMs === 12500 && ran.deadlineSource === 'probe',
  JSON.stringify({ estimateMs: ran.estimateMs, multiplier: ran.multiplier, timeoutMs: ran.timeoutMs, source: ran.deadlineSource })
);
const planned = await byName.get('ssh_run').execute({ host: 'open-host', command: 'deploy.sh --all', expectedMs: 60000 }, {});
check('expected-ms-drives-deadline', seen.execTimeouts.at(-1) === 150000 && planned.deadlineSource === 'expectedMs', `timeoutMs=${seen.execTimeouts.at(-1)} source=${planned.deadlineSource}`);
await byName.get('ssh_run').execute({ host: 'open-host', command: 'echo hi', timeoutMs: 9000 }, {});
check('explicit-deadline-wins', seen.execTimeouts.at(-1) === 9000, `timeoutMs=${seen.execTimeouts.at(-1)}`);

// The hidden host is indistinguishable from one that does not exist.
await expectDenied('hidden-hosts-detail', byName.get('ssh_hosts').execute({ host: 'hidden-host' }));
await expectDenied('hidden-run', byName.get('ssh_run').execute({ host: 'hidden-host', command: 'echo hi' }, {}));
await expectDenied('hidden-transfer', byName.get('ssh_transfer').execute({ direction: 'download', host: 'hidden-host', localPath: 'C:\\tmp\\x', remotePath: '/tmp/x' }, {}));

check('activity-recorded', seen.activities.length >= 3 && seen.activities.every((entry) => entry.alias === 'open-host' && typeof entry.detail === 'string'), JSON.stringify(seen.activities.slice(0, 2)));
check('activity-carries-outcome', seen.activities.some((entry) => entry.exitCode === 0 && entry.kind === 'run'), JSON.stringify(seen.activities.slice(0, 1)));

// A genuinely unknown host keeps its own wording (nothing new leaks).
try {
  await byName.get('ssh_run').execute({ host: 'nope', command: 'x' }, {});
  check('unknown-host-message', false, 'resolved');
} catch (error) {
  check('unknown-host-message', /unknown ssh host "nope"/.test(String(error)), String(error));
}

// The diagnostics wrapper records fixed-shape events, never the command text.
const recorded = [];
const instrumented = createTools(pool, { maxOutputBytes: 200000, defaultTimeoutMs: 60000 }, { diagnostics: { record: (event) => recorded.push(event) } });
await instrumented.find((tool) => tool.name === 'ssh_hosts').execute({});
check('diagnostics-recorded', recorded.length === 1 && recorded[0].tool === 'ssh_hosts' && recorded[0].outcome === 'ok', JSON.stringify(recorded));
try {
  await instrumented.find((tool) => tool.name === 'ssh_run').execute({ host: 'hidden-host', command: 'echo secret' }, {});
} catch {
  /* expected */
}
const failure = recorded.at(-1);
check('diagnostics-error-classified', failure?.tool === 'ssh_run' && failure?.outcome === 'error' && failure?.reason === 'invalid' && failure?.commandKind === 'echo', JSON.stringify(failure));
check('diagnostics-no-command-field', recorded.every((event) => !('command' in event) && !('stdout' in event)), JSON.stringify(recorded));

console.log(`${pass}/${pass + failures.length} passed`);
for (const failure of failures) console.log(`FAIL ${failure}`);
process.exit(failures.length === 0 ? 0 : 2);
