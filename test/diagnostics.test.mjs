/** In-memory diagnostics: bounded, structured, and free of command/output text. */
import { DEFAULT_EVENT_LIMIT, MAX_EVENTS, commandKind, createDiagnostics } from '../lib/diagnostics.js';

let pass = 0;
const failures = [];
const check = (name, ok, detail) => (ok ? (pass += 1) : failures.push(`${name}: ${detail}`));

const diagnostics = createDiagnostics();
for (let index = 0; index < 305; index += 1) {
  diagnostics.record({
    tool: 'ssh_run',
    host: 'host-a',
    outcome: 'ok',
    reason: null,
    durationMs: index,
    bytes: index * 10,
    reused: index % 2 === 0,
    analysis: index === 3 ? 'success' : index === 4 ? 'empty' : null,
    commandKind: index === 0 ? 'du' : null
  });
}
const snapshot = diagnostics.snapshot({ events: MAX_EVENTS });
check('bounded-buffer', snapshot.events.length === 300, String(snapshot.events.length));
check('oldest-dropped', snapshot.events[0].durationMs === 5 && snapshot.events.at(-1).durationMs === 304, JSON.stringify({ first: snapshot.events[0].durationMs, last: snapshot.events.at(-1).durationMs }));
check('counters', snapshot.counters.toolCalls === 305 && snapshot.counters.failures === 0 && snapshot.counters.analyses.success === 1 && snapshot.counters.analyses.empty === 1, JSON.stringify(snapshot.counters));
check('default-limit', diagnostics.snapshot().events.length === DEFAULT_EVENT_LIMIT, String(diagnostics.snapshot().events.length));
check('default-is-newest', diagnostics.snapshot().events.at(-1).durationMs === 304, JSON.stringify(diagnostics.snapshot().events.at(-1)));
check('limit-zero', diagnostics.snapshot({ events: 0 }).events.length === 0 && diagnostics.snapshot({ events: 0 }).counters.toolCalls === 305, JSON.stringify(diagnostics.snapshot({ events: 0 }).counters));
check('limit-small', diagnostics.snapshot({ events: 3 }).events.map((event) => event.durationMs).join(',') === '302,303,304', JSON.stringify(diagnostics.snapshot({ events: 3 }).events.map((event) => event.durationMs)));
check('limit-invalid', diagnostics.snapshot({ events: -5 }).events.length === DEFAULT_EVENT_LIMIT && diagnostics.snapshot({ events: 'abc' }).events.length === DEFAULT_EVENT_LIMIT, 'invalid limits fall back to the default');
check('slow-marked', snapshot.events.every((event) => event.slow === false), JSON.stringify(snapshot.events.slice(0, 2)));

const secrets = createDiagnostics();
secrets.record({
  tool: 'ssh_run',
  host: 'host-a',
  outcome: 'error',
  reason: 'connection',
  command: 'rm -rf /secret && token=abcdef',
  stdout: 'secret output',
  stderr: 'password=hunter2',
  durationMs: 5,
  bytes: 12,
  commandKind: 'du',
  durationMs: 30_000
});
const text = JSON.stringify(secrets.snapshot());
check('no-command-or-output', !/rm -rf|abcdef|secret output|hunter2/.test(text), text);
check('event-shape', Object.keys(secrets.snapshot().events[0]).sort().join(',') === 'analysis,at,bytes,commandKind,durationMs,host,outcome,reason,reused,slow,tool', text);
check('slow-command', secrets.snapshot().events[0].slow === true && secrets.snapshot().events[0].commandKind === 'du', text);

check('command-kind-wrapper', commandKind('sudo -n timeout 20s du -sh /var/lib/mysql') === 'du', commandKind('sudo -n timeout 20s du -sh /var/lib/mysql'));
check('command-kind-path', commandKind('/usr/bin/journalctl -u x -n 10') === 'journalctl', commandKind('/usr/bin/journalctl -u x -n 10'));

const invalid = createDiagnostics();
invalid.record({ tool: '', host: 42, outcome: 'bogus', reason: 'bogus', durationMs: -1, bytes: -2, reused: 'yes', analysis: 'bogus' });
const entry = invalid.snapshot().events[0];
check('invalid-normalized', entry.tool === 'unknown' && entry.host === null && entry.outcome === 'error' && entry.reason === null && entry.durationMs === 0 && entry.bytes === 0 && entry.reused === null && entry.analysis === null, JSON.stringify(entry));

const guards = createDiagnostics();
guards.record({ tool: 'bash', outcome: 'denied', reason: 'local-ssh' });
guards.record({ tool: 'ssh_run', outcome: 'denied', reason: 'plan' });
check('guard-reasons', guards.snapshot().events[0].reason === 'local-ssh' && guards.snapshot().events[1].reason === 'plan', JSON.stringify(guards.snapshot().events));

console.log(`${pass}/${pass + failures.length} passed`);
for (const failure of failures) console.log(`FAIL ${failure}`);
process.exit(failures.length === 0 ? 0 : 2);
