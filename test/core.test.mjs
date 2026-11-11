/**
 * Host-neutral core contract: what any adapter (DSH today, MCP next) can rely
 * on when it mounts `createTools` without `index.js`.
 *
 *  1. The machine-destruction policy is enforced inside the tools, with no
 *     host guard and no `policy` passed in, before any transport work.
 *  2. A refusal is a structured `PolicyDeniedError`, not only prose.
 *  3. Tools read only the neutral call context `{ callerId, signal }`; the DSH
 *     adapter translates its execution shape on registration.
 *  4. The side analyzer runs over any backend that can complete one prompt.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createTools } from '../lib/tools.js';
import { PolicyDeniedError } from '../lib/policy.js';
import { callContext, fromDshExecution, LOCAL_CALLER } from '../lib/call-context.js';
import { createSideAnalyzer, unavailableAnalyzer } from '../lib/analysis.js';
import { createDiagnostics } from '../lib/diagnostics.js';
import { apply, toDshTool } from '../index.js';

let pass = 0;
const failures = [];
const check = (name, ok, detail) => (ok ? (pass += 1) : failures.push(`${name}: ${detail}`));
const failureOf = async (promise) => {
  try {
    await promise;
    return null;
  } catch (error) {
    return error;
  }
};

/** A pool double that records every transport touch. */
function fakePool() {
  const seen = { ensures: 0, execs: [], sessions: [], writes: 0, activities: [] };
  const pool = {
    aliases: ['h'],
    warnings: [],
    has: (alias) => alias === 'h',
    hostVisible: () => true,
    timeoutPolicy: () => ({ multiplier: 3, floorMs: 1000, ceilingMs: 1800000, fallbackEstimateMs: 30000 }),
    transferTimeout: () => 600000,
    recordActivity: (entry) => seen.activities.push(entry),
    status: () => [],
    connections: () => [],
    connection: () => ({
      connected: true,
      ensure: async () => {
        seen.ensures += 1;
      },
      session: (name, owner) => {
        seen.sessions.push({ name, owner });
        return { run: async () => ({ stdout: 'ok\n', stderr: '', exitCode: 0, cwd: '/root' }) };
      },
      exec: async (command, options = {}) => {
        seen.execs.push({ command, signal: options.signal });
        return { stdout: 'ok\n', stderr: '', exitCode: 0, signal: null, timedOut: false };
      },
      sftp: async () => {
        seen.writes += 1;
        throw new Error('sftp must not be reached');
      }
    })
  };
  return { pool, seen };
}

const CONFIG = { maxOutputBytes: 32768, defaultTimeoutMs: 30000 };

// ── 1/2. policy inside the tools, no extras at all ─────────────────────────
{
  const { pool, seen } = fakePool();
  const run = createTools(pool, CONFIG).find((tool) => tool.name === 'ssh_run');
  const error = await failureOf(run.execute({ host: 'h', command: 'rm -rf /' }));
  check('bare-tools-deny', error instanceof PolicyDeniedError, String(error));
  check('deny-code', error?.code === 'POLICY_DENY' && error?.rule === 'danger.rm-root' && error?.target === 'command', JSON.stringify({ code: error?.code, rule: error?.rule, target: error?.target }));
  check('deny-host', error?.host === 'h', String(error?.host));
  check('deny-matches', Array.isArray(error?.matches) && error.matches.some((match) => match.rule === 'danger.rm-root'), JSON.stringify(error?.matches));
  check('deny-message-same-as-guard', /^\[ssh-pool policy\] 命令被拒绝（规则 danger\.rm-root）/.test(error?.message ?? '') && /主机 h/.test(error?.message ?? ''), error?.message);
  check('deny-before-transport', seen.ensures === 0 && seen.execs.length === 0, JSON.stringify(seen));

  const wrapped = await failureOf(run.execute({ host: 'h', command: "bash -c 'rm -rf /etc'", session: 'main' }));
  check('deny-session-mode', wrapped?.code === 'POLICY_DENY' && seen.sessions.length === 0, String(wrapped));

  const ok = await run.execute({ host: 'h', command: 'uptime' });
  check('allow-ordinary', ok.exitCode === 0 && seen.execs.length === 1, JSON.stringify(ok));

  const write = createTools(pool, CONFIG).find((tool) => tool.name === 'ssh_write');
  const writeError = await failureOf(write.execute({ host: 'h', path: '/dev/sda', content: 'x' }));
  check('write-deny-structured', writeError instanceof PolicyDeniedError && writeError.target === 'path' && writeError.path === '/dev/sda' && writeError.rule === 'danger.write-device', JSON.stringify({ target: writeError?.target, path: writeError?.path, rule: writeError?.rule }));
  check('write-deny-before-sftp', seen.writes === 0, `${seen.writes} sftp opens`);

  const transfer = createTools(pool, CONFIG).find((tool) => tool.name === 'ssh_transfer');
  const uploadError = await failureOf(transfer.execute({ host: 'h', direction: 'upload', localPath: '/tmp/x', remotePath: '/boot/vmlinuz' }));
  check('upload-deny-structured', uploadError?.code === 'POLICY_DENY' && uploadError.rule === 'danger.write-system', String(uploadError));
}

// Diagnostics classify the in-tool refusal as a policy denial.
{
  const { pool } = fakePool();
  const diagnostics = createDiagnostics();
  const run = createTools(pool, CONFIG, { diagnostics }).find((tool) => tool.name === 'ssh_run');
  await failureOf(run.execute({ host: 'h', command: 'mkfs.ext4 /dev/sda1' }));
  const snapshot = diagnostics.snapshot();
  const last = snapshot.events[snapshot.events.length - 1] ?? snapshot.events[0];
  check('diagnostics-denied', snapshot.counters.policyDenials === 1 && last?.outcome === 'denied' && last?.reason === 'policy', JSON.stringify({ counters: snapshot.counters, last }));
}

// ── 3. neutral call context ────────────────────────────────────────────────
{
  const signal = new AbortController().signal;
  const context = callContext({ callerId: 'agent-1', signal, agent: { id: 'ignored' } });
  check('context-fields', context.callerId === 'agent-1' && context.signal === signal && Object.keys(context).length === 2, JSON.stringify(Object.keys(context)));
  check('context-frozen', Object.isFrozen(context), 'context must be immutable');
  check('context-default-caller', callContext().callerId === LOCAL_CALLER && callContext({ callerId: '' }).callerId === LOCAL_CALLER, callContext().callerId);
  check('context-bad-signal', callContext({ signal: { aborted: false } }).signal === undefined, 'a non-AbortSignal must be dropped');
  const dsh = fromDshExecution({ agent: { id: 'dsh-7' }, signal, name: 'ssh_run' });
  check('dsh-translation', dsh.callerId === 'dsh-7' && dsh.signal === signal, JSON.stringify(dsh));
  check('dsh-translation-missing', fromDshExecution(undefined).callerId === LOCAL_CALLER, 'missing execution');

  const { pool, seen } = fakePool();
  const run = createTools(pool, CONFIG).find((tool) => tool.name === 'ssh_run');
  await run.execute({ host: 'h', command: 'cd /srv', session: 'main' }, { callerId: 'a' });
  await run.execute({ host: 'h', command: 'pwd', session: 'main' }, { callerId: 'b' });
  check('session-owner-is-caller', seen.sessions.map((entry) => entry.owner).join(',') === 'a,b', JSON.stringify(seen.sessions));
  await run.execute({ host: 'h', command: 'uptime' }, { callerId: 'c', signal });
  check('signal-forwarded', seen.execs[seen.execs.length - 1]?.signal === signal, 'exec did not receive the caller signal');
  check('activity-owner', seen.activities[seen.activities.length - 1]?.owner === 'c', JSON.stringify(seen.activities.at(-1)));

  const dshRun = toDshTool(run);
  await dshRun.execute({ host: 'h', command: 'pwd', session: 'main' }, { agent: { id: 'dsh-agent' }, signal });
  check('dsh-adapter-owner', seen.sessions[seen.sessions.length - 1]?.owner === 'dsh-agent', JSON.stringify(seen.sessions.at(-1)));
}

// The registered DSH tools still refuse on their own when no guard ran.
{
  const dir = mkdtempSync(join(tmpdir(), 'dsh-core-'));
  const registered = [];
  const ctx = {
    logger: { info: () => {}, warn: () => {} },
    get: () => undefined,
    tools: { register: (tool) => (registered.push(tool), () => {}), guard: () => () => {} },
    effect: (callback) => (callback(), () => {}),
    inject: () => () => {}
  };
  // TEST-NET host: the call must be refused before any connection attempt.
  apply(ctx, { useSshConfig: false, hosts: [{ alias: 't', host: '192.0.2.1', user: 'u' }], statePath: join(dir, 'state.json') });
  const run = registered.find((tool) => tool.name === 'ssh_run');
  const started = Date.now();
  const error = await failureOf(run.execute({ host: 't', command: 'dd if=/dev/zero of=/dev/sda' }, { agent: { id: 'x' } }));
  check('dsh-tool-denies-without-guard', error?.code === 'POLICY_DENY' && Date.now() - started < 1000, String(error));
  rmSync(dir, { recursive: true, force: true });
}

// ── 4. side analyzer over a custom backend ─────────────────────────────────
{
  let request;
  const analyzer = createSideAnalyzer({
    backend: {
      status: () => ({ available: true, reason: null, model: 'sampling/client' }),
      complete: async (input) => {
        request = input;
        return { text: '  未发现明显错误  ' };
      }
    }
  });
  check('custom-status', analyzer.status().available === true && analyzer.status().model === 'sampling/client', JSON.stringify(analyzer.status()));
  const result = await analyzer.run({ tool: 'ssh_read', target: '/var/log/app.log', text: 'ERROR password=hunter2', bytes: 22, sessionId: 'mcp-1' });
  check('custom-summary', result.summary === '未发现明显错误' && result.model === 'sampling/client' && result.source === 'ssh_read', JSON.stringify(result));
  check('custom-request-shape', typeof request?.system === 'string' && typeof request?.prompt === 'string' && request?.tools === undefined && request?.sessionId === 'mcp-1' && request?.signal instanceof AbortSignal, JSON.stringify(Object.keys(request ?? {})));
  check('custom-prompt-redacted', !/hunter2/.test(request?.prompt ?? ''), request?.prompt);

  const reported = createSideAnalyzer({ backend: { complete: async () => ({ error: 'sampling not supported' }) } });
  check('backend-error-reported', /sampling not supported/.test((await reported.run({ tool: 'x', target: 'x', text: 'x', bytes: 1 })).error ?? ''), 'backend error must surface');

  const thrown = createSideAnalyzer({ backend: { status: () => { throw new Error('status boom'); }, complete: async () => ({ text: 'x' }) } });
  check('status-throw-contained', thrown.status().available === false && /status boom/.test(thrown.status().reason), JSON.stringify(thrown.status()));

  const none = unavailableAnalyzer('no model on this host');
  check('unavailable-status', none.status().available === false && none.status().reason === 'no model on this host', JSON.stringify(none.status()));
  check('unavailable-run', (await none.run({ text: 'x' })).error === 'no model on this host', 'run must report the reason');
  check('missing-backend', createSideAnalyzer({}).status().available === false, 'no backend means unavailable');
}

console.log(`${pass}/${pass + failures.length} passed`);
for (const failure of failures) console.log(`FAIL ${failure}`);
process.exit(failures.length === 0 ? 0 : 2);
