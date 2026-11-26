/**
 * Failure codes, per-host failed-call memory, host notes as notices, and the local
 * host info in ssh_hosts. Offline: fake connections, TEST-NET addresses only.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { hostname, tmpdir } from 'node:os';
import { join } from 'node:path';
import { annotateError, classifyError, FAILURE_CODES } from '../lib/errors.js';
import { createTools } from '../lib/tools.js';
import { MetadataStore } from '../lib/store.js';
import { SshPool } from '../lib/pool.js';
import { toMcpError, toMcpResult, ERROR_META_KEY } from '../mcp/server.js';
import { PolicyDeniedError } from '../lib/policy.js';
import { suggestAliases, unknownHostMessage } from '../lib/alias-suggest.js';

let pass = 0;
const failures = [];
const check = (name, ok, detail) => (ok ? (pass += 1) : failures.push(`${name}: ${detail}`));

// ── classification ─────────────────────────────────────────────────────────
{
  const cases = [
    ['ssh host "web" (root@192.0.2.10:22) failed: Timed out while waiting for handshake', 'connect_timeout'],
    ['ssh host "web" (root@192.0.2.10:22) failed: connect ECONNREFUSED 192.0.2.10:22', 'connection_refused'],
    ['ssh host "web" failed: getaddrinfo ENOTFOUND web.example', 'host_unreachable'],
    ['ssh host "web" failed: connect EHOSTUNREACH 192.0.2.10:22', 'host_unreachable'],
    ['ssh host "web" failed: All configured authentication methods failed', 'auth_failed'],
    ['ssh host "web" (root@192.0.2.10:22) host key mismatch: expected SHA256:abc', 'host_key_mismatch'],
    ['identity file id_web is encrypted and no passphrase is configured; load it into ssh-agent', 'key_unusable'],
    ['unknown ssh host "nope"; known hosts: web', 'unknown_host'],
    ['tool call aborted', 'cancelled'],
    ['sftp download timed out after 600000ms', 'exec_timeout'],
    ['read ECONNRESET', 'transport_lost'],
    // The socket closed before the server's banner: nothing ran (seen live on a throttling host).
    ['ssh host "web" (root@192.0.2.10:22) failed: Connection lost before handshake', 'closed_before_handshake'],
    ['kex_exchange_identification: Connection closed by remote host', 'closed_before_handshake'],
    // A drop after the handshake stays transport_lost: the command may have run.
    ['ssh host "web" failed: Connection lost', 'transport_lost'],
    ['channel open failure', 'transport_lost'],
    ['local file not found: C:\\deploy\\app.bin', 'local_path'],
    ['host is required', 'invalid_argument'],
    ['something odd', 'error']
  ];
  for (const [message, code] of cases) check(`classify-${code}`, classifyError(new Error(message)).code === code, `${message} → ${classifyError(new Error(message)).code}`);
  check('classify-policy', classifyError(new PolicyDeniedError({ rule: 'x', title: 't', reason: 'r', suggestion: 's', matches: [] }, { host: 'web', target: 'command' }, 'refused')).code === 'policy_denied', 'policy');
  check('every-code-has-hint', Object.values(FAILURE_CODES).every((entry) => typeof entry.hint === 'string' && entry.hint.length > 20), 'missing hint');

  const error = new Error('ssh host "web" failed: All configured authentication methods failed');
  annotateError(error);
  annotateError(error);
  check('annotate-marker-once', error.message.split('[error: auth_failed]').length === 2, error.message);
  check('annotate-fields', error.failureCode === 'auth_failed' && error.retryable === false && error.failureHint.includes('IdentityFile'), JSON.stringify(error));
  const missing = annotateError(new Error('local file not found: /srv/build/app.bin'));
  check(
    'local-path-names-server',
    [`[error: local_path]`, hostname(), `, ${process.platform})`, `cwd ${process.cwd()};`].every((part) => missing.message.includes(part)) && missing.failureHint.includes(hostname()),
    missing.message
  );
  const early = FAILURE_CODES.closed_before_handshake;
  check('early-close-retryable', early.retryable === true && /never ran/.test(early.hint) && /retry is safe/.test(early.hint), JSON.stringify(early));
  check('transport-lost-still-cautious', FAILURE_CODES.transport_lost.retryable === true && /already ran/.test(FAILURE_CODES.transport_lost.hint), FAILURE_CODES.transport_lost.hint);
  check('unknown-hint-does-not-mention-hiding', !/hidden/i.test(FAILURE_CODES.unknown_host.hint), FAILURE_CODES.unknown_host.hint);

  const meta = toMcpError(error)._meta?.[ERROR_META_KEY];
  check('mcp-meta-code', meta?.failureCode === 'auth_failed' && meta.retryable === false && typeof meta.hint === 'string', JSON.stringify(meta));
  const policyError = annotateError(new PolicyDeniedError({ rule: 'root-delete', title: 't', reason: 'r', suggestion: 's', matches: ['rm -rf /'] }, { host: 'web', target: 'command' }, '[ssh-pool policy] refused'));
  const denied = toMcpError(policyError)._meta?.[ERROR_META_KEY];
  check('mcp-meta-policy', denied?.code === 'POLICY_DENY' && denied.failureCode === 'policy_denied' && denied.rule === 'root-delete', JSON.stringify(denied));
}

// ── unknown host: suggest the likely alias ─────────────────────────────────
{
  const known = ['web', 'db_main', 'db_replica', 'cache-01', 'build208', 'lab'];
  const cases = [
    ['dbmain', ['db_main']], // separator dropped
    ['replica', ['db_replica']], // distinctive segment only
    ['db', ['db_main', 'db_replica']], // shared segment: every match, table order
    ['DB_MAIN', ['db_main']], // case
    ['db-main', ['db_main']], // other separator
    ['labb', ['lab']], // one typo
    ['build', ['build208']], // prefix
    ['cache_01', ['cache-01']],
    ['database', []], // nothing close: no guess
    ['a', []] // too short to guess
  ];
  for (const [input, expected] of cases) {
    const got = suggestAliases(input, known);
    check(`suggest-${input}`, JSON.stringify(got) === JSON.stringify(expected), `${input} → ${JSON.stringify(got)}`);
  }
  check('suggest-not-self', suggestAliases('lab', known).length === 0, JSON.stringify(suggestAliases('lab', known)));
  check('suggest-limit', suggestAliases('h', ['h1', 'h2', 'h3', 'h4']).length <= 3, JSON.stringify(suggestAliases('h', ['h1', 'h2', 'h3', 'h4'])));
  // Candidates are whatever the caller passes now: a renamed host is suggested under its new name.
  check('suggest-follows-rename', JSON.stringify(suggestAliases('dbmain', ['web', 'db_primary'])) === '[]' && JSON.stringify(suggestAliases('dbprimary', ['web', 'db_primary'])) === '["db_primary"]', 'stale candidates');
  const message = unknownHostMessage('dbmain', known);
  check('suggest-message', message.startsWith('unknown ssh host "dbmain"; did you mean "db_main"?; known hosts: web, db_main'), message);
  check('suggest-still-classified', classifyError(new Error(message)).code === 'unknown_host', classifyError(new Error(message)).code);
  check('suggest-message-plain', unknownHostMessage('zzz', known) === 'unknown ssh host "zzz"; known hosts: web, db_main, db_replica, cache-01, build208, lab', unknownHostMessage('zzz', known));
  check('suggest-message-empty', unknownHostMessage('zzz', []).endsWith('known hosts: (none available)'), unknownHostMessage('zzz', []));
}

// ── tool layer: failures recorded, note notices, local info ────────────────
function fakePool({ remarks = {}, behaviour = {} } = {}) {
  const specs = new Map([
    ['web', { alias: 'web', host: '192.0.2.10', port: 22, user: 'root', keyName: 'id_web', state: 'idle', connected: false }],
    ['db', { alias: 'db', host: '192.0.2.11', port: 22, user: 'root', keyName: 'id_db', state: 'idle', connected: false }],
    ['secret', { alias: 'secret', host: '192.0.2.12', port: 22, user: 'root', keyName: null, state: 'idle', connected: false }]
  ]);
  const noted = [];
  return {
    noted,
    aliases: [...specs.keys()],
    warnings: [],
    has: (alias) => specs.has(alias),
    hostVisible: (alias) => alias !== 'secret',
    hostMeta: (alias) => ({ remark: remarks[alias] ?? '', hidden: alias === 'secret', idleTimeoutMs: null }),
    noteCallFailure: (alias, failure) => noted.push({ alias, ...failure }),
    timeoutPolicy: () => ({ multiplier: 3, floorMs: 1000, ceilingMs: 3600000, fallbackEstimateMs: 4000 }),
    recordActivity: (entry) => behaviour.activity?.push(entry),
    transferTimeout: () => 5000,
    connection: (alias) => ({
      connected: behaviour.connectError === undefined,
      ensure: async () => {
        if (behaviour.connectError !== undefined) throw new Error(behaviour.connectError);
      },
      exec: async (_command, options) => {
        behaviour.seen?.push({ timeoutMs: options?.timeoutMs, detachAfterMs: options?.detachAfterMs });
        if (behaviour.detachEnd !== undefined && options?.detachAfterMs > 0) {
          setImmediate(() => options.onDetachedEnd?.(behaviour.detachEnd));
          return { stdout: 'partial\n', stderr: '', exitCode: null, signal: null, timedOut: false, aborted: false, detached: true };
        }
        return { stdout: 'ok\n', stderr: '', exitCode: 0, signal: null, timedOut: behaviour.timedOut === true };
      },
      session: () => ({ run: async () => ({ stdout: 'ok\n', stderr: '', exitCode: 0, cwd: '/root' }) })
    }),
    status: () =>
      [...specs.values()].map((spec) => ({
        ...spec,
        sessions: [],
        connects: 0,
        reconnects: 0,
        failures: 0,
        idleSeconds: null,
        hidden: spec.alias === 'secret',
        remark: remarks[spec.alias] ?? '',
        idleTimeoutMs: null,
        effectiveIdleTimeoutMs: 0,
        callFailures: 0,
        lastFailure: null
      })),
    releaseForOwner: () => ({}),
    releaseAllForOwner: () => [],
    connections: () => []
  };
}
const toolsFor = (pool, config = {}) => new Map(createTools(pool, { maxOutputBytes: 100000, ...config }, {}).map((tool) => [tool.name, tool]));
const firstText = (tool, args, value) => tool.output.render(args, value)[0].text;

{
  const pool = fakePool({ behaviour: { connectError: 'ssh host "web" (root@192.0.2.10:22) failed: Timed out while waiting for handshake' } });
  const tools = toolsFor(pool);
  let message = '';
  try {
    await tools.get('ssh_run').execute({ host: 'web', command: 'uptime' }, {});
  } catch (error) {
    message = error.message;
  }
  check('run-error-marker', message.includes('[error: connect_timeout]'), message);
  check('run-error-recorded', pool.noted.length === 1 && pool.noted[0].alias === 'web' && pool.noted[0].code === 'connect_timeout' && !pool.noted[0].message.includes('[error:'), JSON.stringify(pool.noted));

  try {
    await tools.get('ssh_run').execute({ host: 'secret', command: 'uptime' }, {});
  } catch (error) {
    message = error.message;
  }
  check('hidden-not-recorded', pool.noted.length === 1 && /unknown ssh host "secret"/.test(message) && !/hidden/i.test(message.replace(/unknown ssh host "secret"/, '')), `${message} ${JSON.stringify(pool.noted)}`);
  // Suggestions come from visible hosts only: a near-miss of the hidden alias
  // must read exactly like any other unknown name.
  const errorOf = async (tool, args) => {
    try {
      await tools.get(tool).execute(args, {});
      return '';
    } catch (error) {
      return error.message;
    }
  };
  const nearHidden = await errorOf('ssh_run', { host: 'secre', command: 'uptime' });
  check('suggest-no-hidden-leak', /unknown ssh host "secre"/.test(nearHidden) && !nearHidden.includes('secret') && !nearHidden.includes('did you mean'), nearHidden);
  const typo = await errorOf('ssh_run', { host: 'Web', command: 'uptime' });
  check('suggest-run', typo.includes('did you mean "web"?') && typo.includes('[error: unknown_host]') && typo.includes('use the alias the message suggests'), typo);
  const listedTypo = await errorOf('ssh_hosts', { host: 'dbb' });
  check('suggest-hosts', listedTypo.includes('did you mean "db"?') && !listedTypo.includes('secret'), listedTypo);
}
{
  const pool = fakePool({ behaviour: { connectError: 'ssh host "web" (root@192.0.2.10:22) failed: Connection lost before handshake' } });
  const tools = toolsFor(pool);
  let message = '';
  try {
    await tools.get('ssh_run').execute({ host: 'web', command: 'uptime' }, {});
  } catch (error) {
    message = error.message;
  }
  check('early-close-marker', message.includes('[error: closed_before_handshake]') && !message.includes('transport_lost'), message);
  check('early-close-recorded', pool.noted.at(-1)?.code === 'closed_before_handshake', JSON.stringify(pool.noted));
}
// ── per-call cap: answer before the client gives up, never kill ───────────
{
  const seen = [];
  const activity = [];
  const behaviour = { seen, activity, detachEnd: { stdout: 'done\n', stderr: '', exitCode: 0, signal: null, timedOut: false, aborted: false } };
  const pool = fakePool({ behaviour });
  const run = toolsFor(pool, { maxCallMs: 45000 }).get('ssh_run');
  const long = await run.execute({ host: 'web', command: 'make all', expectedMs: 600000 }, {});
  check('cap-detaches-not-shortens', seen[0].timeoutMs === 1800000 && seen[0].detachAfterMs <= 45000 && seen[0].detachAfterMs >= 44000, JSON.stringify(seen[0]));
  check('cap-result-detached', long.detached === true && long.timeoutMs === 1800000 && long.deadlineSource === 'expectedMs' && long.stdout.text === 'partial\n', JSON.stringify({ detached: long.detached, timeoutMs: long.timeoutMs, source: long.deadlineSource }));
  check('cap-hint-not-killed', /NOT killed/.test(long.hint ?? '') && /Do not rerun/.test(long.hint ?? '') && /ssh_hosts/.test(long.hint ?? ''), long.hint);
  check('cap-render-marker', firstText(run, { host: 'web' }, long).includes('[still running on the host'), firstText(run, { host: 'web' }, long));
  check('cap-not-a-failure-yet', pool.noted.length === 0, JSON.stringify(pool.noted));
  await new Promise((resolve) => setImmediate(resolve));
  check('cap-late-end-recorded', activity.some((entry) => /finished after cap: exit 0/.test(entry.detail)) && pool.noted.length === 0, JSON.stringify(activity));

  const quick = await run.execute({ host: 'web', command: 'uptime' }, {});
  check('cap-leaves-short-alone', seen[1].timeoutMs === 15000 && seen[1].detachAfterMs === undefined && quick.detached === false, JSON.stringify(seen[1]));
  const off = await toolsFor(pool).get('ssh_run').execute({ host: 'web', command: 'make all', expectedMs: 600000 }, {});
  check('cap-off-by-default', seen[2].detachAfterMs === undefined && off.detached === false, JSON.stringify(seen[2]));

  // A detached run that later hits its own deadline is recorded as exec_timeout.
  const timedBehaviour = { seen: [], activity: [], detachEnd: { stdout: '', stderr: '', exitCode: null, signal: null, timedOut: true, aborted: false } };
  const timedPool = fakePool({ behaviour: timedBehaviour });
  await toolsFor(timedPool, { maxCallMs: 45000 }).get('ssh_run').execute({ host: 'web', command: 'make all', expectedMs: 600000 }, {});
  await new Promise((resolve) => setImmediate(resolve));
  check('cap-late-timeout-recorded', timedPool.noted.at(-1)?.code === 'exec_timeout' && /per-call cap/.test(timedPool.noted.at(-1)?.message ?? ''), JSON.stringify(timedPool.noted));
}
{
  const pool = fakePool({ behaviour: { timedOut: true } });
  const tools = toolsFor(pool);
  const value = await tools.get('ssh_run').execute({ host: 'web', command: 'sleep 999' }, {});
  check('timeout-result-recorded', value.timedOut === true && pool.noted[0]?.code === 'exec_timeout', JSON.stringify(pool.noted));
}
{
  const pool = fakePool({ remarks: { db: '主库，改动先确认' } });
  const tools = toolsFor(pool);
  const run = tools.get('ssh_run');
  const value = await run.execute({ host: 'db', command: 'uptime' }, {});
  check('note-run-marked', firstText(run, { host: 'db' }, value).startsWith('[note] db: 主库，改动先确认\n'), firstText(run, { host: 'db' }, value).slice(0, 120));
  const plain = await run.execute({ host: 'web', command: 'uptime' }, {});
  check('unnoted-unmarked', !firstText(run, { host: 'web' }, plain).includes('[note]'), firstText(run, { host: 'web' }, plain).slice(0, 80));
  // MCP clients that read structuredContent never see the text: the note
  // must also be in the value, and the schema must allow it.
  check('note-run-notices', JSON.stringify(value.notices) === JSON.stringify(['[note] db: 主库，改动先确认']), JSON.stringify(value.notices));
  check('notices-first-key', Object.keys(value)[0] === 'notices', JSON.stringify(Object.keys(value)));
  check('note-text-not-doubled', firstText(run, { host: 'db' }, value).split('[note] db').length === 2, firstText(run, { host: 'db' }, value).slice(0, 200));
  check('unnoted-no-notices', plain.notices === undefined, JSON.stringify(plain.notices));
  const runProps = run.output.schema.properties;
  check('run-schema-notices', runProps.notices?.type === 'array' && runProps.notices.items?.type === 'string', JSON.stringify(runProps.notices));
  check('run-value-fits-schema', Object.keys(value).every((key) => key in runProps), JSON.stringify(Object.keys(value).filter((key) => !(key in runProps))));
  const structured = toMcpResult(run, { host: 'db' }, value);
  check('mcp-structured-notices', structured.structuredContent?.notices?.[0]?.startsWith('[note] db') === true, JSON.stringify(structured.structuredContent?.notices));
  check('mcp-text-notices', structured.content[0].text.startsWith('[note] db: 主库'), structured.content[0].text.slice(0, 80));
  check('hosts-schema-no-notices', tools.get('ssh_hosts').output.schema.properties.notices === undefined, 'ssh_hosts already carries the remark per host');

  const hosts = tools.get('ssh_hosts');
  const listed = await hosts.execute({});
  const text = firstText(hosts, {}, listed);
  check('hosts-note-render', /db → root@192\.0\.2\.11:22 .*note=主库，改动先确认/.test(text) && !/\[PROD\]|\[prod\]/.test(text), text);
  check('hosts-hidden-still-hidden', !listed.hosts.some((host) => host.alias === 'secret') && !text.includes('secret'), text);
  check('hosts-local', listed.local?.hostname === hostname() && listed.local.platform === process.platform && typeof listed.local.cwd === 'string' && listed.local.uptimeSeconds >= 0, JSON.stringify(listed.local));
  check('hosts-local-render', text.includes(`[local] this server runs on ${hostname()}`) && text.includes('localPath is resolved there'), text);
  check('run-description-first-call', /first call opens the SSH connection/.test(run.description) && /\[error: <code>\]/.test(run.description) && /Do not fall back to local ssh/.test(run.description), run.description);
}

// ── real pool: lastFailure, lastCommandAgeSeconds ──────────────────────────
{
  const dir = mkdtempSync(join(tmpdir(), 'dsh-failures-'));
  const statePath = join(dir, 'state.json');
  const store = new MetadataStore({ filePath: statePath });
  const hosts = new Map([['web', { alias: 'web', host: '192.0.2.10', port: 22, user: 'root', source: 'ssh-config' }]]);
  const pool = new SshPool({ hosts, config: { maxChannelsPerHost: 4, idleTimeoutMs: 0, autoConnect: [] }, meta: store });

  const idle = pool.status()[0];
  check('idle-shape', idle.lastCommandAgeSeconds === null && idle.callFailures === 0 && idle.lastFailure === null && !('prod' in idle), JSON.stringify(idle));
  pool.noteCallFailure('web', { tool: 'ssh_run', code: 'connect_timeout', message: 'handshake timed out password=hunter2' });
  pool.noteCallFailure('nope', { tool: 'ssh_run', code: 'error', message: 'ignored' });
  const after = pool.status()[0];
  check('last-failure', after.callFailures === 1 && after.lastFailure?.code === 'connect_timeout' && after.lastFailure.ageSeconds === 0, JSON.stringify(after.lastFailure));
  check('last-failure-redacted', !after.lastFailure.message.includes('hunter2'), after.lastFailure.message);
  check('connect-counters-untouched', after.failures === 0 && after.connects === 0, JSON.stringify(after));

  pool.dispose();
  rmSync(dir, { recursive: true, force: true });
}

console.log(`${pass}/${pass + failures.length} passed`);
for (const failure of failures) console.log(`FAIL ${failure}`);
process.exit(failures.length === 0 ? 0 : 2);
