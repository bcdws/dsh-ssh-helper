/**
 * Failure codes, per-host failed-call memory, the prod label, and the local
 * host info in ssh_hosts. Offline: fake connections, TEST-NET addresses only.
 */
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { hostname, tmpdir } from 'node:os';
import { join } from 'node:path';
import { annotateError, classifyError, FAILURE_CODES } from '../lib/errors.js';
import { createTools } from '../lib/tools.js';
import { MetadataStore } from '../lib/store.js';
import { SshPool } from '../lib/pool.js';
import { createAssistantApi } from '../lib/assistant-api.js';
import { toMcpError, ERROR_META_KEY } from '../mcp/server.js';
import { PolicyDeniedError } from '../lib/policy.js';

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
  check('unknown-hint-does-not-mention-hiding', !/hidden/i.test(FAILURE_CODES.unknown_host.hint), FAILURE_CODES.unknown_host.hint);

  const meta = toMcpError(error)._meta?.[ERROR_META_KEY];
  check('mcp-meta-code', meta?.failureCode === 'auth_failed' && meta.retryable === false && typeof meta.hint === 'string', JSON.stringify(meta));
  const policyError = annotateError(new PolicyDeniedError({ rule: 'root-delete', title: 't', reason: 'r', suggestion: 's', matches: ['rm -rf /'] }, { host: 'web', target: 'command' }, '[ssh-pool policy] refused'));
  const denied = toMcpError(policyError)._meta?.[ERROR_META_KEY];
  check('mcp-meta-policy', denied?.code === 'POLICY_DENY' && denied.failureCode === 'policy_denied' && denied.rule === 'root-delete', JSON.stringify(denied));
}

// ── tool layer: failures recorded, prod marker, local info ─────────────────
function fakePool({ prod = new Set(), behaviour = {} } = {}) {
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
    isProd: (alias) => prod.has(alias),
    noteCallFailure: (alias, failure) => noted.push({ alias, ...failure }),
    timeoutPolicy: () => ({ multiplier: 3, floorMs: 1000, ceilingMs: 3600000, fallbackEstimateMs: 4000 }),
    recordActivity: () => {},
    transferTimeout: () => 5000,
    connection: (alias) => ({
      connected: behaviour.connectError === undefined,
      ensure: async () => {
        if (behaviour.connectError !== undefined) throw new Error(behaviour.connectError);
      },
      exec: async () => ({ stdout: 'ok\n', stderr: '', exitCode: 0, signal: null, timedOut: behaviour.timedOut === true }),
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
        prod: prod.has(spec.alias),
        remark: '',
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
const toolsFor = (pool) => new Map(createTools(pool, { maxOutputBytes: 100000 }, {}).map((tool) => [tool.name, tool]));
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
}
{
  const pool = fakePool({ behaviour: { timedOut: true } });
  const tools = toolsFor(pool);
  const value = await tools.get('ssh_run').execute({ host: 'web', command: 'sleep 999' }, {});
  check('timeout-result-recorded', value.timedOut === true && pool.noted[0]?.code === 'exec_timeout', JSON.stringify(pool.noted));
}
{
  const pool = fakePool({ prod: new Set(['db']) });
  const tools = toolsFor(pool);
  const run = tools.get('ssh_run');
  const value = await run.execute({ host: 'db', command: 'uptime' }, {});
  check('prod-run-marked', firstText(run, { host: 'db' }, value).startsWith('[PROD] db is a production server.'), firstText(run, { host: 'db' }, value).slice(0, 120));
  const plain = await run.execute({ host: 'web', command: 'uptime' }, {});
  check('non-prod-unmarked', !firstText(run, { host: 'web' }, plain).includes('[PROD]'), firstText(run, { host: 'web' }, plain).slice(0, 80));
  const read = tools.get('ssh_read');
  check('read-tools-unmarked', read.output.render({ host: 'db' }, { path: '/etc/hostname', content: 'x', totalLines: 1, offset: 1, limit: 1, truncated: false, sha256: 'a', host: 'db', analysis: null, analysisError: null })?.[0]?.text?.includes('[PROD]') !== true, 'ssh_read marked');

  const hosts = tools.get('ssh_hosts');
  const listed = await hosts.execute({});
  const text = firstText(hosts, {}, listed);
  check('hosts-prod-field', listed.hosts.find((host) => host.alias === 'db')?.prod === true, JSON.stringify(listed.hosts));
  check('hosts-prod-render', /db → root@192\.0\.2\.11:22 \[PROD\]/.test(text) && text.includes('[prod] Hosts marked [PROD]'), text);
  check('hosts-hidden-still-hidden', !listed.hosts.some((host) => host.alias === 'secret') && !text.includes('secret'), text);
  check('hosts-local', listed.local?.hostname === hostname() && listed.local.platform === process.platform && typeof listed.local.cwd === 'string' && listed.local.uptimeSeconds >= 0, JSON.stringify(listed.local));
  check('hosts-local-render', text.includes(`[local] this server runs on ${hostname()}`) && text.includes('localPath is resolved there'), text);
  check('run-description-first-call', /first call opens the SSH connection/.test(run.description) && /\[error: <code>\]/.test(run.description) && /Do not fall back to local ssh/.test(run.description), run.description);
}

// ── real pool: lastFailure, lastCommandAgeSeconds, prod via the store ──────
{
  const dir = mkdtempSync(join(tmpdir(), 'dsh-failures-'));
  const statePath = join(dir, 'state.json');
  const store = new MetadataStore({ filePath: statePath });
  const hosts = new Map([['web', { alias: 'web', host: '192.0.2.10', port: 22, user: 'root', source: 'ssh-config' }]]);
  const pool = new SshPool({ hosts, config: { maxChannelsPerHost: 4, idleTimeoutMs: 0, autoConnect: [] }, meta: store });

  const idle = pool.status()[0];
  check('idle-shape', idle.lastCommandAgeSeconds === null && idle.callFailures === 0 && idle.lastFailure === null && idle.prod === false, JSON.stringify(idle));
  pool.noteCallFailure('web', { tool: 'ssh_run', code: 'connect_timeout', message: 'handshake timed out password=hunter2' });
  pool.noteCallFailure('nope', { tool: 'ssh_run', code: 'error', message: 'ignored' });
  const after = pool.status()[0];
  check('last-failure', after.callFailures === 1 && after.lastFailure?.code === 'connect_timeout' && after.lastFailure.ageSeconds === 0, JSON.stringify(after.lastFailure));
  check('last-failure-redacted', !after.lastFailure.message.includes('hunter2'), after.lastFailure.message);
  check('connect-counters-untouched', after.failures === 0 && after.connects === 0, JSON.stringify(after));

  store.setHost('web', { prod: true });
  check('prod-from-store', pool.isProd('web') && pool.status()[0].prod === true, JSON.stringify(pool.status()[0]));
  check('prod-persisted', JSON.parse(readFileSync(statePath, 'utf8')).hosts.web.prod === true, readFileSync(statePath, 'utf8'));
  store.setHost('web', { prod: false });
  check('prod-off-not-written', !('prod' in JSON.parse(readFileSync(statePath, 'utf8')).hosts.web), readFileSync(statePath, 'utf8'));
  store.setHost('web', { remark: 'x' });
  check('prod-survives-other-edits', store.host('web').prod === false && store.host('web').remark === 'x', JSON.stringify(store.host('web')));
  pool.dispose();

  // The panel API passes `prod` through to the store.
  const api = createAssistantApi({ pool: { has: () => true, status: () => [], connection: () => ({ state: 'idle', close: () => {} }) }, store, config: {} });
  const patches = [];
  const original = store.setHost.bind(store);
  store.setHost = (alias, patch) => {
    patches.push(patch);
    return original(alias, patch);
  };
  const token = api.token;
  const req = {
    method: 'POST',
    url: '/ssh-pool/meta',
    headers: { 'x-dsh-ssh-pool-token': token },
    socket: { remoteAddress: '127.0.0.1' },
    async *[Symbol.asyncIterator]() {
      yield Buffer.from(JSON.stringify({ alias: 'web', prod: true }));
    }
  };
  let status = 0;
  await api.handler(req, { writeHead: (code) => (status = code), end: () => {} });
  check('api-meta-prod', status === 200 && patches[0]?.prod === true && store.host('web').prod === true, `${status} ${JSON.stringify(patches)}`);
  rmSync(dir, { recursive: true, force: true });
}

console.log(`${pass}/${pass + failures.length} passed`);
for (const failure of failures) console.log(`FAIL ${failure}`);
process.exit(failures.length === 0 ? 0 : 2);
