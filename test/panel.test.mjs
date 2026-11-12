/**
 * MCP panel: the per-process control port, the run-dir discovery, the panel
 * routes (shared assistant API under /api), the hidden-host watcher, and the
 * end-to-end "hide in the panel → the server stops offering the host" path.
 *
 * Offline: hosts are TEST-NET (192.0.2.x) and nothing ever dials them.
 */
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { createServer, request } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { isLoopbackHostHeader } from '../lib/http.js';
import { callInstance, listInstances, TOKEN_HEADER } from '../mcp/control.js';
import { createPanel } from '../mcp/panel.js';
import { createHiddenWatcher } from '../mcp/hidden-watch.js';

let pass = 0;
const failures = [];
const check = (name, ok, detail) => (ok ? (pass += 1) : failures.push(`${name}: ${detail}`));
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const here = dirname(fileURLToPath(import.meta.url));
const BIN = join(here, '..', 'bin', 'dsh-ssh-mcp.js');
const dir = mkdtempSync(join(tmpdir(), 'dsh-mcp-panel-'));
const home = join(dir, 'mcp-home');
const runDir = join(home, 'run');
const statePath = join(home, 'state.json');
const sshConfig = join(dir, 'ssh_config');
writeFileSync(sshConfig, ['Host alpha', '  HostName 192.0.2.10', '  User root', 'Host beta', '  HostName 192.0.2.11', '  User root', ''].join('\n'));
const env = { ...process.env, DSH_SSH_MCP_HOME: home };

/** Raw HTTP so the Host header is exactly what the test sends. */
function raw({ port, path, method = 'GET', headers = {}, body }) {
  return new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port, path, method, headers: { host: `127.0.0.1:${port}`, ...headers } }, (res) => {
      let text = '';
      res.on('data', (chunk) => (text += chunk));
      res.on('end', () => {
        let json = null;
        try {
          json = JSON.parse(text);
        } catch {
          /* html */
        }
        resolve({ status: res.statusCode, headers: res.headers, json, text });
      });
    });
    req.on('error', reject);
    if (body !== undefined) {
      req.setHeader('content-type', 'application/json');
      req.end(JSON.stringify(body));
    } else req.end();
  });
}

/** A real server over stdio. */
function startServer(args = []) {
  const child = spawn(process.execPath, [BIN, '--ssh-config', sshConfig, '--quiet', ...args], { stdio: ['pipe', 'pipe', 'pipe'], env });
  const waiting = new Map();
  createInterface({ input: child.stdout }).on('line', (line) => {
    const message = JSON.parse(line);
    waiting.get(message.id)?.(message);
    waiting.delete(message.id);
  });
  let nextId = 1;
  const call = (method, params) => {
    const id = nextId++;
    const reply = new Promise((resolve) => waiting.set(id, resolve));
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
    return Promise.race([reply, sleep(10_000).then(() => ({ timeout: true }))]);
  };
  const stop = () =>
    new Promise((resolve) => {
      child.once('exit', resolve);
      child.stdin.end();
    });
  return { child, call, stop };
}
const initialize = (server) => server.call('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'panel-test', version: '9' } });
const hostAliases = async (server) => {
  const reply = await server.call('tools/call', { name: 'ssh_hosts', arguments: {} });
  return (reply.result?.structuredContent?.hosts ?? []).map((host) => host.alias);
};
const waitFor = async (predicate, ms = 5000) => {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (await predicate()) return true;
    await sleep(50);
  }
  return false;
};

// ── Host header (DNS rebinding) ────────────────────────────────────────────
{
  const req = (host) => ({ headers: { host } });
  check('host-localhost', isLoopbackHostHeader(req('localhost:7318')), 'localhost:7318');
  check('host-ipv4', isLoopbackHostHeader(req('127.0.0.1:1')), '127.0.0.1:1');
  check('host-ipv6', isLoopbackHostHeader(req('[::1]:7318')), '[::1]:7318');
  check('host-rebinding', !isLoopbackHostHeader(req('evil.example:7318')), 'evil.example');
  check('host-suffix-trick', !isLoopbackHostHeader(req('localhost.evil.example')), 'localhost.evil.example');
  check('host-missing', !isLoopbackHostHeader({ headers: {} }), 'missing');
}

// ── Hidden watcher (fakes) ─────────────────────────────────────────────────
{
  const hidden = new Set();
  let changed = false;
  const meta = { refresh: () => changed, host: (alias) => ({ hidden: hidden.has(alias) }) };
  const closes = [];
  const connection = (alias, state = 'connected') => {
    let ensured = null;
    return {
      alias,
      state,
      close: (reason) => closes.push(`${alias}:${reason}`),
      ensure: () => (ensured ??= Promise.resolve())
    };
  };
  const live = [connection('alpha'), connection('beta', 'connecting')];
  const pool = { aliases: ['alpha', 'beta', 'gamma'], connections: () => live };
  const watch = createHiddenWatcher({ pool, meta });

  check('watch-no-change', watch().length === 0 && closes.length === 0, JSON.stringify(closes));
  hidden.add('alpha');
  changed = true;
  check('watch-hide-closes', JSON.stringify(watch()) === '["alpha"]' && closes.length === 1, JSON.stringify(closes));
  check('watch-already-hidden-left-alone', watch().length === 0 && closes.length === 1, JSON.stringify(closes));
  hidden.delete('alpha');
  check('watch-unhide-left-alone', watch().length === 0 && closes.length === 1, JSON.stringify(closes));
  hidden.add('beta');
  watch();
  await sleep(0);
  check('watch-connecting-closed-twice', closes.filter((entry) => entry.startsWith('beta:')).length === 2, JSON.stringify(closes));
}

// ── Control port of a real server ──────────────────────────────────────────
{
  const started = Date.now();
  const server = startServer();
  const init = await initialize(server);
  check('init-fast', init.result?.serverInfo !== undefined && Date.now() - started < 5000, `${Date.now() - started}ms`);
  const announced = await waitFor(() => listInstances(runDir).some((entry) => entry.pid === server.child.pid));
  check('run-file-announced', announced, JSON.stringify(existsSync(runDir) ? readdirSync(runDir) : []));
  const entry = listInstances(runDir).find((candidate) => candidate.pid === server.child.pid);
  if (entry !== undefined) {
    if (process.platform !== 'win32') {
      const mode = statSync(join(runDir, `${entry.pid}.json`)).mode & 0o777;
      check('run-file-private', mode === 0o600, mode.toString(8));
    }
    const state = await callInstance(entry, 'state');
    check('control-client-info', state.instance?.client?.name === 'panel-test', JSON.stringify(state.instance));
    check('control-own-state-file', state.instance?.statePath === statePath && state.instance?.followsDsh === false, JSON.stringify(state.instance));
    check('control-hosts', state.state?.hosts?.map((host) => host.alias).join(',') === 'alpha,beta', JSON.stringify(state.state?.hosts?.map((host) => host.alias)));
    check('control-no-token-material', !JSON.stringify(state).includes(entry.token), 'token echoed');

    const noToken = await raw({ port: entry.port, path: '/state' });
    check('control-needs-token', noToken.status === 403, String(noToken.status));
    const wrongToken = await raw({ port: entry.port, path: '/state', headers: { [TOKEN_HEADER]: 'x'.repeat(48) } });
    check('control-wrong-token', wrongToken.status === 403, String(wrongToken.status));
    const rebinding = await raw({ port: entry.port, path: '/state', headers: { host: `evil.example:${entry.port}`, [TOKEN_HEADER]: entry.token } });
    check('control-rebinding', rebinding.status === 403, String(rebinding.status));
    const closed = await callInstance(entry, 'action', { action: 'close', alias: 'alpha' });
    check('control-close', closed.ok === true, JSON.stringify(closed));
    let unknown = null;
    try {
      await callInstance(entry, 'action', { action: 'close', alias: 'nope' });
    } catch (error) {
      unknown = error.message;
    }
    check('control-unknown-host', /unknown host/.test(unknown ?? ''), String(unknown));
  }
  await server.stop();
  check('run-file-removed-on-exit', !existsSync(join(runDir, `${server.child.pid}.json`)), 'still there');
}

// ── --no-control ───────────────────────────────────────────────────────────
{
  const server = startServer(['--no-control']);
  await initialize(server);
  await sleep(300);
  check('no-control', !listInstances(runDir).some((entry) => entry.pid === server.child.pid), 'announced anyway');
  await server.stop();
}

// ── Stale run files are dropped ────────────────────────────────────────────
{
  const dead = spawnSync(process.execPath, ['-e', '0']).pid;
  mkdirSync(runDir, { recursive: true });
  writeFileSync(join(runDir, `${dead}.json`), JSON.stringify({ pid: dead, port: 1, token: 't', startedAt: 0 }));
  writeFileSync(join(runDir, 'junk.json'), '{');
  check('stale-dropped', !listInstances(runDir).some((entry) => entry.pid === dead) && !existsSync(join(runDir, `${dead}.json`)), 'stale entry kept');
}

// ── Panel routes + end-to-end hide ─────────────────────────────────────────
{
  const dshState = join(dir, 'dsh-home', 'ssh-pool', 'state.json');
  const panel = createPanel({ config: { sshConfigPath: sshConfig }, statePath, runDir });
  const http = createServer((req, res) => void panel.handler(req, res));
  await new Promise((resolve) => http.listen(0, '127.0.0.1', resolve));
  const port = http.address().port;

  const page = await raw({ port, path: '/' });
  check('page-served', page.status === 200 && /SSH 助手/.test(page.text), String(page.status));
  check('page-csp', /frame-ancestors 'none'/.test(page.headers['content-security-policy'] ?? ''), String(page.headers['content-security-policy']));
  const pageRebinding = await raw({ port, path: '/', headers: { host: 'evil.example' } });
  check('page-rebinding', pageRebinding.status === 403, String(pageRebinding.status));
  const apiRebinding = await raw({ port, path: '/api/state', headers: { host: `evil.example:${port}` } });
  check('api-rebinding', apiRebinding.status === 403, String(apiRebinding.status));

  let state = await raw({ port, path: '/api/state' });
  const token = state.json?.token;
  check('state-ok', state.status === 200 && typeof token === 'string', String(state.status));
  check('state-cookie-path', /Path=\/api/.test(state.headers['set-cookie']?.[0] ?? ''), String(state.headers['set-cookie']));
  check('state-no-instances', state.json?.state?.instances?.length === 0, JSON.stringify(state.json?.state?.instances));
  check('state-panel-paths', state.json?.state?.panel?.statePath === statePath, JSON.stringify(state.json?.state?.panel));

  const noOpen = await raw({ port, path: '/api/action', method: 'POST', headers: { 'x-dsh-ssh-pool-token': token }, body: { action: 'open', alias: 'alpha' } });
  check('open-needs-a-server', noOpen.status === 400 && /no MCP server/.test(noOpen.json?.error ?? ''), JSON.stringify(noOpen.json));
  const unauthorized = await raw({ port, path: '/api/meta', method: 'POST', body: { alias: 'alpha', hidden: true } });
  check('meta-needs-token', unauthorized.status === 403, String(unauthorized.status));
  const crossSite = await raw({ port, path: '/api/state', headers: { 'sec-fetch-site': 'cross-site' } });
  check('cross-site', crossSite.status === 403, String(crossSite.status));

  const server = startServer();
  await initialize(server);
  check('e2e-alpha-visible', (await hostAliases(server)).includes('alpha'), 'alpha missing before hide');
  await waitFor(() => listInstances(runDir).some((entry) => entry.pid === server.child.pid));
  state = await raw({ port, path: '/api/state' });
  const instance = state.json?.state?.instances?.find((candidate) => candidate.pid === server.child.pid);
  check('panel-sees-server', instance?.client?.name === 'panel-test' && instance?.hostCount === 2, JSON.stringify(state.json?.state?.instances));
  const alphaRow = state.json?.state?.hosts?.find((host) => host.alias === 'alpha');
  check('panel-row-has-instance', alphaRow?.instances?.length === 1 && alphaRow.instances[0].pid === server.child.pid, JSON.stringify(alphaRow));

  const hide = await raw({ port, path: '/api/meta', method: 'POST', headers: { 'x-dsh-ssh-pool-token': token }, body: { alias: 'alpha', hidden: true, remark: 'retired' } });
  check('meta-ok', hide.status === 200 && hide.json?.ok === true, JSON.stringify(hide.json));
  const written = JSON.parse(readFileSync(statePath, 'utf8'));
  check('meta-persisted', written.hosts?.alpha?.hidden === true && written.hosts?.alpha?.remark === 'retired', JSON.stringify(written));
  const followed = await waitFor(async () => !(await hostAliases(server)).includes('alpha'), 6000);
  check('e2e-server-follows-hide', followed, 'alpha still offered');

  const settings = await raw({ port, path: '/api/settings', method: 'POST', headers: { 'x-dsh-ssh-pool-token': token }, body: { maxOutputBytes: 8192 } });
  check('settings-ok', settings.json?.state?.settings?.maxOutputBytes === 8192, JSON.stringify(settings.json?.state?.settings));

  const closeAll = await raw({ port, path: '/api/action', method: 'POST', headers: { 'x-dsh-ssh-pool-token': token }, body: { action: 'close_all' } });
  check('close-all-forwarded', closeAll.json?.result?.targets?.includes(server.child.pid), JSON.stringify(closeAll.json));
  await server.stop();

  check('panel-never-writes-dsh-state', !existsSync(dshState), 'dsh state written');
  http.close();
  panel.dispose();
}

rmSync(dir, { recursive: true, force: true });
console.log(`${pass}/${pass + failures.length} passed`);
for (const failure of failures) console.log(`FAIL ${failure}`);
process.exit(failures.length === 0 ? 0 : 2);
