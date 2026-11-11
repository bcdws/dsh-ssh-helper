/**
 * The MCP adapter, offline.
 *
 * Part 1 drives the real `bin/dsh-ssh-mcp.js` over stdio with raw JSON-RPC
 * against a temp ssh config whose only host is a TEST-NET address, so nothing
 * ever connects. Part 2 exercises the session core in-process: cancellation,
 * sampling round trips, serialization of non-concurrency-safe tools.
 */
import { spawn } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, utimesSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { createMcpSession, ERROR_META_KEY, SUPPORTED_PROTOCOL_VERSIONS } from '../mcp/server.js';
import { createSamplingBackend } from '../mcp/sampling.js';
import { createSideAnalyzer } from '../lib/analysis.js';

let pass = 0;
const failures = [];
const check = (name, ok, detail) => (ok ? (pass += 1) : failures.push(`${name}: ${detail}`));
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const here = dirname(fileURLToPath(import.meta.url));
const BIN = join(here, '..', 'bin', 'dsh-ssh-mcp.js');
const dir = mkdtempSync(join(tmpdir(), 'dsh-mcp-'));
const sshConfig = join(dir, 'ssh_config');
const statePath = join(dir, 'state.json');
writeFileSync(sshConfig, ['Host alpha', '  HostName 192.0.2.10', '  User root', 'Host beta', '  HostName 192.0.2.11', '  User root', ''].join('\n'));
writeFileSync(statePath, JSON.stringify({ hosts: { beta: { hidden: true } }, settings: {} }));

/** Spawn the server and talk newline-delimited JSON-RPC to it. */
function startServer({ args = ['--state', statePath], env = process.env } = {}) {
  const child = spawn(process.execPath, [BIN, '--ssh-config', sshConfig, ...args, '--quiet'], { stdio: ['pipe', 'pipe', 'pipe'], env });
  const waiting = new Map();
  const stray = [];
  let stderr = '';
  child.stderr.on('data', (chunk) => (stderr += chunk));
  createInterface({ input: child.stdout }).on('line', (line) => {
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      stray.push(line);
      return;
    }
    const key = message.id ?? null;
    const resolve = waiting.get(key);
    if (resolve) {
      waiting.delete(key);
      resolve(message);
    } else stray.push(message);
  });
  let nextId = 1;
  const call = (method, params) => {
    const id = nextId++;
    const reply = new Promise((resolve) => waiting.set(id, resolve));
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, ...(params === undefined ? {} : { params }) })}\n`);
    return Promise.race([reply, sleep(10_000).then(() => ({ timeout: true, method }))]);
  };
  const raw = (line, key = null) => {
    const reply = new Promise((resolve) => waiting.set(key, resolve));
    child.stdin.write(`${line}\n`);
    return Promise.race([reply, sleep(10_000).then(() => ({ timeout: true }))]);
  };
  const notify = (method, params) => child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method, ...(params === undefined ? {} : { params }) })}\n`);
  const stop = () =>
    new Promise((resolve) => {
      child.once('exit', (code) => resolve(code));
      child.stdin.end();
    });
  return { call, raw, notify, stop, stray, stderr: () => stderr };
}

const initParams = (protocolVersion) => ({ protocolVersion, capabilities: {}, clientInfo: { name: 'test-client', version: '1' } });

// ── Part 1: the real binary over stdio ─────────────────────────────────────
{
  const server = startServer();
  const init = await server.call('initialize', initParams('2025-06-18'));
  check('init-version', init.result?.protocolVersion === '2025-06-18', JSON.stringify(init));
  check('init-capabilities', init.result?.capabilities?.tools !== undefined && init.result?.serverInfo?.name === 'dsh-ssh-helper', JSON.stringify(init.result));
  check('init-instructions', /ssh_hosts/.test(init.result?.instructions ?? '') && /\[policy\]/.test(init.result?.instructions ?? ''), String(init.result?.instructions).slice(0, 120));
  server.notify('notifications/initialized');

  const list = await server.call('tools/list');
  const tools = list.result?.tools ?? [];
  const byName = new Map(tools.map((tool) => [tool.name, tool]));
  check('list-eight', tools.length === 8, tools.map((tool) => tool.name).join(','));
  check('list-input-schema', tools.every((tool) => tool.inputSchema?.type === 'object'), 'every inputSchema must be an object schema');
  check('list-output-schema', tools.every((tool) => tool.outputSchema?.type === 'object'), 'every tool has an outputSchema on 2025-06-18');
  check('annotation-readonly', byName.get('ssh_read')?.annotations?.readOnlyHint === true && byName.get('ssh_hosts')?.annotations?.readOnlyHint === true, JSON.stringify(byName.get('ssh_read')?.annotations));
  check('annotation-destructive', byName.get('ssh_run')?.annotations?.destructiveHint === true && byName.get('ssh_write')?.annotations?.destructiveHint === true, JSON.stringify(byName.get('ssh_run')?.annotations));
  check('required-host-command', JSON.stringify(byName.get('ssh_run')?.inputSchema?.required) === '["host","command"]', JSON.stringify(byName.get('ssh_run')?.inputSchema?.required));

  const hosts = await server.call('tools/call', { name: 'ssh_hosts', arguments: {} });
  const aliases = hosts.result?.structuredContent?.hosts?.map((host) => host.alias) ?? [];
  check('hosts-structured', hosts.result?.isError === false && aliases.join(',') === 'alpha', JSON.stringify(aliases));
  check('hosts-text', /alpha → root@192\.0\.2\.10:22/.test(hosts.result?.content?.[0]?.text ?? ''), hosts.result?.content?.[0]?.text);
  check('hidden-host-hidden', !(hosts.result?.content?.[0]?.text ?? '').includes('beta'), 'a host hidden in the panel must not be listed');

  const denied = await server.call('tools/call', { name: 'ssh_run', arguments: { host: 'alpha', command: 'rm -rf /' } });
  const meta = denied.result?._meta?.[ERROR_META_KEY];
  check('deny-is-error', denied.result?.isError === true && denied.result?.structuredContent === undefined, JSON.stringify(denied.result));
  check('deny-meta', meta?.code === 'POLICY_DENY' && meta?.rule === 'danger.rm-root' && meta?.host === 'alpha' && meta?.target === 'command', JSON.stringify(meta));
  check('deny-text', /\[ssh-pool policy\]/.test(denied.result?.content?.[0]?.text ?? ''), denied.result?.content?.[0]?.text);

  const hiddenRun = await server.call('tools/call', { name: 'ssh_run', arguments: { host: 'beta', command: 'uptime' } });
  check('hidden-host-unreachable', hiddenRun.result?.isError === true && /unknown ssh host "beta"/.test(hiddenRun.result?.content?.[0]?.text ?? ''), JSON.stringify(hiddenRun.result));

  const writeDenied = await server.call('tools/call', { name: 'ssh_write', arguments: { host: 'alpha', path: '/dev/sda', content: 'x' } });
  check('write-deny-meta', writeDenied.result?._meta?.[ERROR_META_KEY]?.target === 'path', JSON.stringify(writeDenied.result?._meta));

  const unknownTool = await server.call('tools/call', { name: 'nope', arguments: {} });
  check('unknown-tool', unknownTool.error?.code === -32602, JSON.stringify(unknownTool));
  const badArgs = await server.call('tools/call', { name: 'ssh_hosts', arguments: [1] });
  check('bad-arguments', badArgs.error?.code === -32602, JSON.stringify(badArgs));
  const unknownMethod = await server.call('resources/list');
  check('unknown-method', unknownMethod.error?.code === -32601, JSON.stringify(unknownMethod));
  const ping = await server.call('ping');
  check('ping', ping.result !== undefined && Object.keys(ping.result).length === 0, JSON.stringify(ping));
  const parse = await server.raw('{not json');
  check('parse-error', parse.error?.code === -32700 && parse.id === null, JSON.stringify(parse));

  // The panel un-hides beta while the server runs: the view follows the file.
  writeFileSync(statePath, JSON.stringify({ hosts: { beta: { hidden: false } }, settings: {} }));
  const later = new Date(Date.now() + 5000);
  utimesSync(statePath, later, later);
  await sleep(1100);
  const relisted = await server.call('tools/call', { name: 'ssh_hosts', arguments: {} });
  check('state-followed', (relisted.result?.structuredContent?.hosts ?? []).map((host) => host.alias).join(',') === 'alpha,beta', JSON.stringify(relisted.result?.structuredContent?.hosts?.map((host) => host.alias)));

  // A host added to ~/.ssh/config appears without a restart.
  writeFileSync(sshConfig, ['Host alpha', '  HostName 192.0.2.10', '  User root', 'Host beta', '  HostName 192.0.2.11', '  User root', 'Host gamma', '  HostName 192.0.2.12', '  User root', ''].join('\n'));
  const laterStill = new Date(Date.now() + 10000);
  utimesSync(sshConfig, laterStill, laterStill);
  const refreshed = await server.call('tools/call', { name: 'ssh_hosts', arguments: {} });
  check('ssh-config-followed', (refreshed.result?.structuredContent?.hosts ?? []).some((host) => host.alias === 'gamma'), JSON.stringify(refreshed.result?.structuredContent?.hosts?.map((host) => host.alias)));

  check('stdout-protocol-only', server.stray.length === 0, JSON.stringify(server.stray).slice(0, 200));
  const code = await server.stop();
  check('exit-on-stdin-close', code === 0, `exit ${code}; stderr ${server.stderr().slice(0, 200)}`);
}

// Older protocol: no annotations / outputSchema / structuredContent.
{
  const server = startServer();
  const init = await server.call('initialize', initParams('2024-11-05'));
  check('old-version-kept', init.result?.protocolVersion === '2024-11-05', JSON.stringify(init.result?.protocolVersion));
  const list = await server.call('tools/list');
  check('old-no-output-schema', (list.result?.tools ?? []).every((tool) => tool.outputSchema === undefined && tool.annotations === undefined), 'old clients must not receive newer fields');
  const hosts = await server.call('tools/call', { name: 'ssh_hosts', arguments: {} });
  check('old-no-structured', hosts.result?.structuredContent === undefined && typeof hosts.result?.content?.[0]?.text === 'string', JSON.stringify(hosts.result).slice(0, 200));
  await server.stop();
}
{
  const server = startServer();
  const init = await server.call('initialize', initParams('1999-01-01'));
  check('unknown-version-latest', init.result?.protocolVersion === SUPPORTED_PROTOCOL_VERSIONS[0], JSON.stringify(init.result?.protocolVersion));
  await server.stop();
}

// Independent of DSH by default: without --state, a host hidden in the DSH
// panel state (under $DSH_HOME) stays visible to MCP agents.
{
  const dshHome = join(dir, 'dsh-home');
  mkdirSync(join(dshHome, 'ssh-pool'), { recursive: true });
  writeFileSync(join(dshHome, 'ssh-pool', 'state.json'), JSON.stringify({ hosts: { alpha: { hidden: true } }, settings: {} }));
  const server = startServer({ args: [], env: { ...process.env, DSH_HOME: dshHome } });
  await server.call('initialize', initParams('2025-06-18'));
  const hosts = await server.call('tools/call', { name: 'ssh_hosts', arguments: {} });
  check('standalone-ignores-dsh-state', (hosts.result?.structuredContent?.hosts ?? []).some((host) => host.alias === 'alpha'), JSON.stringify(hosts.result?.structuredContent?.hosts?.map((host) => host.alias)));
  await server.stop();
}

// ── Part 2: the session core in-process ────────────────────────────────────
const output = { type: 'object', properties: { ok: { type: 'boolean' } }, required: ['ok'], additionalProperties: false };
/** A session whose outgoing messages land in `sent`. */
function makeSession(tools, capabilities = {}) {
  const sent = [];
  const session = createMcpSession({ tools, send: (message) => sent.push(message), serverInfo: { name: 't', version: '0' } });
  return { session, sent, init: () => session.receive({ jsonrpc: '2.0', id: 0, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities, clientInfo: { name: 'unit' } } }) };
}

// Cancellation aborts the running call's signal and suppresses its response.
{
  let seenSignal;
  let seenCaller;
  const slow = {
    name: 'slow',
    description: 'waits for abort',
    parameters: { type: 'object', properties: {} },
    output: { schema: output, render: () => [{ type: 'text', text: 'done' }] },
    execute: (_args, call) =>
      new Promise((resolve, reject) => {
        seenSignal = call.signal;
        seenCaller = call.callerId;
        call.signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
      })
  };
  const { session, sent, init } = makeSession([slow]);
  await init();
  const running = session.receive({ jsonrpc: '2.0', id: 7, method: 'tools/call', params: { name: 'slow', arguments: {} } });
  await sleep(0);
  check('caller-from-client', seenCaller === 'mcp:unit', String(seenCaller));
  await session.receive({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: 7 } });
  await running;
  check('cancel-aborts', seenSignal?.aborted === true, 'signal not aborted');
  check('cancel-no-response', !sent.some((message) => message.id === 7), JSON.stringify(sent.filter((message) => message.id === 7)));
}

// Non-concurrency-safe tools run one at a time; safe ones do not wait.
{
  const order = [];
  const gate = {};
  const make = (name, safe) => ({
    name,
    description: name,
    parameters: { type: 'object', properties: {} },
    isConcurrencySafe: () => safe,
    output: { schema: output, render: () => [{ type: 'text', text: name }] },
    execute: async (args) => {
      order.push(`start:${args.tag}`);
      await new Promise((resolve) => (gate[args.tag] = resolve));
      order.push(`end:${args.tag}`);
      return { ok: true };
    }
  });
  const { session, init } = makeSession([make('write', false), make('read', true)]);
  await init();
  const first = session.receive({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'write', arguments: { tag: 'w1' } } });
  const second = session.receive({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'write', arguments: { tag: 'w2' } } });
  const third = session.receive({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'read', arguments: { tag: 'r' } } });
  await sleep(5);
  check('unsafe-serialized', order.includes('start:w1') && !order.includes('start:w2'), order.join(','));
  check('safe-not-blocked', order.includes('start:r'), order.join(','));
  gate.w1();
  await sleep(5);
  check('unsafe-next-runs', order.includes('start:w2'), order.join(','));
  gate.w2();
  gate.r();
  await Promise.all([first, second, third]);
}

// Sampling: the analyzer round-trips through the client.
{
  const { session, sent, init } = makeSession([], { sampling: {} });
  await init();
  const analyzer = createSideAnalyzer({ backend: createSamplingBackend(session) });
  check('sampling-available', analyzer.status().available === true, JSON.stringify(analyzer.status()));
  const running = analyzer.run({ tool: 'ssh_read', target: '/var/log/syslog', text: 'ERROR token=abcdef0123456789abcdef', bytes: 30, sessionId: 'mcp:unit' });
  await sleep(0);
  const requestMessage = sent.find((message) => message.method === 'sampling/createMessage');
  check('sampling-request', requestMessage !== undefined && requestMessage.params?.includeContext === 'none' && requestMessage.params?.tools === undefined && typeof requestMessage.params?.systemPrompt === 'string', JSON.stringify(requestMessage?.params ?? null).slice(0, 200));
  await session.receive({ jsonrpc: '2.0', id: requestMessage.id, result: { role: 'assistant', content: { type: 'text', text: '连接超时 3 次' }, model: 'client-model', stopReason: 'endTurn' } });
  const result = await running;
  check('sampling-summary', result.summary === '连接超时 3 次' && result.model === 'mcp/client-model', JSON.stringify(result));

  const failing = analyzer.run({ tool: 'ssh_read', target: 'x', text: 'x', bytes: 1 });
  await sleep(0);
  const second = sent.filter((message) => message.method === 'sampling/createMessage').at(-1);
  await session.receive({ jsonrpc: '2.0', id: second.id, error: { code: -1, message: 'User rejected sampling request' } });
  check('sampling-rejected', /User rejected/.test((await failing).error ?? ''), 'a rejected sampling request must surface');

  const without = makeSession([]);
  await without.init();
  const none = createSideAnalyzer({ backend: createSamplingBackend(without.session) });
  check('no-sampling-unavailable', none.status().available === false && /sampling/.test(none.status().reason), JSON.stringify(none.status()));

  const pendingAtClose = session.request('sampling/createMessage', {});
  session.close();
  check('close-rejects-pending', await pendingAtClose.then(() => false, (error) => /closed/.test(error.message)), 'pending request survived close');

  // Packaging: `npx -y github:…` must install with zero dependencies and no
  // lifecycle scripts. Desktop MCP clients stop waiting for `initialize` after
  // a few tens of seconds (about 30 s for a command server), and ssh2's
  // `node-gyp` postinstall either blows that budget or fails outright when the
  // client spawns npx with a PATH that has no `node`. ssh2 therefore ships
  // pre-bundled in vendor/ — putting it back in `dependencies` brings both
  // problems back.
  const root = join(here, '..');
  const manifest = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
  check('packaging-no-runtime-deps', Object.keys(manifest.dependencies ?? {}).length === 0, `dependencies: ${JSON.stringify(manifest.dependencies ?? {})}`);
  const vendored = createRequire(import.meta.url)(join(root, 'vendor', 'ssh2.cjs'));
  check('packaging-vendored-ssh2', typeof vendored.Client === 'function' && typeof vendored.utils?.parseKey === 'function', 'vendor/ssh2.cjs must export ssh2 (npm run build:vendor)');
  check('packaging-vendor-shipped', (manifest.files ?? []).some((entry) => entry.startsWith('vendor/')), 'package.json files must ship vendor/');
}

rmSync(dir, { recursive: true, force: true });
console.log(`${pass}/${pass + failures.length} passed`);
for (const failure of failures) console.log(`FAIL ${failure}`);
process.exit(failures.length === 0 ? 0 : 2);
