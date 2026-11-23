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
import { createMcpSession, ERROR_META_KEY, SUPPORTED_PROTOCOL_VERSIONS, toMcpResult, toMcpTool } from '../mcp/server.js';
import { createSamplingBackend } from '../mcp/sampling.js';
import { createStandaloneRuntime, defaultCallCapFor, SHORT_CLIENT_CALL_CAP_MS } from '../mcp/runtime.js';
import { createSideAnalyzer } from '../lib/analysis.js';
import { createStateView } from '../mcp/state-view.js';
import { createTools } from '../lib/tools.js';

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
// Keep the server's own state file and run dir out of the real home.
process.env.DSH_SSH_MCP_HOME = join(dir, 'mcp-home');

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
  check('list-three', tools.map((tool) => tool.name).join(',') === 'ssh_hosts,ssh_run,ssh_transfer', tools.map((tool) => tool.name).join(','));
  check('list-input-schema', tools.every((tool) => tool.inputSchema?.type === 'object'), 'every inputSchema must be an object schema');
  check('list-output-schema', tools.every((tool) => tool.outputSchema?.type === 'object'), 'every tool has an outputSchema on 2025-06-18');
  check('annotation-readonly', byName.get('ssh_hosts')?.annotations?.readOnlyHint === true, JSON.stringify(byName.get('ssh_hosts')?.annotations));
  check('annotation-destructive', byName.get('ssh_run')?.annotations?.destructiveHint === true && byName.get('ssh_transfer')?.annotations?.destructiveHint === true, JSON.stringify(byName.get('ssh_run')?.annotations));
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

  const writeDenied = await server.call('tools/call', { name: 'ssh_transfer', arguments: { host: 'alpha', direction: 'upload', localPath: '/tmp/x', remotePath: '/dev/sda' } });
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
function makeSession(tools, capabilities = {}, options = {}) {
  const sent = [];
  const session = createMcpSession({ tools, send: (message) => sent.push(message), serverInfo: { name: 't', version: '0' }, ...options });
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

// A long call with a progressToken gets heartbeats (so a client may reset its
// timeout); they stop when the call ends, and never name the host.
{
  let release;
  const slow = {
    name: 'slow',
    description: 'waits for release',
    parameters: { type: 'object', properties: {} },
    output: { schema: output, render: () => [{ type: 'text', text: 'done' }] },
    execute: () => new Promise((resolve) => (release = () => resolve({ ok: true })))
  };
  const { session, sent, init } = makeSession([slow], {}, { progressIntervalMs: 20 });
  await init();
  const running = session.receive({ jsonrpc: '2.0', id: 11, method: 'tools/call', params: { name: 'slow', arguments: { host: 'secret-db' }, _meta: { progressToken: 'tok-1' } } });
  await sleep(90);
  const beats = sent.filter((message) => message.method === 'notifications/progress');
  check('progress-sent', beats.length >= 2 && beats.every((message) => message.params.progressToken === 'tok-1'), JSON.stringify(beats));
  check('progress-increasing', beats.every((message, index) => index === 0 || message.params.progress > beats[index - 1].params.progress), JSON.stringify(beats.map((message) => message.params.progress)));
  check('progress-no-host', beats.every((message) => !message.params.message.includes('secret-db') && message.params.message.startsWith('slow: still running')), JSON.stringify(beats[0]));
  release();
  await running;
  const count = sent.filter((message) => message.method === 'notifications/progress').length;
  await sleep(60);
  check('progress-stops', sent.filter((message) => message.method === 'notifications/progress').length === count, 'heartbeat kept running after the result');
  check('progress-result', sent.some((message) => message.id === 11 && message.result?.isError === false), JSON.stringify(sent.filter((message) => message.id === 11)));

  // No token, no heartbeat.
  const quiet = makeSession([slow], {}, { progressIntervalMs: 20 });
  await quiet.init();
  const plain = quiet.session.receive({ jsonrpc: '2.0', id: 12, method: 'tools/call', params: { name: 'slow', arguments: {} } });
  await sleep(70);
  check('progress-only-with-token', !quiet.sent.some((message) => message.method === 'notifications/progress'), JSON.stringify(quiet.sent));
  release();
  await plain;
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

// Non-concurrency-safe calls queue per target file: another file (or host)
// does not wait, the same file (spelled differently) does.
{
  const order = [];
  const gate = {};
  const write = {
    name: 'write',
    description: 'write',
    parameters: { type: 'object', properties: {} },
    isConcurrencySafe: () => false,
    output: { schema: output, render: () => [{ type: 'text', text: 'w' }] },
    execute: async (args) => {
      order.push(`start:${args.tag}`);
      await new Promise((resolve) => (gate[args.tag] = resolve));
      return { ok: true };
    }
  };
  const { session, init } = makeSession([write]);
  await init();
  const call = (id, host, path, tag) => session.receive({ jsonrpc: '2.0', id, method: 'tools/call', params: { name: 'write', arguments: { host, path, tag } } });
  const calls = [call(1, 'alpha', '/etc/app.conf', 'a1'), call(2, 'alpha', '/etc/./app.conf', 'a2'), call(3, 'alpha', '/etc/other.conf', 'b'), call(4, 'beta', '/etc/app.conf', 'c')];
  await sleep(5);
  check('exclusive-other-files-run', ['start:a1', 'start:b', 'start:c'].every((step) => order.includes(step)), order.join(','));
  check('exclusive-same-file-waits', !order.includes('start:a2'), order.join(','));
  gate.a1();
  await sleep(5);
  check('exclusive-same-file-next', order.includes('start:a2'), order.join(','));
  gate.a2();
  gate.b();
  gate.c();
  await Promise.all(calls);
}

// Progress messages quote the latest output line: redacted, without escape
// codes, a `\r` progress bar at its current state.
{
  let release;
  let feed;
  const streaming = {
    name: 'stream',
    description: 'streams output',
    parameters: { type: 'object', properties: {} },
    output: { schema: output, render: () => [{ type: 'text', text: 'done' }] },
    execute: (_args, call) =>
      new Promise((resolve) => {
        feed = call.onOutput;
        release = () => resolve({ ok: true });
      })
  };
  const { session, sent, init } = makeSession([streaming], {}, { progressIntervalMs: 20 });
  await init();
  const running = session.receive({ jsonrpc: '2.0', id: 21, method: 'tools/call', params: { name: 'stream', arguments: {}, _meta: { progressToken: 'tok-2' } } });
  await sleep(0);
  check('progress-feed-given', typeof feed === 'function', 'a call with a progressToken must get onOutput');
  feed('stdout', 'step 1\nusing token=abcdef123456 now\n');
  await sleep(40);
  const quoted = sent.filter((message) => message.method === 'notifications/progress').at(-1)?.params.message ?? '';
  check('progress-quotes-line', quoted.startsWith('stream: still running') && quoted.includes(' · using token=<redacted:token> now'), quoted);
  feed('stdout', '\x1b[32mdownload\x1b[0m 10%\r50%\r75%');
  await sleep(40);
  const bar = sent.filter((message) => message.method === 'notifications/progress').at(-1)?.params.message ?? '';
  check('progress-bar-state', bar.endsWith(' · 75%'), bar);
  feed('stderr', `${'x'.repeat(400)}\n`);
  await sleep(40);
  const long = sent.filter((message) => message.method === 'notifications/progress').at(-1)?.params.message ?? '';
  check('progress-line-clipped', long.length < 220 && long.endsWith('…'), String(long.length));
  release();
  await running;

  // Without a progressToken there is nothing to report to: no listener.
  let plainFeed = 'unset';
  const plain = makeSession([{ ...streaming, execute: async (_args, call) => ((plainFeed = call.onOutput), { ok: true }) }]);
  await plain.init();
  await plain.session.receive({ jsonrpc: '2.0', id: 22, method: 'tools/call', params: { name: 'stream', arguments: {} } });
  check('progress-no-token-no-feed', plainFeed === undefined, String(plainFeed));
}

/** The structural part of JSON Schema the lean output must satisfy. */
function violations(schema, value, at = '$') {
  if (schema === undefined || schema === null) return [];
  const typeOk = (node, candidate) => {
    if (node.type === undefined) return true;
    if (node.type === 'null') return candidate === null;
    if (node.type === 'object') return candidate !== null && typeof candidate === 'object' && !Array.isArray(candidate);
    if (node.type === 'array') return Array.isArray(candidate);
    if (node.type === 'number' || node.type === 'integer') return typeof candidate === 'number';
    return typeof candidate === node.type;
  };
  if (Array.isArray(schema.oneOf)) {
    const branch = schema.oneOf.find((node) => typeOk(node, value));
    return branch === undefined ? [`${at}: no oneOf branch fits`] : violations(branch, value, at);
  }
  if (!typeOk(schema, value)) return [`${at}: expected ${schema.type}`];
  const found = [];
  if (schema.type === 'object') {
    for (const key of schema.required ?? []) if (!(key in value)) found.push(`${at}.${key}: required`);
    for (const [key, child] of Object.entries(value)) {
      const sub = schema.properties?.[key];
      if (sub === undefined) {
        if (schema.additionalProperties === false) found.push(`${at}.${key}: not allowed`);
      } else found.push(...violations(sub, child, `${at}.${key}`));
    }
  }
  if (schema.type === 'array' && schema.items !== undefined) value.forEach((entry, index) => found.push(...violations(schema.items, entry, `${at}[${index}]`)));
  return found;
}

/** A pool double: one host, never connects. */
const stubPool = (status = []) => ({
  aliases: ['h1'],
  warnings: [],
  has: (alias) => alias === 'h1',
  hostVisible: () => true,
  outputLimit: () => 16000,
  connection: () => ({ connected: false, ensure: async () => {}, session: () => ({ run: async () => ({}) }), exec: async () => ({}) }),
  status: () => status,
  connections: () => []
});

// structuredContent is lean (no null/false fields, no deadline arithmetic
// unless the deadline was hit) and still matches the advertised outputSchema.
{
  const idleHost = { alias: 'h1', host: '192.0.2.10', port: 22, user: 'root', keyName: null, source: 'ssh-config', state: 'idle', connected: false, connectedSeconds: 0, idleSeconds: null, connects: 0, reconnects: 0, failures: 0, handshakeTimeouts: 0, retryPaused: false, commands: 0, lastCommand: null, lastCommandAgeSeconds: null, lastCommandSeconds: null, callFailures: 0, lastFailure: null, sessions: [], hostKey: null, lastError: null, hidden: false, remark: '', idleTimeoutMs: null, effectiveIdleTimeoutMs: 0 };
  const tools = new Map(createTools(stubPool([idleHost]), { defaultTimeoutMs: 60000 }, {}).map((tool) => [tool.name, tool]));
  const run = tools.get('ssh_run');
  const runSchema = toMcpTool(run).outputSchema;
  check('lean-schema-relaxed', ['timedOut', 'aborted', 'sessionEnded', 'handshakeMs', 'reused', 'stderr', 'analysis', 'analysisError'].every((key) => !runSchema.required.includes(key)) && ['host', 'mode', 'stdout'].every((key) => runSchema.required.includes(key)), JSON.stringify(runSchema.required));
  check('lean-schema-nested', JSON.stringify(runSchema.properties.stdout.required) === '["text"]', JSON.stringify(runSchema.properties.stdout));
  check('lean-schema-original-kept', run.output.schema.required.includes('timedOut'), 'the shared tool schema must stay as it is (DSH uses it)');
  const base = { host: 'h1', mode: 'exec', session: null, exitCode: 0, signal: null, timedOut: false, aborted: false, detached: false, sessionEnded: false, endReason: null, timeoutMs: 15000, estimateMs: 5000, multiplier: 3, deadlineSource: 'inferred', stdout: { text: 'ok\n', truncated: false }, stderr: { text: '', truncated: false }, cwd: null, durationMs: 12, handshakeMs: 0, reused: true, pid: null, logPath: null, scriptPath: null, hint: null, analysis: null, analysisError: null };
  const ok = toMcpResult(run, { host: 'h1', command: 'true' }, base).structuredContent;
  check('lean-run-value', JSON.stringify(ok) === '{"host":"h1","mode":"exec","exitCode":0,"timeoutMs":15000,"stdout":{"text":"ok\\n"},"durationMs":12}', JSON.stringify(ok));
  check('lean-run-conforms', violations(runSchema, ok).length === 0, violations(runSchema, ok).join('; '));
  const hit = toMcpResult(run, { host: 'h1', command: 'sleep 99' }, { ...base, timedOut: true, exitCode: null, stderr: { text: 'boom', truncated: false } }).structuredContent;
  check('lean-run-timeout-keeps-deadline', hit.timedOut === true && hit.estimateMs === 5000 && hit.multiplier === 3 && hit.stderr?.text === 'boom' && !('exitCode' in hit), JSON.stringify(hit));
  check('lean-run-timeout-conforms', violations(runSchema, hit).length === 0, violations(runSchema, hit).join('; '));
  check('lean-text-unchanged', toMcpResult(run, { host: 'h1', command: 'true' }, base).content[0].text === 'ok\n', 'the text content must not change');

  const hosts = tools.get('ssh_hosts');
  const listed = await hosts.execute({}, { callerId: 'mcp:t' });
  const lean = toMcpResult(hosts, {}, listed).structuredContent;
  check('lean-hosts-entry', JSON.stringify(lean.hosts[0]) === '{"alias":"h1","host":"192.0.2.10","port":22,"user":"root","source":"ssh-config","state":"idle"}', JSON.stringify(lean.hosts[0]));
  check('lean-hosts-conforms', violations(toMcpTool(hosts).outputSchema, lean).length === 0, violations(toMcpTool(hosts).outputSchema, lean).join('; '));
  const busy = { ...idleHost, state: 'connected', connected: true, connects: 2, commands: 5, remark: '主库' };
  const busyLean = toMcpResult(hosts, {}, { ...listed, hosts: [busy] }).structuredContent.hosts[0];
  check('lean-hosts-keeps-facts', busyLean.connected === true && busyLean.connects === 2 && busyLean.commands === 5 && busyLean.remark === '主库' && !('reconnects' in busyLean), JSON.stringify(busyLean));
}

// The full [policy] text comes once per caller, and again after a refusal;
// without the option (DSH) every ssh_hosts result carries it.
{
  const oneHost = [{ alias: 'h1', host: '192.0.2.10', port: 22, user: 'root', state: 'idle', connected: false, connects: 0, idleSeconds: null }];
  const tools = new Map(createTools(stubPool(oneHost), { defaultTimeoutMs: 60000 }, { policyOncePerCaller: true }).map((tool) => [tool.name, tool]));
  const hosts = tools.get('ssh_hosts');
  const hint = async (callerId) => (await hosts.execute({}, { callerId })).policyHint;
  const first = await hint('mcp:a');
  const second = await hint('mcp:a');
  check('policy-first-full', first.length > 100 && /唯一门禁/.test(first), first.slice(0, 60));
  check('policy-repeat-brief', second.startsWith('unchanged;') && second.length < first.length, second);
  check('policy-repeat-marker', /\[policy\] unchanged/.test(hosts.output.render({}, await hosts.execute({}, { callerId: 'mcp:a' }))[0].text), 'the [policy] marker must stay');
  check('policy-other-caller-full', (await hint('mcp:b')) === first, 'each caller gets the full text once');
  const refused = await tools.get('ssh_run').execute({ host: 'h1', command: 'rm -rf /etc' }, { callerId: 'mcp:a' }).then(() => null, (error) => error);
  check('policy-refused', refused?.failureCode === 'policy_denied', String(refused?.message));
  check('policy-full-after-refusal', (await hint('mcp:a')) === first, 'a refusal must bring the full text back');
  check('policy-brief-again', (await hint('mcp:a')).startsWith('unchanged;'), 'then brief again');

  const dshTools = new Map(createTools(stubPool(), { defaultTimeoutMs: 60000 }, {}).map((tool) => [tool.name, tool]));
  const dshHint = async () => (await dshTools.get('ssh_hosts').execute({}, { callerId: 'agent-1' })).policyHint;
  check('policy-dsh-always-full', (await dshHint()) === first && (await dshHint()) === first, 'DSH keeps the full text on every call');
}

// ssh_run hands the call's onOutput to the pool, stateless and in a session.
{
  const seen = [];
  const result = { stdout: 'x', stderr: '', exitCode: 0, timedOut: false };
  const pool = {
    ...stubPool(),
    connection: () => ({
      connected: true,
      ensure: async () => {},
      exec: async (_command, options) => (seen.push(options.onOutput), result),
      session: () => ({ run: async (_command, options) => (seen.push(options.onOutput), result) })
    })
  };
  const run = createTools(pool, { defaultTimeoutMs: 60000 }, {}).find((tool) => tool.name === 'ssh_run');
  const listener = () => {};
  await run.execute({ host: 'h1', command: 'make' }, { callerId: 'mcp:x', onOutput: listener });
  await run.execute({ host: 'h1', command: 'make', session: true }, { callerId: 'mcp:x', onOutput: listener });
  check('run-passes-on-output', seen.length === 2 && seen.every((entry) => entry === listener), String(seen.length));
}

// The per-call cap defaults by client: ~60 s clients get one, others do not,
// and an explicit maxCallMs (0 included) always wins.
{
  check('cap-codex', defaultCallCapFor({ name: 'codex-mcp-client' }) === SHORT_CLIENT_CALL_CAP_MS, String(defaultCallCapFor({ name: 'codex-mcp-client' })));
  check('cap-claude-desktop', defaultCallCapFor({ name: 'claude-ai' }) === SHORT_CLIENT_CALL_CAP_MS, String(defaultCallCapFor({ name: 'claude-ai' })));
  check('cap-cursor', defaultCallCapFor({ name: 'cursor-vscode' }) === SHORT_CLIENT_CALL_CAP_MS, String(defaultCallCapFor({ name: 'cursor-vscode' })));
  check('cap-claude-code', defaultCallCapFor({ name: 'claude-code' }) === 0 && defaultCallCapFor(null) === 0, String(defaultCallCapFor({ name: 'claude-code' })));
  const quietLogger = { info: () => {}, warn: () => {} };
  const capAfterInit = async (config, name) => {
    const runtime = createStandaloneRuntime({ config: { sshConfigPath: sshConfig, ...config }, logger: quietLogger });
    const session = runtime.createSession(() => {});
    await session.receive({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name } } });
    const cap = runtime.config.maxCallMs;
    runtime.dispose();
    return cap;
  };
  check('cap-runtime-default', (await capAfterInit({}, 'codex-mcp-client')) === SHORT_CLIENT_CALL_CAP_MS, 'codex must get the default cap');
  check('cap-runtime-off', (await capAfterInit({}, 'claude-code')) === 0, 'claude-code must stay uncapped');
  check('cap-explicit-zero-wins', (await capAfterInit({ maxCallMs: 0 }, 'codex-mcp-client')) === 0, 'an explicit 0 must win');
  check('cap-explicit-wins', (await capAfterInit({ maxCallMs: 20000 }, 'codex-mcp-client')) === 20000, 'an explicit value must win');
}

// Sampling: the analyzer round-trips through the client.
{
  const { session, sent, init } = makeSession([], { sampling: {} });
  await init();
  const analyzer = createSideAnalyzer({ backend: createSamplingBackend(session) });
  check('sampling-available', analyzer.status().available === true, JSON.stringify(analyzer.status()));
  const running = analyzer.run({ tool: 'ssh_run', target: 'tail -n 50 /var/log/syslog', text: 'ERROR token=abcdef0123456789abcdef', bytes: 30, sessionId: 'mcp:unit' });
  await sleep(0);
  const requestMessage = sent.find((message) => message.method === 'sampling/createMessage');
  check('sampling-request', requestMessage !== undefined && requestMessage.params?.includeContext === 'none' && requestMessage.params?.tools === undefined && typeof requestMessage.params?.systemPrompt === 'string', JSON.stringify(requestMessage?.params ?? null).slice(0, 200));
  await session.receive({ jsonrpc: '2.0', id: requestMessage.id, result: { role: 'assistant', content: { type: 'text', text: '连接超时 3 次' }, model: 'client-model', stopReason: 'endTurn' } });
  const result = await running;
  check('sampling-summary', result.summary === '连接超时 3 次' && result.model === 'mcp/client-model', JSON.stringify(result));

  const failing = analyzer.run({ tool: 'ssh_run', target: 'x', text: 'x', bytes: 1 });
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

// The read-only state view follows the panel's card order like the rest of the file.
{
  const viewFile = join(dir, 'order-view.json');
  writeFileSync(viewFile, JSON.stringify({ hosts: {}, order: ['b', 'a'] }), 'utf8');
  const view = createStateView({ filePath: viewFile, minIntervalMs: 0 });
  check('view-order', view.hostOrder().join() === 'b,a', view.hostOrder().join());
  writeFileSync(viewFile, JSON.stringify({ hosts: {}, order: ['a', 'b'] }), 'utf8');
  utimesSync(viewFile, new Date(), new Date(Date.now() + 5000));
  check('view-order-follows', view.refresh() === true && view.hostOrder().join() === 'a,b', view.hostOrder().join());
}

rmSync(dir, { recursive: true, force: true });
console.log(`${pass}/${pass + failures.length} passed`);
for (const failure of failures) console.log(`FAIL ${failure}`);
process.exit(failures.length === 0 ? 0 : 2);
