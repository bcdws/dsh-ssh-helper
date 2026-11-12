/**
 * The shared panel UI: `ui/panel-view.js` (pure HTML renderers) and
 * `<ssh-helper-panel>` (`ui/panel-element.js`), plus the thin DSH host in
 * `client.js`.
 *
 * Both surfaces — the DSH sidebar and the MCP management page — render from
 * these same functions, so this suite is what keeps the two from drifting:
 * every tab, host card, control, prod badge and dictionary key is checked
 * here. No browser: the element is imported with a two-line DOM stand-in and
 * only its non-DOM logic (fetch, credential retry, attributes) is exercised.
 */
import { readFileSync } from 'node:fs';
import {
  TEXT,
  age,
  diagnosticsCounters,
  esc,
  hostState,
  renderBanners,
  renderDiagnostics,
  renderHostCard,
  renderEditDialog,
  renderFooter,
  renderHeader,
  renderHosts,
  renderProcesses,
  renderSettings,
  renderTab,
  renderTabs,
  tabsFor
} from '../ui/panel-view.js';

let pass = 0;
const failures = [];
const check = (name, ok, detail) => (ok ? (pass += 1) : failures.push(`${name}: ${detail}`));
const count = (html, needle) => html.split(needle).length - 1;

const web = {
  alias: 'web', host: '192.0.2.10', port: 22, user: 'root', keyName: 'id_web', source: 'ssh-config',
  state: 'ready', connected: true, connectedSeconds: 3660, idleSeconds: 5, connects: 3, reconnects: 1,
  failures: 0, handshakeTimeouts: 0, sessions: [{ name: 'main', ownerShort: 'dsh', commands: 3, idleSeconds: 20 }],
  commands: 3, prod: true, hidden: false, remark: '生产 Web', idleTimeoutMs: null, effectiveIdleTimeoutMs: 30000,
  hostKey: { status: 'trusted', type: 'ssh-ed25519' }, lastCommand: 'uptime', lastCommandAgeSeconds: 5,
  callFailures: 0, lastFailure: null, instances: [{ pid: 111, state: 'ready', connected: true }]
};
const db = {
  alias: 'db', host: '192.0.2.11', port: 2222, user: 'deploy', keyName: null, source: 'config',
  state: 'idle', connected: false, connectedSeconds: 0, idleSeconds: null, connects: 0, reconnects: 0,
  failures: 1, handshakeTimeouts: 0, sessions: [], commands: 0, retryPaused: true, prod: false, hidden: true,
  remark: '<b>', idleTimeoutMs: 60000, effectiveIdleTimeoutMs: 60000, lastError: 'ssh host "db" failed: timeout',
  lastFailure: { tool: 'ssh_run', code: 'connect_timeout', message: 'handshake timed out', ageSeconds: 12 },
  callFailures: 2, lastCommand: null, lastCommandAgeSeconds: null, instances: []
};
const settings = { idleTimeoutMs: 0, sshVisible: true, maxOutputBytes: 32768, transferTimeoutMs: 600000, logAnalysis: false };
const dsh = {
  hosts: [web, db],
  settings,
  totals: { hosts: 2, connected: 1, sessions: 1, commands: 5 },
  diagnostics: {
    counters: { toolCalls: 7, failures: 2, policyDenials: 1, timeouts: 0, slowCalls: 1 },
    events: [
      { tool: 'ssh_run', host: 'web', commandKind: 'read', outcome: 'ok', durationMs: 120, at: Date.now() - 5000 },
      { tool: 'ssh_run', host: 'db', commandKind: 'write', outcome: 'error', reason: 'connect_timeout', durationMs: 30000, at: Date.now() - 60000 }
    ]
  },
  panel: { statePath: '/home/u/.dsh-ssh-mcp/state.json', sshConfigPath: '/home/u/.ssh/config', warnings: ['示例警告'] },
  analysis: { available: false, reason: 'not configured' },
  generatedAt: Date.now()
};
const instances = [
  {
    pid: 111, version: '0.6.0', startedAt: Date.now() - 60000, connected: 1, hostCount: 3,
    client: { name: 'Claude Desktop', version: '1.2' },
    diagnostics: { counters: { toolCalls: 4, failures: 1, policyDenials: 0, timeouts: 1, slowCalls: 0 }, events: [{ tool: 'ssh_run', host: 'web', commandKind: 'read', outcome: 'ok', durationMs: 90, at: Date.now() - 4000 }] }
  },
  { pid: 222, error: 'ECONNREFUSED', nextRetryMs: 1000, followsDsh: true, statePath: '/x/state.json' }
];
const mcp = { ...dsh, instances };
const twoLive = { ...mcp, instances: [instances[0], { pid: 333, connected: 0, hostCount: 1 }] };

// ── html escaping and small helpers ────────────────────────────────────────
{
  check('esc', esc('<a href="x">&\'') === '&lt;a href=&quot;x&quot;&gt;&amp;&#39;', esc('<a href="x">&\''));
  check('esc-null', esc(null) === '' && esc(undefined) === '', `${esc(null)}/${esc(undefined)}`);
  check('age', age(5) === '5 秒前' && age(125) === '2 分钟前' && age(7300) === '2 小时前' && age(200000) === '2 天前', `${age(5)}/${age(125)}/${age(7300)}/${age(200000)}`);
  check('host-state', hostState(web).key === 'ready' && hostState(db).key === 'paused' && hostState({ state: 'down' }).key === 'down' && hostState({ state: 'connecting' }).key === 'connecting' && hostState({}).key === 'idle', 'state mapping');
}

// ── header and tabs ────────────────────────────────────────────────────────
{
  const dshHeader = renderHeader({ mode: 'dsh', floatable: true });
  check('header-dsh', dshHeader.includes(TEXT.title) && dshHeader.includes('data-float') && !dshHeader.includes('data-close-panel'), dshHeader.slice(0, 200));
  const mcpHeader = renderHeader({ mode: 'mcp', closable: true, busy: true });
  check('header-mcp', mcpHeader.includes('title-tag') && mcpHeader.includes('data-close-panel') && /data-refresh disabled/.test(mcpHeader), mcpHeader.slice(0, 240));
  check('tabs-for', tabsFor('dsh').join(',') === 'hosts,settings,diagnostics' && tabsFor('mcp').join(',') === 'hosts,processes,settings,diagnostics', JSON.stringify({ dsh: tabsFor('dsh'), mcp: tabsFor('mcp') }));
  const tabsDsh = renderTabs({ mode: 'dsh', tab: 'hosts', state: dsh });
  check('tabs-dsh', count(tabsDsh, 'role="tab"') === 3 && tabsDsh.includes('data-tab="diagnostics"') && !tabsDsh.includes('data-tab="processes"'), tabsDsh);
  check('tabs-counts', tabsDsh.includes('>1/2<') && tabsDsh.includes('>2<'), tabsDsh);
  const tabsMcp = renderTabs({ mode: 'mcp', tab: 'processes', state: mcp });
  check('tabs-mcp', count(tabsMcp, 'role="tab"') === 4 && /class="tab on" aria-selected="true" data-tab="processes"/.test(tabsMcp), tabsMcp);
}

// ── host cards: everything visible, no side panel ──────────────────────────
{
  const html = renderHosts(dsh, { mode: 'dsh' });
  check('host-cards', count(html, 'class="host"') === 2 && html.includes('class="hosts"'), `${count(html, 'class="host"')} cards`);
  check('no-side-panel', !html.includes('drawer') && !html.includes('data-select="') && !html.includes('class="row"'), 'the list must not open a side panel');
  check('card-identity', html.includes('data-alias="web"') && html.includes('data-alias="db"') && html.includes('class="badge prod"') && html.includes('class="badge muted"'), 'identity and badges');
  check('card-address', html.includes('root@192.0.2.10:22') && html.includes('deploy@192.0.2.11:2222'), 'address line');
  check('card-key', html.includes('id_web') && html.includes('—'), 'key names');
  check('card-host-key', html.includes('trusted · ssh-ed25519'), 'host key');
  check('card-status', html.includes('已连接 · 已连 1 小时 1 分 · 1 会话 · 3 命令'), 'status line');
  check('card-counters', html.includes('3 次建连 · 1 次重连'), 'connect counters');
  check('card-switches', count(html, 'data-toggle data-field="hidden"') === 2 && count(html, 'data-toggle data-field="prod"') === 2, 'per-card switches');
  check('card-prod-state', /role="switch" aria-checked="true"[^>]*data-field="prod" data-alias="web"/.test(html) && /role="switch" aria-checked="false"[^>]*data-field="prod" data-alias="db"/.test(html), 'prod switch states');
  check('card-hidden-state', /role="switch" aria-checked="true"[^>]*data-field="hidden" data-alias="db"/.test(html), 'hidden switch states');
  check('card-inputs', count(html, 'data-meta-input data-field="idleTimeoutMs"') === 2 && count(html, 'data-meta-input data-field="remark"') === 2, 'per-card overrides');
  check('card-idle-value', /value="60"[^>]*data-field="idleTimeoutMs" data-alias="db"/.test(html), 'idle override in seconds');
  check('card-remark', html.includes('value="生产 Web"') && html.includes('value="&lt;b&gt;"') && !html.includes('value="<b>"'), 'remark values are escaped');
  check('card-edit', count(html, 'data-edit=') === 1 && html.includes('data-edit="web"'), 'only ssh-config hosts are editable');
  check('card-source', html.includes(TEXT.sourceConfig), 'config hosts say where they come from');
  check('card-failure', html.includes('connect_timeout') && html.includes('handshake timed out') && html.includes('共 2 次') && html.includes('12 秒前'), 'last failed call');
  check('card-last-error', html.includes('ssh host &quot;db&quot; failed: timeout'), 'connect error also visible');
  check('card-last-command', html.includes(TEXT.lastCommand) && html.includes('uptime') && html.includes('5 秒前'), 'last command');
  check('card-sessions', html.includes(TEXT.sessions) && html.includes('main') && html.includes('空闲 20 秒'), 'sessions');
  check('card-chips', html.includes('1 台隐藏') && html.includes('1 台生产'), 'summary chips');
  check('card-empty', renderHosts({ hosts: [] }, { mode: 'dsh' }).includes(TEXT.noHosts), 'empty state');
  check('card-note-dsh', html.includes(TEXT.hostsNoteDsh) && !html.includes(TEXT.hostsNoteMcp), 'dsh note');
  check('card-note-mcp', renderHosts(mcp, { mode: 'mcp' }).includes(TEXT.hostsNoteMcp), 'mcp note');
  check('card-order', html.indexOf('data-alias="web"') < html.indexOf('data-alias="db"'), 'hosts keep their order');
}

// ── primary action depends on the surface and the live processes ───────────
{
  check('action-dsh', renderHosts(dsh, { mode: 'dsh' }).includes('data-action="close" data-alias="web"') && /data-action="open" data-alias="db"[^>]*>重试/.test(renderHosts(dsh, { mode: 'dsh' })), 'dsh actions');
  const oneLive = { ...mcp, instances: [instances[0]] };
  check('action-one-process', renderHosts(oneLive, { mode: 'mcp' }).includes('data-action="open" data-alias="db"'), 'one server means direct open');
  const many = renderHostCard(db, { state: twoLive, mode: 'mcp' });
  check('action-many-processes', many.includes('<div class="host-actions"></div>') && count(many, 'data-pid=') === 2, 'several servers: the per-process buttons own connect');
  const dead = renderHostCard(db, { state: { ...mcp, instances: [instances[1]] }, mode: 'mcp' });
  check('action-no-process', dead.includes('<div class="host-actions"></div>') && dead.includes(TEXT.noProcesses), 'no live server: no connect button, the process block explains');
}

// ── per-process rows live inside each card (MCP) ───────────────────────────
{
  const mcpHtml = renderHostCard(web, { state: mcp, mode: 'mcp' });
  check('card-per-process', mcpHtml.includes(TEXT.perProcess) && mcpHtml.includes('pid 111') && mcpHtml.includes('data-pid="111"'), 'process actions in the card');
  check('card-pick-process', renderHostCard(db, { state: twoLive, mode: 'mcp' }).includes('data-pid="333"') && count(renderHostCard(db, { state: twoLive, mode: 'mcp' }), 'data-pid=') === 2, 'each live server gets a row');
  check('card-no-processes', renderHostCard(db, { state: { ...mcp, instances: [] }, mode: 'mcp' }).includes(TEXT.noProcesses), 'empty process list');
  check('card-dsh-no-processes', !renderHostCard(web, { state: dsh, mode: 'dsh' }).includes(TEXT.perProcess), 'the DSH card has no process block');
}

// ── processes (MCP only) ───────────────────────────────────────────────────
{
  const html = renderProcesses(mcp);
  check('process-rows', count(html, 'class="row static"') === 2, `${count(html, 'class="row static"')} rows`);
  check('process-client', html.includes('Claude Desktop 1.2') && html.includes('pid 111') && html.includes('1 / 3 台已连接'), html.slice(0, 400));
  check('process-error', html.includes('ECONNREFUSED') && html.includes(TEXT.followsOther), 'error and state-file badge');
  check('process-close', count(html, `data-action="close_all"`) === 1 && html.includes('data-pid="111"'), 'only the reachable process can be closed');
  check('process-empty', renderProcesses({ instances: [] }).includes(TEXT.noProcesses), 'empty state');
}

// ── settings ───────────────────────────────────────────────────────────────
{
  const dshHtml = renderSettings(dsh, { mode: 'dsh' });
  check('settings-visible-dsh', dshHtml.includes('data-setting-toggle="sshVisible"'), 'master visibility switch');
  const mcpHtml = renderSettings(dsh, { mode: 'mcp' });
  check('settings-visible-mcp', !mcpHtml.includes('data-setting-toggle="sshVisible"'), 'no DSH switch on the MCP page');
  check('settings-numbers', /data-setting-input="maxOutputBytes" data-scale="1024"/.test(dshHtml) && /value="32"/.test(dshHtml), 'KB input');
  check('settings-seconds', /data-setting-input="idleTimeoutMs" data-scale="1000"/.test(dshHtml) && /data-setting-input="transferTimeoutMs" data-scale="1000"/.test(dshHtml), 'second inputs');
  check('settings-analysis', dshHtml.includes(TEXT.logAnalysis) && dshHtml.includes('not configured'), 'analysis availability');
  check('settings-policy', dshHtml.includes(TEXT.policyText) && dshHtml.includes('journalctl'), 'policy prose');
  check('settings-panel-foot', dshHtml.includes('/home/u/.dsh-ssh-mcp/state.json') && dshHtml.includes('示例警告'), 'state path and warnings');
  check('settings-groups', count(dshHtml, 'group-title') === 3, `${count(dshHtml, 'group-title')} groups`);
  const withPolicy = renderSettings({ settings: { ...settings, hostKeyPolicy: 'warn' } }, { mode: 'mcp' });
  check('settings-host-key-label', withPolicy.includes('<code>仅提醒（记录并继续）</code>'), withPolicy.slice(withPolicy.indexOf('主机密钥'), withPolicy.indexOf('主机密钥') + 200));
}

// ── diagnostics ────────────────────────────────────────────────────────────
{
  check('counters-dsh', diagnosticsCounters(dsh, 'dsh').toolCalls === 7 && diagnosticsCounters(dsh, 'dsh').slowCalls === 1, JSON.stringify(diagnosticsCounters(dsh, 'dsh')));
  const summed = diagnosticsCounters(mcp, 'mcp');
  check('counters-mcp-sum', summed.toolCalls === 4 && summed.failures === 1 && summed.timeouts === 1 && summed.policyDenials === 0, JSON.stringify(summed));
  const html = renderDiagnostics(mcp, { mode: 'mcp' });
  check('diagnostics-tiles', count(html, 'tile-num') === 5 && html.includes('>4<') && html.includes('>1<'), 'counter tiles');
  check('diagnostics-events', html.includes('ssh_run') && html.includes('data-read') === false && html.includes('read') && html.includes('90 ms'), 'event table');
  check('diagnostics-pid-column', html.includes('<th>pid</th>') && html.includes('>111<'), 'MCP table carries the pid');
  const dshHtml = renderDiagnostics(dsh, { mode: 'dsh' });
  check('diagnostics-dsh', !dshHtml.includes('<th>pid</th>') && dshHtml.includes('connect_timeout'), 'DSH table has no pid column');
  check('diagnostics-empty', renderDiagnostics({ diagnostics: { counters: {}, events: [] } }, { mode: 'dsh' }).includes(TEXT.noEvents), 'empty state');
}

// ── edit dialog, banners, footer, tab switch ───────────────────────────────
{
  const html = renderEditDialog(web);
  check('dialog-fields', html.includes('name="alias"') && html.includes('name="key"') && html.includes('value="web"') && html.includes('value="id_web"'), html.slice(0, 400));
  check('dialog-actions', html.includes('data-dialog-cancel') && html.includes('type="submit"') && html.includes(TEXT.save), 'dialog buttons');
  check('dialog-agent-key', renderEditDialog({ ...web, keyName: 'agent:default' }).includes('name="key" value="agent:default"') && /name="key"[^>]*disabled/.test(renderEditDialog({ ...web, keyName: 'agent:default' })), 'agent keys are read-only');
  check('dialog-error', renderEditDialog(web, { error: '改名失败', saving: true }).includes('改名失败'), 'error line');
  check('dialog-none', renderEditDialog(null) === '', 'no dialog');

  const banners = renderBanners({ error: '挂了', notice: '保存失败' });
  check('banners', banners.includes('banner err') && banners.includes('挂了') && banners.includes('banner warn'), banners);
  check('footer', renderFooter(dsh, { mode: 'dsh' }).includes('2 台主机') && renderFooter(mcp, { mode: 'mcp' }).includes('2 个进程'), 'footer counts');
  check('footer-hidden', renderFooter(dsh, { mode: 'dsh' }).includes('1 台隐藏'), 'hidden count');
  check('tab-dispatch', renderTab('processes', mcp, { mode: 'mcp' }).includes(TEXT.processesNote) && renderTab('processes', dsh, { mode: 'dsh' }).includes(TEXT.hostsNoteDsh), 'tab fallback');
}

// ── no raw dictionary key or JS value leaks into rendered text ─────────────
{
  const html = [
    renderHeader({ mode: 'mcp', floatable: true, closable: true }),
    ...['hosts', 'processes', 'settings', 'diagnostics'].map((tab) => renderTab(tab, mcp, { mode: 'mcp' })),
    renderHostCard(web, { state: mcp, mode: 'mcp' }),
    renderEditDialog(web),
    renderFooter(mcp, { mode: 'mcp' })
  ].join('\n');
  const suspicious = ['idleOverrideDesc', 'hostsNoteDsh', 'remarkPlaceholder', 'confirmCloseAll', 'logAnalysisDesc', 'sshVisibleDesc', 'statePathNote', 'editDialogWarning', 'processesNote', 'noProcesses'];
  const leaked = suspicious.find((key) => html.includes(key));
  check('no-raw-keys', leaked === undefined, `leaked ${leaked}`);
  check('no-js-values', !/undefined|\[object Object\]|NaN/.test(html), (html.match(/.{0,40}(undefined|\[object Object\]|NaN).{0,40}/) ?? [])[0]);
  check('no-null-text', !/>null</.test(html), 'null rendered');
}

// ── the custom element: attributes, theme hooks, fetch + credential retry ──
{
  globalThis.HTMLElement = class {};
  globalThis.customElements = { get: () => undefined, define: () => {} };
  const { SshHelperPanel, STYLES } = await import('../ui/panel-element.js');
  check('element-defined-by-name', readFileSync(new URL('../ui/panel-element.js', import.meta.url), 'utf8').includes("customElements.define('ssh-helper-panel'"), 'the element must define itself');
  check('observed-attributes', SshHelperPanel.observedAttributes.join(',') === 'api-base,mode,floatable,closable', JSON.stringify(SshHelperPanel.observedAttributes));
  check('theme-pierces-shadow', STYLES.includes(':host') && STYLES.includes('--dsw-alias-bg-base') && STYLES.includes('prefers-color-scheme:dark') && STYLES.includes('container-type:inline-size'), 'theme hooks');

  const makePanel = (attrs = {}) => {
    const panel = Object.create(SshHelperPanel.prototype);
    panel.getAttribute = (name) => attrs[name] ?? null;
    panel.credential = undefined;
    panel.state = null;
    panel.error = null;
    panel.notice = null;
    panel.failures = 0;
    panel.busy = false;
    panel.setBusy = () => {};
    panel.render = () => {};
    return panel;
  };
  check('api-base-default', makePanel().apiBase === '/ssh-pool' && makePanel().mode === 'dsh', 'defaults');
  check('api-base-normalised', makePanel({ 'api-base': '/api/' }).apiBase === '/api' && makePanel({ mode: 'mcp' }).mode === 'mcp', 'attribute values');
  const tokenPanel = makePanel();
  tokenPanel.token = 'abc';
  tokenPanel.token = '';
  check('token-property', tokenPanel.credential === 'abc', String(tokenPanel.credential));

  const calls = [];
  let queue = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, options = {}) => {
    calls.push({ url, method: options.method ?? 'GET', token: options.headers?.['x-dsh-ssh-pool-token'], body: options.body });
    const next = queue.shift() ?? { status: 500, json: { ok: false, error: 'unexpected call' } };
    return { ok: next.status >= 200 && next.status < 300, status: next.status, json: async () => next.json };
  };
  try {
    // A read stores the state and adopts the credential the API hands back.
    const panel = makePanel({ 'api-base': '/api' });
    panel.credential = 'seed';
    queue = [{ status: 200, json: { ok: true, state: { hosts: [{ alias: 'a' }] }, token: 'fresh' } }];
    const payload = await panel.call('state');
    check('call-read', payload?.ok === true && panel.state?.hosts?.length === 1 && panel.credential === 'fresh', JSON.stringify({ state: panel.state, credential: panel.credential }));
    check('call-read-request', calls[0].url === '/api/state' && calls[0].method === 'GET' && calls[0].token === 'seed', JSON.stringify(calls[0]));

    // A write with a stale credential re-reads once, then repeats the write.
    calls.length = 0;
    const writer = makePanel({ 'api-base': '/api' });
    writer.credential = 'stale';
    queue = [
      { status: 403, json: { ok: false, error: 'bad credential' } },
      { status: 200, json: { ok: true, state: { hosts: [] }, token: 'new' } },
      { status: 200, json: { ok: true, state: { hosts: [{ alias: 'b' }] } } }
    ];
    const written = await writer.call('meta', { alias: 'a', prod: true });
    check('call-retry', written?.ok === true && calls.map((entry) => entry.method).join(',') === 'POST,GET,POST', JSON.stringify(calls.map((entry) => `${entry.method} ${entry.url}`)));
    check('call-retry-credential', calls[2].token === 'new' && writer.state?.hosts?.[0]?.alias === 'b' && writer.notice === null, JSON.stringify({ token: calls[2].token, state: writer.state }));

    // A write that still fails surfaces on the notice line and rejects.
    const failing = makePanel();
    queue = [
      { status: 403, json: { ok: false, error: 'nope' } },
      { status: 200, json: { ok: true, state: {} } },
      { status: 403, json: { ok: false, error: 'nope' } }
    ];
    let rejected = null;
    await failing.call('settings', { idleTimeoutMs: 1 }).catch((error) => (rejected = error.message));
    check('call-write-notice', rejected === 'nope' && failing.notice === 'nope', `${rejected} / ${failing.notice}`);

    // One dropped poll keeps the last state visible; two show the banner.
    const poll = makePanel();
    poll.state = { hosts: [] };
    queue = [{ status: 500, json: null }, { status: 500, json: null }];
    await poll.call('state', undefined, { silent: true }).catch(() => {});
    check('poll-first-failure-hidden', poll.failures === 1 && poll.error === null, JSON.stringify({ failures: poll.failures, error: poll.error }));
    await poll.call('state', undefined, { silent: true }).catch(() => {});
    check('poll-second-failure-banner', poll.failures === 2 && poll.error === 'HTTP 500', JSON.stringify({ failures: poll.failures, error: poll.error }));
    const cold = makePanel();
    queue = [{ status: 500, json: null }];
    await cold.call('state', undefined, { silent: true }).catch(() => {});
    check('poll-cold-failure-banner', cold.error === 'HTTP 500', String(cold.error));
  } finally {
    globalThis.fetch = originalFetch;
  }
}

// ── client.js is only the DSH host now ─────────────────────────────────────
{
  const element = (type, props, ...children) => ({ type, props: props ?? {}, children: children.flat(Infinity) });
  const React = { createElement: element, useState: (init) => [typeof init === 'function' ? init() : init, () => {}], useEffect: () => {}, useRef: (init) => ({ current: init }) };
  let registered;
  globalThis.window = { __ModuleLoader__: { load: (module) => (registered = module) }, addEventListener: () => {}, removeEventListener: () => {} };
  await import('../client.js');
  const module = registered.factory((name) => (name === 'react' ? React : undefined));
  const slots = [];
  const ctx = {
    get: (name) => (name === 'layout' ? { selectPanel: () => {} } : undefined),
    slots: { inject: (_name, callback) => callback(), register: (definition, component) => (slots.push({ definition, component }), () => {}) }
  };
  module.apply(ctx);
  check('client-slots', slots.length === 3 && slots.some((entry) => entry.definition.name === 'sidebar.panellist' && entry.definition.id === 'ssh-assistant') && slots.some((entry) => entry.definition.name === 'main' && entry.definition.key === 'ssh-assistant') && slots.some((entry) => entry.definition.name === 'shell.overlay'), JSON.stringify(slots.map((entry) => entry.definition)));
  const panel = slots.find((entry) => entry.definition.name === 'main');
  const expand = (node) => {
    if (node === null || typeof node !== 'object') return node;
    if (Array.isArray(node)) return node.map(expand);
    if (typeof node.type === 'function') return expand(node.type({ ...node.props, children: node.children }));
    return { ...node, children: (node.children ?? []).map(expand) };
  };
  const tree = expand(panel.component());
  check('client-mount', tree?.props?.className === 'ssh-mount', JSON.stringify(tree?.props));
  const source = readFileSync(new URL('../client.js', import.meta.url), 'utf8');
  check('client-mounts-element', source.includes("element.setAttribute('api-base', '/ssh-pool')") && source.includes("element.setAttribute('mode', 'dsh')") && source.includes('ssh-helper-float') && source.includes('ssh-helper-close'), 'host wiring');
  check('client-loads-shared-ui', source.includes("const ELEMENT_URL = '/ssh-pool/ui/panel-element.js'") && source.includes('globalThis.__DSH_SSH_ASSISTANT__?.token'), 'shared UI + token');
  check('client-has-no-css', !/STYLES|\.ssh-setrow\{|createElement\('style'/.test(source), 'the styles moved into the shared element');
}

console.log(`${pass}/${pass + failures.length} passed`);
for (const failure of failures) console.log(`FAIL ${failure}`);
process.exit(failures.length === 0 ? 0 : 2);
