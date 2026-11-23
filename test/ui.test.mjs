/**
 * The shared panel UI: `ui/panel-view.js` (pure HTML renderers) and
 * `<ssh-helper-panel>` (`ui/panel-element.js`), plus the thin DSH host in
 * `client.js`.
 *
 * Both surfaces — the DSH sidebar and the MCP management page — render from
 * these same functions, so this suite is what keeps the two from drifting:
 * every tab, host card, control, badge and dictionary key is checked
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
  moveAlias,
  renderBanners,
  renderDiagnostics,
  renderHostRow,
  renderEditDialog,
  renderFooter,
  renderHeader,
  renderHosts,
  renderProcesses,
  renderSettings,
  renderTab,
  renderTabs,
  sortTarget,
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
  commands: 3, hidden: false, remark: '生产 Web', idleTimeoutMs: null, effectiveIdleTimeoutMs: 30000,
  hostKey: { status: 'match', type: 'ssh-ed25519' }, lastCommand: 'uptime', lastCommandAgeSeconds: 5,
  callFailures: 0, lastFailure: null, instances: [{ pid: 111, state: 'ready', connected: true }]
};
const db = {
  alias: 'db', host: '192.0.2.11', port: 2222, user: 'deploy', keyName: null, source: 'config',
  state: 'idle', connected: false, connectedSeconds: 0, idleSeconds: null, connects: 0, reconnects: 0,
  failures: 1, handshakeTimeouts: 0, sessions: [], commands: 0, retryPaused: true, hidden: true,
  remark: '<b>', idleTimeoutMs: 60000, effectiveIdleTimeoutMs: 60000, lastError: 'ssh host "db" failed: timeout',
  lastFailure: { tool: 'ssh_run', code: 'connect_timeout', message: 'handshake timed out', ageSeconds: 12 },
  callFailures: 2, lastCommand: null, lastCommandAgeSeconds: null, instances: []
};
const settings = { idleTimeoutMs: 0, sshVisible: true, maxOutputBytes: 32768, transferTimeoutMs: 600000, logAnalysis: false, maskAddresses: false };
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
  const dshHeader = renderHeader({ mode: 'dsh' });
  check('header-dsh', dshHeader.includes(TEXT.title) && dshHeader.includes('data-mask') && !dshHeader.includes('data-float') && !dshHeader.includes('data-close-panel'), dshHeader.slice(0, 200));
  check('header-mask-off', /aria-pressed="false"[^>]*>.*?<span class="label">打码</.test(dshHeader) && dshHeader.includes('<path d="M2 12s3.5-6 10-6'), 'the off state shows the plain eye and 打码');
  const mcpHeader = renderHeader({ mode: 'mcp', busy: true, masked: true });
  check('header-mcp', mcpHeader.includes('title-tag') && /aria-pressed="true"/.test(mcpHeader) && /data-refresh disabled/.test(mcpHeader), mcpHeader.slice(0, 240));
  check('header-mask-on', mcpHeader.includes(TEXT.maskOn) && mcpHeader.includes('<path d="M4 4l16 16"/>'), 'the on state shows eye-off and 已打码');
  check('tabs-for', tabsFor('dsh').join(',') === 'hosts,settings,diagnostics' && tabsFor('mcp').join(',') === 'hosts,processes,settings,diagnostics', JSON.stringify({ dsh: tabsFor('dsh'), mcp: tabsFor('mcp') }));
  const tabsDsh = renderTabs({ mode: 'dsh', tab: 'hosts', state: dsh });
  check('tabs-dsh', count(tabsDsh, 'role="tab"') === 3 && tabsDsh.includes('data-tab="diagnostics"') && !tabsDsh.includes('data-tab="processes"'), tabsDsh);
  check('tabs-counts', tabsDsh.includes('>1/2<') && tabsDsh.includes('>2<'), tabsDsh);
  const tabsMcp = renderTabs({ mode: 'mcp', tab: 'processes', state: mcp });
  check('tabs-mcp', count(tabsMcp, 'role="tab"') === 4 && /class="tab on" aria-selected="true" data-tab="processes"/.test(tabsMcp), tabsMcp);
}

// ── hosts table: one row per host, details on demand ───────────────────────
{
  const html = renderHosts(dsh, { mode: 'dsh' });
  const open = renderHosts(dsh, { mode: 'dsh', expanded: ['web', 'db'] });
  check('host-rows', count(html, '<article class="host') === 2 && html.includes('class="host-table"') && html.includes('class="hosts"'), `${count(html, '<article class="host')} rows`);
  check('no-side-panel', !html.includes('drawer') && !html.includes('data-select="') && !html.includes('class="row"'), 'the list must not open a side panel');
  const headings = [...html.matchAll(/<span role="columnheader">([^<]*)<\/span>/g)].map((match) => match[1]);
  const c = TEXT.columns;
  check('host-columns', headings.join(',') === [c.host, c.address, c.key, c.hostKey, c.state, c.visible, c.idle, c.remark].join(','), headings.join(','));
  check('row-cells', count(renderHostRow(web, { state: dsh, mode: 'dsh' }), '<div class="cell') === 8 && count(renderHostRow(db, { state: dsh, mode: 'dsh' }), '<div class="cell') === 8, 'every row has the same cells');
  check('row-identity', html.includes('data-alias="web"') && html.includes('data-alias="db"') && html.includes('class="badge muted"') && html.includes('class="host is-hidden"'), 'identity and badges');
  check('row-address', html.includes('root@192.0.2.10:22') && html.includes('deploy@192.0.2.11:2222'), 'address cell');
  const masked = renderHosts({ ...dsh, settings: { ...settings, maskAddresses: true } }, { mode: 'dsh', expanded: ['web', 'db'] });
  check('row-address-masked', masked.includes('class="mosaic"') && !masked.includes('192.0.2.10') && !masked.includes('deploy@'), 'mask switch hides endpoints behind a mosaic');
  const maskedDialog = renderEditDialog(web, { masked: true });
  check('dialog-address-masked', maskedDialog.includes('class="mosaic"') && !maskedDialog.includes('192.0.2.10') && !renderEditDialog(web).includes('mosaic'), 'dialog follows the switch');
  check('row-key', html.includes('id_web') && html.includes('—'), 'key names');
  check('row-host-key', html.includes('>一致 <span class="muted small">ed25519</span>') && html.includes(TEXT.hostKeyStates.match[1]), 'host key verdict in words');
  check('row-host-key-none', html.includes(`title="${TEXT.hostKeyNone}">—`), 'an unknown host key says why');
  const keyed = (status) => renderHostRow({ ...web, hostKey: { status, type: 'ssh-ed25519' } }, { state: dsh, mode: 'dsh' });
  check('row-host-key-mismatch', keyed('mismatch').includes('class="hk fail"') && keyed('mismatch').includes('>不一致') && keyed('unknown').includes('>未登记') && keyed('unreadable').includes('>无法核对'), 'every verdict has a label');
  check('row-status', html.includes('已连接 <span class="muted small">1 小时 1 分 · 1 会话 · 3 命令</span>'), 'state cell');
  check('row-switches', count(html, 'data-toggle data-field="hidden"') === 2 && count(html, 'data-toggle ') === 2, 'one visibility switch per row');
  check('row-visible-state', /role="switch" aria-checked="true"[^>]*data-field="hidden" data-alias="web"/.test(html) && /role="switch" aria-checked="false"[^>]*data-field="hidden" data-alias="db"/.test(html), 'the switch is on when the agent can see the host');
  check('row-no-prod', !html.includes('data-field="prod"') && !html.includes('PROD') && !html.includes('生产服务器'), 'the prod label is gone');
  check('row-inputs', count(html, 'data-meta-input data-field="idleTimeoutMs"') === 2 && count(html, 'data-meta-input data-field="remark"') === 2, 'per-row overrides');
  check('row-idle-value', /value="60"[^>]*data-field="idleTimeoutMs" data-alias="db"/.test(html), 'idle override in seconds');
  check('row-remark', html.includes('value="生产 Web"') && html.includes('value="&lt;b&gt;"') && !html.includes('value="<b>"'), 'remark values are escaped');
  check('row-edit', count(html, 'data-edit=') === 1 && html.includes('data-edit="web"'), 'only ssh-config hosts are editable');
  check('row-source', html.includes(TEXT.sourceConfig), 'config hosts say where they come from');
  check('row-failure-chip', /class="chip err" data-expand="db"[^>]*>失败 ×2</.test(html) && !/data-expand="web"[^>]*class="chip/.test(html), 'a failed host shows a chip that opens its details');
  check('row-collapsed', !html.includes('host-detail') && count(html, 'aria-expanded="false"') === 2, 'details stay closed until asked');
  check('row-expanded', count(open, 'class="host-detail"') === 2 && count(open, 'aria-expanded="true"') === 2 && open.includes('class="host open" data-alias="web"'), 'expanded rows show their details');
  check('detail-counters', open.includes('3 次建连 · 1 次重连') && !html.includes('3 次建连'), 'counters live in the details');
  check('detail-failure', open.includes('connect_timeout') && open.includes('handshake timed out') && open.includes('共 2 次') && open.includes('12 秒前'), 'last failed call');
  check('detail-last-error', open.includes('ssh host &quot;db&quot; failed: timeout'), 'connect error also visible');
  check('detail-last-command', open.includes(TEXT.lastCommand) && open.includes('uptime') && open.includes('5 秒前'), 'last command');
  check('detail-sessions', open.includes(TEXT.sessions) && open.includes('main') && open.includes('空闲 20 秒') && open.includes(TEXT.noSessions), 'sessions, or a placeholder');
  check('row-chips', html.includes('1 台隐藏') && !html.includes('台生产'), 'summary chips');
  check('row-empty', renderHosts({ hosts: [] }, { mode: 'dsh' }).includes(TEXT.noHosts), 'empty state');
  check('row-note-dsh', html.includes(TEXT.hostsNoteDsh) && !html.includes(TEXT.hostsNoteMcp), 'dsh note');
  check('row-note-mcp', renderHosts(mcp, { mode: 'mcp' }).includes(TEXT.hostsNoteMcp), 'mcp note');
  check('row-drag-handles', count(html, 'data-drag-handle data-alias=') === 2 && html.includes(`aria-label="${TEXT.dragHandle}：web"`), 'every row has a labelled handle');
  check('row-order', html.indexOf('data-alias="web"') < html.indexOf('data-alias="db"'), 'hosts keep their order');
}

// ── reordering: keyboard moves and the drag geometry ───────────────────────
{
  check('move-down', moveAlias(['a', 'b', 'c'], 'a', 1).join() === 'b,a,c', moveAlias(['a', 'b', 'c'], 'a', 1).join());
  check('move-up', moveAlias(['a', 'b', 'c'], 'c', -1).join() === 'a,c,b', moveAlias(['a', 'b', 'c'], 'c', -1).join());
  check('move-clamped', moveAlias(['a', 'b', 'c'], 'a', -5).join() === 'a,b,c' && moveAlias(['a', 'b', 'c'], 'a', 9).join() === 'b,c,a', 'moves stop at the ends');
  check('move-unknown', moveAlias(['a', 'b'], 'zz', 1).join() === 'a,b', 'an unknown alias changes nothing');
  check('move-pure', (() => { const input = ['a', 'b']; moveAlias(input, 'a', 1); return input.join() === 'a,b'; })(), 'the input array is not mutated');
  const rows = [0, 50, 100, 150].map((top) => ({ top, height: 50 }));
  const at = (from, dy) => sortTarget(rows, from, dy);
  check('drag-not-past-middle', at(0, 20).index === 0 && at(0, 20).shifts.every((shift) => shift === 0), JSON.stringify(at(0, 20)));
  check('drag-past-one', at(0, 30).index === 1 && at(0, 30).shifts.join() === '0,-50,0,0', JSON.stringify(at(0, 30)));
  check('drag-to-end', at(0, 160).index === 3 && at(0, 160).shifts.join() === '0,-50,-50,-50', JSON.stringify(at(0, 160)));
  check('drag-up', at(3, -60).index === 2 && at(3, -60).shifts.join() === '0,0,50,0', JSON.stringify(at(3, -60)));
  const tall = [{ top: 0, height: 50 }, { top: 50, height: 140 }, { top: 190, height: 50 }];
  check('drag-past-tall-row', sortTarget(tall, 0, 60).index === 0 && sortTarget(tall, 0, 100).index === 1 && sortTarget(tall, 0, 100).shifts[1] === -50, JSON.stringify(sortTarget(tall, 0, 100)));
  const spaced = [{ top: 0, height: 50 }, { top: 60, height: 50 }];
  check('drag-gap', sortTarget(spaced, 0, 40).shifts[1] === -60, JSON.stringify(sortTarget(spaced, 0, 40)));
}

// ── primary action depends on the surface and the live processes ───────────
{
  check('action-dsh', renderHosts(dsh, { mode: 'dsh' }).includes('data-action="close" data-alias="web"') && /data-action="open" data-alias="db"[^>]*>重试/.test(renderHosts(dsh, { mode: 'dsh' })), 'dsh actions');
  const oneLive = { ...mcp, instances: [instances[0]] };
  check('action-one-process', renderHosts(oneLive, { mode: 'mcp' }).includes('data-action="open" data-alias="db"'), 'one server means direct open');
  const many = renderHostRow(db, { state: twoLive, mode: 'mcp' });
  check('action-many-processes', !many.includes('data-action="open"') && many.includes(`data-expand="db">${TEXT.processesShort}<`) && count(renderHostRow(db, { state: twoLive, mode: 'mcp', expanded: true }), 'data-pid=') === 2, 'several servers: the per-process buttons in the details own connect');
  const dead = renderHostRow(db, { state: { ...mcp, instances: [instances[1]] }, mode: 'mcp', expanded: true });
  check('action-no-process', !dead.includes('data-action="open"') && dead.includes(TEXT.noProcesses), 'no live server: no connect button, the details explain');
}

// ── per-process rows live in the details (MCP) ─────────────────────────────
{
  const mcpHtml = renderHostRow(web, { state: mcp, mode: 'mcp', expanded: true });
  check('detail-per-process', mcpHtml.includes(TEXT.perProcess) && mcpHtml.includes('pid 111') && mcpHtml.includes('data-pid="111"'), 'process actions in the details');
  check('detail-pick-process', renderHostRow(db, { state: twoLive, mode: 'mcp', expanded: true }).includes('data-pid="333"'), 'each live server gets a row');
  check('detail-no-processes', renderHostRow(db, { state: { ...mcp, instances: [] }, mode: 'mcp', expanded: true }).includes(TEXT.noProcesses), 'empty process list');
  check('detail-dsh-no-processes', !renderHostRow(web, { state: dsh, mode: 'dsh', expanded: true }).includes(TEXT.perProcess), 'DSH details have no process block');
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
  check('settings-analysis-local', dshHtml.includes('本地规则摘要'), 'an unavailable model must say the local digest is used');
  const availableHtml = renderSettings({ settings, analysis: { available: true, model: 'fake/model' } }, { mode: 'mcp' });
  check('settings-analysis-model', availableHtml.includes('当前模型') && availableHtml.includes('fake/model'), 'an available model must be named');
  check('settings-policy', dshHtml.includes(TEXT.policyText) && dshHtml.includes('journalctl'), 'policy prose');
  check('settings-panel-foot', dshHtml.includes('/home/u/.dsh-ssh-mcp/state.json') && dshHtml.includes('示例警告'), 'state path and warnings');
  check('settings-mask', dshHtml.includes('data-setting-toggle="maskAddresses"') && mcpHtml.includes('data-setting-toggle="maskAddresses"'), 'mask switch on both surfaces');
  check('settings-groups', count(dshHtml, 'group-title') === 4, `${count(dshHtml, 'group-title')} groups`);
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
  const drafted = renderEditDialog(web, { saving: true, draft: { alias: 'web2', keyName: 'id_web2' } });
  check('dialog-draft-kept', drafted.includes('value="web2"') && drafted.includes('value="id_web2"') && !drafted.includes('value="id_web"'), 'a redraw while saving keeps the typed names');
  check('dialog-draft-agent', renderEditDialog({ ...web, keyName: 'agent:default' }, { draft: { alias: 'web', keyName: 'x' } }).includes('name="key" value="agent:default"'), 'a draft never replaces a read-only key');

  const banners = renderBanners({ error: '挂了', notice: '保存失败' });
  check('banners', banners.includes('banner err') && banners.includes('挂了') && banners.includes('banner warn'), banners);
  check('footer', renderFooter(dsh, { mode: 'dsh' }).includes('2 台主机') && renderFooter(mcp, { mode: 'mcp' }).includes('2 个进程'), 'footer counts');
  check('footer-hidden', renderFooter(dsh, { mode: 'dsh' }).includes('1 台隐藏'), 'hidden count');
  check('tab-dispatch', renderTab('processes', mcp, { mode: 'mcp' }).includes(TEXT.processesNote) && renderTab('processes', dsh, { mode: 'dsh' }).includes(TEXT.hostsNoteDsh), 'tab fallback');
}

// ── no raw dictionary key or JS value leaks into rendered text ─────────────
{
  const html = [
    renderHeader({ mode: 'mcp', masked: true }),
    ...['hosts', 'processes', 'settings', 'diagnostics'].map((tab) => renderTab(tab, mcp, { mode: 'mcp' })),
    renderHostRow(web, { state: mcp, mode: 'mcp', expanded: true }),
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
  check('observed-attributes', SshHelperPanel.observedAttributes.join(',') === 'api-base,mode', JSON.stringify(SshHelperPanel.observedAttributes));
  check('host-columns-css', STYLES.includes('.host-cols{display:grid;grid-template-columns:28px') && STYLES.includes('@container (min-width:1320px)') && !STYLES.includes('.host-table{min-width:'), 'header and rows share one column template, and the table never forces a horizontal scroll');
  check('host-cells-placed', ['name', 'addr', 'key', 'hk', 'state', 'vis', 'idle', 'remark', 'act'].every((area) => STYLES.includes(`grid-area:${area}`)), 'every cell is placed by name, so one markup serves the one-line and the two-line layout');
  check('drag-motion-css', STYLES.includes('.hosts.sorting .host{transition:transform') && STYLES.includes('.hosts.no-motion .host{transition:none!important}'), 'rows slide while sorting and snap without motion when the DOM is reordered');
  check('grip-touch', STYLES.includes('touch-action:none') && STYLES.includes('cursor:grab'), 'the handle drags on touch screens too');
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

  // An open edit dialog is redrawn only by its own transitions. A poll or the
  // focusout catch-up used to rebuild the form between the Save button's
  // mousedown and mouseup, so the click was lost and the typed key name reset.
  {
    const panel = makePanel();
    panel.render = SshHelperPanel.prototype.render;
    panel.tab = 'hosts';
    panel.state = { hosts: [web], settings: {} };
    panel.frame = { innerHTML: 'UNTOUCHED' };
    panel.shadowRoot = { activeElement: null, querySelector: () => null };
    panel.dialog = { host: web, error: null, saving: false };
    panel.render();
    check('dialog-no-passive-redraw', panel.frame.innerHTML === 'UNTOUCHED', 'a non-forced render must leave an open dialog alone');
    panel.dialog = { ...panel.dialog, saving: true, draft: { alias: 'web', keyName: 'id_new' } };
    panel.render(true);
    check('dialog-forced-redraw', panel.frame.innerHTML.includes('value="id_new"'), 'a forced render shows the draft');
    panel.dialog = null;
    panel.frame.innerHTML = 'UNTOUCHED';
    panel.render();
    check('closed-dialog-redraws', panel.frame.innerHTML !== 'UNTOUCHED', 'polls redraw again once the dialog is closed');
  }

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
    const written = await writer.call('meta', { alias: 'a', hidden: true });
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

    // Saving a card order reorders the local state at once, then posts it.
    calls.length = 0;
    const sorter = makePanel({ 'api-base': '/api' });
    sorter.state = { hosts: [{ alias: 'a' }, { alias: 'b' }, { alias: 'c' }] };
    queue = [{ status: 200, json: { ok: true, state: { hosts: [{ alias: 'c' }, { alias: 'a' }, { alias: 'b' }] } } }];
    const saving = sorter.saveOrder(['c', 'a', 'b']);
    check('order-optimistic', sorter.state.hosts.map((host) => host.alias).join() === 'c,a,b', JSON.stringify(sorter.state.hosts));
    await saving;
    check('order-posted', calls[0]?.url === '/api/order' && calls[0]?.method === 'POST' && calls[0]?.body === JSON.stringify({ order: ['c', 'a', 'b'] }), JSON.stringify(calls[0]));
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
  check('client-slots', slots.length === 2 && slots.some((entry) => entry.definition.name === 'sidebar.panellist' && entry.definition.id === 'ssh-assistant') && slots.some((entry) => entry.definition.name === 'main' && entry.definition.key === 'ssh-assistant') && !slots.some((entry) => entry.definition.name === 'shell.overlay'), JSON.stringify(slots.map((entry) => entry.definition)));
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
  check('client-mounts-element', source.includes("element.setAttribute('api-base', '/ssh-pool')") && source.includes("element.setAttribute('mode', 'dsh')") && !source.includes('ssh-helper-float') && !source.includes('shell.overlay'), 'host wiring, no floating window');
  check('client-loads-shared-ui', source.includes("const ELEMENT_URL = '/ssh-pool/ui/panel-element.js'") && source.includes('globalThis.__DSH_SSH_ASSISTANT__?.token'), 'shared UI + token');
  check('client-has-no-css', !/STYLES|\.ssh-setrow\{|createElement\('style'/.test(source), 'the styles moved into the shared element');
}

console.log(`${pass}/${pass + failures.length} passed`);
for (const failure of failures) console.log(`FAIL ${failure}`);
process.exit(failures.length === 0 ? 0 : 2);
