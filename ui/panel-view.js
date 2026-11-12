/**
 * The SSH assistant's view: pure functions from panel state to HTML strings.
 *
 * Shared by both surfaces through `<ssh-helper-panel>` (`panel-element.js`):
 * the DSH sidebar panel (`mode="dsh"`, API under `/ssh-pool`) and the MCP
 * management page (`mode="mcp"`, API under `/api`). No DOM access here, so
 * the whole layout is testable in plain Node. Every interpolated value goes
 * through `esc`.
 *
 * Every host is a self-contained card (address, key, status, switches,
 * overrides, failures, sessions, MCP process rows); there is no side panel.
 *
 * Interaction hooks are `data-*` attributes; the element wires them:
 *   data-tab, data-action (+ data-alias, data-pid), data-toggle
 *   (+ data-alias, data-field), data-setting-toggle, data-meta-input
 *   (+ data-alias, data-field), data-setting-input (+ data-scale), data-edit,
 *   data-refresh, data-close-all, dialog: data-dialog-cancel / form submit.
 *
 * @module dsh-ssh-helper/ui/panel-view
 */

export const TEXT = {
  title: 'SSH 助手',
  subtitleDsh: '常驻连接池：同一连接复用',
  subtitleMcp: '本机所有 dsh-ssh-mcp 进程与连接',
  tabs: { hosts: '主机', processes: '进程', settings: '设置', diagnostics: '诊断' },
  refresh: '刷新',
  closeAll: '全部断开',
  open: '连接',
  disconnect: '断开',
  retry: '重试',
  states: { ready: '已连接', connecting: '连接中', idle: '未连接', down: '已断开', paused: '已暂停' },
  prod: '生产',
  prodShort: '只提醒，不拦截',
  hidden: '隐藏',
  visible: '可见',
  sessions: '会话',
  commands: '命令',
  noHosts: '没有可用的 SSH 主机：检查 ~/.ssh/config 或插件配置。',
  hostsNoteDsh: '「隐藏」后任何会话都看不到、也连不上它，现有连接会在 20 秒后自动断开；每台主机的详情和开关都在卡片上。',
  hostsNoteMcp: '「隐藏」后任何 MCP 会话都看不到、也连不上它，各进程的现有连接会在 20 秒后自动断开；每台主机的详情、开关和各进程连接都在卡片上。',
  prodHint: '生产服务器（实际业务在跑）。不拦截命令；agent 在 ssh_hosts 和每次改动类调用的结果里都会看到 [PROD] 提醒，先说明影响、取得你的确认再重启、删除或改配置/数据。',
  hiddenHint: '隐藏后 agent 看不到也连不上该主机；现有连接会在 20 秒后自动断开，期间恢复可见则不会断开；这里仍可管理。',
  idleOverride: '空闲超时',
  idleOverrideDesc: '秒；留空跟随全局设置，0 = 永不断开。',
  remark: '备注',
  remarkPlaceholder: '这台机器是做什么的…',
  address: '地址',
  key: '密钥',
  source: '来源',
  sourceConfig: '插件配置',
  edit: '编辑 Host / 密钥',
  editShort: '编辑',
  state: '状态',
  connection: '连接',
  lastFailure: '最近失败',
  lastCommand: '最近命令',
  hostKey: '主机密钥',
  perProcess: '各进程',
  noProcesses: '没有正在运行的 MCP 进程。启动一个使用此 server 的客户端会话后，这里会显示它。',
  processesNote: '每个客户端会话各起一个 dsh-ssh-mcp 进程，各有自己的连接池；进程启动后会自动出现在这里。',
  followsOther: '跟随其他状态文件，这里的隐藏/设置对它无效',
  closeProcess: '断开它的全部连接',
  sshVisible: 'SSH 工具对会话可见',
  sshVisibleDesc: '总开关。关闭后 8 个 ssh_* 工具对任何会话（含子 agent）都不再存在，已建立的连接不受影响。',
  groupOutput: '输出与上下文',
  groupConnection: '连接与空闲',
  groupPrivacy: '隐私与截图',
  maskAddresses: '地址打码',
  maskAddressesDesc: '开启后卡片和编辑框里的地址（user@host:port）显示为马赛克块，截图时不用再手动打码；只影响显示，不影响连接。',
  mask: '打码',
  maskOn: '已打码',
  maskHint: '地址打码（只影响显示，不影响连接）',
  maskOnHint: '地址已打码；点击恢复显示',
  groupPolicy: '命令护栏',
  maxOutputBytes: '命令输出上限',
  maxOutputBytesDesc: '每条命令回传的每个流（stdout / stderr）的字节上限，单位 KB；默认 32 KB，超出时保留头尾并标注省略。调小更省上下文。',
  logAnalysis: '日志旁路分析',
  logAnalysisDesc:
    '开启后，较大的日志读取/搜索/日志类命令会交给一个没有工具的旁路模型分析，主会话只收到摘要；需要原文时在调用里传 analyze:false。日志会先脱敏。默认关闭，敏感日志请保持关闭。',
  idleTimeout: '空闲超时',
  idleTimeoutDesc: '秒；0 = 永不自动断开。未使用时不创建连接，只有会话真正用到该主机才首次建连。',
  transferTimeout: '文件传输超时',
  transferTimeoutDesc: '秒。单次 SFTP 上传/下载的默认时限，默认 600 秒；到点即取消，避免链路卡住时一直挂着。',
  hostKeyPolicy: '主机密钥策略',
  hostKeyPolicyDesc: '来自配置的 hostKeyPolicy，这里只读。',
  policyText:
    '只拦会让整台机器报废的操作：递归/通配删除系统关键目录、mkfs/分区、dd 或 > 写块设备、覆写系统关键文件、递归 chmod/chown 系统目录。业务目录和普通维护不拦。护栏在工具内部执行，这里不能关闭。',
  logExamples: '查日志要有界；数字只是写法示例，不是固定上限',
  counters: { toolCalls: '调用', failures: '失败', policyDenials: '拦截', timeouts: '超时', slowCalls: '慢调用' },
  recentEvents: '最近调用',
  noEvents: '还没有调用记录。',
  editDialog: '编辑连接',
  editDialogDesc: 'Host 名和密钥文件名可以一起改；保存时会备份 ~/.ssh/config，密钥文件会被真实重命名。',
  editDialogWarning: 'Host 改名会影响会话里使用的名字；密钥改名会真实重命名本机 key 文件。两项在一次提交中完成，任一项失败都不会写入。',
  hostNameLabel: 'Host 名',
  keyNameLabel: '密钥文件名',
  save: '保存',
  cancel: '取消',
  loading: '加载中…',
  loadFailed: '读取状态失败',
  saveFailed: '保存失败',
  statePath: '状态文件',
  statePathNote: '仅本面板写入，各 MCP 进程只读跟随',
  sshConfig: 'SSH 配置',
  confirmCloseAll: '断开全部 SSH 连接？'
};

const ENTITIES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
/** HTML-escape any value (null/undefined → ''). */
export const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (ch) => ENTITIES[ch]);

/** "N 秒前" style age from seconds. */
export function age(seconds) {
  const s = Math.max(0, Math.round(Number(seconds) || 0));
  if (s < 60) return `${s} 秒前`;
  if (s < 3600) return `${Math.round(s / 60)} 分钟前`;
  if (s < 86400) return `${Math.round(s / 3600)} 小时前`;
  return `${Math.round(s / 86400)} 天前`;
}
/** Duration text from seconds. */
function span(seconds) {
  const s = Math.max(0, Math.round(Number(seconds) || 0));
  if (s < 60) return `${s} 秒`;
  if (s < 3600) return `${Math.floor(s / 60)} 分 ${s % 60} 秒`;
  return `${Math.floor(s / 3600)} 小时 ${Math.floor((s % 3600) / 60)} 分`;
}

/** The display state of a host: `{ key, label }` with key ∈ ready|connecting|idle|down|paused. */
export function hostState(host) {
  const key = host.retryPaused === true ? 'paused' : host.state === 'ready' || host.connected === true ? 'ready' : host.state === 'connecting' ? 'connecting' : host.state === 'down' ? 'down' : 'idle';
  return { key, label: TEXT.states[key] };
}

const ICON_PATHS = {
  logo: ['M3 6a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z', 'M8 21h8', 'M12 17v4', 'M7 9.5l2 1.5-2 1.5', 'M12.5 12.5H16'],
  refresh: ['M20 12a8 8 0 1 1-2.3-5.6', 'M20 4v5h-5'],
  eye: ['M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12z', 'M12 9.5a2.5 2.5 0 1 1 0 5 2.5 2.5 0 0 1 0-5z'],
  eyeOff: ['M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12z', 'M12 9.5a2.5 2.5 0 1 1 0 5 2.5 2.5 0 0 1 0-5z', 'M4 4l16 16'],
  chevron: ['M9 6l6 6-6 6'],
  power: ['M12 4v8', 'M7.5 6.6a7 7 0 1 0 9 0']
};
export const icon = (name, size = 14) =>
  `<svg viewBox="0 0 24 24" width="${size}" height="${size}" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${ICON_PATHS[name]
    .map((d) => `<path d="${d}"/>`)
    .join('')}</svg>`;

const switchHtml = ({ checked, attrs, label, neutral = false, danger = false }) =>
  `<button type="button" class="switch${neutral ? ' neutral' : ''}${danger ? ' danger' : ''}" role="switch" aria-checked="${checked ? 'true' : 'false'}" aria-label="${esc(label)}" title="${esc(label)}" ${attrs}><span class="knob"></span></button>`;

const badge = (text, kind = '', title = '') => `<span class="badge ${kind}"${title ? ` title="${esc(title)}"` : ''}>${esc(text)}</span>`;

// ── header & tabs ───────────────────────────────────────────────────────────

export function renderHeader({ mode, busy = false, masked = false }) {
  const actions = [
    `<button type="button" class="btn ghost" data-refresh ${busy ? 'disabled' : ''} title="${TEXT.refresh}">${icon('refresh')}<span class="label">${TEXT.refresh}</span></button>`,
    `<button type="button" class="btn ghost${masked ? ' on' : ''}" data-mask aria-pressed="${masked ? 'true' : 'false'}" title="${masked ? TEXT.maskOnHint : TEXT.maskHint}">${icon(masked ? 'eyeOff' : 'eye')}<span class="label">${masked ? TEXT.maskOn : TEXT.mask}</span></button>`,
    `<button type="button" class="btn ghost danger" data-close-all title="${TEXT.closeAll}">${icon('power')}<span class="label">${TEXT.closeAll}</span></button>`
  ].join('');
  return `<header class="top">
  <span class="mark">${icon('logo', 16)}</span>
  <div class="titles"><div class="title">${TEXT.title}${mode === 'mcp' ? ' <span class="title-tag">MCP</span>' : ''}</div><div class="sub">${mode === 'mcp' ? TEXT.subtitleMcp : TEXT.subtitleDsh}</div></div>
  <div class="grow"></div>
  <div class="actions">${actions}</div>
</header>`;
}

export function tabsFor(mode) {
  return mode === 'mcp' ? ['hosts', 'processes', 'settings', 'diagnostics'] : ['hosts', 'settings', 'diagnostics'];
}

export function renderTabs({ mode, tab, state }) {
  const hosts = state?.hosts ?? [];
  const counts = {
    hosts: `${state?.totals?.connected ?? 0}/${hosts.length}`,
    processes: String(state?.instances?.length ?? 0),
    settings: '',
    diagnostics: diagnosticsCounters(state, mode).failures > 0 ? String(diagnosticsCounters(state, mode).failures) : ''
  };
  return `<nav class="tabs" role="tablist">${tabsFor(mode)
    .map(
      (key) =>
        `<button type="button" role="tab" class="tab${key === tab ? ' on' : ''}" aria-selected="${key === tab}" data-tab="${key}">${TEXT.tabs[key]}${counts[key] ? `<span class="count${key === 'diagnostics' ? ' warn' : ''}">${esc(counts[key])}</span>` : ''}</button>`
    )
    .join('')}</nav>`;
}

// ── hosts ───────────────────────────────────────────────────────────────────

/** Live MCP servers that answered (the ones an "open" can go to). */
const liveInstances = (state) => (state?.instances ?? []).filter((instance) => !instance.error);
const clientName = (instance) =>
  instance?.client && typeof instance.client.name === 'string' ? `${instance.client.name}${instance.client.version ? ` ${instance.client.version}` : ''}` : '（未初始化）';

/** Header action: with exactly one MCP server (or in DSH) connect / disconnect / retry; with none or several, the process rows below own it. */
function primaryAction(host, state, mode) {
  if (mode === 'mcp' && liveInstances(state).length !== 1) return '';
  const { key } = hostState(host);
  const alias = esc(host.alias);
  if (key === 'ready' || key === 'connecting') return `<button type="button" class="btn sm" data-action="close" data-alias="${alias}">${TEXT.disconnect}</button>`;
  return `<button type="button" class="btn sm primary" data-action="open" data-alias="${alias}">${key === 'paused' ? TEXT.retry : TEXT.open}</button>`;
}

/** The always-visible status line: state, uptime, sessions, commands. */
function hostStatus(host) {
  const { key, label } = hostState(host);
  const parts = [label];
  if (key === 'ready' && host.connectedSeconds) parts.push(`已连 ${span(host.connectedSeconds)}`);
  const sessions = host.sessions?.length ?? 0;
  if (sessions > 0) parts.push(`${sessions} ${TEXT.sessions}`);
  if ((host.commands ?? 0) > 0) parts.push(`${host.commands} ${TEXT.commands}`);
  return parts.map(esc).join(' · ');
}

/** Connection counters, only the ones that are non-zero. */
function hostCounters(host) {
  return [host.connects ? `${host.connects} 次建连` : '', host.reconnects ? `${host.reconnects} 次重连` : '', host.failures ? `${host.failures} 次建连失败` : '', host.handshakeTimeouts ? `${host.handshakeTimeouts} 次握手超时` : '']
    .filter(Boolean)
    .map(esc)
    .join(' · ');
}

/** One row per live MCP server, with its own connect/disconnect. */
function processRows(host, state) {
  const instances = liveInstances(state);
  if (instances.length === 0) return `<div class="muted small">${TEXT.noProcesses}</div>`;
  const reports = new Map((host.instances ?? []).map((report) => [report.pid, report]));
  return instances
    .map((instance) => {
      const { key, label } = hostState(reports.get(instance.pid) ?? { state: 'idle' });
      const connected = key === 'ready' || key === 'connecting';
      return `<div class="proc"><span class="dot ${key}"></span><span class="ell">${esc(clientName(instance))} <span class="muted small">pid ${esc(instance.pid)}</span></span><span class="muted small">${esc(label)}</span><button type="button" class="btn sm${connected ? '' : ' primary'}" data-action="${connected ? 'close' : 'open'}" data-alias="${esc(host.alias)}" data-pid="${esc(instance.pid)}">${connected ? TEXT.disconnect : TEXT.open}</button></div>`;
    })
    .join('');
}

const field = (label, value) => `<div class="kv"><span class="k">${esc(label)}</span><span class="v">${value}</span></div>`;

/** The endpoint as text; the masked view never puts it in the DOM at all. */
export function addressText(host) {
  return `${host.user ?? ''}@${host.host}:${host.port}`;
}

/**
 * A screenshot-safe mosaic block sized like the endpoint it replaces. The real
 * address is only used for the width and is never emitted, so neither a
 * screenshot nor inspecting the DOM reveals it.
 */
export function mosaicHtml(host) {
  const characters = Math.max(5, Math.min(22, addressText(host).length));
  return `<span class="mosaic" role="img" aria-label="${esc(TEXT.maskOn)}" style="width:${(characters * 0.55).toFixed(2)}em"></span>`;
}

/**
 * One host as a self-contained card: identity, address and key, status,
 * counters, the two switches and the per-host overrides, failures, the last
 * command, sessions, and (MCP) the process rows. Everything is visible at
 * once — no side panel to open.
 */
export function renderHostCard(host, { state, mode }) {
  const { key } = hostState(host);
  const alias = esc(host.alias);
  const masked = state?.settings?.maskAddresses === true;
  const editable = host.source === 'ssh-config';
  const idle = host.idleTimeoutMs === null || host.idleTimeoutMs === undefined ? '' : String(Math.round(host.idleTimeoutMs / 1000));
  const effective = Math.round((host.effectiveIdleTimeoutMs ?? 0) / 1000);
  const sessions = host.sessions ?? [];
  const counters = hostCounters(host);
  const failures = [
    host.lastFailure
      ? `<div class="failure"><b>${esc(host.lastFailure.code)}</b> · ${esc(host.lastFailure.tool)} · ${esc(age(host.lastFailure.ageSeconds))}${host.callFailures ? ` · 共 ${esc(host.callFailures)} 次` : ''}<div class="msg">${esc(host.lastFailure.message)}</div></div>`
      : '',
    host.lastError && key !== 'ready' ? `<div class="failure"><b>${TEXT.connection}</b><div class="msg">${esc(host.lastError)}</div></div>` : ''
  ]
    .filter(Boolean)
    .join('');
  return `<article class="host" data-alias="${alias}">
  <header class="host-head">
    <span class="dot ${key}"></span>
    <div class="host-id"><span class="name ell">${alias}</span>${host.prod ? badge('PROD', 'prod', TEXT.prodHint) : ''}${host.hidden ? badge(TEXT.hidden, 'muted', TEXT.hiddenHint) : ''}</div>
    <div class="host-actions">${primaryAction(host, state, mode)}${editable ? `<button type="button" class="btn sm ghost" data-edit="${alias}">${TEXT.editShort}</button>` : ''}</div>
  </header>
  <div class="facts">
    ${field(TEXT.address, masked ? mosaicHtml(host) : esc(addressText(host)))}
    ${field(TEXT.key, esc(host.keyName ?? '—'))}
    ${editable ? '' : field(TEXT.source, TEXT.sourceConfig)}
    ${host.hostKey ? field(TEXT.hostKey, `${esc(host.hostKey.status)}${host.hostKey.type ? ` · ${esc(host.hostKey.type)}` : ''}`) : ''}
    ${field(TEXT.state, hostStatus(host))}
  </div>
  ${counters ? `<div class="muted small">${counters}</div>` : ''}
  <div class="host-controls">
    <div class="switch-row" title="${esc(TEXT.hiddenHint)}"><span class="toggle-label${host.hidden ? '' : ' on'}">${TEXT.visible}</span>${switchHtml({ checked: host.hidden === true, neutral: true, label: TEXT.hiddenHint, attrs: `data-toggle data-field="hidden" data-alias="${alias}"` })}<span class="toggle-label${host.hidden ? ' on' : ''}">${TEXT.hidden}</span></div>
    <div class="switch-row" title="${esc(TEXT.prodHint)}">${switchHtml({ checked: host.prod === true, danger: true, label: TEXT.prodHint, attrs: `data-toggle data-field="prod" data-alias="${alias}"` })}<span class="toggle-label prod${host.prod ? ' on' : ''}">${TEXT.prod}</span>${host.prod ? `<span class="hint">${TEXT.prodShort}</span>` : ''}</div>
    <label class="inline-field" title="${esc(TEXT.idleOverrideDesc)}"><span>${TEXT.idleOverride}</span><input class="num" type="number" min="0" inputmode="numeric" placeholder="全局 ${effective}" value="${esc(idle)}" data-meta-input data-field="idleTimeoutMs" data-alias="${alias}"></label>
  </div>
  <label class="inline-field wide"><span>${TEXT.remark}</span><input class="text" maxlength="500" placeholder="${TEXT.remarkPlaceholder}" value="${esc(host.remark ?? '')}" data-meta-input data-field="remark" data-alias="${alias}"></label>
  ${failures}
  ${
    host.lastCommand
      ? `<div class="host-line"><span class="k">${TEXT.lastCommand}</span><code class="cmd-inline" title="${esc(host.lastCommand)}">${esc(host.lastCommand)}</code><span class="muted small">${esc(age(host.lastCommandAgeSeconds ?? host.lastCommandSeconds))}</span></div>`
      : ''
  }
  ${
    sessions.length > 0
      ? `<div class="host-procs"><div class="block-title">${TEXT.sessions} <span class="count">${sessions.length}</span></div>${sessions
          .map(
            (session) =>
              `<div class="proc"><span class="dot ${session.alive === false ? 'down' : 'ready'}"></span><span class="ell">${esc(session.name)} <span class="muted small">${esc(session.ownerShort ?? session.owner ?? '')}</span></span><span class="muted small">${esc(session.commands ?? 0)} ${TEXT.commands}${session.idleSeconds !== undefined ? ` · 空闲 ${esc(span(session.idleSeconds))}` : ''}</span></div>`
          )
          .join('')}</div>`
      : ''
  }
  ${mode === 'mcp' ? `<div class="host-procs"><div class="block-title">${TEXT.perProcess}</div>${processRows(host, state)}</div>` : ''}
</article>`;
}

export function renderHosts(state, { mode }) {
  const hosts = state?.hosts ?? [];
  const hidden = hosts.filter((host) => host.hidden).length;
  const prod = hosts.filter((host) => host.prod).length;
  const chips = [hidden ? badge(`${hidden} 台隐藏`, 'muted') : '', prod ? badge(`${prod} 台生产`, 'prod') : ''].join('');
  return `<section class="pane">
  <div class="note">${mode === 'mcp' ? TEXT.hostsNoteMcp : TEXT.hostsNoteDsh}${chips ? ` <span class="chips">${chips}</span>` : ''}</div>
  ${hosts.length === 0 ? `<div class="empty">${TEXT.noHosts}</div>` : `<div class="hosts">${hosts.map((host) => renderHostCard(host, { state, mode })).join('')}</div>`}
</section>`;
}

// ── processes (MCP) ─────────────────────────────────────────────────────────

export function renderProcesses(state) {
  const instances = state?.instances ?? [];
  const rows = instances
    .map((instance) => {
      const counters = instance.diagnostics?.counters;
      return `<div class="row static">
  <span class="dot ${instance.error ? 'down' : (instance.connected ?? 0) > 0 ? 'ready' : 'idle'}"></span>
  <div class="who"><div class="name"><span class="ell">${esc(clientName(instance))}</span>${instance.followsDsh ? badge('其他状态文件', 'warn', `${TEXT.followsOther}：${instance.statePath ?? ''}`) : ''}</div><div class="sub">pid ${esc(instance.pid)}${instance.version ? ` · v${esc(instance.version)}` : ''}${instance.startedAt ? ` · 启动于 ${esc(age((Date.now() - instance.startedAt) / 1000))}` : ''}</div></div>
  <div class="what">${
    instance.error
      ? `<span class="fail">无法连接控制端口：${esc(instance.error)}</span>`
      : `<div>${esc(instance.connected ?? 0)} / ${esc(instance.hostCount ?? 0)} 台已连接</div>${counters ? `<div class="muted small">${['toolCalls', 'failures', 'policyDenials', 'timeouts'].map((name) => `${TEXT.counters[name]} ${esc(counters[name] ?? 0)}`).join(' · ')}</div>` : ''}`
  }</div>
  <div class="act">${instance.error ? '' : `<button type="button" class="btn sm" data-action="close_all" data-pid="${esc(instance.pid)}">${TEXT.closeProcess}</button>`}</div>
</div>`;
    })
    .join('');
  return `<section class="pane"><div class="note">${TEXT.processesNote}</div>${rows ? `<div class="list">${rows}</div>` : `<div class="empty">${TEXT.noProcesses}</div>`}</section>`;
}

// ── settings ────────────────────────────────────────────────────────────────

const setRow = (title, desc, control) => `<div class="set"><div class="set-text"><div class="set-title">${title}</div><div class="set-desc">${desc}</div></div><div class="set-ctl">${control}</div></div>`;
const HOST_KEY_LABELS = { strict: '严格校验', warn: '仅提醒（记录并继续）', off: '不检查' };
const numberInput = (name, value, scale, attrs = '') =>
  `<input class="num" type="number" inputmode="numeric" value="${esc(value)}" data-setting-input="${name}" data-scale="${scale}" ${attrs}>`;

export function renderSettings(state, { mode }) {
  const s = state?.settings ?? {};
  const analysis = state?.analysis;
  const analysisNote = analysis && analysis.available === false && analysis.reason ? `（当前不可用：${esc(analysis.reason)}）` : '';
  const panel = state?.panel;
  return `<section class="pane">
  ${
    mode === 'dsh'
      ? `<div class="group"><div class="card">${setRow(TEXT.sshVisible, TEXT.sshVisibleDesc, switchHtml({ checked: s.sshVisible !== false, label: TEXT.sshVisible, attrs: 'data-setting-toggle="sshVisible"' }))}</div></div>`
      : ''
  }
  <div class="group"><div class="group-title">${TEXT.groupOutput}</div><div class="card">
    ${setRow(TEXT.maxOutputBytes, TEXT.maxOutputBytesDesc, numberInput('maxOutputBytes', Math.max(1, Math.round((s.maxOutputBytes ?? 32768) / 1024)), 1024, 'min="1" max="4096"'))}
    ${setRow(TEXT.logAnalysis, `${TEXT.logAnalysisDesc}${analysisNote}`, switchHtml({ checked: s.logAnalysis === true, label: TEXT.logAnalysis, attrs: 'data-setting-toggle="logAnalysis"' }))}
  </div></div>
  <div class="group"><div class="group-title">${TEXT.groupConnection}</div><div class="card">
    ${setRow(TEXT.idleTimeout, TEXT.idleTimeoutDesc, numberInput('idleTimeoutMs', Math.round((s.idleTimeoutMs ?? 0) / 1000), 1000, 'min="0"'))}
    ${setRow(TEXT.transferTimeout, TEXT.transferTimeoutDesc, numberInput('transferTimeoutMs', Math.round((s.transferTimeoutMs ?? 600000) / 1000), 1000, 'min="5" max="7200"'))}
    ${s.hostKeyPolicy ? setRow(TEXT.hostKeyPolicy, TEXT.hostKeyPolicyDesc, `<code>${esc(HOST_KEY_LABELS[s.hostKeyPolicy] ?? s.hostKeyPolicy)}</code>`) : ''}
  </div></div>
  <div class="group"><div class="group-title">${TEXT.groupPrivacy}</div><div class="card">
    ${setRow(TEXT.maskAddresses, TEXT.maskAddressesDesc, switchHtml({ checked: s.maskAddresses === true, label: TEXT.maskAddresses, attrs: 'data-setting-toggle="maskAddresses"' }))}
  </div></div>
  <div class="group"><div class="group-title">${TEXT.groupPolicy}</div><div class="card prose">
    <p>${TEXT.policyText}</p>
    <div class="set-title">${TEXT.logExamples}</div>
    <pre class="code">journalctl -u &lt;unit&gt; --since "&lt;time&gt;" -n &lt;lines&gt;
tail -n &lt;lines&gt; &lt;file&gt;
grep -m &lt;matches&gt; -n &lt;pattern&gt; &lt;file&gt;
sed -n "&lt;start&gt;,&lt;end&gt;p" &lt;file&gt;</pre>
  </div></div>
  ${
    panel
      ? `<div class="foot">${panel.statePath ? `<div>${TEXT.statePath}：<code>${esc(panel.statePath)}</code>（${TEXT.statePathNote}）</div>` : ''}${panel.sshConfigPath ? `<div>${TEXT.sshConfig}：<code>${esc(panel.sshConfigPath)}</code></div>` : ''}${(panel.warnings ?? []).map((warning) => `<div class="fail">${esc(warning)}</div>`).join('')}</div>`
      : ''
  }
</section>`;
}

// ── diagnostics ─────────────────────────────────────────────────────────────

/** DSH: its own buffer; MCP: the sum over every server. */
export function diagnosticsCounters(state, mode) {
  const zero = { toolCalls: 0, failures: 0, policyDenials: 0, timeouts: 0, slowCalls: 0 };
  if (mode !== 'mcp') return { ...zero, ...(state?.diagnostics?.counters ?? {}) };
  for (const instance of state?.instances ?? []) {
    const counters = instance.diagnostics?.counters ?? {};
    for (const key of Object.keys(zero)) zero[key] += Number(counters[key] ?? 0);
  }
  return zero;
}

function diagnosticsEvents(state, mode) {
  if (mode !== 'mcp') return (state?.diagnostics?.events ?? []).map((event) => ({ ...event, pid: null }));
  return (state?.instances ?? []).flatMap((instance) => (instance.diagnostics?.events ?? []).map((event) => ({ ...event, pid: instance.pid })));
}

export function renderDiagnostics(state, { mode }) {
  const counters = diagnosticsCounters(state, mode);
  const events = diagnosticsEvents(state, mode)
    .sort((a, b) => (b.at ?? 0) - (a.at ?? 0))
    .slice(0, 50);
  const now = state?.generatedAt ?? Date.now();
  const tiles = ['toolCalls', 'failures', 'policyDenials', 'timeouts', 'slowCalls']
    .map((name) => `<div class="tile${name !== 'toolCalls' && counters[name] > 0 ? ' warn' : ''}"><div class="tile-num">${esc(counters[name])}</div><div class="tile-label">${TEXT.counters[name]}</div></div>`)
    .join('');
  const rows = events
    .map(
      (event) =>
        `<tr class="${event.outcome === 'ok' ? '' : 'bad'}"><td>${esc(age((now - (event.at ?? now)) / 1000))}</td><td>${esc(event.tool)}</td><td>${esc(event.host ?? '—')}</td><td>${esc(event.commandKind ?? '')}</td><td>${esc(event.outcome)}${event.reason ? ` · ${esc(event.reason)}` : ''}</td><td class="r">${esc(event.durationMs ?? 0)} ms</td>${mode === 'mcp' ? `<td class="muted">${esc(event.pid)}</td>` : ''}</tr>`
    )
    .join('');
  return `<section class="pane">
  <div class="tiles">${tiles}</div>
  <div class="group"><div class="group-title">${TEXT.recentEvents}</div>${
    rows
      ? `<div class="card flush"><table class="events"><thead><tr><th>时间</th><th>工具</th><th>主机</th><th>命令</th><th>结果</th><th class="r">耗时</th>${mode === 'mcp' ? '<th>pid</th>' : ''}</tr></thead><tbody>${rows}</tbody></table></div>`
      : `<div class="empty">${TEXT.noEvents}</div>`
  }</div>
</section>`;
}

// ── dialog, banners, footer ─────────────────────────────────────────────────

export function renderEditDialog(host, { error = null, saving = false, masked = false } = {}) {
  if (!host) return '';
  const keyEditable = typeof host.keyName === 'string' && host.keyName.length > 0 && !host.keyName.startsWith('agent:');
  return `<div class="backdrop" data-dialog-backdrop>
  <form class="dialog" role="dialog" aria-modal="true" aria-label="${TEXT.editDialog}">
    <div class="dialog-title">${TEXT.editDialog}</div>
    <div class="dialog-desc">${TEXT.editDialogDesc}</div>
    <div class="dialog-host">${masked ? mosaicHtml(host) : esc(addressText(host))}</div>
    <label class="field"><span>${TEXT.hostNameLabel}</span><input class="text" name="alias" value="${esc(host.alias)}" autocomplete="off" spellcheck="false" ${saving ? 'disabled' : ''}></label>
    <label class="field"><span>${TEXT.keyNameLabel}</span><input class="text" name="key" value="${esc(host.keyName ?? '—')}" autocomplete="off" spellcheck="false" ${keyEditable && !saving ? '' : 'disabled'}></label>
    <div class="dialog-desc">${TEXT.editDialogWarning}</div>
    ${error ? `<div class="fail">${esc(error)}</div>` : ''}
    <div class="dialog-actions"><button type="button" class="btn" data-dialog-cancel ${saving ? 'disabled' : ''}>${TEXT.cancel}</button><button type="submit" class="btn primary" ${saving ? 'disabled' : ''}>${TEXT.save}</button></div>
  </form>
</div>`;
}

export function renderBanners({ error, notice }) {
  return `${error ? `<div class="banner err">${TEXT.loadFailed}：${esc(error)}</div>` : ''}${notice ? `<div class="banner warn">${TEXT.saveFailed}：${esc(notice)}</div>` : ''}`;
}

export function renderFooter(state, { mode }) {
  if (!state?.totals) return '';
  const hosts = state.hosts ?? [];
  const parts = [`${state.totals.hosts} 台主机`, `${state.totals.connected} 已连接`, `${state.totals.sessions} 会话`];
  if (mode === 'mcp') parts.push(`${state.instances?.length ?? 0} 个进程`);
  if (mode === 'dsh' && state.settings?.sshVisible === false) parts.push('SSH 工具已对会话关闭');
  const hidden = hosts.filter((host) => host.hidden).length;
  if (hidden) parts.push(`${hidden} 台隐藏`);
  return `<footer class="status">${parts.map(esc).join(' · ')}</footer>`;
}

/** The body for one tab. */
export function renderTab(tab, state, options) {
  if (tab === 'processes' && options.mode === 'mcp') return renderProcesses(state);
  if (tab === 'settings') return renderSettings(state, options);
  if (tab === 'diagnostics') return renderDiagnostics(state, options);
  return renderHosts(state, options);
}
