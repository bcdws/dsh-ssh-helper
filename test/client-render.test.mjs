/**
 * Render the assistant panel without a browser.
 *
 * The client half is a plain script that registers a module through
 * `window.__ModuleLoader__`, so it can be loaded here with a minimal React
 * stand-in and rendered to a plain element tree. This catches the failures a
 * syntax check cannot: undefined components, a missing dictionary key leaking
 * as raw text, a row that lost its controls, or a layout that no longer carries
 * the responsive hooks.
 */
import { readFileSync } from 'node:fs';

const element = (type, props, ...children) => ({ type, props: props ?? {}, children: children.flat(Infinity) });
const stateQueue = [];
const React = {
  createElement: element,
  useState: (init) => [stateQueue.length > 0 ? stateQueue.shift() : typeof init === 'function' ? init() : init, () => {}],
  useMemo: (fn) => fn(),
  useEffect: () => {},
  useRef: (init) => ({ current: init }),
  useCallback: (fn) => fn
};

let registered;
globalThis.window = { __ModuleLoader__: { load: (module) => (registered = module) }, addEventListener: () => {}, removeEventListener: () => {} };
await import('../client.js');

const module = registered.factory((name) => (name === 'react' ? React : undefined));
const slots = [];
const ctx = {
  get: (name) => (name === 'slots' ? { inject: (_name, callback) => callback(), register: (definition, component) => (slots.push({ definition, component }), () => {}) } : undefined),
  slots: { inject: (_name, callback) => callback(), register: (definition, component) => (slots.push({ definition, component }), () => {}) }
};
module.apply(ctx);

const hosts = [
  {
    alias: 'web-host', host: '203.0.113.10', port: 22, user: 'root', keyName: 'web-host', source: 'ssh-config',
    state: 'ready', connected: true, connectedSeconds: 60, idleSeconds: 5, connects: 3, reconnects: 0, failures: 0,
    sessions: [{ name: 'main' }], hidden: false, remark: '生产 Web 主库',
    idleTimeoutMs: 30000, effectiveIdleTimeoutMs: 30000, lastError: null
  },
  {
    alias: 'db-host', host: '203.0.113.11', port: 22, user: 'root', keyName: 'db-host_rsa', source: 'ssh-config',
    state: 'idle', connected: false, connectedSeconds: 0, idleSeconds: null, connects: 0, reconnects: 0, failures: 0,
    sessions: [], hidden: true, retryPaused: true, handshakeTimeouts: 6, remark: '', idleTimeoutMs: null,
    effectiveIdleTimeoutMs: 0, lastError: 'ssh host "db-host" failed: timeout'
  }
];
const state = {
  hosts,
  settings: { idleTimeoutMs: 0, sshVisible: true, maxOutputBytes: 32768, transferTimeoutMs: 600000, logAnalysis: false },
  totals: { hosts: 2, connected: 1, sessions: 1, commands: 2 },
};

let pass = 0;
const failures = [];
const check = (name, ok, detail) => (ok ? (pass += 1) : failures.push(`${name}: ${detail}`));
const textOf = (node) => {
  if (node === null || node === undefined || node === false) return '';
  if (typeof node === 'string' || typeof node === 'number') return String(node);
  if (Array.isArray(node)) return node.map(textOf).join('');
  return (node.children ?? []).map(textOf).join('');
};
const collect = (node, predicate, found = []) => {
  if (node === null || typeof node !== 'object') return found;
  if (Array.isArray(node)) {
    for (const child of node) collect(child, predicate, found);
    return found;
  }
  if (predicate(node)) found.push(node);
  for (const child of node.children ?? []) collect(child, predicate, found);
  return found;
};
const classesOf = (node) => String(node?.props?.className ?? '');
const byClass = (tree, name) => collect(tree, (node) => classesOf(node).split(/\s+/).includes(name));

// One panel render with the assistant already holding data.
stateQueue.push(state, null, null, false, state.settings, {}, state.hosts[0]);
const panel = slots.find((entry) => entry.definition.name === 'main' && entry.definition.key === 'ssh-assistant');
check('panel-registered', panel !== undefined, JSON.stringify(slots.map((entry) => entry.definition)));
check('sidebar-row-registered', slots.some((entry) => entry.definition.name === 'sidebar.panellist' && entry.definition.id === 'ssh-assistant'), 'no sidebar entry');
check('overlay-registered', slots.some((entry) => entry.definition.name === 'shell.overlay'), 'no overlay');

/** Expand function components so the tree is plain host elements. */
const expand = (node) => {
  if (node === null || typeof node !== 'object') return node;
  if (Array.isArray(node)) return node.map(expand);
  if (typeof node.type === 'function') return expand(node.type({ ...node.props, children: node.children }));
  return { ...node, children: (node.children ?? []).map(expand) };
};

const tree = expand(panel.component());
check('renders-without-throwing', tree !== null && tree !== undefined, 'null tree');
check('shell', byClass(tree, 'ssh-root').length === 1 && byClass(tree, 'ssh-content').length === 1, 'missing shell');
check('rows-one-per-host', byClass(tree, 'ssh-row').length === 2, `${byClass(tree, 'ssh-row').length} rows`);
check('header-row', byClass(tree, 'ssh-th').length === 1, `${byClass(tree, 'ssh-th').length} header rows`);
check('no-production-mark', byClass(tree, 'ssh-tag').length === 0, 'there must be no production mark anywhere');
check('row-identity', byClass(tree, 'ssh-row').every((row) => byClass(row, 'ssh-keycell').length === 1), 'each row needs one key cell');
check('row-controls', byClass(tree, 'ssh-row').every((row) => byClass(row, 'ssh-controls').length === 1), 'each row needs one control cluster');
// Per row: the hidden switch and the prod switch; plus the settings switches.
check('row-switches', byClass(tree, 'ssh-mini').length === 3 && byClass(tree, 'ssh-switch').length === 6, `${byClass(tree, 'ssh-switch').length} switches / ${byClass(tree, 'ssh-mini').length} labelled inline controls`);

// Settings rows: control — switch or number box — in the fixed left column,
// with every title and description starting on the same vertical line.
const setrows = byClass(tree, 'ssh-setrow');
check('setting-rows', setrows.length === 4, `${setrows.length} settings rows`);
const leftSwitchRows = setrows.filter((row) => byClass(byClass(row, 'ssh-setctl')[0] ?? { children: [] }, 'ssh-switch').length > 0);
const leftNumberRows = setrows.filter((row) => byClass(byClass(row, 'ssh-setctl')[0] ?? { children: [] }, 'ssh-num').length > 0);
check('visibility-switch-in-connections', byClass(byClass(byClass(tree, 'ssh-sec-row')[0] ?? { children: [] }, 'ssh-mini')[0] ?? { children: [] }, 'ssh-switch').length === 1, 'the tool visibility switch belongs to the connections section');
check('number-in-left-column', leftNumberRows.length === 3, `${leftNumberRows.length} rows carry a number box on the left`);
check('no-right-control-column', byClass(tree, 'ssh-setval').length === 0, 'numeric controls must sit in the left column too');
// The left column must be a left-aligned stack: every control starts at the same
// x, so the column cannot look centred.
const clientSource = readFileSync(new URL('../client.js', import.meta.url), 'utf8');
check('control-column-centred', /\.ssh-setctl\{[^}]*justify-content:center/.test(clientSource), 'ssh-setctl must centre its control in the column');
check('numeric-centred', /\.ssh-setctl \.ssh-num\{[^}]*text-align:center/.test(clientSource), 'numeric settings must be centred in their column');
check('control-text-margin', /\.ssh-setrow\{[^}]*gap:6px 18px/.test(clientSource), 'the control column needs a margin before the text');
check('content-padding', /\.ssh-content\{[^}]*padding:26px 52px 36px/.test(clientSource), 'the panel needs generous side padding');
check('top-padding-matches', /\.ssh-top\{[^}]*padding:14px 52px/.test(clientSource), 'the header must share the content padding');
// The activity trail is gone: the panel manages connections, and a log of what
// the agent ran is not something the operator reads.
check('no-activity-section', byClass(tree, 'ssh-act').length === 0 && byClass(tree, 'ssh-activity-empty').length === 0 && !textOf(tree).includes('最近执行'), 'the activity section must not render');
// Settings are grouped into captioned cards rather than one long list.
check('settings-grouped', byClass(tree, 'ssh-group').length === 2 && byClass(tree, 'ssh-group-title').length === 2, `${byClass(tree, 'ssh-group').length} groups`);
// The policy explanation is prose, not a settings row: it must not inherit the
// settings grid (that left a deep indent and a half-empty card).
check('policy-is-prose', byClass(tree, 'ssh-prose').length === 1, `${byClass(tree, 'ssh-prose').length} prose blocks`);
check('policy-not-a-setting-row', byClass(tree, 'ssh-prose').every((block) => byClass(block, 'ssh-setrow').length === 0), 'policy must not reuse the settings grid');
check('privacy-note', /敏感日志/.test(textOf(tree)), 'log analysis must disclose that logs are sent to the model provider');
check('paused-retry-label', /已暂停/.test(textOf(tree)) && /重试/.test(textOf(tree)), 'paused host must show retry');

// No text key may leak into the UI as raw text.
const rendered = textOf(tree);
const rawKey = ['sessionsUnit', 'sshVisibleDesc', 'sshVisibleShort', 'maxOutputBytesDesc', 'idleTimeoutDesc', 'connectionsHint', 'hiddenHint'].find((key) => rendered.includes(key));
check('no-raw-keys', rawKey === undefined, `leaked ${rawKey}`);
check('renders-chinese', rendered.includes('可见') && rendered.includes('隐藏') && rendered.includes('SSH 助手') && rendered.includes('命令护栏') && rendered.includes('日志旁路分析'), 'labels missing');
check('shows-key-metadata', byClass(tree, 'ssh-keyname').some((node) => String(node.props.title).includes('web-host') && String(node.props.title).includes('203.0.113.10')), 'key cell title must identify the host');
check('address-not-visible', byClass(tree, 'ssh-row').every((row) => !textOf(row).includes('root@203.0.113.10')), 'the row must show the host alias, not the address');
check('host-editable', byClass(tree, 'ssh-keyname').length === 2, `${byClass(tree, 'ssh-keyname').length} host buttons`);
const keyCells = byClass(tree, 'ssh-keyfile');
check('key-editable', keyCells.length === 2 && keyCells.map((node) => textOf(node)).join('|') === 'web-host|db-host_rsa', `${keyCells.length} key cells: ${keyCells.map((node) => textOf(node)).join('|')}`);
check('key-column-header', byClass(tree, 'ssh-th').some((head) => byClass(head, 'ssh-filecell').some((cell) => textOf(cell) === '密钥')), 'key column header missing');
check('edit-dialog', byClass(tree, 'ssh-dialog').length === 1, 'edit dialog missing');
check('edit-dialog-fields', byClass(tree, 'ssh-dialog-input').length === 2 && byClass(tree, 'ssh-dialog-input').map((node) => String(node.props.value)).join('|') === 'web-host|web-host', JSON.stringify(byClass(tree, 'ssh-dialog-input').map((node) => node.props.value)));
check('edit-dialog-actions', /取消/.test(textOf(tree)) && /保存/.test(textOf(tree)), 'dialog action labels missing');

// The profile select is gone: each host row carries one neutral hidden switch
// with "visible" on the left and "hidden" on the right, and the panel header
// carries the master sshVisible switch.
check('no-profile-select', byClass(tree, 'ssh-select').length === 0, `${byClass(tree, 'ssh-select').length} selects left`);
check('no-capability-chips', byClass(tree, 'ssh-cap').length === 0, 'capability chips must stay gone');
const rowSwitches = byClass(tree, 'ssh-row').map((row) => byClass(row, 'ssh-switch'));
check('hidden-and-prod-switch-per-row', rowSwitches.length === 2 && rowSwitches.every((switches) => switches.length === 2), JSON.stringify(rowSwitches.map((switches) => switches.length)));
const prodToggles = byClass(tree, 'ssh-prod-toggle');
check('prod-switch-off-by-default', prodToggles.length === 2 && prodToggles.every((toggle) => byClass(toggle, 'ssh-switch')[0]?.props?.['aria-checked'] === 'false'), JSON.stringify(prodToggles.map((toggle) => byClass(toggle, 'ssh-switch')[0]?.props?.['aria-checked'])));
check('no-prod-badge-when-unset', byClass(tree, 'ssh-prod-badge').length === 0, `${byClass(tree, 'ssh-prod-badge').length} badges`);
check('hidden-switch-state', rowSwitches[0][0].props['aria-checked'] === 'false' && rowSwitches[1][0].props['aria-checked'] === 'true', JSON.stringify(rowSwitches.map((switches) => switches[0]?.props?.['aria-checked'])));
check('hidden-switch-neutral', rowSwitches.every((switches) => switches[0].props.className.includes('ssh-switch-neutral')), JSON.stringify(rowSwitches.map((switches) => switches[0]?.props?.className)));
const labels = byClass(tree, 'ssh-hidden-label');
check('hidden-labels', labels.length === 4 && labels[0].props.className.includes('is-on') && !labels[1].props.className.includes('is-on') && !labels[2].props.className.includes('is-on') && labels[3].props.className.includes('is-on'), JSON.stringify(labels.map((label) => label.props.className)));
check('hidden-count', rendered.includes('1 台隐藏'), rendered.slice(-80));

console.log(`${pass}/${pass + failures.length} passed`);
for (const failure of failures) console.log(`FAIL ${failure}`);
process.exit(failures.length === 0 ? 0 : 2);


