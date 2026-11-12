/** Assistant API: routing, loopback gate, write credential (header or cookie), and mutations. */
import { createAssistantApi } from '../dsh/api.js';

const calls = [];
const settingsNotices = [];
let hostRefreshes = 0;
let renamed = null;
let renamedHost = null;
let edited = null;
const hosts = new Map([
  ['web-host', { alias: 'web-host', hidden: false, remark: '', idleTimeoutMs: null }],
  ['prod-1', { alias: 'prod-1', hidden: true, remark: '', idleTimeoutMs: null }]
]);
const connectionStates = new Map();
const pool = {
  has: (alias) => hosts.has(alias),
  status: () =>
    [...hosts.keys()].map((alias) => ({
      alias,
      host: '10.0.0.1',
      port: 22,
      user: 'root',
      keyName: `${alias}_rsa`,
      state: 'idle',
      connected: false,
      connectedSeconds: 0,
      idleSeconds: null,
      connects: 0,
      reconnects: 0,
      failures: 0,
      sessions: [],
      lastError: null,
      hidden: hosts.get(alias).hidden,
      remark: hosts.get(alias).remark,
      idleTimeoutMs: hosts.get(alias).idleTimeoutMs,
      effectiveIdleTimeoutMs: 0
    })),
  connection: (alias) => ({
    get state() {
      return connectionStates.get(alias) ?? 'idle';
    },
    ensure: async () => {
      calls.push(`ensure:${alias}`);
    },
    close: (reason) => {
      calls.push(`close:${alias}:${reason}`);
      connectionStates.set(alias, 'idle');
    }
  }),
  closeAll: () => calls.push('closeAll')
};
/** The retained settings the panel still exposes (sshVisible is the safety master switch). */
const settings = { idleTimeoutMs: 0, maxOutputBytes: 32768, transferTimeoutMs: 600000, sshVisible: true, logAnalysis: false, maskAddresses: false };
/** Keys removed in the slimming: they must never come back through the API. */
const DELETED_SETTINGS = ['timeoutMultiplier', 'timeoutFloorMs', 'timeoutCeilingMs', 'maxLogLines', 'blockResourceSpikes', 'productionEnforced'];
const settingsPatches = [];
const store = {
  settings: () => ({ ...settings }),
  setSettings: (patch) => {
    settingsPatches.push(patch);
    calls.push(`setSettings:${JSON.stringify(patch)}`);
    Object.assign(settings, patch);
    return { ...settings };
  },
  host: (alias) => hosts.get(alias) ?? { remark: '', hidden: false, idleTimeoutMs: null },
  setHost: (alias, patch) => {
    calls.push(`setHost:${alias}:${JSON.stringify(patch)}`);
    Object.assign(hosts.get(alias), patch);
    return hosts.get(alias);
  }
};


const seenLimits = [];
const api = createAssistantApi({
  pool,
  store,
  config: { hostKeyPolicy: 'warn' },
  logger: undefined,
  diagnostics: (options) => {
    seenLimits.push(options);
    return { counters: { toolCalls: 0 }, events: [] };
  },
  onSettingsChanged: () => settingsNotices.push(Date.now()),
  // Close immediately in the test; production keeps the 20 s grace period.
  hiddenCloseDelayMs: 0,
  refreshHosts: () => { hostRefreshes += 1; },
  renameKey: async ({ alias, keyName }) => {
    renamed = { alias, keyName };
    return { changed: true, oldName: 'web-host', newName: keyName, references: 1 };
  },
  renameHost: async ({ alias, newAlias }) => {
    renamedHost = { alias, newAlias };
    return { changed: true, oldAlias: alias, newAlias, references: 1 };
  },
  editHost: async ({ alias, newAlias, keyName }) => {
    edited = { alias, newAlias, keyName };
    return { changed: true, aliasChanged: Boolean(newAlias), keyChanged: Boolean(keyName), references: 1 };
  }
});

/** A minimal node-http request double. */
function request({ method = 'GET', url = '/ssh-pool/state', headers = {}, body, peer = '127.0.0.1' }) {
  const chunks = body === undefined ? [] : [Buffer.from(JSON.stringify(body))];
  return {
    method,
    url,
    headers,
    socket: { remoteAddress: peer },
    async *[Symbol.asyncIterator]() {
      for (const chunk of chunks) yield chunk;
    }
  };
}

/** A minimal response double that keeps status, headers and payload. */
function response() {
  const state = { status: 0, body: '', headers: {} };
  return {
    state,
    writeHead(status, headers) {
      state.status = status;
      state.headers = headers ?? {};
    },
    end(payload) {
      state.body = payload ?? '';
    }
  };
}

const call = async (input) => {
  const res = response();
  await api.route.handler(request(input), res);
  let parsed = null;
  try {
    parsed = JSON.parse(res.state.body);
  } catch {
    parsed = null;
  }
  return { status: res.state.status, payload: parsed, cookie: res.state.headers['set-cookie'] };
};

let pass = 0;
const failures = [];
const check = (name, ok, detail) => (ok ? (pass += 1) : failures.push(`${name}: ${detail}`));

check('route-shape', api.route.kind === 'prefix' && api.route.path === '/ssh-pool', JSON.stringify(api.route));
check('token-injected', /__DSH_SSH_ASSISTANT__=\{"token":"[0-9a-f]{48}"\}/.test(api.indexInjection), api.indexInjection);

// The shared `<ssh-helper-panel>` element is preloaded from the boot page and
// served by this same route, from a fixed file list.
check('ui-injected', api.indexInjection.includes('src="/ssh-pool/ui/panel-element.js"'), api.indexInjection);
const uiElement = response();
await api.route.handler(request({ url: '/ssh-pool/ui/panel-element.js' }), uiElement);
check('ui-element-served', uiElement.state.status === 200 && String(uiElement.state.headers['content-type']).startsWith('text/javascript') && uiElement.state.body.includes("customElements.define('ssh-helper-panel'"), `${uiElement.state.status} ${uiElement.state.body.slice(0, 80)}`);
check('ui-element-no-cookie', uiElement.state.headers['set-cookie'] === undefined, String(uiElement.state.headers['set-cookie']));
const uiView = response();
await api.route.handler(request({ url: '/ssh-pool/ui/panel-view.js' }), uiView);
check('ui-view-served', uiView.state.status === 200 && uiView.state.body.includes('export const TEXT'), `${uiView.state.status} ${uiView.state.body.slice(0, 80)}`);
const uiUnknown = response();
await api.route.handler(request({ url: '/ssh-pool/ui/package.json' }), uiUnknown);
check('ui-fixed-list', uiUnknown.state.status === 404, String(uiUnknown.state.status));
const uiTraversal = response();
await api.route.handler(request({ url: '/ssh-pool/ui/../package.json' }), uiTraversal);
check('ui-no-traversal', uiTraversal.state.status !== 200 || !uiTraversal.state.body.includes('"name"'), `${uiTraversal.state.status} ${uiTraversal.state.body.slice(0, 80)}`);

const state = await call({});
check('get-state', state.status === 200 && state.payload.ok === true && state.payload.state.hosts.length === 2, JSON.stringify(state.payload).slice(0, 160));
check('state-refreshes-hosts', hostRefreshes >= 1, String(hostRefreshes));
check('state-default-limits', seenLimits[0] !== undefined && Object.keys(seenLimits[0]).length === 0, JSON.stringify(seenLimits[0]));
await call({ url: '/ssh-pool/state?events=2' });
check('state-events-param', seenLimits.at(-1)?.events === 2, JSON.stringify(seenLimits.at(-1)));
await call({ url: '/ssh-pool/state?events=0' });
check('state-events-zero', seenLimits.at(-1)?.events === 0, JSON.stringify(seenLimits.at(-1)));
await call({ url: '/ssh-pool/state?events=9999' });
check('state-events-forwarded', seenLimits.at(-1)?.events === 9999, 'the route validates and forwards; the buffer clamps to its size');
await call({ url: '/ssh-pool/state?events=abc' });
check('state-events-invalid', seenLimits.at(-1) !== undefined && Object.keys(seenLimits.at(-1)).length === 0, JSON.stringify(seenLimits.at(-1)));
check('state-has-no-key-path', !JSON.stringify(state.payload).includes('C:\\\\') && state.payload.state.hosts[0].keyName === 'web-host_rsa', 'only the key file name may cross the API');
check('state-has-no-policy', state.payload.state.hosts.every((host) => host.policy === undefined), JSON.stringify(state.payload.state.hosts));
check('state-has-no-activity-trail', state.payload.state.activity === undefined, JSON.stringify(state.payload.state.activity));
check('state-has-commands-total', state.payload.state.totals.commands === 0, JSON.stringify(state.payload.state.totals));
check('state-has-hidden', state.payload.state.hosts[0].hidden === false && state.payload.state.hosts[1].hidden === true, JSON.stringify(state.payload.state.hosts.map((host) => host.hidden)));
check('state-settings-shape', Object.keys(state.payload.state.settings).filter((key) => key !== 'hostKeyPolicy').sort().join(',') === 'idleTimeoutMs,logAnalysis,maskAddresses,maxOutputBytes,sshVisible,transferTimeoutMs', JSON.stringify(state.payload.state.settings));
check('state-settings-no-deleted-keys', DELETED_SETTINGS.every((key) => !(key in state.payload.state.settings)), JSON.stringify(state.payload.state.settings));
check('read-issues-cookie', /dsh_ssh_pool_token=[0-9a-f]{48}/.test(state.cookie ?? ''), String(state.cookie));
check('cookie-is-scoped', /Path=\/ssh-pool/.test(state.cookie ?? '') && /HttpOnly/.test(state.cookie ?? '') && /SameSite=Strict/.test(state.cookie ?? ''), String(state.cookie));
check('write-token-in-response', state.payload.token === api.token, 'the read must hand back the write credential');
check('token-not-in-state', !JSON.stringify(state.payload.state).includes(api.token), 'the state object itself stays credential-free');

const deniedToken = await call({ method: 'POST', url: '/ssh-pool/settings', headers: {}, body: { idleTimeoutMs: 9000 } });
check('post-needs-credential', deniedToken.status === 403 && settings.idleTimeoutMs === 0, JSON.stringify(deniedToken.payload));

const remote = await call({ method: 'POST', url: '/ssh-pool/settings', headers: { 'x-dsh-ssh-pool-token': api.token }, body: {}, peer: '10.1.2.3' });
check('loopback-only', remote.status === 403, JSON.stringify(remote.payload));

const crossSite = await call({ headers: { 'sec-fetch-site': 'cross-site' } });
check('cross-site-read-refused', crossSite.status === 403 && crossSite.payload.token === undefined, JSON.stringify(crossSite.payload));
const sameSite = await call({ headers: { 'sec-fetch-site': 'same-origin' } });
check('same-site-read-allowed', sameSite.status === 200 && typeof sameSite.payload.token === 'string', `status ${sameSite.status}`);

const authorized = { 'x-dsh-ssh-pool-token': api.token };
const meta = await call({ method: 'POST', url: '/ssh-pool/meta', headers: authorized, body: { alias: 'web-host', remark: '生产 Web 主库', hidden: true, caps: { read: true, files: true, packages: false, services: false }, idleTimeoutMs: 0 } });
check('post-meta', meta.status === 200 && hosts.get('web-host').remark === '生产 Web 主库' && hosts.get('web-host').hidden === true, JSON.stringify(calls.slice(-1)));
check('meta-does-not-forward-caps', !('caps' in hosts.get('web-host')), JSON.stringify(hosts.get('web-host')));
check('meta-returns-state', meta.payload.state.hosts[0].remark === '生产 Web 主库', JSON.stringify(meta.payload.state.hosts[0]));

// Hiding is also a disconnect for the panel's own pool: a hidden row must not
// keep a live transport. The MCP adapter is a separate process with its own
// pool and only reads state.json, so this never reaches it.
const closeCalls = () => calls.filter((entry) => entry.startsWith('close:web-host:')).length;
check('hide-closes-connection', closeCalls() === 1 && calls.at(-1) === 'close:web-host:hidden in the SSH assistant', JSON.stringify(calls.slice(-2)));
check('hide-reports-disconnect', meta.payload.disconnected === true, JSON.stringify(meta.payload).slice(0, 200));
const hiddenNote = await call({ method: 'POST', url: '/ssh-pool/meta', headers: authorized, body: { alias: 'web-host', remark: '隐藏时只改备注' } });
check('hidden-note-keeps-connection', hiddenNote.status === 200 && closeCalls() === 1 && hiddenNote.payload.disconnected === undefined, JSON.stringify(calls.slice(-2)));
const unhide = await call({ method: 'POST', url: '/ssh-pool/meta', headers: authorized, body: { alias: 'web-host', hidden: false } });
check('unhide-does-not-close', unhide.status === 200 && closeCalls() === 1 && hosts.get('web-host').hidden === false, JSON.stringify(calls.slice(-2)));
// A hide that lands while the handshake is still running: close() can only end
// a ready client, so the panel closes the transport that lands afterwards.
// `ensure()` on the same entry returns that in-flight handshake, not a new
// connect, so a hide never starts a connection of its own.
connectionStates.set('web-host', 'connecting');
const hideDuringConnect = await call({ method: 'POST', url: '/ssh-pool/meta', headers: authorized, body: { alias: 'web-host', hidden: true } });
await new Promise((resolve) => setImmediate(resolve));
check('hide-during-connect-closes-again', hideDuringConnect.status === 200 && closeCalls() === 3 && connectionStates.get('web-host') === 'idle', JSON.stringify(calls.slice(-4)));

// ── POST /settings: the retained knobs only ─────────────────────────────────
const settingsCall = await call({ method: 'POST', url: '/ssh-pool/settings', headers: authorized, body: { idleTimeoutMs: 30000, maxOutputBytes: 32768 } });
check('post-settings', settingsCall.status === 200 && settings.idleTimeoutMs === 30000 && settings.maxOutputBytes === 32768, JSON.stringify(settings));
check('post-settings-patch-is-retained-only', settingsPatches.length === 1 && Object.keys(settingsPatches[0]).sort().join(',') === 'idleTimeoutMs,maxOutputBytes', JSON.stringify(settingsPatches));
check('post-settings-response-shape', Object.keys(settingsCall.payload.state.settings).filter((key) => key !== 'hostKeyPolicy').sort().join(',') === 'idleTimeoutMs,logAnalysis,maskAddresses,maxOutputBytes,sshVisible,transferTimeoutMs', JSON.stringify(settingsCall.payload.state.settings));
check('settings-notified', settingsNotices.length >= 1, `${settingsNotices.length} notifications`);

// The safety master switch travels through the API like any retained setting.
const visibilityOff = await call({ method: 'POST', url: '/ssh-pool/settings', headers: authorized, body: { sshVisible: false } });
check('post-settings-sshVisible', visibilityOff.status === 200 && settings.sshVisible === false && visibilityOff.payload.state.settings.sshVisible === false, JSON.stringify(visibilityOff.payload.state.settings));
const visibilityOn = await call({ method: 'POST', url: '/ssh-pool/settings', headers: authorized, body: { sshVisible: true } });
check('post-settings-sshVisible-restored', visibilityOn.status === 200 && settings.sshVisible === true, JSON.stringify(settings));

// An old panel posting deleted keys is ignored: a normal 200, no deleted key in
// the patch the store receives, and none in the state it sends back.
const deletedCall = await call({
  method: 'POST',
  url: '/ssh-pool/settings',
  headers: authorized,
  body: { timeoutMultiplier: 4, timeoutFloorMs: 1000, timeoutCeilingMs: 60000, maxLogLines: 5, blockResourceSpikes: false, productionEnforced: false }
});
check('post-deleted-settings-ok', deletedCall.status === 200 && deletedCall.payload.ok === true, JSON.stringify(deletedCall.payload).slice(0, 200));
check('post-deleted-settings-ignored-by-store', deletedCall.status === 200 && settingsPatches.length === 4 && Object.keys(settingsPatches[3]).length === 0, JSON.stringify(settingsPatches));
check('post-deleted-settings-untouched', settings.idleTimeoutMs === 30000 && settings.maxOutputBytes === 32768 && settings.transferTimeoutMs === 600000 && settings.sshVisible === true, JSON.stringify(settings));
check('post-deleted-settings-response-clean', DELETED_SETTINGS.every((key) => !(key in deletedCall.payload.state.settings)), JSON.stringify(deletedCall.payload.state.settings));

// A deleted key travelling with retained ones is dropped, the retained ones apply.
const mixedCall = await call({ method: 'POST', url: '/ssh-pool/settings', headers: authorized, body: { idleTimeoutMs: 120000, sshVisible: false, maxLogLines: 7 } });
check('post-mixed-settings', mixedCall.status === 200 && settings.idleTimeoutMs === 120000 && settings.sshVisible === false && Object.keys(settingsPatches[4]).sort().join(',') === 'idleTimeoutMs,sshVisible', JSON.stringify(settingsPatches[4]));
check('post-mixed-settings-response-clean', DELETED_SETTINGS.every((key) => !(key in mixedCall.payload.state.settings)), JSON.stringify(mixedCall.payload.state.settings));
settings.sshVisible = true;

// The write credential may also arrive as the cookie the read handed out.
const cookieOnly = await call({
  method: 'POST',
  url: '/ssh-pool/settings',
  headers: { cookie: `other=1; dsh_ssh_pool_token=${api.token}` },
  body: { maxOutputBytes: 8192 }
});
check('cookie-authorizes', cookieOnly.status === 200 && settings.maxOutputBytes === 8192, JSON.stringify(cookieOnly.payload));
const badCookie = await call({ method: 'POST', url: '/ssh-pool/settings', headers: { cookie: 'dsh_ssh_pool_token=deadbeef' }, body: { maxOutputBytes: 1024 } });
check('bad-cookie-rejected', badCookie.status === 403 && settings.maxOutputBytes === 8192, JSON.stringify(badCookie.payload));

const editCall = await call({ method: 'POST', url: '/ssh-pool/edit-host', headers: authorized, body: { alias: 'web-host', newAlias: 'web-host-new', keyName: 'web-host_new' } });
check('edit-host', editCall.status === 200 && edited?.alias === 'web-host' && edited?.newAlias === 'web-host-new' && edited?.keyName === 'web-host_new' && editCall.payload.edit.changed === true, JSON.stringify({ editCall, edited }));
const editUnknown = await call({ method: 'POST', url: '/ssh-pool/edit-host', headers: authorized, body: { alias: 'nope', newAlias: 'x' } });
check('edit-host-unknown', editUnknown.status === 400, JSON.stringify(editUnknown.payload));

const renameHostCall = await call({ method: 'POST', url: '/ssh-pool/rename-host', headers: authorized, body: { alias: 'web-host', newAlias: 'web-host-new' } });
check('rename-host', renameHostCall.status === 200 && renamedHost?.alias === 'web-host' && renamedHost?.newAlias === 'web-host-new' && renameHostCall.payload.rename.changed === true, JSON.stringify({ renameHostCall, renamedHost }));
const renameCall = await call({ method: 'POST', url: '/ssh-pool/rename-key', headers: authorized, body: { alias: 'web-host', keyName: 'web-host_new' } });
check('rename-key', renameCall.status === 200 && renamed?.alias === 'web-host' && renamed?.keyName === 'web-host_new' && renameCall.payload.rename.changed === true, JSON.stringify({ renameCall, renamed }));
const renameUnknown = await call({ method: 'POST', url: '/ssh-pool/rename-key', headers: authorized, body: { alias: 'nope', keyName: 'x' } });
check('rename-key-unknown-host', renameUnknown.status === 400, JSON.stringify(renameUnknown.payload));

const opened = await call({ method: 'POST', url: '/ssh-pool/action', headers: authorized, body: { action: 'open', alias: 'web-host' } });
check('action-open', opened.status === 200 && calls.includes('ensure:web-host'), JSON.stringify(calls));
const closed = await call({ method: 'POST', url: '/ssh-pool/action', headers: authorized, body: { action: 'close', alias: 'web-host' } });
check('action-close', closed.status === 200 && calls.some((entry) => entry.startsWith('close:web-host')), JSON.stringify(calls));
const closeAll = await call({ method: 'POST', url: '/ssh-pool/action', headers: authorized, body: { action: 'close_all' } });
check('action-close-all', closeAll.status === 200 && calls.includes('closeAll'), JSON.stringify(calls.slice(-2)));

const unknownHost = await call({ method: 'POST', url: '/ssh-pool/meta', headers: authorized, body: { alias: 'nope', remark: 'x' } });
check('unknown-host-400', unknownHost.status === 400 && /unknown host/.test(unknownHost.payload.error), JSON.stringify(unknownHost.payload));
const unknownAction = await call({ method: 'POST', url: '/ssh-pool/action', headers: authorized, body: { action: 'explode', alias: 'web-host' } });
check('unknown-action-400', unknownAction.status === 400, JSON.stringify(unknownAction.payload));
const badMethod = await call({ method: 'DELETE', url: '/ssh-pool/state' });
check('bad-method-405', badMethod.status === 405, JSON.stringify(badMethod.payload));

console.log(`${pass}/${pass + failures.length} passed`);
for (const failure of failures) console.log(`FAIL ${failure}`);
process.exit(failures.length === 0 ? 0 : 2);
