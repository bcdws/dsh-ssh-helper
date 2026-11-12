/**
 * The SSH assistant's Host API, served on the Harness web server.
 *
 * The panel is a browser surface, so it reaches the Host over these routes
 * instead of the agent tool registry. Everything here is read-only against the
 * connection pool except the explicit human actions (`open`/`close`), and no
 * response ever carries key material: only the key's own file name.
 *
 * Access control: loopback peers only, and mutations additionally require the
 * per-activation write token. The state read hands that token back (in the
 * body and as an HttpOnly cookie) because a browser page cannot read the boot
 * injection reliably; a page on another origin cannot read the body at all, so
 * the credential stays out of reach of cross-site script.
 *
 * Host-neutral: plain `node:http` handlers. DSH mounts the route on its web
 * server (`dsh/api.js`); the MCP panel serves it from its own loopback server
 * with `checkHost` on, because a fixed port is open to DNS rebinding.
 *
 * @module dsh-ssh-helper/assistant-api
 */
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { SETTINGS_KEYS } from './store.js';
import { isLoopback, isLoopbackHostHeader, readCookie, readJson, send, tokenMatches } from './http.js';

const COOKIE_NAME = 'dsh_ssh_pool_token';
/** The shared panel UI (`<ssh-helper-panel>`), served to both surfaces. Fixed list: no path is ever taken from the URL. */
const UI_FILES = new Set(['panel-element.js', 'panel-view.js']);
const UI_DIR = new URL('../ui/', import.meta.url);

/**
 * Keep only the settings the panel may still change.
 *
 * The request body is untrusted and an older panel posts keys this version no
 * longer keeps; they are dropped here (never rejected) so the response stays a
 * normal 200 and the store is only ever handed a retained key. Range checking
 * stays in the store.
 */
function pickSettings(body) {
  const source = body !== null && typeof body === 'object' ? body : {};
  const patch = {};
  for (const key of SETTINGS_KEYS) if (source[key] !== undefined) patch[key] = source[key];
  return patch;
}

/**
 * Close a host's transport because it was just hidden, including a handshake
 * already in flight: ssh2 only hands the client over once it is ready, so the
 * pending `ensure()` is awaited and the transport dropped when it lands.
 * `ensure()` here returns the pending handshake, never a new connect.
 *
 * @param connection - the pool's `HostConnection` for the host.
 * @param stillHidden - `() => boolean`, re-checked after the handshake.
 */
export function closeHiddenConnection(connection, stillHidden, reason = 'hidden in the SSH assistant') {
  const connecting = connection.state === 'connecting';
  connection.close(reason);
  if (connecting) {
    void connection.ensure().then(
      () => {
        if (stillHidden()) connection.close(reason);
      },
      () => undefined
    );
  }
}

/**
 * Build the assistant API.
 * @param input - pool, store, config and logger, plus the adapter hooks:
 *   `prefix` (route prefix), `checkHost` (reject a non-loopback `Host`
 *   header), `decorateState(state)` (extend every state answer),
 *   `onHidden(alias)` (after a host is newly hidden, beside closing it in
 *   `pool`), `onAction(body)` (replace the pool-backed open/close actions).
 * @returns the route, the page injection, and the state projection.
 */
export function createAssistantApi({
  pool,
  store,
  config,
  logger,
  analysisStatus,
  diagnostics,
  onSettingsChanged,
  refreshHosts,
  renameKey,
  renameHost,
  editHost,
  prefix = '/ssh-pool',
  checkHost = false,
  decorateState,
  onHidden,
  onAction
}) {
  const token = randomBytes(24).toString('hex');

  /** Re-scan the OpenSSH config on every panel read; cheap and idempotent. */
  const refresh = () => {
    if (typeof refreshHosts !== 'function') return undefined;
    try {
      return refreshHosts();
    } catch (error) {
      logger?.warn?.(`ssh-pool: host refresh failed: ${error instanceof Error ? error.message : String(error)}`);
      return undefined;
    }
  };

  /**
   * Build the panel state. `events` limits the diagnostics history the caller
   * receives; `undefined` lets the buffer apply its own default.
   */
  const buildState = (options = {}) => {
    const hosts = pool.status();
    const state = {
      generatedAt: Date.now(),
      settings: { ...store.settings(), hostKeyPolicy: config.hostKeyPolicy },
      analysis: typeof analysisStatus === 'function' ? analysisStatus() : { available: false, reason: null, model: null },
      diagnostics: typeof diagnostics === 'function' ? diagnostics(options) : { counters: { toolCalls: 0, failures: 0, policyDenials: 0, timeouts: 0, slowCalls: 0, analyses: {} }, events: [] },
      hosts,
      totals: {
        hosts: hosts.length,
        connected: hosts.filter((host) => host.connected).length,
        sessions: hosts.reduce((sum, host) => sum + host.sessions.length, 0),
        commands: hosts.reduce((sum, host) => sum + (host.commands ?? 0), 0)
      }
    };
    return typeof decorateState === 'function' ? decorateState(state, options) : state;
  };
  const prefixPattern = new RegExp(`^${prefix.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}/?`);

  const handler = async (req, res) => {
    try {
      if (!isLoopback(req)) {
        send(res, 403, { ok: false, error: 'the SSH assistant API answers loopback requests only' });
        return;
      }
      if (checkHost && !isLoopbackHostHeader(req)) {
        send(res, 403, { ok: false, error: 'the Host header must name this machine (localhost / 127.0.0.1)' });
        return;
      }
      const url = new URL(req.url ?? '/', 'http://localhost');
      const path = url.pathname.replace(prefixPattern, '');
      // Diagnostics history is opt-in above the default so the panel's poll
      // stays small while a debugging caller can ask for the whole buffer.
      const rawEvents = url.searchParams.get('events');
      const eventsLimit = rawEvents === null || rawEvents.trim() === '' ? undefined : Number(rawEvents);
      // A cross-site page can send a request but must never read the answer:
      // the read below also hands out the write credential, and the browser
      // refuses to expose the body without CORS headers.
      const fetchSite = req.headers['sec-fetch-site'];
      if (typeof fetchSite === 'string' && fetchSite === 'cross-site') {
        send(res, 403, { ok: false, error: 'cross-site requests are not accepted' });
        return;
      }
      if (req.method === 'GET' && path.startsWith('ui/')) {
        const name = path.slice(3);
        if (!UI_FILES.has(name)) {
          send(res, 404, { ok: false, error: `unknown ui file ${name}` });
          return;
        }
        res.writeHead(200, { 'content-type': 'text/javascript; charset=utf-8', 'cache-control': 'no-cache', 'x-content-type-options': 'nosniff' });
        res.end(readFileSync(new URL(name, UI_DIR), 'utf8'));
        return;
      }
      if (req.method === 'GET' && (path === '' || path === 'state')) {
        refresh();
        const state = buildState(Number.isFinite(eventsLimit) ? { events: eventsLimit } : {});
        send(res, 200, { ok: true, state, token }, {
          'set-cookie': `${COOKIE_NAME}=${token}; Path=${prefix}; HttpOnly; SameSite=Strict`
        });
        return;
      }
      if (req.method !== 'POST') {
        send(res, 405, { ok: false, error: `unsupported method ${req.method ?? '?'}` });
        return;
      }
      const authorized =
        tokenMatches(token, req.headers['x-dsh-ssh-pool-token']) || tokenMatches(token, readCookie(req, COOKIE_NAME));
      if (!authorized) {
        send(res, 403, { ok: false, error: 'missing or invalid write credential (cookie or x-dsh-ssh-pool-token)' });
        return;
      }
      const body = await readJson(req);
      refresh();

      if (path === 'edit-host') {
        const alias = typeof body.alias === 'string' ? body.alias : '';
        if (alias.length === 0) throw new Error('alias is required');
        if (!pool.has(alias)) throw new Error(`unknown host "${alias}"`);
        if (typeof editHost !== 'function') throw new Error('host editing is not available');
        const edited = await editHost({
          alias,
          newAlias: typeof body.newAlias === 'string' ? body.newAlias : undefined,
          keyName: typeof body.keyName === 'string' ? body.keyName : undefined
        });
        send(res, 200, { ok: true, state: buildState(), edit: edited });
        return;
      }

      if (path === 'rename-host') {
        const alias = typeof body.alias === 'string' ? body.alias : '';
        const newAlias = typeof body.newAlias === 'string' ? body.newAlias : '';
        if (alias.length === 0) throw new Error('alias is required');
        if (!pool.has(alias)) throw new Error(`unknown host "${alias}"`);
        if (typeof renameHost !== 'function') throw new Error('host renaming is not available');
        const renamed = await renameHost({ alias, newAlias });
        send(res, 200, { ok: true, state: buildState(), rename: renamed });
        return;
      }

      if (path === 'rename-key') {
        const alias = typeof body.alias === 'string' ? body.alias : '';
        const keyName = typeof body.keyName === 'string' ? body.keyName : '';
        if (alias.length === 0) throw new Error('alias is required');
        if (!pool.has(alias)) throw new Error(`unknown host "${alias}"`);
        if (typeof renameKey !== 'function') throw new Error('key renaming is not available');
        const renamed = await renameKey({ alias, keyName });
        send(res, 200, { ok: true, state: buildState(), rename: renamed });
        return;
      }

      if (path === 'meta') {
        const alias = typeof body.alias === 'string' ? body.alias : '';
        if (!pool.has(alias)) throw new Error(`unknown host "${alias}"`);
        const wasHidden = store.host(alias)?.hidden === true;
        store.setHost(alias, {
          ...(body.remark !== undefined ? { remark: body.remark } : {}),
          ...(body.hidden !== undefined ? { hidden: body.hidden } : {}),
          ...(body.prod !== undefined ? { prod: body.prod } : {}),
          ...(body.visible !== undefined ? { visible: body.visible } : {}),
          ...(body.level !== undefined ? { level: body.level } : {}),
          ...(body.idleTimeoutMs !== undefined ? { idleTimeoutMs: body.idleTimeoutMs } : {})
        });
        // Hiding a host is the human saying "stop using this one": its live
        // transport (and any scheduled reconnect) goes with the switch, so a
        // hidden row can never keep showing 已连接. Only a switch that actually
        // turns hiding on disconnects — a remark edit or unhiding leaves the
        // connection alone. `pool` is the pool behind this API; other
        // processes (MCP servers) follow the state file and close their own.
        const nowHidden = store.host(alias)?.hidden === true;
        const disconnected = wasHidden === false && nowHidden === true;
        if (disconnected) {
          closeHiddenConnection(pool.connection(alias), () => store.host(alias)?.hidden === true);
          onHidden?.(alias);
          logger?.info?.(`ssh-pool: ${alias} hidden; closed its live connection`);
        }
        send(res, 200, { ok: true, state: buildState(), ...(disconnected ? { disconnected: true } : {}) });
        return;
      }

      if (path === 'settings') {
        store.setSettings(pickSettings(body));
        onSettingsChanged?.();
        send(res, 200, { ok: true, state: buildState() });
        return;
      }

      if (path === 'action' && typeof onAction === 'function') {
        const result = await onAction(body);
        send(res, 200, { ok: true, state: buildState(), ...(result === undefined ? {} : { result }) });
        return;
      }

      if (path === 'action') {
        const action = body.action;
        if (action === 'close_all') {
          pool.closeAll();
          send(res, 200, { ok: true, state: buildState() });
          return;
        }
        const alias = typeof body.alias === 'string' ? body.alias : '';
        if (!pool.has(alias)) throw new Error(`unknown host "${alias}"`);
        if (action === 'open') {
          const started = Date.now();
          await pool.connection(alias).ensure();
          logger?.info?.(`ssh-pool: ${alias} opened from the SSH assistant in ${Date.now() - started}ms`);
        } else if (action === 'close') {
          pool.connection(alias).close('closed from the SSH assistant');
        } else {
          throw new Error(`unknown action "${String(action)}"`);
        }
        send(res, 200, { ok: true, state: buildState() });
        return;
      }

      send(res, 404, { ok: false, error: `unknown endpoint ${prefix}/${path}` });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      logger?.warn?.(`ssh-pool: assistant API error: ${message}`);
      send(res, 400, { ok: false, error: message });
    }
  };

  return {
    token,
    // A prefix route matches `/ssh-pool` itself and `/ssh-pool/...`; a trailing
    // slash in `path` would never match (the matcher appends its own).
    route: { kind: 'prefix', path: prefix, handler },
    handler,
    /**
     * The boot-page additions: the token global the client reads, and the
     * shared `<ssh-helper-panel>` element (defined before the client renders).
     */
    indexInjection: `<script>globalThis.__DSH_SSH_ASSISTANT__=${JSON.stringify({ token })}</script><script type="module" src="${prefix}/ui/panel-element.js"></script>`,
    buildState
  };
}
