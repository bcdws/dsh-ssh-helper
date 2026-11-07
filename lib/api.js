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
 * @module dsh-ssh-pool/api
 */
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { SETTINGS_KEYS } from './store.js';

const MAX_BODY_BYTES = 64 * 1024;
const LOOPBACK = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1']);
const COOKIE_NAME = 'dsh_ssh_pool_token';

/** Write a JSON response, optionally with extra headers. */
function send(res, status, payload, headers = {}) {
  const body = JSON.stringify(payload);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers });
  res.end(body);
}

/** Read one cookie from the request, or undefined. */
function readCookie(req, name) {
  const header = req.headers?.cookie;
  if (typeof header !== 'string' || header.length === 0) return undefined;
  for (const part of header.split(';')) {
    const at = part.indexOf('=');
    if (at < 0) continue;
    if (part.slice(0, at).trim() === name) return decodeURIComponent(part.slice(at + 1).trim());
  }
  return undefined;
}

/** Read and parse a bounded JSON request body. */
async function readJson(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw new Error('request body too large');
    chunks.push(chunk);
  }
  if (size === 0) return {};
  const text = Buffer.concat(chunks).toString('utf8');
  const parsed = JSON.parse(text);
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('body must be a JSON object');
  return parsed;
}

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

/** Whether the peer is this machine. */
function isLoopback(req) {
  return LOOPBACK.has(req.socket?.remoteAddress ?? '');
}

/** Constant-time token comparison. */
function tokenMatches(expected, provided) {
  if (typeof provided !== 'string' || provided.length !== expected.length) return false;
  try {
    return timingSafeEqual(Buffer.from(expected), Buffer.from(provided));
  } catch {
    return false;
  }
}

/**
 * Build the assistant API.
 * @param input - pool, store, config and logger.
 * @returns the route, the page injection, and the state projection.
 */
export function createAssistantApi({ pool, store, config, logger, analysisStatus, diagnostics, onSettingsChanged, refreshHosts, renameKey, renameHost, editHost }) {
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
    return {
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
  };

  const handler = async (req, res) => {
    try {
      if (!isLoopback(req)) {
        send(res, 403, { ok: false, error: 'the SSH assistant API answers loopback requests only' });
        return;
      }
      const url = new URL(req.url ?? '/', 'http://localhost');
      const path = url.pathname.replace(/^\/ssh-pool\/?/, '');
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
      if (req.method === 'GET' && (path === '' || path === 'state')) {
        refresh();
        const state = buildState(Number.isFinite(eventsLimit) ? { events: eventsLimit } : {});
        send(res, 200, { ok: true, state, token }, {
          'set-cookie': `${COOKIE_NAME}=${token}; Path=/ssh-pool; HttpOnly; SameSite=Strict`
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
        store.setHost(alias, {
          ...(body.remark !== undefined ? { remark: body.remark } : {}),
          ...(body.hidden !== undefined ? { hidden: body.hidden } : {}),
          ...(body.visible !== undefined ? { visible: body.visible } : {}),
          ...(body.level !== undefined ? { level: body.level } : {}),
          ...(body.idleTimeoutMs !== undefined ? { idleTimeoutMs: body.idleTimeoutMs } : {})
        });
        send(res, 200, { ok: true, state: buildState() });
        return;
      }

      if (path === 'settings') {
        store.setSettings(pickSettings(body));
        onSettingsChanged?.();
        send(res, 200, { ok: true, state: buildState() });
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

      send(res, 404, { ok: false, error: `unknown endpoint /ssh-pool/${path}` });
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
    route: { kind: 'prefix', path: '/ssh-pool', handler },
    /** The boot-page global the client module reads its token from. */
    indexInjection: `<script>globalThis.__DSH_SSH_ASSISTANT__=${JSON.stringify({ token })}</script>`,
    buildState
  };
}
