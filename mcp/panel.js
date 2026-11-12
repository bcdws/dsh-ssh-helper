/**
 * `dsh-ssh-mcp panel` — the MCP side's management page.
 *
 * One process, started by the user, serving `http://127.0.0.1:<port>/`:
 *
 * - the only writer of `~/.dsh-ssh-mcp/state.json` (hidden hosts, remarks,
 *   per-host idle, settings); every MCP server follows it read-only;
 * - host edits against `~/.ssh/config` (rename alias / key, with backup);
 * - live status of every running MCP server, discovered through
 *   `~/.dsh-ssh-mcp/run/*.json`, and their open/close actions, forwarded to
 *   each server's control port.
 *
 * The panel never opens an SSH connection itself: its pool exists only for the
 * host table. The routes are `lib/assistant-api.js` (shared with the DSH
 * panel) under `/api`, with the `Host` check on because a fixed loopback port
 * is reachable from any page via DNS rebinding.
 *
 * @module dsh-ssh-helper/mcp/panel
 */
import { readFileSync } from 'node:fs';
import { createServer, request } from 'node:http';
import { buildHostTable, normalizeConfig } from '../lib/config.js';
import { MetadataStore } from '../lib/store.js';
import { SshPool } from '../lib/pool.js';
import { createAssistantApi } from '../lib/assistant-api.js';
import { createHostRefresher } from '../lib/host-refresh.js';
import { createHostEditors } from '../lib/host-edits.js';
import { isLoopback, isLoopbackHostHeader, send } from '../lib/http.js';
import { createPolicy } from '../lib/policy.js';
import { callInstance, listInstances } from './control.js';
import { mcpRunDir, mcpStatePath } from './home.js';

export const DEFAULT_PANEL_PORT = 7318;
/** How many ports after the default to try before letting the OS pick one. */
const FALLBACK_PORTS = 9;
/** Identity probe: tells a second `panel` run who already holds a port. */
export const IDENTITY_PATH = '/__dsh-ssh-mcp-panel';
const PAGE_URL = new URL('./panel.html', import.meta.url);
const STATE_RANK = { connected: 4, connecting: 3, down: 2, idle: 1 };

/** Merge one host row with what every MCP server reports for that alias. */
function mergeHost(row, instances) {
  const reports = [];
  for (const instance of instances) {
    const live = instance.hosts?.find((host) => host.alias === row.alias);
    if (live === undefined) continue;
    reports.push({
      pid: instance.pid,
      client: instance.client,
      state: live.state,
      connected: live.connected === true,
      connectedSeconds: live.connectedSeconds,
      idleSeconds: live.idleSeconds,
      sessions: live.sessions ?? [],
      commands: live.commands ?? 0,
      lastCommand: live.lastCommand ?? null,
      lastError: live.lastError ?? null,
      lastFailure: live.lastFailure ?? null,
      retryPaused: live.retryPaused === true
    });
  }
  const best = reports.reduce((top, report) => ((STATE_RANK[report.state] ?? 0) > (STATE_RANK[top?.state] ?? 0) ? report : top), null);
  return {
    ...row,
    state: best?.state ?? 'idle',
    connected: reports.some((report) => report.connected),
    sessions: reports.flatMap((report) => report.sessions),
    commands: reports.reduce((sum, report) => sum + report.commands, 0),
    lastError: reports.find((report) => report.lastError !== null)?.lastError ?? null,
    // The freshest failed call across every server.
    lastFailure:
      reports
        .map((report) => report.lastFailure)
        .filter((failure) => failure !== null)
        .sort((a, b) => a.ageSeconds - b.ageSeconds)[0] ?? null,
    retryPaused: reports.some((report) => report.retryPaused),
    instances: reports
  };
}

/**
 * Build the panel: an HTTP handler plus the pieces tests reach into.
 *
 * @param input
 * @param input.config - raw plugin-style config (same keys as the MCP server).
 * @param input.statePath - the state file this panel owns.
 * @param input.runDir - where MCP servers announce themselves.
 * @param input.logger - `{ info, warn }`.
 */
export function createPanel({ config: raw = {}, statePath = mcpStatePath(), runDir = mcpRunDir(), logger } = {}) {
  const config = normalizeConfig(raw);
  const { hosts, warnings } = buildHostTable(config);
  for (const warning of warnings) logger?.warn?.(warning);
  const store = new MetadataStore({
    filePath: statePath,
    defaults: {
      settings: { idleTimeoutMs: config.idleTimeoutMs, maxOutputBytes: config.maxOutputBytes, transferTimeoutMs: config.transferTimeoutMs }
    }
  });
  // Host table only: `onAction` below forwards every connect to a server, so
  // this pool never dials.
  const pool = new SshPool({ hosts, config, logger, warnings, meta: store });
  const refreshHosts = createHostRefresher({ pool, config, logger });
  const editors = createHostEditors({ pool, store, config, refreshHosts, logger });

  /** The last poll of every MCP server; refreshed before each API answer. */
  let instances = [];
  const pollInstances = async () => {
    const entries = listInstances(runDir);
    instances = await Promise.all(
      entries.map(async (entry) => {
        try {
          const { instance, state } = await callInstance(entry, 'state', undefined, { timeoutMs: 2000 });
          return { ...instance, pid: entry.pid, hosts: state.hosts, diagnostics: state.diagnostics, analysis: state.analysis, error: null };
        } catch (error) {
          return { pid: entry.pid, startedAt: entry.startedAt, hosts: [], error: error instanceof Error ? error.message : String(error) };
        }
      })
    );
    return instances;
  };
  const entryFor = (pid) => {
    const entry = listInstances(runDir).find((candidate) => candidate.pid === pid);
    if (entry === undefined) throw new Error(`no running MCP server with pid ${pid}`);
    return entry;
  };

  const decorateState = (state) => {
    const rows = state.hosts.map((row) => mergeHost(row, instances));
    return {
      ...state,
      hosts: rows,
      totals: {
        hosts: rows.length,
        connected: rows.filter((host) => host.connected).length,
        sessions: rows.reduce((sum, host) => sum + host.sessions.length, 0),
        commands: rows.reduce((sum, host) => sum + host.commands, 0)
      },
      instances: instances.map(({ hosts: live = [], ...instance }) => ({
        ...instance,
        hostCount: live.length,
        connected: live.filter((host) => host.connected).length
      })),
      panel: { statePath: store.filePath, runDir, sshConfigPath: config.useSshConfig ? config.sshConfigPath : null, warnings: [...(pool.warnings ?? [])] },
      policy: createPolicy().hints()
    };
  };

  /**
   * Open/close go to the servers: `pid` picks one; without it, `close` and
   * `close_all` reach every server and `open` needs exactly one running.
   */
  const onAction = async (body) => {
    const action = body.action;
    if (!['open', 'close', 'close_all'].includes(action)) throw new Error(`unknown action "${String(action)}"`);
    if (action !== 'close_all') {
      const alias = typeof body.alias === 'string' ? body.alias : '';
      if (!pool.has(alias)) throw new Error(`unknown host "${alias}"`);
    }
    const payload = { action, ...(typeof body.alias === 'string' ? { alias: body.alias } : {}) };
    let targets;
    if (Number.isInteger(body.pid)) targets = [entryFor(body.pid)];
    else {
      targets = listInstances(runDir);
      if (action === 'open' && targets.length !== 1) {
        throw new Error(targets.length === 0 ? 'no MCP server is running; start a client session first' : 'several MCP servers are running; pick one to connect from');
      }
    }
    const results = await Promise.allSettled(targets.map((entry) => callInstance(entry, 'action', payload, { timeoutMs: 60_000 })));
    await pollInstances();
    const failed = results.map((result, index) => ({ result, pid: targets[index].pid })).filter(({ result }) => result.status === 'rejected');
    if (failed.length > 0 && failed.length === targets.length) throw new Error(failed.map(({ pid, result }) => `pid ${pid}: ${result.reason?.message ?? result.reason}`).join('; '));
    return { targets: targets.map((entry) => entry.pid), failed: failed.map(({ pid }) => pid) };
  };

  const api = createAssistantApi({
    pool,
    store,
    config,
    logger,
    prefix: '/api',
    checkHost: true,
    refreshHosts,
    decorateState,
    onAction,
    ...editors
  });

  const page = () => readFileSync(PAGE_URL, 'utf8');

  const handler = async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://localhost');
    if (url.pathname === '/api' || url.pathname.startsWith('/api/')) {
      // Refresh the server list first so the (synchronous) state projection
      // inside the API sees current connections. A meta/settings write does
      // not wait for the servers: they follow the state file within ~1s.
      if (req.method === 'GET' && isLoopback(req) && isLoopbackHostHeader(req)) await pollInstances();
      await api.handler(req, res);
      return;
    }
    if (!isLoopback(req) || !isLoopbackHostHeader(req)) {
      send(res, 403, { ok: false, error: 'loopback only' });
      return;
    }
    if (req.method === 'GET' && url.pathname === IDENTITY_PATH) {
      // No secrets: just enough for another run to decide "same panel, reuse it".
      send(res, 200, { ok: true, panel: 'dsh-ssh-mcp', runDir, platform: process.platform, pid: process.pid });
      return;
    }
    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
      res.writeHead(200, {
        'content-type': 'text/html; charset=utf-8',
        'cache-control': 'no-store',
        'x-frame-options': 'DENY',
        'content-security-policy': "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
      });
      res.end(page());
      return;
    }
    send(res, 404, { ok: false, error: 'not found' });
  };

  return { handler, pool, store, pollInstances, dispose: () => pool.dispose() };
}

/**
 * Ask whatever listens on `127.0.0.1:port` whether it is a panel.
 * Plain `node:http`, so a configured HTTP proxy is never involved.
 * @returns the identity body, or `null` (nothing there, or not a panel).
 */
export function probePanel(port, { timeoutMs = 1500 } = {}) {
  return new Promise((resolve) => {
    const req = request({ host: '127.0.0.1', port, path: IDENTITY_PATH, method: 'GET', timeout: timeoutMs }, (res) => {
      let text = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => {
        if (text.length < 4096) text += chunk;
      });
      res.on('end', () => {
        try {
          const body = JSON.parse(text);
          resolve(res.statusCode === 200 && body?.panel === 'dsh-ssh-mcp' ? body : null);
        } catch {
          resolve(null);
        }
      });
    });
    req.on('timeout', () => req.destroy());
    req.on('error', () => resolve(null));
    req.end();
  });
}

/** Listen on one port; resolves `true`, `false` when taken, rejects otherwise. */
function tryListen(server, port) {
  return new Promise((resolve, reject) => {
    const onError = (error) => {
      server.off('listening', onListening);
      if (error?.code === 'EADDRINUSE' || error?.code === 'EACCES') resolve(false);
      else reject(error);
    };
    const onListening = () => {
      server.off('error', onError);
      resolve(true);
    };
    server.once('error', onError);
    server.once('listening', onListening);
    server.listen(port, '127.0.0.1');
  });
}

/**
 * Serve the panel on `127.0.0.1`.
 *
 * When the port is taken, the holder is probed first: a panel for the same
 * run dir is reused (`existing: true`, nothing new is started). Anything else
 * — another program, a hidden OS reservation, or a panel for a different home
 * such as the other side of a WSL mirrored network — is skipped: an explicit
 * `port` then fails, the default walks the next ports and finally lets the OS
 * pick one.
 *
 * `basePort` moves the default range (tests only).
 *
 * @returns `Promise<{ url, existing, server?, panel?, skipped }>`; `skipped`
 *   lists the busy ports and what held them.
 */
export async function servePanel({ port, basePort = DEFAULT_PANEL_PORT, ...options } = {}) {
  const explicit = port !== undefined;
  const runDir = options.runDir ?? mcpRunDir();
  const candidates = explicit
    ? [port]
    : [...Array.from({ length: FALLBACK_PORTS + 1 }, (_, index) => basePort + index), 0];
  const server = createServer();
  const skipped = [];
  for (const candidate of candidates) {
    if (await tryListen(server, candidate)) {
      const panel = createPanel({ ...options, runDir });
      server.on('request', (req, res) => {
        panel.handler(req, res).catch((error) => {
          if (!res.headersSent) send(res, 500, { ok: false, error: error instanceof Error ? error.message : String(error) });
        });
      });
      return { url: `http://127.0.0.1:${server.address().port}/`, existing: false, server, panel, skipped };
    }
    const holder = await probePanel(candidate);
    if (holder !== null && holder.runDir === runDir) {
      return { url: `http://127.0.0.1:${candidate}/`, existing: true, skipped };
    }
    skipped.push({ port: candidate, holder: holder === null ? 'other' : `panel for ${holder.runDir} (${holder.platform})` });
  }
  const last = skipped[skipped.length - 1];
  throw new Error(
    explicit
      ? `port ${port} is in use by ${last.holder === 'other' ? 'another program (or a stale OS reservation)' : `a different ${last.holder}`}; pick another --port`
      : 'no free port for the panel'
  );
}
