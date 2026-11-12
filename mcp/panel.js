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
import { createServer } from 'node:http';
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
 * Listen on `127.0.0.1:port` and serve the panel until the process ends.
 * @returns `Promise<{ url, server, panel }>`; rejects when the port is taken.
 */
export async function servePanel({ port = DEFAULT_PANEL_PORT, ...options } = {}) {
  const panel = createPanel(options);
  const server = createServer((req, res) => {
    panel.handler(req, res).catch((error) => {
      if (!res.headersSent) send(res, 500, { ok: false, error: error instanceof Error ? error.message : String(error) });
    });
  });
  await new Promise((resolve, reject) => {
    server.once('error', (error) => {
      reject(
        error?.code === 'EADDRINUSE'
          ? new Error(`port ${port} is in use — the panel may already be running at http://127.0.0.1:${port}/ (or pass --port)`)
          : error
      );
    });
    server.listen(port, '127.0.0.1', resolve);
  });
  const actual = server.address().port;
  return { url: `http://127.0.0.1:${actual}/`, server, panel };
}
