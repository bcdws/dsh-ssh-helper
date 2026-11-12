/**
 * The per-process control port of an MCP server.
 *
 * Each `dsh-ssh-mcp` process listens on `127.0.0.1:<ephemeral>` and announces
 * itself in `$DSH_SSH_MCP_HOME/run/<pid>.json` (mode 0600: port + token). The
 * panel discovers live servers there, reads their pool status and asks them to
 * open or close a connection. Nothing else is exposed: metadata edits go
 * through the panel's state file, which every server already follows.
 *
 * Every request must come from loopback, name localhost in `Host`, and carry
 * the token in `x-dsh-ssh-mcp-token` — reads included, since host status is
 * only for the panel.
 *
 * The port opens after the transport is up; it never delays `initialize`, and
 * a failure to listen is logged and ignored (the tools keep working).
 *
 * @module dsh-ssh-helper/mcp/control
 */
import { randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import { chmodSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { isLoopback, isLoopbackHostHeader, readJson, send, tokenMatches } from '../lib/http.js';

export const TOKEN_HEADER = 'x-dsh-ssh-mcp-token';

/**
 * @param input
 * @param input.pool - the server's `SshPool`.
 * @param input.describe - `() => object`, instance details (client, state file…).
 * @param input.extraState - `() => object`, merged into `state` (diagnostics, analysis).
 * @param input.runDir - where to write the run file.
 * @param input.logger - `{ info, warn }`, stderr only.
 * @returns `Promise<{ port, token, runFile, close() }>`.
 */
export async function startControlServer({ pool, describe = () => ({}), extraState = () => ({}), runDir, logger }) {
  const token = randomBytes(24).toString('hex');
  const startedAt = Date.now();

  const snapshot = () => ({
    instance: { pid: process.pid, startedAt, ...describe() },
    state: { generatedAt: Date.now(), hosts: pool.status(), ...extraState() }
  });

  const handler = async (req, res) => {
    try {
      if (!isLoopback(req) || !isLoopbackHostHeader(req)) {
        send(res, 403, { ok: false, error: 'loopback only' });
        return;
      }
      if (!tokenMatches(token, req.headers[TOKEN_HEADER])) {
        send(res, 403, { ok: false, error: `missing or invalid ${TOKEN_HEADER}` });
        return;
      }
      const path = new URL(req.url ?? '/', 'http://localhost').pathname.replace(/^\/+/, '');
      if (req.method === 'GET' && (path === '' || path === 'state')) {
        send(res, 200, { ok: true, ...snapshot() });
        return;
      }
      if (req.method === 'POST' && path === 'action') {
        const body = await readJson(req);
        const action = body.action;
        if (action === 'close_all') {
          pool.closeAll();
        } else {
          const alias = typeof body.alias === 'string' ? body.alias : '';
          if (!pool.has(alias)) throw new Error(`unknown host "${alias}"`);
          if (action === 'open') await pool.connection(alias).ensure();
          else if (action === 'close') pool.connection(alias).close('closed from the MCP panel');
          else throw new Error(`unknown action "${String(action)}"`);
        }
        send(res, 200, { ok: true, ...snapshot() });
        return;
      }
      send(res, 404, { ok: false, error: `unknown endpoint ${req.method} /${path}` });
    } catch (error) {
      send(res, 400, { ok: false, error: error instanceof Error ? error.message : String(error) });
    }
  };

  const server = createServer((req, res) => void handler(req, res));
  // The control port must never keep a finished MCP process alive.
  server.unref();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', reject);
      resolve();
    });
  });
  const { port } = server.address();

  mkdirSync(runDir, { recursive: true, mode: 0o700 });
  const runFile = join(runDir, `${process.pid}.json`);
  const temporary = `${runFile}.tmp`;
  writeFileSync(temporary, `${JSON.stringify({ pid: process.pid, port, token, startedAt })}\n`, { mode: 0o600 });
  try {
    chmodSync(temporary, 0o600);
  } catch {
    /* Windows: mode bits are advisory */
  }
  renameSync(temporary, runFile);

  let closed = false;
  const close = () => {
    if (closed) return;
    closed = true;
    try {
      rmSync(runFile, { force: true });
    } catch {
      /* already gone */
    }
    server.close();
  };
  // `exit` handlers must be synchronous; rmSync is.
  process.once('exit', close);
  logger?.info?.(`control port 127.0.0.1:${port} (${runFile})`);
  return { port, token, runFile, close };
}

/** Whether a process id is alive on this machine. */
function alive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    // EPERM: it exists but belongs to someone else.
    return error?.code === 'EPERM';
  }
}

/**
 * Read every announced server; stale files (dead pid, unreadable) are removed.
 * @returns `[{ pid, port, token, startedAt }]`.
 */
export function listInstances(runDir) {
  let names;
  try {
    names = readdirSync(runDir);
  } catch {
    return [];
  }
  const instances = [];
  for (const name of names) {
    if (!/^\d+\.json$/.test(name)) continue;
    const file = join(runDir, name);
    let entry;
    try {
      entry = JSON.parse(readFileSync(file, 'utf8'));
    } catch {
      continue;
    }
    if (!Number.isInteger(entry?.pid) || !Number.isInteger(entry?.port) || typeof entry?.token !== 'string') continue;
    if (!alive(entry.pid)) {
      try {
        rmSync(file, { force: true });
      } catch {
        /* someone else cleaned it */
      }
      continue;
    }
    instances.push(entry);
  }
  return instances.sort((a, b) => a.startedAt - b.startedAt);
}

/** Call one server's control port. Resolves to the parsed body or throws. */
export async function callInstance(entry, path, body, { timeoutMs = 15_000 } = {}) {
  const response = await fetch(`http://127.0.0.1:${entry.port}/${path}`, {
    method: body === undefined ? 'GET' : 'POST',
    headers: { [TOKEN_HEADER]: entry.token, ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    signal: AbortSignal.timeout(timeoutMs)
  });
  const payload = await response.json().catch(() => null);
  if (!response.ok || payload?.ok !== true) throw new Error(payload?.error ?? `HTTP ${response.status}`);
  return payload;
}
