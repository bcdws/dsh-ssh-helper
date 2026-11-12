/**
 * Small HTTP helpers shared by every loopback surface: the SSH assistant API
 * (DSH panel and MCP panel) and the per-process MCP control port.
 *
 * Plain `node:http` request/response objects only, so nothing here depends on
 * a particular host web server.
 *
 * @module dsh-ssh-helper/http
 */
import { timingSafeEqual } from 'node:crypto';

export const MAX_BODY_BYTES = 64 * 1024;
const LOOPBACK = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1']);
const LOOPBACK_NAMES = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

/** Write a JSON response, optionally with extra headers. */
export function send(res, status, payload, headers = {}) {
  const body = JSON.stringify(payload);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers });
  res.end(body);
}

/** Read one cookie from the request, or undefined. */
export function readCookie(req, name) {
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
export async function readJson(req) {
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

/** Whether the peer is this machine. */
export function isLoopback(req) {
  return LOOPBACK.has(req.socket?.remoteAddress ?? '');
}

/**
 * Whether the `Host` header names this machine. A standalone server on a fixed
 * loopback port is reachable from any page via DNS rebinding (attacker.example
 * resolving to 127.0.0.1); the peer address cannot tell, the `Host` header can.
 */
export function isLoopbackHostHeader(req) {
  const header = req.headers?.host;
  if (typeof header !== 'string' || header.length === 0) return false;
  const name = header.startsWith('[') ? header.slice(0, header.indexOf(']') + 1) : header.replace(/:\d+$/, '');
  return LOOPBACK_NAMES.has(name.toLowerCase());
}

/** Constant-time token comparison. */
export function tokenMatches(expected, provided) {
  if (typeof provided !== 'string' || provided.length !== expected.length) return false;
  try {
    return timingSafeEqual(Buffer.from(expected), Buffer.from(provided));
  } catch {
    return false;
  }
}
