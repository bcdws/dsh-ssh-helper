/**
 * Structured failure codes for tool errors.
 *
 * An agent that only sees "timed out" cannot tell a dead network from a bad
 * key from its own client giving up, and falls back to raw local ssh. Every
 * failure therefore carries one stable code plus a one-line hint about what to
 * do next. Both adapters use it: the code and hint are appended to the error
 * text (what DSH shows) and, in MCP, also sent under
 * `_meta["dsh-ssh-helper/error"]`.
 *
 * Classification works on the error text the pool and ssh2 produce; it only
 * has to be right for the common shapes, anything else is `error`.
 *
 * @module dsh-ssh-helper/errors
 */

/** code → { hint, retryable }. `retryable` means "the same call may succeed later unchanged". */
export const FAILURE_CODES = {
  policy_denied: {
    retryable: false,
    hint: 'refused by the machine-destruction guard; do not rewrite it into an equivalent command — explain host, intent and impact, and let the user decide'
  },
  unknown_host: { retryable: false, hint: 'call ssh_hosts for the available aliases' },
  invalid_argument: { retryable: false, hint: 'fix the arguments and call again' },
  connect_timeout: {
    retryable: true,
    hint: 'the SSH handshake did not finish in time (slow network, firewall dropping packets, or sshd overloaded); retry once, then check the network or ask the user'
  },
  connection_refused: { retryable: false, hint: 'nothing accepts SSH on that host:port; check that sshd runs and the port in ~/.ssh/config' },
  host_unreachable: { retryable: true, hint: 'the host name does not resolve or the network has no route to it; check HostName, DNS, VPN or proxy' },
  auth_failed: { retryable: false, hint: 'the server rejected the key; check IdentityFile / ssh-agent and the user name — retrying will not help' },
  key_unusable: { retryable: false, hint: 'the local identity file cannot be used (missing, unreadable or encrypted without an agent); fix it locally' },
  host_key_mismatch: {
    retryable: false,
    hint: 'the host key differs from known_hosts — possibly a reinstalled server, possibly a man-in-the-middle; ask the user before changing known_hosts'
  },
  transport_lost: { retryable: true, hint: 'the SSH connection dropped mid-call; the pool reconnects on the next call — check whether the command already ran before repeating it' },
  exec_timeout: {
    retryable: false,
    hint: 'the remote command hit its deadline and was killed; pass expectedMs for slow work, use background:true for daemons, or filter output remotely'
  },
  cancelled: {
    retryable: false,
    hint: 'the call was cancelled (usually the MCP client gave up waiting); the remote command may have started — inspect state before repeating it'
  },
  local_path: { retryable: false, hint: 'localPath is resolved on the machine running this server (see ssh_hosts → local), not on the agent\'s machine' },
  error: { retryable: false, hint: 'unexpected failure; read the message above' }
};

const RULES = [
  ['policy_denied', /\[ssh-pool (?:policy|plan|guard)\]/],
  ['unknown_host', /unknown ssh host|unknown host "/i],
  ['host_key_mismatch', /host key (?:mismatch|changed)|Host denied \(verification failed\)/i],
  ['auth_failed', /All configured authentication methods failed|authentication failed|Permission denied \(publickey/i],
  ['key_unusable', /identity file .*(?:encrypted|not found|cannot be read|unreadable)|Cannot parse privateKey|no such identity/i],
  ['connection_refused', /ECONNREFUSED|connection refused/i],
  ['host_unreachable', /ENOTFOUND|EAI_AGAIN|getaddrinfo|EHOSTUNREACH|ENETUNREACH|No route to host|Network is unreachable/i],
  ['connect_timeout', /Timed out while waiting for handshake|handshake timed out|ETIMEDOUT|connect timed out/i],
  ['local_path', /local file not found|local directory|ENOENT: no such file or directory, (?:open|stat|lstat) '(?:[A-Za-z]:\\|\/)/],
  ['cancelled', /\babort(?:ed)?\b|\bcancel(?:led|ed)?\b/i],
  ['exec_timeout', /timed out|timeout/i],
  ['transport_lost', /ECONNRESET|EPIPE|Connection lost|connection (?:was closed|ended)|Not connected|No response from server|channel open failure/i],
  ['invalid_argument', /\bis required\b|\binvalid\b|must be\b/i]
];

/**
 * Classify a thrown error.
 * @returns `{ code, hint, retryable }`.
 */
export function classifyError(error) {
  if (error?.code === 'POLICY_DENY') return { code: 'policy_denied', ...FAILURE_CODES.policy_denied };
  if (typeof error?.failureCode === 'string' && FAILURE_CODES[error.failureCode] !== undefined) {
    return { code: error.failureCode, ...FAILURE_CODES[error.failureCode] };
  }
  const message = error instanceof Error ? error.message : String(error ?? '');
  for (const [code, pattern] of RULES) {
    if (pattern.test(message)) return { code, ...FAILURE_CODES[code] };
  }
  return { code: 'error', ...FAILURE_CODES.error };
}

/** The marker line appended to an error's text. */
export function failureMarker({ code, hint }) {
  return `[error: ${code}] ${hint}`;
}

/**
 * Attach the classification to an error in place (message gets the marker
 * once; `failureCode` / `failureHint` / `retryable` are set) and return it.
 */
export function annotateError(error) {
  const target = error instanceof Error ? error : new Error(String(error ?? 'tool failed'));
  if (typeof target.failureCode === 'string' && target.message.includes('[error: ')) return target;
  const failure = classifyError(target);
  target.failureCode = failure.code;
  target.failureHint = failure.hint;
  target.retryable = failure.retryable;
  if (!target.message.includes('[error: ')) target.message = `${target.message}\n${failureMarker(failure)}`;
  return target;
}
