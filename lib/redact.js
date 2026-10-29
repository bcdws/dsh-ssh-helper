/**
 * Output redaction for tool results.
 *
 * An incident showed that subscription URLs carrying live tokens can come
 * back inside command output and be copied verbatim into a session transcript.
 * Anything a tool is about to return to the agent now goes through
 * `redactSecrets` first.
 *
 * Contract:
 *   - never throws: a failed redaction degrades to the original text, hits `[]`;
 *   - idempotent: placeholders are inert, so redacting an already redacted text
 *     changes nothing and the second pass reports zero hits;
 *   - readable: the secret is replaced in place (`token=<redacted:token>`),
 *     surrounding prose, indentation and line breaks stay put;
 *   - linear time: no nested quantifiers, no unbounded lazy scan.
 *
 * The `hits` name is always the placeholder suffix, so `{ name: 'uuid' }` means
 * the text contains `<redacted:uuid>`.
 */

/** Placeholder for one redacted class. Never matches any rule below. */
const PH = (name) => `<redacted:${name}>`;

/** Trailing sentence punctuation a bare URI must not swallow. */
const URI_TAIL = /[,.;!?)\]}>。，；：）】》]+$/;

/** One name segment may wrap the keyword; the suffix must be a known one. */
const KEY_VALUE_RE =
  /(?<![A-Za-z0-9])((?:[A-Za-z0-9]{1,32}[_-]?)?(?:token|apikey|api[_-]?key|secret|password|passwd|pwd)(?:[_-](?:key|token|secret|hash|salt|value|pass|password|pwd|access[_-]?key|private[_-]?key))?["']?\s*[=:]\s*)(['"]?)([^\s'"<>]{4,})\2/gi;

/** `token=` / `SECRET_KEY:` / `{"api_key": ...}` -> a stable semantic label. */
function keyLabel(key) {
  const lower = String(key).toLowerCase();
  if (lower.includes('token')) return 'token';
  if (lower.includes('secret')) return 'secret';
  if (lower.includes('pass') || lower.includes('pwd')) return 'password';
  if (lower.includes('key')) return 'api-key';
  return 'secret';
}

/**
 * Ordered rules. Specific detectors run before the generic `key=value` grabber
 * so a cloud key inside `GITHUB_TOKEN=...` is reported as `github-token` rather
 * than folded into the generic bucket.
 */
const RULES = [
  // 7. private key blocks: whole block, before anything can nibble the body.
  // The body is length-capped so many unterminated headers cannot turn the
  // lazy scan into N × text-length work; rule 7b redacts what is left over.
  {
    re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]{0,65536}?-----END [A-Z ]*PRIVATE KEY-----/g,
    apply: () => ({ text: PH('private-key'), name: 'private-key' }),
  },
  // 7b. truncated key (output cut off before `-----END`): header plus the
  // base64 lines that follow, so a 64KB scrollback is not eaten by one hit.
  {
    re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[^\n]*(?:\r?\n[ \t]*[A-Za-z0-9+/=]{16,}[ \t]*)*/g,
    apply: () => ({ text: PH('private-key'), name: 'private-key' }),
  },
  // 4. proxy protocol URIs: whole URI including userinfo, query and fragment.
  {
    re: /\b(?:vless|vmess|trojan|ssr|ss|hysteria2?|tuic):\/\/[^\s"'<>]+/g,
    apply: (match) => {
      const body = match.replace(URI_TAIL, '');
      return { text: PH('proxy-uri') + match.slice(body.length), name: 'proxy-uri' };
    },
  },
  // 8. cloud credentials (specific shapes only).
  { re: /\bAKIA[0-9A-Z]{16}\b/g, apply: () => ({ text: PH('aws-key'), name: 'aws-key' }) },
  { re: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, apply: () => ({ text: PH('github-token'), name: 'github-token' }) },
  { re: /\bsk-[A-Za-z0-9_-]{20,}\b/g, apply: () => ({ text: PH('openai-key'), name: 'openai-key' }) },
  { re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, apply: () => ({ text: PH('slack-token'), name: 'slack-token' }) },
  // 2. authorization schemes. The value must carry a digit/dot/dash/upper-case
  // so the English word "authentication" is not mistaken for a token.
  {
    re: /\bBearer\s+(?=[A-Za-z0-9._~+/=-]*[0-9A-Z._~+/=-])([A-Za-z0-9._~+/=-]{8,})/gi,
    apply: () => ({ text: `Bearer ${PH('bearer')}`, name: 'bearer' }),
  },
  {
    re: /\bBasic\s+(?=[A-Za-z0-9+/=_-]*[0-9A-Z=])([A-Za-z0-9+/=_-]{12,})/g,
    apply: () => ({ text: `Basic ${PH('basic')}`, name: 'basic' }),
  },
  // 5. JWT: three dot-separated segments, the first decoding to `{"`.
  // Segments are length-capped (real JWTs are well under 8KB) so a long run
  // that starts with `eyJ` but never contains a dot cannot backtrack for long.
  {
    re: /\beyJ[A-Za-z0-9_-]{0,8192}\.[A-Za-z0-9_-]{1,8192}\.[A-Za-z0-9_-]{0,8192}/g,
    apply: () => ({ text: PH('jwt'), name: 'jwt' }),
  },
  // 6. UUID: the credential in sing-box / vless / vmess.
  {
    re: /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi,
    apply: () => ({ text: PH('uuid'), name: 'uuid' }),
  },
  // 3a. credentials inline in a URL's userinfo (`ssh://root:pw@host`). The
  // scheme run is bounded: an unbounded `[A-Za-z0-9+.-]*` here backtracks
  // quadratically over a long word that contains no `://` (79s on a 600KB line).
  {
    re: /([A-Za-z][A-Za-z0-9+.-]{1,15}:\/\/)([^/\s:@'"<>]+):([^/\s@'"<>]+)@/g,
    apply: (match, scheme) => ({ text: `${scheme}${PH('url-userinfo')}@`, name: 'url-userinfo' }),
  },
  // 3b. subscription paths with an intermediate segment (`/api/v1/<token>` the
  // single-segment pattern below cannot see). Gated on a digit inside the long
  // segment so an ordinary `/api/v1/notification-settings` stays readable.
  {
    re: /\/(subs?|subscribe|api|link)\/((?:[A-Za-z0-9._~-]{1,15}\/)*)(?=[A-Za-z0-9._~-]*[0-9])[A-Za-z0-9._~-]{16,}/g,
    apply: (match, prefix, mid) => ({ text: `/${prefix}/${mid}${PH('url-path')}`, name: 'url-path' }),
  },
  // 3c. long random path segment on subscription endpoints.
  {
    re: /\/(subs?|subscribe|api|link)\/[A-Za-z0-9._~-]{16,}/g,
    apply: (match, prefix) => ({ text: `/${prefix}/${PH('url-path')}`, name: 'url-path' }),
  },
  // 3d. credential query parameters, value only.
  {
    re: /([?&](?:token|access_token|api[_-]?key|apikey|auth|secret|password|passwd|pwd|key)=)([^&\s'"<>#]+)/gi,
    apply: (match, head) => ({ text: head + PH('url-query'), name: 'url-query' }),
  },
  // 1. key/value pairs; the quotes around the value are kept.
  {
    re: KEY_VALUE_RE,
    apply: (match, head, quote) => {
      const label = keyLabel((head.match(/[A-Za-z_-]+/) || ['secret'])[0]);
      return { text: head + quote + PH(label) + quote, name: label };
    },
  },
];

/**
 * Redact credentials from tool output.
 *
 * @param {unknown} text any value; non-strings are stringified first
 * @returns {{ text: string, hits: Array<{ name: string, count: number }> }}
 *   `text` is the redacted string (the input itself when nothing matched),
 *   `hits` lists one entry per distinct class, in the fixed rule order.
 */
export function redactSecrets(text) {
  let input;
  try {
    input = typeof text === 'string' ? text : String(text);
  } catch {
    return { text: '', hits: [] };
  }
  if (typeof input !== 'string') return { text: '', hits: [] };
  if (input.length === 0) return { text: input, hits: [] };

  try {
    let out = input;
    const counts = new Map();
    for (const rule of RULES) {
      rule.re.lastIndex = 0;
      out = out.replace(rule.re, (...args) => {
        try {
          const hit = rule.apply(...args);
          counts.set(hit.name, (counts.get(hit.name) || 0) + 1);
          return hit.text;
        } catch {
          return args[0];
        }
      });
    }
    if (counts.size === 0) return { text: input, hits: [] };
    return { text: out, hits: Array.from(counts, ([name, count]) => ({ name, count })) };
  } catch {
    return { text: input, hits: [] };
  }
}

/**
 * Convenience wrapper: the redacted text only.
 *
 * @param {unknown} text
 * @returns {string}
 */
export function redactText(text) {
  return redactSecrets(text).text;
}
