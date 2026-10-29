/**
 * Output redaction: every credential class we expect to see in command output,
 * plus the false-positive, idempotency and robustness guards that keep a
 * transcript readable. Pure string work, no SSH involved, runs everywhere.
 */
import { redactSecrets, redactText } from '../lib/redact.js';

let pass = 0;
const failures = [];
const check = (name, ok, detail) => (ok ? (pass += 1) : failures.push(`${name}: ${detail}`));
const has = (text, needle) => text.includes(needle);
const names = (hits) => hits.map((h) => `${h.name}:${h.count}`).join(',');

// ── 1. key/value secrets ────────────────────────────────────────────────────
const kv = redactSecrets('curl --data token=abcdef123456 https://example.com');
check('kv-token', kv.text === 'curl --data token=<redacted:token> https://example.com', kv.text);
check('kv-token-hit', names(kv.hits) === 'token:1', names(kv.hits));

const quoted = redactSecrets('api_key="LIVEVALUE0123456789abcdef"');
check('kv-quoted-value-only', quoted.text === 'api_key="<redacted:api-key>"', quoted.text);
check('kv-quoted-hit', names(quoted.hits) === 'api-key:1', names(quoted.hits));

const yaml = redactSecrets('database:\n  password: hunter2xyz\n');
check('kv-colon-yaml', yaml.text === 'database:\n  password: <redacted:password>\n', JSON.stringify(yaml.text));
check('kv-colon-hit', names(yaml.hits) === 'password:1', names(yaml.hits));

const json = redactSecrets('{"token": "abcdef123456", "keep": true}');
check('kv-json-quoted-key', json.text === '{"token": "<redacted:token>", "keep": true}', json.text);

check('kv-uppercase-key', redactSecrets('TOKEN=abcdefgh').text === 'TOKEN=<redacted:token>', redactSecrets('TOKEN=abcdefgh').text);
check('kv-apikey-alias', redactSecrets('apikey=abcdefgh').text === 'apikey=<redacted:api-key>', redactSecrets('apikey=abcdefgh').text);
check('kv-prefixed-key', redactSecrets('DB_PASSWORD=s3cr3tvalue').text === 'DB_PASSWORD=<redacted:password>', redactSecrets('DB_PASSWORD=s3cr3tvalue').text);
check('kv-two-segment-key', redactSecrets('AWS_SECRET_ACCESS_KEY=abcdefghijklmnop').text === 'AWS_SECRET_ACCESS_KEY=<redacted:secret>', redactSecrets('AWS_SECRET_ACCESS_KEY=abcdefghijklmnop').text);
check('kv-suffix-key', redactSecrets('MY_TOKEN=abcdefgh').text === 'MY_TOKEN=<redacted:token>', redactSecrets('MY_TOKEN=abcdefgh').text);
check('kv-glued-key', redactSecrets('PGPASSWORD=hunter2xyz').text === 'PGPASSWORD=<redacted:password>', redactSecrets('PGPASSWORD=hunter2xyz').text);
check('kv-min-length', redactSecrets('pwd=123').text === 'pwd=123' && redactSecrets('pwd=123').hits.length === 0, 'a value shorter than 4 must survive');
check('kv-empty-value', redactSecrets('secret=').hits.length === 0, 'empty value is not a secret');

const repeated = redactSecrets('token=aaaa1111 then token=bbbb2222');
check('kv-count-two', names(repeated.hits) === 'token:2' && !has(repeated.text, 'aaaa1111') && !has(repeated.text, 'bbbb2222'), names(repeated.hits));
check('kv-indentation-kept', redactSecrets('\ttoken = abcdefgh').text === '\ttoken = <redacted:token>', JSON.stringify(redactSecrets('\ttoken = abcdefgh').text));

// ── 2. authorization headers ────────────────────────────────────────────────
const bearer = redactSecrets('Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig');
check('bearer-auth-header', bearer.text === 'Authorization: Bearer <redacted:bearer>', bearer.text);
check('bearer-hit', names(bearer.hits) === 'bearer:1', names(bearer.hits));
check('bearer-bare', redactSecrets('-H "Authorization: Bearer abcDEF123456ghi"').text === '-H "Authorization: Bearer <redacted:bearer>"', redactSecrets('-H "Authorization: Bearer abcDEF123456ghi"').text);

const basic = redactSecrets('Authorization: Basic dXNlcjpwYXNzd29yZA==');
check('basic-b64', basic.text === 'Authorization: Basic <redacted:basic>', basic.text);
check('basic-hit', names(basic.hits) === 'basic:1', names(basic.hits));
check('basic-prose-guard', redactSecrets('Basic authentication is required').hits.length === 0, 'the English word "authentication" is not a token');

// ── 3. subscription URLs ────────────────────────────────────────────────────
const subPath = redactSecrets('https://example.com/subs/AbCdEf0123456789xyzQWE');
check('url-sub-path', subPath.text === 'https://example.com/subs/<redacted:url-path>', subPath.text);
check('url-path-hit', names(subPath.hits) === 'url-path:1', names(subPath.hits));
check('url-api-path', redactSecrets('GET /api/VeryLongRandomToken1234567890').text === 'GET /api/<redacted:url-path>', redactSecrets('GET /api/VeryLongRandomToken1234567890').text);

const deepPath = redactSecrets('https://sub.example.com/api/v1/SUBTOKEN2abcdefghijklmnop');
check('url-deep-path', deepPath.text === 'https://sub.example.com/api/v1/<redacted:url-path>', deepPath.text);
check('url-deep-path-hit', names(deepPath.hits) === 'url-path:1', names(deepPath.hits));

const query = redactSecrets('https://example.com/subs/new?token=SECRETVALUE12345&x=1');
check('url-query-value', query.text === 'https://example.com/subs/new?token=<redacted:url-query>&x=1', query.text);
check('url-query-hit', names(query.hits) === 'url-query:1', names(query.hits));

const twoBuckets = redactSecrets('token=aaaa1111 and https://h/p?token=bbbb2222&z=1');
check('url-query-generic-split', names(twoBuckets.hits) === 'url-query:1,token:1', names(twoBuckets.hits));

const userinfo = redactSecrets('sftp url ssh://root:hunter2xyz@example.com:22/srv');
check('url-userinfo', userinfo.text === 'sftp url ssh://<redacted:url-userinfo>@example.com:22/srv', userinfo.text);
check('url-userinfo-hit', names(userinfo.hits) === 'url-userinfo:1', names(userinfo.hits));
check('git-remote-token', redactSecrets(`origin\thttps://ghp_${'A'.repeat(36)}@github.com/u/r.git (fetch)`).text === 'origin\thttps://<redacted:github-token>@github.com/u/r.git (fetch)', redactSecrets(`origin\thttps://ghp_${'A'.repeat(36)}@github.com/u/r.git (fetch)`).text);

// ── 4. proxy protocol URIs ──────────────────────────────────────────────────
const vless = redactSecrets('vless://3f2504e0-4f89-11d3-9a0c-0305e82c3301@example.com:443?type=ws&security=tls#tokyo-01');
check('proxy-vless-whole-line', vless.text === '<redacted:proxy-uri>', vless.text);
check('proxy-vless-hit', names(vless.hits) === 'proxy-uri:1', names(vless.hits));
check('proxy-vmess', redactSecrets('vmess://eyJ2IjoiMiIsInBzIjoibm9kZSJ9').text === '<redacted:proxy-uri>', redactSecrets('vmess://eyJ2IjoiMiIsInBzIjoibm9kZSJ9').text);

const multiProxy = redactSecrets('a ss://YWVzOnBhc3M@1.2.3.4:8388#n1 b trojan://pw123456@h.example:443#n2 c');
check('proxy-multi', multiProxy.text === 'a <redacted:proxy-uri> b <redacted:proxy-uri> c', multiProxy.text);
check('proxy-multi-hit', names(multiProxy.hits) === 'proxy-uri:2', names(multiProxy.hits));
check('proxy-fragment-gone', !has(multiProxy.text, 'n1') && !has(multiProxy.text, 'n2'), 'the fragment (node name) must not leak');
check('proxy-keeps-punctuation', redactSecrets('see trojan://pw123456@h.example:443, then').text === 'see <redacted:proxy-uri>, then', redactSecrets('see trojan://pw123456@h.example:443, then').text);

// ── 5. JWT ──────────────────────────────────────────────────────────────────
const jwt = redactSecrets('token from log: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk');
check('jwt', jwt.text === 'token from log: <redacted:jwt>', jwt.text);
check('jwt-hit', names(jwt.hits) === 'jwt:1', names(jwt.hits));

// ── 6. UUID ─────────────────────────────────────────────────────────────────
const uuid = redactSecrets('peer id 3f2504e0-4f89-11d3-9a0c-0305e82c3301 online');
check('uuid', uuid.text === 'peer id <redacted:uuid> online', uuid.text);
check('uuid-hit', names(uuid.hits) === 'uuid:1', names(uuid.hits));

// ── 7. private keys ─────────────────────────────────────────────────────────
const pem = 'before\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1234567890abcdefghij\nAAAA\n-----END RSA PRIVATE KEY-----\nafter';
const pemOut = redactSecrets(pem);
check('pem-block', pemOut.text === 'before\n<redacted:private-key>\nafter', JSON.stringify(pemOut.text));
check('pem-hit', names(pemOut.hits) === 'private-key:1', names(pemOut.hits));
check('pem-openssh', redactSecrets('-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk=\n-----END OPENSSH PRIVATE KEY-----').text === '<redacted:private-key>', redactSecrets('-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk=\n-----END OPENSSH PRIVATE KEY-----').text);

const truncated = redactSecrets('log\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\ntruncated');
check('pem-truncated', truncated.text === 'log\n<redacted:private-key>\ntruncated', JSON.stringify(truncated.text));

check('pubkey-not-redacted', redactSecrets('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExample user@host').hits.length === 0, 'a public key body is not a secret');
check('pubkey-padding-not-redacted', redactSecrets('ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQ== user@host').hits.length === 0, 'base64 padding in a public key is not a secret');

// ── 8. cloud credentials ────────────────────────────────────────────────────
check('aws-key', redactSecrets('key id AKIAIOSFODNN7EXAMPLE leaked').text === 'key id <redacted:aws-key> leaked', redactSecrets('key id AKIAIOSFODNN7EXAMPLE leaked').text);
const gh = redactSecrets(`GITHUB_TOKEN=ghp_${'A'.repeat(36)}`);
check('github-token', gh.text === 'GITHUB_TOKEN=<redacted:github-token>', gh.text);
check('github-hit-specific', names(gh.hits) === 'github-token:1', names(gh.hits));
const oa = redactSecrets('export OPENAI_API_KEY=sk-a1B2c3D4e5F6g7H8i9J0k1L2m3N4');
check('openai-key', oa.text === 'export OPENAI_API_KEY=<redacted:openai-key>', oa.text);
check('openai-hit', names(oa.hits) === 'openai-key:1', names(oa.hits));
const slackToken = `xoxb-${'1'.repeat(12)}-${'a'.repeat(16)}`;
check('slack-token', redactSecrets(`slack token ${slackToken}`).text === 'slack token <redacted:slack-token>', redactSecrets(`slack token ${slackToken}`).text);

// ── false positives: ordinary output must survive untouched ─────────────────
const untouched = [
  ['fp-prose', 'The password is stored in the vault.'],
  ['fp-word-password', 'Password rotation happens every 90 days.'],
  ['fp-echo', 'echo hello'],
  ['fp-env-path', 'PATH=/usr/bin:/bin'],
  ['fp-plain-url', 'https://example.com/a/b'],
  ['fp-api-url', 'https://example.com/api/v1/users'],
  ['fp-listing', 'drwxr-xr-x 2 root root 4096 Oct 19 10:00 .'],
  ['fp-npm', 'added 42 packages in 3s'],
  ['fp-word-token', 'tokenization is not a credential'],
  ['fp-shell-pwd', 'sudo pwd'],
  ['fp-email', 'contact ops@example.com if it fails'],
  ['fp-scp-remote', 'git@github.com:foo/bar.git'],
  ['fp-kv-prose', 'no_password_needed=true'],
  ['fp-api-resource', 'https://example.com/api/v1/notification-settings'],
];
for (const [name, text] of untouched) {
  const res = redactSecrets(text);
  check(name, res.text === text && res.hits.length === 0, JSON.stringify(res.text));
}

// ── idempotency ─────────────────────────────────────────────────────────────
const soup = [
  'token=abcdef123456',
  'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig',
  'vless://3f2504e0-4f89-11d3-9a0c-0305e82c3301@example.com:443?type=ws#node',
  'https://example.com/subs/AbCdEf0123456789xyzQWE',
  'password: hunter2xyz',
  'AKIAIOSFODNN7EXAMPLE',
  '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1234\n-----END RSA PRIVATE KEY-----',
].join('\n');
const once = redactSecrets(soup);
const twice = redactSecrets(once.text);
const thrice = redactSecrets(twice.text);
check('idempotent-changes-first', once.text !== soup && once.hits.length > 0, JSON.stringify(once.hits));
check('idempotent-stable', twice.text === once.text && thrice.text === once.text, 'the second pass must not rewrite anything');
check('idempotent-no-hits', twice.hits.length === 0 && thrice.hits.length === 0, JSON.stringify(twice.hits));
check('idempotent-nothing-left', !has(once.text, 'abcdef123456') && !has(once.text, 'hunter2xyz') && !has(once.text, 'AKIAIOSFODNN7EXAMPLE'), once.text);

// ── hits shape ──────────────────────────────────────────────────────────────
const mixed = redactSecrets('token=aaaa1111 token=bbbb2222 password=cccc3333 Authorization: Bearer abcDEF123456ghi');
const byName = Object.fromEntries(mixed.hits.map((h) => [h.name, h.count]));
check('hits-shape', mixed.hits.every((h) => typeof h.name === 'string' && Number.isInteger(h.count) && h.count > 0), JSON.stringify(mixed.hits));
check('hits-merged-counts', byName.token === 2 && byName.password === 1 && byName.bearer === 1 && mixed.hits.length === 3, JSON.stringify(mixed.hits));
check('hits-names-sorted', mixed.hits.map((h) => h.name).sort().join(',') === 'bearer,password,token', mixed.hits.map((h) => h.name).join(','));

// ── empty / plain input ─────────────────────────────────────────────────────
check('empty-string', redactSecrets('').text === '' && redactSecrets('').hits.length === 0, 'empty in, empty out');
const plain = 'just some ordinary output\nsecond line';
const plainRes = redactSecrets(plain);
check('no-match-identity', plainRes.text === plain && plainRes.hits.length === 0, 'no hit means the very same string back');

// ── non-string input ────────────────────────────────────────────────────────
const nonStrings = [
  ['nonstring-number', 42, '42'],
  ['nonstring-null', null, 'null'],
  ['nonstring-undefined', undefined, 'undefined'],
  ['nonstring-bool', true, 'true'],
  ['nonstring-object', {}, '[object Object]'],
  ['nonstring-array', ['a', 'b'], 'a,b'],
  ['nonstring-symbol', Symbol('x'), 'Symbol(x)'],
  ['nonstring-bigint', 10n, '10'],
];
for (const [name, value, expected] of nonStrings) {
  let res;
  let threw = false;
  try { res = redactSecrets(value); } catch { threw = true; }
  check(name, !threw && res.text === expected && Array.isArray(res.hits) && res.hits.length === 0, `${expected} -> ${threw ? 'THREW' : JSON.stringify(res.text)}`);
}
check('nonstring-throwing-tostring', (() => {
  const res = redactSecrets({ toString() { throw new Error('nope'); } });
  return res.text === '' && Array.isArray(res.hits) && res.hits.length === 0;
})(), 'a throwing toString must not escape');

// ── long input: no throw, no runaway ────────────────────────────────────────
// A single 600KB line of one long word is the shape that turns an unbounded
// `[A-Za-z0-9+.-]*` scheme run quadratic; the bound is deliberately loose.
const longLine = `${'x'.repeat(300000)} token=abcdef123456 ${'x'.repeat(300000)}`;
const longStarted = Date.now();
const longRes = redactSecrets(longLine);
const longMs = Date.now() - longStarted;
check('long-line', has(longRes.text, '<redacted:token>') && !has(longRes.text, 'abcdef123456') && longRes.text.length > 600000, `${longRes.text.length} chars`);
check('long-line-perf', longMs < 2000, `${longMs}ms — a quadratic rule lives here`);

const eyjRun = 'eyJ'.repeat(50000);
const eyjStarted = Date.now();
const eyjRes = redactSecrets(eyjRun);
check('pathological-eyj', Date.now() - eyjStarted < 2000 && eyjRes.hits.length === 0 && eyjRes.text.length === eyjRun.length, `${Date.now() - eyjStarted}ms`);

const noSchemeRun = `${'ab-cd.ef'.repeat(40000)} user@host`;
const schemeStarted = Date.now();
const schemeRes = redactSecrets(noSchemeRun);
check('pathological-scheme-run', Date.now() - schemeStarted < 2000 && schemeRes.hits.length === 0, `${Date.now() - schemeStarted}ms`);

const manyLines = Array.from({ length: 5000 }, () => 'some ordinary output line').join('\n');
const manyRes = redactSecrets(manyLines);
check('many-lines-preserved', manyRes.text.split('\n').length === 5000 && manyRes.hits.length === 0, 'line count must not change');

const lineCount = redactSecrets('first line\ntoken=abcdef123456\nthird line\n');
check('line-context-kept', lineCount.text === 'first line\ntoken=<redacted:token>\nthird line\n', JSON.stringify(lineCount.text));

// ── redactText convenience ──────────────────────────────────────────────────
check('redactText-string', redactText('token=abcdef123456') === 'token=<redacted:token>', redactText('token=abcdef123456'));
check('redactText-nonstring', redactText(12345) === '12345', redactText(12345));
check('redactText-matches-secrets', redactText('secret=abcdefgh') === redactSecrets('secret=abcdefgh').text, 'both entry points must agree');

// ── throughput: ~1MB of realistic log output in tens of milliseconds ────────
const bigLine = 'GET /index.html 200 1234 - 10.0.0.1 token=aaaa1111\n';
const big = bigLine.repeat(20000);
const started = Date.now();
const bigRes = redactSecrets(big);
const elapsed = Date.now() - started;
check('perf-1mb', elapsed < 2000 && has(bigRes.text, '<redacted:token>'), `${elapsed}ms for ${(big.length / 1048576).toFixed(2)}MB, ${bigRes.hits[0]?.count ?? 0} hits`);
console.log(`perf: ${(big.length / 1048576).toFixed(2)}MB in ${elapsed}ms`);

console.log(`${pass}/${pass + failures.length} passed`);
for (const failure of failures) console.log(`FAIL ${failure}`);
process.exit(failures.length === 0 ? 0 : 2);
