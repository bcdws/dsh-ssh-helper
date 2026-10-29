/**
 * Pure helpers behind the remote file tools: glob matching, unique-match
 * detection and content hashing. No SSH involved, so these run everywhere.
 */
import { findUnique, globToRegExp, matchesGlob, sha256Of } from '../lib/files.js';

let pass = 0;
const failures = [];
const check = (name, ok, detail) => (ok ? (pass += 1) : failures.push(`${name}: ${detail}`));

// Glob matching: `*` stays inside one segment, `**` crosses directories.
check('glob-flat', matchesGlob('/srv/app/main.conf', '*.conf') && matchesGlob('app/main.js', '*.js'), 'basename matching');
check('glob-single-star', !matchesGlob('src/deep/main.js', 'src/*.js'), 'single star must not cross a directory');
check('glob-double-star', matchesGlob('src/deep/main.js', 'src/**/*.js') && matchesGlob('src/main.js', 'src/**/*.js'), '** must match zero or more segments');
check('glob-question', matchesGlob('app1.log', 'app?.log') && !matchesGlob('app12.log', 'app?.log'), '? matches one character');
check('glob-exact', matchesGlob('/etc/nginx/nginx.conf', '/etc/nginx/nginx.conf') && !matchesGlob('/etc/nginx/x.conf', '/etc/nginx/nginx.conf'), 'exact path');
check('glob-escapes-regex', globToRegExp('a.b+c').test('a.b+c') && !globToRegExp('a.b+c').test('axb+c'), 'regex metacharacters must be escaped');

// Unique-match detection: the edit tool refuses ambiguous replacements.
check('unique-single', (() => { const found = findUnique('alpha beta', 'beta'); return found.count === 1 && found.start === 6; })(), 'single occurrence');
check('unique-multiple', findUnique('x=1; x=2', 'x=').count === 2, 'two occurrences counted');
check('unique-missing', findUnique('abc', 'zzz').count === 0, 'missing occurrence');
check('unique-empty-needle', findUnique('abc', '').count === 0, 'empty needle is not a match');
check('unique-leading-match', findUnique('head tail', 'head').start === 0, 'match at index 0');

// Hashing is deterministic and stable for the sha256 round trip.
check('sha256-known', sha256Of(Buffer.from('abc')) === 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', sha256Of(Buffer.from('abc')));
check('sha256-changes', sha256Of(Buffer.from('a')) !== sha256Of(Buffer.from('b')), 'different content, different hash');

console.log(`${pass}/${pass + failures.length} passed`);
for (const failure of failures) console.log(`FAIL ${failure}`);
process.exit(failures.length === 0 ? 0 : 2);
