/** Host alias rename: exact token, comments, collisions, backup. */
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { renameHostAlias } from '../lib/hostalias.js';

const dir = mkdtempSync(join(tmpdir(), 'dsh-hostalias-'));
const config = join(dir, 'config');
const original = [
  'Host ir_kua',
  '  HostName 192.0.2.1',
  '  IdentityFile ~/.ssh/irkua',
  '',
  'Host jy # old client',
  '  HostName 192.0.2.2',
  '  IdentityFile ~/.ssh/irjy',
  ''
].join('\n');
writeFileSync(config, original, { mode: 0o600 });

let pass = 0;
const failures = [];
const check = (name, ok, detail) => (ok ? (pass += 1) : failures.push(`${name}: ${detail}`));

const result = renameHostAlias({ configPath: config, oldAlias: 'ir_kua', newAlias: 'irkua' });
const updated = readFileSync(config, 'utf8');
check('returns-changed', result.changed === true && result.references === 1 && result.oldAlias === 'ir_kua' && result.newAlias === 'irkua', JSON.stringify(result));
check('host-renamed', /Host irkua\n/.test(updated) && !/Host ir_kua\b/.test(updated), updated);
check('other-host-untouched', /Host jy # old client/.test(updated), updated);

let collision = '';
try { renameHostAlias({ configPath: config, oldAlias: 'jy', newAlias: 'irkua' }); } catch (error) { collision = error.message; }
check('collision-refused', /already exists/.test(collision), collision);

let missing = '';
try { renameHostAlias({ configPath: config, oldAlias: 'nope', newAlias: 'nope2' }); } catch (error) { missing = error.message; }
check('missing-refused', /no Host alias/.test(missing), missing);

let invalid = '';
try { renameHostAlias({ configPath: config, oldAlias: 'irkua', newAlias: '../bad' }); } catch (error) { invalid = error.message; }
check('invalid-refused', /only contain/.test(invalid), invalid);

const same = renameHostAlias({ configPath: config, oldAlias: 'irkua', newAlias: 'irkua' });
check('same-noop', same.changed === false && same.references === 0, JSON.stringify(same));

const proxy = join(dir, 'proxy-config');
writeFileSync(proxy, [
  'Host bastion',
  '  HostName 192.0.2.9',
  '  ProxyJump irkua',
  '',
  'Host irkua',
  '  HostName 192.0.2.1',
  ''
].join('\n'));
let proxyError = '';
try { renameHostAlias({ configPath: proxy, oldAlias: 'irkua', newAlias: 'irkua2' }); } catch (error) { proxyError = error.message; }
check('proxy-reference-refused', /ProxyJump/.test(proxyError), proxyError);

const include = join(dir, 'include-config');
writeFileSync(include, 'Include other.conf\nHost irkua\n  HostName 192.0.2.1\n');
let includeError = '';
try { renameHostAlias({ configPath: include, oldAlias: 'irkua', newAlias: 'irkua2' }); } catch (error) { includeError = error.message; }
check('include-refused', /Include/.test(includeError), includeError);

rmSync(dir, { recursive: true, force: true });
console.log(`${pass}/${pass + failures.length} passed`);
for (const failure of failures) console.log(`FAIL ${failure}`);
process.exit(failures.length === 0 ? 0 : 2);
