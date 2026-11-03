/** Atomic Host alias + key rename: both apply, or a preflight refuses. */
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, chmodSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { editHostIdentity } from '../lib/edit-host.js';

const dir = mkdtempSync(join(tmpdir(), 'dsh-edit-host-'));
const ssh = join(dir, '.ssh');
mkdirSync(ssh);
const config = join(ssh, 'config');
const oldKey = join(ssh, 'alpha');
const oldPub = `${oldKey}.pub`;
writeFileSync(oldKey, 'private\n');
chmodSync(oldKey, 0o600);
writeFileSync(oldPub, 'public\n');
const original = [
  'Host alpha',
  '  HostName 192.0.2.1',
  '  IdentityFile ' + oldKey,
  '',
  'Host beta',
  '  HostName 192.0.2.2',
  '  IdentityFile ' + oldKey + ' # shared',
  ''
].join('\n');
writeFileSync(config, original, { mode: 0o600 });

let pass = 0;
const failures = [];
const check = (name, ok, detail) => (ok ? (pass += 1) : failures.push(`${name}: ${detail}`));

const both = editHostIdentity({ configPath: config, oldAlias: 'alpha', newAlias: 'alpha2', oldKeyPath: oldKey, newKeyName: 'alpha2_key', home: dir });
const afterBoth = readFileSync(config, 'utf8');
const newKey = join(ssh, 'alpha2_key');
check('both-flags', both.changed === true && both.aliasChanged === true && both.keyChanged === true, JSON.stringify(both));
check('both-files', existsSync(newKey) && existsSync(`${newKey}.pub`) && !existsSync(oldKey) && !existsSync(oldPub), JSON.stringify({ newKey: existsSync(newKey), newPub: existsSync(`${newKey}.pub`) }));
check('both-config', /Host alpha2\n/.test(afterBoth) && afterBoth.split(newKey).length - 1 === 2 && !afterBoth.includes(`${oldKey}\n`) && !afterBoth.includes(`${oldKey} #`), afterBoth);
check('both-comment', afterBoth.includes('# shared'), afterBoth);

const onlyHost = editHostIdentity({ configPath: config, oldAlias: 'alpha2', newAlias: 'alpha3', oldKeyPath: newKey, newKeyName: undefined, home: dir });
check('host-only', onlyHost.aliasChanged === true && onlyHost.keyChanged === false && /Host alpha3\n/.test(readFileSync(config, 'utf8')), JSON.stringify(onlyHost));

const onlyKey = editHostIdentity({ configPath: config, oldAlias: 'alpha3', newAlias: undefined, oldKeyPath: newKey, newKeyName: 'alpha3_key', home: dir });
check('key-only', onlyKey.aliasChanged === false && onlyKey.keyChanged === true && existsSync(join(ssh, 'alpha3_key')), JSON.stringify(onlyKey));

const beforeBad = readFileSync(config, 'utf8');
const target = join(ssh, 'taken');
writeFileSync(target, 'x');
let bad = '';
try {
  editHostIdentity({ configPath: config, oldAlias: 'alpha3', newAlias: 'should-not-apply', oldKeyPath: join(ssh, 'alpha3_key'), newKeyName: 'taken', home: dir });
} catch (error) { bad = error.message; }
check('target-refused', /target already exists/.test(bad), bad);
check('target-refused-before-write', readFileSync(config, 'utf8') === beforeBad, 'config must not change on preflight failure');

const proxy = join(dir, 'proxy');
writeFileSync(proxy, 'Host jump\n  ProxyJump alpha3\n\nHost alpha3\n  HostName 192.0.2.1\n');
let proxyError = '';
try { editHostIdentity({ configPath: proxy, oldAlias: 'alpha3', newAlias: 'alpha4', home: dir }); } catch (error) { proxyError = error.message; }
check('proxy-refused', /ProxyJump/.test(proxyError), proxyError);

rmSync(dir, { recursive: true, force: true });
console.log(`${pass}/${pass + failures.length} passed`);
for (const failure of failures) console.log(`FAIL ${failure}`);
process.exit(failures.length === 0 ? 0 : 2);
