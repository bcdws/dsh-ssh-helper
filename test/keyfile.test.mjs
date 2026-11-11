/** Rename a key and update every IdentityFile reference, with refusals. */
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, chmodSync, symlinkSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { quoteConfigValue, renameIdentityFile } from '../lib/keyfile.js';

const dir = mkdtempSync(join(tmpdir(), 'dsh-keyfile-'));
const sshDir = join(dir, '.ssh');
mkdirSync(sshDir);
const config = join(sshDir, 'config');
const oldKey = join(sshDir, 'alpha');
const oldPub = `${oldKey}.pub`;
writeFileSync(oldKey, 'private\n');
chmodSync(oldKey, 0o600);
writeFileSync(oldPub, 'public\n');
const configText = [
  'Host alpha',
  '  HostName 192.0.2.1',
  '  IdentityFile ' + oldKey,
  '',
  'Host beta',
  '  HostName 192.0.2.2',
  '  IdentityFile=' + oldKey + ' # shared key',
  ''
].join('\n');
writeFileSync(config, configText, { mode: 0o600 });

let pass = 0;
const failures = [];
const check = (name, ok, detail) => (ok ? (pass += 1) : failures.push(`${name}: ${detail}`));

const result = renameIdentityFile({ configPath: config, identityFile: oldKey, newName: 'alpha_new', home: dir });
const newKey = join(sshDir, 'alpha_new');
check('returns-facts', result.changed === true && result.references === 2 && result.publicRenamed === true, JSON.stringify(result));
check('private-renamed', existsSync(newKey) && !existsSync(oldKey), JSON.stringify({ newKey: existsSync(newKey), oldKey: existsSync(oldKey) }));
check('public-renamed', existsSync(`${newKey}.pub`) && !existsSync(oldPub), 'public key must follow');
const updated = readFileSync(config, 'utf8');
// ssh_config doubles a Windows backslash, so compare against the rendered form.
const identityLines = updated.split(/\r?\n/).filter((line) => /^\s*IdentityFile/i.test(line));
// Both lines must point at the new key; a line still on the old one would not.
check('both-references-updated', identityLines.length === 2 && identityLines.every((line) => line.includes(quoteConfigValue(newKey))), updated);
check('comment-preserved', updated.includes('# shared key'), updated);

const target = join(sshDir, 'taken');
writeFileSync(target, 'x');
let targetError = '';
try { renameIdentityFile({ configPath: config, identityFile: newKey, newName: 'taken', home: dir }); } catch (error) { targetError = error.message; }
check('target-exists-refused', /target already exists/.test(targetError), targetError);

const missing = join(sshDir, 'missing');
let missingError = '';
try { renameIdentityFile({ configPath: config, identityFile: missing, newName: 'x', home: dir }); } catch (error) { missingError = error.message; }
check('missing-key-refused', /identity file not found/.test(missingError), missingError);

const link = join(sshDir, 'linkkey');
let linkCreated = true;
try {
  symlinkSync(newKey, link);
} catch (error) {
  // Windows without Developer Mode or admin rights cannot create symlinks;
  // there is nothing to test there.
  if (error.code !== 'EPERM' && error.code !== 'ENOSYS') throw error;
  linkCreated = false;
}
if (linkCreated) {
  let linkError = '';
  try { renameIdentityFile({ configPath: config, identityFile: link, newName: 'linkkey2', home: dir }); } catch (error) { linkError = error.message; }
  check('symlink-refused', /symlink/.test(linkError), linkError);
}

let unreferencedError = '';
try { renameIdentityFile({ configPath: config, identityFile: join(sshDir, 'other'), newName: 'other2', home: dir }); } catch (error) { unreferencedError = error.message; }
check('missing-key-before-config-refused', /identity file not found/.test(unreferencedError), unreferencedError);

writeFileSync(join(sshDir, 'other'), 'x');
let noRefError = '';
try { renameIdentityFile({ configPath: config, identityFile: join(sshDir, 'other'), newName: 'other2', home: dir }); } catch (error) { noRefError = error.message; }
check('no-config-reference-refused', /no IdentityFile/.test(noRefError), noRefError);

const included = join(sshDir, 'included');
writeFileSync(included, `Include ${config}\nHost gamma\n  IdentityFile ${newKey}\n`);
let includeError = '';
try { renameIdentityFile({ configPath: included, identityFile: newKey, newName: 'included2', home: dir }); } catch (error) { includeError = error.message; }
check('include-refused', /Include/.test(includeError), includeError);

rmSync(dir, { recursive: true, force: true });
console.log(`${pass}/${pass + failures.length} passed`);
for (const failure of failures) console.log(`FAIL ${failure}`);
process.exit(failures.length === 0 ? 0 : 2);
