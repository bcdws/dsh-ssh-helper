/**
 * Metadata store: host remarks, the hidden switch, the idle override, settings,
 * migration from the old profile/capability shape, clamps, persistence, and the
 * secret-free guarantee.
 *
 * The migration checks are built from a hand-written *old* state file: that is
 * the only way to prove a file produced by a previous version still upgrades,
 * which is not something the current writer can exercise.
 */
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MAX_IDLE_TIMEOUT_MS, MetadataStore } from '../lib/store.js';

const dir = mkdtempSync(join(tmpdir(), 'dsh-store-'));
const file = join(dir, 'state.json');
let pass = 0;
const failures = [];
const check = (name, ok, detail) => (ok ? (pass += 1) : failures.push(`${name}: ${detail}`));
const document = (path) => JSON.parse(readFileSync(path, 'utf8'));
const hostsOf = (path) => document(path).hosts;
/** The frozen shape, field names fixed by the contract. */
const SHAPE = 'alias,hidden,idleTimeoutMs,remark';
/** The only keys ever written for a host. */
const STORED_KEYS = 'hidden,idleTimeoutMs,remark';
/** The four settings the panel exposes, field names fixed by the contract. */
const SETTINGS_SHAPE = 'idleTimeoutMs,logAnalysis,maxOutputBytes,sshVisible,transferTimeoutMs';
/** Removed in the single-guard slimming: never read back, accepted or persisted. */
const LEGACY_HOST_KEYS = ['profile', 'caps', 'level', 'visible'];
const DELETED_SETTINGS = ['timeoutMultiplier', 'timeoutFloorMs', 'timeoutCeilingMs', 'maxLogLines', 'blockResourceSpikes', 'productionEnforced'];

const store = new MetadataStore({
  filePath: file,
  defaults: { settings: { idleTimeoutMs: 5000, maxOutputBytes: 32000, transferTimeoutMs: 120000 } }
});

// ── the frozen shape ────────────────────────────────────────────────────────
const fresh = store.host('prod-1');
check('shape-keys', Object.keys(fresh).sort().join(',') === SHAPE, Object.keys(fresh).join(','));
check('default-hidden', fresh.hidden === false, JSON.stringify(fresh));
check('default-remark', fresh.remark === '' && fresh.idleTimeoutMs === null, JSON.stringify(fresh));
check('unknown-alias-same-shape', JSON.stringify(store.host('other')) === JSON.stringify({ ...fresh, alias: 'other' }), JSON.stringify(store.host('other')));
check('legacy-keys-gone', LEGACY_HOST_KEYS.every((key) => !(key in fresh)), JSON.stringify(fresh));

check('defaults-settings', store.settings().idleTimeoutMs === 5000 && store.settings().maxOutputBytes === 32000 && store.settings().transferTimeoutMs === 120000 && store.settings().sshVisible === true && store.settings().logAnalysis === false, JSON.stringify(store.settings()));
check('defaults-settings-shape', Object.keys(store.settings()).sort().join(',') === SETTINGS_SHAPE, Object.keys(store.settings()).join(','));
check('no-file-yet', !existsSync(file), 'the store must not write before a change');

// ── round trips ─────────────────────────────────────────────────────────────
const saved = store.setHost('web-1', { remark: '生产 Web 主库', hidden: false, idleTimeoutMs: 30000 });
check('set-returns', saved.remark === '生产 Web 主库' && saved.hidden === false && saved.idleTimeoutMs === 30000, JSON.stringify(saved));
check('persisted', hostsOf(file)['web-1'].remark === '生产 Web 主库', JSON.stringify(hostsOf(file)));

const hidden = store.setHost('web-1', { hidden: true });
check('hidden-returns', hidden.hidden === true, JSON.stringify(hidden));
check('hidden-persisted', hostsOf(file)['web-1'].hidden === true, JSON.stringify(hostsOf(file)));
check('unhide-keeps-remark', store.setHost('web-1', { hidden: false }).remark === '生产 Web 主库', JSON.stringify(store.host('web-1')));

const idleReset = store.setHost('web-1', { idleTimeoutMs: null });
check('idle-reset', idleReset.idleTimeoutMs === null, JSON.stringify(idleReset));
const idleClamped = store.setHost('web-1', { idleTimeoutMs: MAX_IDLE_TIMEOUT_MS + 1 });
check('idle-clamped-to-current', idleClamped.idleTimeoutMs === null, JSON.stringify(idleClamped));

// An old panel may still send profile/caps/level; they must not break the write
// and must never reach disk.
const legacyWrite = store.setHost('legacy-write', { profile: 'managed', caps: { read: true }, level: 'services', remark: 'kept' });
check('legacy-write-ignores-profile', legacyWrite.remark === 'kept' && !('profile' in legacyWrite) && !('caps' in legacyWrite), JSON.stringify(legacyWrite));
check('legacy-write-stored-keys', Object.keys(hostsOf(file)['legacy-write']).sort().join(',') === STORED_KEYS, JSON.stringify(hostsOf(file)['legacy-write']));

// ── an old state file upgrades on read, and the next write cleans it ────────
const legacyFile = join(dir, 'legacy.json');
writeFileSync(
  legacyFile,
  JSON.stringify({
    hosts: {
      old: { profile: 'production', caps: { read: true, files: true, packages: true, services: true }, level: 'services', visible: true, remark: 'old box', idleTimeoutMs: 60000 },
      oldHidden: { profile: 'managed', level: 'hidden', visible: false, remark: '' },
      oldVisibleFalse: { visible: false },
      oldCaps: { caps: { read: true, files: true, packages: false, services: false } }
    },
    settings: { idleTimeoutMs: 9000, maxOutputBytes: 65536, transferTimeoutMs: 60000, sshVisible: false, maxLogLines: 200, productionEnforced: true }
  }),
  'utf8'
);
const migrated = new MetadataStore({ filePath: legacyFile });
const old = migrated.host('old');
check('legacy-old-visible', old.hidden === false && old.remark === 'old box' && old.idleTimeoutMs === 60000, JSON.stringify(old));
check('legacy-level-hidden', migrated.host('oldHidden').hidden === true, JSON.stringify(migrated.host('oldHidden')));
check('legacy-visible-false', migrated.host('oldVisibleFalse').hidden === true, JSON.stringify(migrated.host('oldVisibleFalse')));
check('legacy-caps-ignored', migrated.host('oldCaps').hidden === false && !('caps' in migrated.host('oldCaps')), JSON.stringify(migrated.host('oldCaps')));
check('legacy-settings-retained', migrated.settings().idleTimeoutMs === 9000 && migrated.settings().maxOutputBytes === 65536 && migrated.settings().transferTimeoutMs === 60000 && migrated.settings().sshVisible === false, JSON.stringify(migrated.settings()));

// A host edit rewrites the whole document, so the deleted keys and the old
// profile fields must be gone from disk afterwards.
migrated.setHost('old', { remark: 'still old' });
const cleaned = JSON.parse(readFileSync(legacyFile, 'utf8'));
check('legacy-host-cleaned', Object.keys(cleaned.hosts.old).sort().join(',') === STORED_KEYS, JSON.stringify(cleaned.hosts.old));
check('legacy-settings-cleaned', Object.keys(cleaned.settings).sort().join(',') === SETTINGS_SHAPE, JSON.stringify(cleaned.settings));
check('deleted-settings-never-returned', DELETED_SETTINGS.every((key) => !(key in cleaned.settings)), JSON.stringify(cleaned.settings));

// ── settings patches ────────────────────────────────────────────────────────
const patched = migrated.setSettings({ idleTimeoutMs: 120000, maxOutputBytes: 32768, transferTimeoutMs: 90000, sshVisible: false, maxLogLines: 7 });
check('settings-patch', patched.idleTimeoutMs === 120000 && patched.maxOutputBytes === 32768 && patched.transferTimeoutMs === 90000 && patched.sshVisible === false, JSON.stringify(patched));
check('settings-deleted-key-ignored', !('maxLogLines' in patched), JSON.stringify(patched));
check('settings-bad-value-kept', migrated.setSettings({ maxOutputBytes: 10 }).maxOutputBytes === 32768, JSON.stringify(migrated.settings()));
check('settings-idle-bad-value-kept', migrated.setSettings({ idleTimeoutMs: -1 }).idleTimeoutMs === 120000, JSON.stringify(migrated.settings()));
check('ssh-visible-false-survives-reload', new MetadataStore({ filePath: legacyFile }).settings().sshVisible === false, JSON.stringify(new MetadataStore({ filePath: legacyFile }).settings()));

// ── a corrupt file never blocks loading and is replaced on the next write ───
const corruptFile = join(dir, 'corrupt.json');
writeFileSync(corruptFile, '{not json', 'utf8');
const corrupt = new MetadataStore({ filePath: corruptFile });
check('corrupt-defaults', corrupt.settings().maxOutputBytes === 32768 && Object.keys(corrupt.raw().hosts).length === 0, JSON.stringify(corrupt.raw()));
corrupt.setHost('x', { remark: 'r' });
check('corrupt-replaced', document(corruptFile).hosts.x.remark === 'r', JSON.stringify(document(corruptFile)));

// ── no secret material is persisted ────────────────────────────────────────
const text = readFileSync(file, 'utf8');
check('no-secret-keys', !/identityFile|passphrase|password|privateKey/i.test(text), text.slice(0, 120));

rmSync(dir, { recursive: true, force: true });
console.log(`${pass}/${pass + failures.length} passed`);
for (const failure of failures) console.log(`FAIL ${failure}`);
process.exit(failures.length === 0 ? 0 : 2);
