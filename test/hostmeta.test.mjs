/**
 * hostMeta: the seam between the store and the pool.
 *
 * The store's shape is now only a remark, the hidden switch and an idle
 * override; these checks pin that the pool never re-introduces the removed
 * profile/capability fields and that a legacy record still maps to `hidden`.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SshPool } from '../lib/pool.js';
import { MetadataStore } from '../lib/store.js';

const spec = { alias: 'h', host: '127.0.0.1', port: 22, user: 'root' };
const config = { idleTimeoutMs: 0, maxOutputBytes: 32768, transferTimeoutMs: 600000 };
let pass = 0;
const failures = [];
const check = (name, ok, detail) => (ok ? (pass += 1) : failures.push(`${name}: ${detail}`));
const pools = [];
const pool = (stored, meta, cfg = config) => {
  const created = new SshPool({
    hosts: new Map([['h', spec]]),
    config: cfg,
    logger: { warn: () => {}, info: () => {} },
    meta: meta ?? { host: () => stored, settings: () => ({ idleTimeoutMs: 0, maxOutputBytes: 32768, transferTimeoutMs: 600000 }) }
  });
  pools.push(created);
  return created;
};
const meta = (stored) => pool(stored).hostMeta('h');

// ── the frozen host-meta shape ──────────────────────────────────────────────
const fresh = meta(undefined);
check('shape-keys', Object.keys(fresh).sort().join(',') === 'hidden,idleTimeoutMs,remark', Object.keys(fresh).join(','));
check('fresh-visible', fresh.hidden === false && fresh.remark === '' && fresh.idleTimeoutMs === null, JSON.stringify(fresh));
check('shape-has-no-legacy-fields', ['profile', 'caps', 'level', 'visible'].every((key) => !(key in fresh)), JSON.stringify(fresh));

const hidden = meta({ hidden: true, remark: 'off', idleTimeoutMs: null });
check('hidden-true', hidden.hidden === true && hidden.remark === 'off', JSON.stringify(hidden));
check('legacy-visible-false', meta({ visible: false }).hidden === true, JSON.stringify(meta({ visible: false })));
check('legacy-level-hidden', meta({ level: 'hidden' }).hidden === true, JSON.stringify(meta({ level: 'hidden' })));
check('legacy-profile-ignored', !('profile' in meta({ profile: 'managed', caps: { read: true } })), JSON.stringify(meta({ profile: 'managed' })));

// ── hostVisible is the only agent-facing gate ───────────────────────────────
check('hostVisible-visible', pool(undefined).hostVisible('h') === true, 'a configured host is visible');
check('hostVisible-hidden', pool({ hidden: true }).hostVisible('h') === false, 'a hidden host is invisible');

// ── idle resolution: host override, then global settings, then config ───────
check('idle-host-override', pool({ idleTimeoutMs: 60000 }).idleTimeoutFor('h') === 60000, String(pool({ idleTimeoutMs: 60000 }).idleTimeoutFor('h')));
const live = { host: () => ({}), settings: () => ({ idleTimeoutMs: 120000, maxOutputBytes: 32000, transferTimeoutMs: 90000 }) };
check('idle-live-setting', pool(undefined, live).idleTimeoutFor('h') === 120000, String(pool(undefined, live).idleTimeoutFor('h')));
check('output-live-setting', pool(undefined, live).outputLimit() === 32000, String(pool(undefined, live).outputLimit()));
check('transfer-live-setting', pool(undefined, live).transferTimeout() === 90000, String(pool(undefined, live).transferTimeout()));
const offline = { host: () => ({}), settings: () => ({}) };
check('output-config-fallback', pool(undefined, offline, { ...config, maxOutputBytes: 40000 }).outputLimit() === 40000, String(pool(undefined, offline, { ...config, maxOutputBytes: 40000 }).outputLimit()));

// ── status carries the same shape, never the old profile fields ─────────────
const status = pool({ hidden: true, remark: 'x', idleTimeoutMs: null }).status()[0];
check('status-alias', status.alias === 'h' && status.hidden === true && status.remark === 'x', JSON.stringify(status));
check('status-no-legacy-fields', ['profile', 'caps', 'level', 'visible'].every((key) => !(key in status)), JSON.stringify(status));
check('status-effective-idle', typeof status.effectiveIdleTimeoutMs === 'number', JSON.stringify(status));

// ── the real store as the metadata source ───────────────────────────────────
const dir = mkdtempSync(join(tmpdir(), 'dsh-hostmeta-'));
const store = new MetadataStore({ filePath: join(dir, 'state.json') });
const wired = pool(undefined, store);
store.setHost('h', { remark: 'wired', hidden: true, idleTimeoutMs: 45000 });
const wiredMeta = wired.hostMeta('h');
check('wired-meta', wiredMeta.remark === 'wired' && wiredMeta.hidden === true && wiredMeta.idleTimeoutMs === 45000, JSON.stringify(wiredMeta));
check('wired-visible', wired.hostVisible('h') === false, 'hidden host must be invisible');
store.setHost('h', { hidden: false });
check('wired-unhidden', wired.hostVisible('h') === true && wired.hostMeta('h').remark === 'wired', JSON.stringify(wired.hostMeta('h')));

for (const created of pools) created.dispose();
rmSync(dir, { recursive: true, force: true });
console.log(`${pass}/${pass + failures.length} passed`);
for (const failure of failures) console.log(`FAIL ${failure}`);
process.exit(failures.length === 0 ? 0 : 2);
