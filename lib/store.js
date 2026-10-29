/**
 * Persistent, secret-free metadata for the SSH pool.
 *
 * A host carries a remark, a `hidden` switch (the agent cannot see or reach it,
 * while the SSH assistant still can) and an optional idle override. The four
 * global settings are the output budget, the idle timeout, the transfer timeout
 * and the master `sshVisible` switch.
 *
 * Only what the SSH assistant edits lives here. Keys, passphrases and passwords
 * are never written: the pool reads credentials from the user's own OpenSSH
 * setup and this file must stay safe to read or copy.
 *
 * @module dsh-ssh-pool/store
 */
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { homedir } from 'node:os';

const DEFAULT_SETTINGS = {
  idleTimeoutMs: 0,
  maxOutputBytes: 32768,
  transferTimeoutMs: 600000,
  sshVisible: true,
  logAnalysis: false
};
/** The only setting keys that may be read, patched or persisted. */
const SETTINGS_KEYS = ['idleTimeoutMs', 'maxOutputBytes', 'transferTimeoutMs', 'sshVisible', 'logAnalysis'];
const MAX_REMARK_LENGTH = 500;
const MAX_IDLE_TIMEOUT_MS = 7 * 24 * 60 * 60 * 1000;
/** Legacy permission levels, kept only as accepted input for old callers. */
const LEVELS = ['hidden', 'read', 'files', 'packages', 'services'];

/** The default metadata location: `$DSH_HOME/ssh-pool/state.json`. */
export function defaultStatePath() {
  const home = process.env.DSH_HOME ?? join(homedir(), '.dsh');
  return join(home, 'ssh-pool', 'state.json');
}

/** Coerce a non-negative integer, or return the fallback. */
function toInt(value, min, max, fallback) {
  const number = Number(value);
  if (!Number.isFinite(number)) return fallback;
  const rounded = Math.round(number);
  if (rounded < min || rounded > max) return fallback;
  return rounded;
}

/** Coerce a boolean, or return the fallback. */
function toBool(value, fallback) {
  return typeof value === 'boolean' ? value : fallback;
}

/** Whether a record hides its host, honouring the legacy `visible`/`level` aliases. */
function isHidden(record) {
  if (typeof record?.hidden === 'boolean') return record.hidden;
  if (record?.visible === false) return true;
  return record?.level === 'hidden';
}

/**
 * The frozen read shape of one host: the persisted fields, with legacy records
 * migrated on read. `profile`/`caps` from old state files are ignored.
 */
export function normalizeHost(alias, record) {
  const stored = record !== null && typeof record === 'object' ? record : {};
  return {
    alias,
    remark: typeof stored.remark === 'string' ? stored.remark.slice(0, MAX_REMARK_LENGTH) : '',
    hidden: isHidden(stored),
    idleTimeoutMs:
      stored.idleTimeoutMs === null || stored.idleTimeoutMs === undefined
        ? null
        : toInt(stored.idleTimeoutMs, 0, MAX_IDLE_TIMEOUT_MS, null)
  };
}

/** The only shape ever written to disk. */
function toStored(host) {
  return {
    remark: host.remark,
    hidden: host.hidden === true,
    idleTimeoutMs: host.idleTimeoutMs
  };
}

/** Host metadata that is safe to persist and show. */
export class MetadataStore {
  #data;
  #defaults;

  constructor({ filePath, defaults = {} } = {}) {
    this.filePath = filePath ?? defaultStatePath();
    this.#defaults = {
      settings: { ...DEFAULT_SETTINGS, ...(defaults.settings ?? {}) },
    };
    this.#data = this.#read();
  }

  #read() {
    try {
      if (!existsSync(this.filePath)) return { hosts: {}, settings: {} };
      const parsed = JSON.parse(readFileSync(this.filePath, 'utf8'));
      const rawHosts =
        parsed !== null && typeof parsed === 'object' && parsed.hosts !== null && typeof parsed.hosts === 'object' && !Array.isArray(parsed.hosts)
          ? parsed.hosts
          : {};
      // Migration happens here, once, for every record: a state file written
      // before the single-guard model is upgraded in memory, so the next persist
      // writes the canonical shape without anyone re-visiting each host.
      const hosts = {};
      for (const [alias, record] of Object.entries(rawHosts)) hosts[alias] = toStored(normalizeHost(alias, record));
      // Settings are narrowed to the retained keys here rather than only on
      // read: #persist writes this.#data wholesale, so a host edit must not
      // carry a deleted key the old file still holds back onto disk.
      return { hosts, settings: this.#cleanSettings(parsed?.settings) };
    } catch {
      // A corrupt file must never stop the plugin from loading.
      return { hosts: {}, settings: {} };
    }
  }

  #persist() {
    try {
      mkdirSync(dirname(this.filePath), { recursive: true });
      const temporary = `${this.filePath}.tmp`;
      writeFileSync(temporary, `${JSON.stringify(this.#data, null, 2)}\n`, 'utf8');
      renameSync(temporary, this.filePath);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * The retained settings, defaults filled in and every value clamped.
   *
   * Only `SETTINGS_KEYS` is ever returned: a deleted key sitting in an old state
   * file (or handed in as a default) is ignored rather than surfaced.
   */
  #cleanSettings(raw) {
    const stored = raw !== null && typeof raw === 'object' ? raw : {};
    const defaults = this.#defaults.settings;
    return {
      idleTimeoutMs: toInt(stored.idleTimeoutMs, 0, MAX_IDLE_TIMEOUT_MS, defaults.idleTimeoutMs),
      maxOutputBytes: toInt(stored.maxOutputBytes, 1024, 4 * 1024 * 1024, defaults.maxOutputBytes),
      transferTimeoutMs: toInt(stored.transferTimeoutMs, 5000, 7200000, defaults.transferTimeoutMs),
      // A stored `false` is a deliberate safety choice and must never be
      // replaced by the `true` default; only a missing or non-boolean value
      // falls back.
      sshVisible: toBool(stored.sshVisible, defaults.sshVisible),
      logAnalysis: toBool(stored.logAnalysis, defaults.logAnalysis)
    };
  }

  /** Global settings: the four knobs the panel exposes, defaults filled in. */
  settings() {
    return this.#cleanSettings(this.#data.settings);
  }

  /**
   * Apply a partial settings patch.
   *
   * Only the retained keys are considered; a deleted or unknown key is ignored
   * silently (never rejected) so an old panel cannot break the write path.
   */
  setSettings(patch = {}) {
    const input = patch !== null && typeof patch === 'object' ? patch : {};
    const current = this.settings();
    const next = { ...current };
    if (input.idleTimeoutMs !== undefined) next.idleTimeoutMs = toInt(input.idleTimeoutMs, 0, MAX_IDLE_TIMEOUT_MS, current.idleTimeoutMs);
    if (input.maxOutputBytes !== undefined) next.maxOutputBytes = toInt(input.maxOutputBytes, 1024, 4 * 1024 * 1024, current.maxOutputBytes);
    if (input.transferTimeoutMs !== undefined) next.transferTimeoutMs = toInt(input.transferTimeoutMs, 5000, 7200000, current.transferTimeoutMs);
    if (input.sshVisible !== undefined) next.sshVisible = toBool(input.sshVisible, current.sshVisible);
    if (input.logAnalysis !== undefined) next.logAnalysis = toBool(input.logAnalysis, current.logAnalysis);
    this.#data.settings = next;
    this.#persist();
    return next;
  }

  /**
   * Per-host metadata: a remark, the hidden switch and an idle override.
   *
   * `hidden` removes the host from the agent's view entirely; the SSH assistant
   * still connects and manages it. Old `profile`/`caps`/`level` fields are
   * accepted as input (so an old panel keeps working) but only `hidden` is kept.
   */
  host(alias) {
    return normalizeHost(alias, this.#data.hosts?.[alias]);
  }

  /**
   * Apply a partial per-host patch.
   *
   * Priority is `hidden`, then the legacy `visible`/`level` aliases: the aliases
   * are converted into `hidden` first so an explicit field in the same patch
   * always wins. Only `{ remark, hidden, idleTimeoutMs }` is persisted.
   */
  setHost(alias, patch = {}) {
    if (typeof alias !== 'string' || alias.length === 0) throw new Error('alias is required');
    const current = this.host(alias);
    const next = { ...current };
    if (patch.remark !== undefined) next.remark = String(patch.remark).slice(0, MAX_REMARK_LENGTH);
    if (patch.level !== undefined) {
      if (!LEVELS.includes(patch.level)) throw new Error(`level must be one of ${LEVELS.join(', ')}`);
      next.hidden = patch.level === 'hidden';
    }
    if (patch.visible !== undefined) next.hidden = toBool(patch.visible, !current.hidden) !== true;
    // The explicit field takes priority over every alias above.
    if (patch.hidden !== undefined) next.hidden = toBool(patch.hidden, current.hidden);
    if (patch.idleTimeoutMs !== undefined) {
      next.idleTimeoutMs = patch.idleTimeoutMs === null ? null : toInt(patch.idleTimeoutMs, 0, MAX_IDLE_TIMEOUT_MS, current.idleTimeoutMs);
    }
    this.#data.hosts = { ...(this.#data.hosts ?? {}), [alias]: toStored(next) };
    this.#persist();
    return this.host(alias);
  }

  /** The raw persisted document, for diagnostics. */
  raw() {
    return { filePath: this.filePath, hosts: this.#data.hosts ?? {}, settings: this.settings() };
  }
}

export { DEFAULT_SETTINGS, SETTINGS_KEYS, MAX_REMARK_LENGTH, MAX_IDLE_TIMEOUT_MS };
