/**
 * Host configuration for the SSH connection pool.
 *
 * Hosts come from three sources, later ones winning:
 *   1. the OpenSSH client configuration (`~/.ssh/config` by default),
 *   2. `include` (aliases resolved through that same file),
 *   3. explicit `hosts` entries in the plugin config.
 *
 * The parser implements the OpenSSH rule that matters here: for any option the
 * first value obtained while scanning the file top-down wins, so a later `Host`
 * stanza never overrides an earlier one for the same option.
 *
 * @module dsh-ssh-pool/config
 */
import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, isAbsolute } from 'node:path';

const DEFAULT_EXCLUDES = ['github.com', 'gitee.com', 'gitlab.com', 'bitbucket.org', 'ssh.dev.azure.com'];
const DEFAULT_IDENTITY_NAMES = ['id_ed25519', 'id_ecdsa', 'id_rsa', 'id_dsa'];
const WINDOWS_AGENT_PIPE = '\\\\.\\pipe\\openssh-ssh-agent';

/** Expand a leading `~` and `%d`/`%u`-style OpenSSH tokens used in paths. */
export function expandPath(value, home = homedir()) {
  let out = String(value ?? '').trim();
  if (out === '~') return home;
  if (out.startsWith('~/') || out.startsWith('~\\')) out = join(home, out.slice(2));
  out = out.replace(/%d/g, home).replace(/%u/g, localUser());
  return out;
}

/** The local account name, used as the default SSH user, matching OpenSSH's behavior. */
export function localUser() {
  return process.env.USERNAME || process.env.USER || 'root';
}

/** Whether `value` starts with an absolute path (POSIX or Windows form). */
function isAbsoluteAnywhere(value) {
  return /^[a-zA-Z]:[\\/]/.test(value) || value.startsWith('/') || value.startsWith('\\\\');
}

/** Split one `Key Value` / `Key=Value` configuration line, or return null for non-options. */
function parseOptionLine(line) {
  const text = line.trim();
  if (text.length === 0 || text.startsWith('#')) return null;
  const eq = text.indexOf('=');
  let key;
  let value;
  if (eq > 0 && !/\s/.test(text.slice(0, eq))) {
    key = text.slice(0, eq);
    value = text.slice(eq + 1);
  } else {
    const match = /^(\S+)\s+(.*)$/.exec(text);
    if (match === null) return null;
    key = match[1];
    value = match[2];
  }
  value = value.trim();
  // Strip an unquoted trailing comment, the way OpenSSH reads the file.
  const hash = value.indexOf('#');
  if (hash > 0 && /\s/.test(value[hash - 1])) value = value.slice(0, hash).trim();
  return [key.toLowerCase(), value];
}

/**
 * Parse an ssh_config document into ordered stanzas.
 * @param text - the configuration file contents.
 * @returns one entry per `Host` stanza: its patterns and every option it sets, in file order.
 */
export function parseSshConfig(text) {
  const stanzas = [];
  let current = null;
  for (const line of String(text).split(/\r?\n/)) {
    const option = parseOptionLine(line);
    if (option === null) continue;
    const [key, value] = option;
    if (key === 'host') {
      current = { patterns: value.split(/\s+/).filter((p) => p.length > 0), options: {} };
      stanzas.push(current);
      continue;
    }
    if (key === 'match') {
      // `Match` blocks are conditional on factors this plugin does not model.
      current = null;
      continue;
    }
    if (current === null) continue;
    if (value.length === 0) continue;
    if (current.options[key] === undefined) current.options[key] = [];
    current.options[key].push(value);
  }
  return stanzas;
}

/** Whether one `Host` pattern matches a name (supports `*`, `?` and leading `!`). */
function patternMatches(pattern, name) {
  if (pattern.startsWith('!')) return !patternMatches(pattern.slice(1), name);
  const lowered = name.toLowerCase();
  const glob = pattern.toLowerCase().replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
  return new RegExp(`^${glob}$`).test(lowered);
}

/** Whether any pattern of a stanza matches the name, under OpenSSH's ordered-negation rule. */
function stanzaMatches(stanza, name) {
  let matched = false;
  for (const pattern of stanza.patterns) {
    if (!patternMatches(pattern, name)) continue;
    if (pattern.startsWith('!')) return false;
    matched = true;
  }
  return matched;
}

/**
 * Resolve the effective options for one alias: first value obtained wins per option.
 * @param stanzas - parsed stanzas in file order.
 * @param alias - the `Host` alias being resolved.
 * @returns a flat option map with single string values.
 */
export function effectiveOptions(stanzas, alias) {
  const resolved = {};
  for (const stanza of stanzas) {
    if (!stanzaMatches(stanza, alias)) continue;
    for (const [key, values] of Object.entries(stanza.options)) {
      if (resolved[key] === undefined && values.length > 0) resolved[key] = values[0];
    }
  }
  return resolved;
}

/** Every alias a config file offers: concrete `Host` names only, wildcards dropped. */
export function listAliases(stanzas) {
  const aliases = [];
  for (const stanza of stanzas) {
    for (const pattern of stanza.patterns) {
      if (pattern.startsWith('!')) continue;
      if (/[*?]/.test(pattern)) continue;
      if (!aliases.includes(pattern)) aliases.push(pattern);
    }
  }
  return aliases;
}

/** Expand `%h`, `%n`, `%r`, `%%` tokens in a configuration value. */
function expandTokens(value, alias) {
  return String(value).replace(/%([hnr%])/g, (_, token) => {
    if (token === 'h') return alias;
    if (token === 'n') return alias;
    if (token === 'r') return localUser();
    return '%';
  });
}

/** Locate an ssh-agent endpoint usable by the pool, if the machine runs one. */
export function detectAgent() {
  if (process.env.SSH_AUTH_SOCK) return process.env.SSH_AUTH_SOCK;
  if (process.platform === 'win32' && existsSync(WINDOWS_AGENT_PIPE)) return WINDOWS_AGENT_PIPE;
  return undefined;
}

/** The first default identity file present in the user's ~/.ssh directory. */
function defaultIdentityFile(home) {
  for (const name of DEFAULT_IDENTITY_NAMES) {
    const candidate = join(home, '.ssh', name);
    if (existsSync(candidate)) return candidate;
  }
  return undefined;
}

/** Convert one resolved option map into a connect-ready host spec. */
export function specFromOptions(alias, options, home = homedir()) {
  const host = options.hostname !== undefined ? expandTokens(options.hostname, alias) : alias;
  const rawIdentity = options.identityfile;
  const identityFile = rawIdentity !== undefined ? expandPath(rawIdentity, home) : defaultIdentityFile(home);
  const port = options.port !== undefined ? Number.parseInt(options.port, 10) : 22;
  return {
    alias,
    host,
    port: Number.isFinite(port) ? port : 22,
    user: options.user !== undefined ? expandTokens(options.user, alias) : localUser(),
    identityFile,
    source: 'ssh-config'
  };
}

/** Whether a name matches one of the exclude entries (exact, or glob when it contains wildcards). */
function isExcluded(spec, exclude) {
  const candidates = [spec.alias, spec.host, `${spec.user}@${spec.host}`].map((value) => String(value).toLowerCase());
  for (const raw of exclude) {
    const pattern = String(raw).trim().toLowerCase();
    if (pattern.length === 0) continue;
    if (/[*?]/.test(pattern)) {
      const glob = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
      const re = new RegExp(`^${glob}$`);
      if (candidates.some((candidate) => re.test(candidate))) return true;
      continue;
    }
    if (candidates.some((candidate) => candidate === pattern)) return true;
    // A bare domain also excludes any alias that resolves to it with a path suffix.
    if (candidates.some((candidate) => candidate.startsWith(`${pattern}:`) || candidate.startsWith(`${pattern}/`))) return true;
  }
  return false;
}

/** Normalize the plugin `config` mapping, filling every documented default. */
export function normalizeConfig(raw = {}) {
  const config = raw === null || typeof raw !== 'object' ? {} : raw;
  const number = (value, fallback) => (Number.isFinite(Number(value)) && Number(value) >= 0 ? Number(value) : fallback);
  return {
    useSshConfig: config.useSshConfig !== false,
    sshConfigPath: config.sshConfigPath ? expandPath(config.sshConfigPath) : join(homedir(), '.ssh', 'config'),
    exclude: Array.isArray(config.exclude) ? config.exclude : DEFAULT_EXCLUDES,
    include: Array.isArray(config.include) ? config.include.map(String) : [],
    hosts: Array.isArray(config.hosts) ? config.hosts : [],
    connectTimeoutMs: number(config.connectTimeoutMs, 15000) || 15000,
    keepaliveIntervalMs: number(config.keepaliveIntervalMs, 15000),
    keepaliveCountMax: number(config.keepaliveCountMax, 4),
    idleTimeoutMs: number(config.idleTimeoutMs, 0),
    autoConnect: config.autoConnect === true ? '*' : Array.isArray(config.autoConnect) ? config.autoConnect.map(String) : [],
    maxChannelsPerHost: Math.max(1, number(config.maxChannelsPerHost, 4) || 4),
    // Deadlines are derived, not fixed: estimate × the constant multiplier, clamped.
    defaultTimeoutMs: number(config.defaultTimeoutMs, 30000) || 30000,
    maxOutputBytes: number(config.maxOutputBytes, 32768) || 32768,
    // Every remote operation is bounded: no command or transfer may wait forever.
    transferTimeoutMs: number(config.transferTimeoutMs, 600000) || 600000,
    hostKeyPolicy: ['warn', 'strict', 'off'].includes(config.hostKeyPolicy) ? config.hostKeyPolicy : 'warn',
    knownHostsPath: config.knownHostsPath ? expandPath(config.knownHostsPath) : join(homedir(), '.ssh', 'known_hosts'),
    statePath: config.statePath ? expandPath(config.statePath) : undefined
  };
}

/**
 * Build the host table from configuration.
 * @param config - a normalized config from {@link normalizeConfig}.
 * @returns `{ hosts, warnings }`, hosts keyed by alias in declaration order.
 */
export function buildHostTable(config) {
  const warnings = [];
  const hosts = new Map();
  let stanzas = [];
  let home = homedir();

  if (config.useSshConfig) {
    if (existsSync(config.sshConfigPath)) {
      try {
        stanzas = parseSshConfig(readFileSync(config.sshConfigPath, 'utf8'));
      } catch (error) {
        warnings.push(`cannot read ${config.sshConfigPath}: ${error instanceof Error ? error.message : String(error)}`);
      }
    } else {
      warnings.push(`ssh config not found at ${config.sshConfigPath}`);
    }
    for (const alias of listAliases(stanzas)) {
      const spec = specFromOptions(alias, effectiveOptions(stanzas, alias), home);
      // A stanza whose HostName looks like a file path is not a remote shell target.
      if (isAbsoluteAnywhere(spec.host)) continue;
      if (isExcluded(spec, config.exclude)) continue;
      hosts.set(alias, spec);
    }
  }

  for (const alias of config.include) {
    if (hosts.has(alias)) continue;
    const options = effectiveOptions(stanzas, alias);
    if (Object.keys(options).length === 0) {
      warnings.push(`include "${alias}" is not declared in ${config.sshConfigPath}`);
      continue;
    }
    const spec = specFromOptions(alias, options, home);
    if (isExcluded(spec, config.exclude)) continue;
    hosts.set(alias, spec);
  }

  for (const entry of config.hosts) {
    if (entry === null || typeof entry !== 'object' || !entry.host) continue;
    const alias = entry.alias ? String(entry.alias) : String(entry.host);
    hosts.set(alias, {
      alias,
      host: String(entry.host),
      port: Number.isFinite(Number(entry.port)) && Number(entry.port) > 0 ? Number(entry.port) : 22,
      user: entry.user ? String(entry.user) : localUser(),
      identityFile: entry.identityFile ? expandPath(String(entry.identityFile)) : defaultIdentityFile(home),
      passphrase: entry.passphrase !== undefined ? String(entry.passphrase) : undefined,
      agent: entry.agent !== undefined ? String(entry.agent) : undefined,
      source: 'config'
    });
  }

  return { hosts, warnings };
}

export { DEFAULT_EXCLUDES };
