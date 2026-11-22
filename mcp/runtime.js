/**
 * A standalone runtime: the pool, the tools and an MCP session factory, built
 * from plugin-style config without DSH.
 *
 * The transport (stdio today) only supplies `send`; everything SSH-side —
 * host table, read-only assistant state, policy, diagnostics, sampling-backed
 * side analysis, the panel's control port — is assembled here once per
 * process.
 *
 * @module dsh-ssh-helper/mcp/runtime
 */
import { readFileSync } from 'node:fs';
import { buildHostTable, normalizeConfig } from '../lib/config.js';
import { createPolicy } from '../lib/policy.js';
import { SshPool } from '../lib/pool.js';
import { createTools } from '../lib/tools.js';
import { createDiagnostics } from '../lib/diagnostics.js';
import { createSideAnalyzer, unavailableAnalyzer } from '../lib/analysis.js';
import { createChangeRefresher, createHostRefresher } from '../lib/host-refresh.js';
import { createMcpSession } from './server.js';
import { createSamplingBackend } from './sampling.js';
import { createStateView } from './state-view.js';
import { createHiddenWatcher } from './hidden-watch.js';
import { startControlServer } from './control.js';
import { mcpRunDir, mcpStatePath } from './home.js';

const PACKAGE = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

/**
 * Usage notes returned by `initialize`; clients surface them to the model.
 * The tool descriptions carry the details, so this only orders the work and
 * carries the policy, which `ssh_hosts` then repeats only when needed.
 */
function instructionsFor(policy) {
  return [
    'SSH tools over a persistent connection pool (one SSH connection per host, reused by every call).',
    '- Call ssh_hosts first; hosts come from ~/.ssh/config (key/agent auth only).',
    '- Prefer ssh_read / ssh_grep / ssh_glob over cat/grep/find in ssh_run, and ssh_edit for small changes.',
    '- ssh_run: `session` keeps cwd and env, `expectedMs` for slow work, `background: true` for daemons (never append "&").',
    '- If the guard refuses a command, do NOT retry an equivalent rewrite; state the host, the action and its impact, and let the user decide.',
    '',
    '[policy]',
    policy.hints()
  ].join('\n');
}

/**
 * Clients that give up on a tool call after about 60 s by default and do not
 * reset that on progress: Codex (`tool_timeout_sec` = 60), Claude Desktop
 * (`claude-ai`), Cursor. Matched on `clientInfo.name`.
 */
const SHORT_TIMEOUT_CLIENTS = /codex|cursor|^claude-ai$/i;
/** The per-call cap those clients get unless `--max-call-ms` / `maxCallMs` says otherwise. */
export const SHORT_CLIENT_CALL_CAP_MS = 50_000;

/** The default per-call cap for a client: answer before it gives up, never kill. */
export function defaultCallCapFor(clientInfo) {
  const name = typeof clientInfo?.name === 'string' ? clientInfo.name : '';
  return SHORT_TIMEOUT_CLIENTS.test(name) ? SHORT_CLIENT_CALL_CAP_MS : 0;
}

/** A logger that never touches stdout (stdout is the protocol channel). */
export function stderrLogger({ quiet = false } = {}) {
  const write = (level) => (message) => {
    if (quiet && level === 'info') return;
    process.stderr.write(`[dsh-ssh-mcp] ${level}: ${message}\n`);
  };
  return { info: write('info'), warn: write('warn'), error: write('error'), debug: () => {} };
}

/**
 * @param options
 * @param options.config - raw plugin config (same keys as `cordis.patch.yml`).
 * @param options.logger - `{ info, warn }`; defaults to stderr.
 * @returns `{ pool, tools, config, meta, createSession(send), startControl(), prewarm(), dispose() }`.
 */
export function createStandaloneRuntime({ config: raw = {}, logger = stderrLogger() } = {}) {
  const config = normalizeConfig(raw);
  const { hosts, warnings } = buildHostTable(config);
  for (const warning of warnings) logger.warn?.(warning);
  // Independent of DSH by default: the server follows the MCP panel's own
  // state file (`~/.dsh-ssh-mcp/state.json`), read-only. `--state` points it at
  // another file instead, e.g. DSH's, so hiding a host in DSH only affects an
  // MCP agent when the user asked for that.
  const followsDsh = config.statePath !== undefined;
  const meta = createStateView({
    filePath: config.statePath ?? mcpStatePath(),
    defaults: {
      settings: {
        idleTimeoutMs: config.idleTimeoutMs,
        maxOutputBytes: config.maxOutputBytes,
        transferTimeoutMs: config.transferTimeoutMs
      }
    }
  });
  const pool = new SshPool({ hosts, config, logger, warnings, meta });
  const refresh = createHostRefresher({ pool, config, logger });

  // The analyzer is built per session (sampling goes back to that client);
  // the tools are built once, so they reach it through this indirection.
  let analyzer = unavailableAnalyzer();
  const diagnostics = createDiagnostics();
  const policy = createPolicy();
  const tools = createTools(pool, config, {
    policy,
    diagnostics,
    analyzer: { status: () => analyzer.status(), run: (input) => analyzer.run(input) },
    // `initialize` already carries the policy; ssh_hosts repeats it only when needed.
    policyOncePerCaller: true
  });
  const instructions = instructionsFor(policy);

  /** Re-read ~/.ssh/config only when it changed since the last call. */
  const refreshIfChanged = createChangeRefresher({ config, refresh, logger });

  // Hiding a host in the panel closes this process's live connection to it.
  const watchHidden = createHiddenWatcher({ pool, meta, logger });
  const hiddenTimer = setInterval(watchHidden, 1000);
  hiddenTimer.unref?.();

  // An explicit maxCallMs (config file or --max-call-ms, 0 included) always
  // wins; otherwise the client that connects picks the default.
  const capExplicit = raw.maxCallMs !== undefined;
  const pickCallCap = ({ clientInfo }) => {
    if (capExplicit) return;
    config.maxCallMs = defaultCallCapFor(clientInfo);
    if (config.maxCallMs > 0) {
      logger.info?.(`client ${clientInfo?.name} gives up on tool calls after about 60 s: ssh_run answers after ${config.maxCallMs}ms (override with --max-call-ms)`);
    }
  };

  let currentSession = null;
  const createSession = (send) => {
    const session = createMcpSession({
      tools,
      send,
      serverInfo: { name: PACKAGE.name, title: 'DSH SSH helper', version: PACKAGE.version },
      instructions,
      beforeCall: refreshIfChanged,
      onInitialize: pickCallCap,
      logger
    });
    analyzer = createSideAnalyzer({ backend: createSamplingBackend(session), logger });
    currentSession = session;
    return session;
  };

  /**
   * Connect the `autoConnect` hosts in the background, so the agent's first
   * call is already warm. Hidden hosts are skipped; failures only log (and
   * land in the host's lastError for ssh_hosts).
   */
  const prewarm = () => {
    const aliases = pool.autoConnectAliases().filter((alias) => pool.hostVisible(alias));
    for (const alias of aliases) {
      pool
        .connection(alias)
        .ensure()
        .then(() => logger.info?.(`prewarmed ${alias}`))
        .catch((error) => logger.warn?.(`prewarm of ${alias} failed: ${error instanceof Error ? error.message : String(error)}`));
    }
    return aliases;
  };

  /** Open the panel's control port and announce this process in the run dir. */
  let control = null;
  const startControl = async ({ runDir = mcpRunDir() } = {}) => {
    try {
      control = await startControlServer({
        pool,
        runDir,
        logger,
        describe: () => ({
          version: PACKAGE.version,
          client: currentSession?.clientInfo ?? null,
          statePath: meta.filePath,
          followsDsh,
          sshConfigPath: config.useSshConfig ? config.sshConfigPath : null,
          maxCallMs: config.maxCallMs,
          warnings: [...(pool.warnings ?? [])]
        }),
        extraState: () => ({
          diagnostics: diagnostics.snapshot({ events: 20 }),
          analysis: analyzer.status()
        })
      });
    } catch (error) {
      logger.warn?.(`control port unavailable (the panel will not see this server): ${error instanceof Error ? error.message : String(error)}`);
    }
    return control;
  };

  logger.info?.(`${hosts.size} host(s): ${[...hosts.keys()].join(', ') || 'none'}; following ${meta.filePath} (read-only)`);
  const dispose = () => {
    clearInterval(hiddenTimer);
    control?.close();
    pool.dispose();
  };
  return { pool, tools, config, meta, createSession, startControl, prewarm, dispose };
}

export { PACKAGE };
