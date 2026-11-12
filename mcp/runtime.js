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
import { readFileSync, statSync } from 'node:fs';
import { buildHostTable, normalizeConfig } from '../lib/config.js';
import { createPolicy } from '../lib/policy.js';
import { SshPool } from '../lib/pool.js';
import { createTools } from '../lib/tools.js';
import { createDiagnostics } from '../lib/diagnostics.js';
import { createSideAnalyzer, unavailableAnalyzer } from '../lib/analysis.js';
import { createHostRefresher } from '../lib/host-refresh.js';
import { createMcpSession } from './server.js';
import { createSamplingBackend } from './sampling.js';
import { createStateView } from './state-view.js';
import { createHiddenWatcher } from './hidden-watch.js';
import { startControlServer } from './control.js';
import { mcpRunDir, mcpStatePath } from './home.js';

const PACKAGE = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

/** Usage notes returned by `initialize`; clients surface them to the model. */
function instructionsFor(policy) {
  return [
    'SSH tools over a persistent connection pool (one SSH connection per host, reused by every call).',
    '- Call ssh_hosts first to see host aliases; hosts come from ~/.ssh/config (key/agent auth only).',
    '- ssh_run: pass `session` to keep cwd/exported variables across calls; give `expectedMs` for slow work (build, deploy, backup) instead of a long `timeoutMs`; use `background: true` for daemons and never append "&" yourself.',
    '- Prefer ssh_read / ssh_grep / ssh_glob over cat/grep/find in ssh_run; prefer ssh_edit for small changes to an existing file.',
    '- Output is capped; filter remotely (grep -m, tail -n, journalctl --since) rather than reading whole logs.',
    '- A guard refuses only machine-destroying commands. If refused, do NOT retry an equivalent rewrite; explain the intent (host, action, expected impact) and let the user decide.',
    '',
    '[policy]',
    policy.hints()
  ].join('\n');
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
 * @returns `{ pool, tools, config, meta, createSession(send), startControl(), dispose() }`.
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
  const tools = createTools(pool, config, {
    policy: createPolicy(),
    diagnostics,
    analyzer: { status: () => analyzer.status(), run: (input) => analyzer.run(input) }
  });
  const instructions = instructionsFor(createPolicy());

  /** Re-read ~/.ssh/config only when it changed since the last call. */
  let sshConfigMtime = null;
  const refreshIfChanged = () => {
    if (!config.useSshConfig) return;
    let mtime;
    try {
      mtime = statSync(config.sshConfigPath).mtimeMs;
    } catch {
      return;
    }
    if (sshConfigMtime === null) {
      sshConfigMtime = mtime;
      return;
    }
    if (mtime === sshConfigMtime) return;
    sshConfigMtime = mtime;
    refresh();
  };
  refreshIfChanged();

  // Hiding a host in the panel closes this process's live connection to it.
  const watchHidden = createHiddenWatcher({ pool, meta, logger });
  const hiddenTimer = setInterval(watchHidden, 1000);
  hiddenTimer.unref?.();

  let currentSession = null;
  const createSession = (send) => {
    const session = createMcpSession({
      tools,
      send,
      serverInfo: { name: PACKAGE.name, title: 'DSH SSH helper', version: PACKAGE.version },
      instructions,
      beforeCall: refreshIfChanged,
      logger
    });
    analyzer = createSideAnalyzer({ backend: createSamplingBackend(session), logger });
    currentSession = session;
    return session;
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
  return { pool, tools, config, meta, createSession, startControl, dispose };
}

export { PACKAGE };
