/**
 * Host plugin: a persistent SSH connection pool, its model-facing tools, the
 * command policy, and the SSH assistant's Host API.
 *
 * Hosts are resolved once at activation (OpenSSH config plus the plugin's own
 * `hosts`) and held in `SshPool`, so every tool call reuses an existing
 * connection instead of paying a fresh handshake. Persistent shell state is
 * scoped to the calling DSH session; the transport is shared because a channel
 * carries no shell state.
 *
 * @module @local/dsh-ssh-pool
 */
import { buildHostTable, normalizeConfig } from './lib/config.js';
import { MetadataStore } from './lib/store.js';
import { createPolicy } from './lib/policy.js';
import { createAssistantApi } from './lib/api.js';
import { SshPool } from './lib/pool.js';
import { createTools } from './lib/tools.js';
import { commandKind, createDiagnostics } from './lib/diagnostics.js';
import { createAnalyzer } from './lib/analysis.js';

export const name = 'ssh-pool';
export const inject = ['tools'];

/** The model-facing denial for a policy verdict. */
export function denyMessage(verdict, alias = '') {
  // Name EVERY rule that matched, not just the first one: reporting one at a
  // time is what made the agent guess its way through three rules in a row.
  const others = (Array.isArray(verdict.matches) ? verdict.matches : []).filter((match) => match.rule !== verdict.rule);
  return [
    `[ssh-pool policy] 命令被拒绝（规则 ${verdict.rule}）: ${verdict.title}`,
    `主机 ${alias || '?'}`,
    others.length === 0 ? '' : `同时命中: ${others.map((match) => `${match.rule}（${match.title}）`).join('、')}`,
    `原因: ${verdict.reason}`,
    `建议: ${verdict.suggestion}`,
    '规则全表与合规写法: 调用 ssh_hosts 查看 [policy] 提示，或查看插件 README'
  ]
    .filter((line) => line.length > 0)
    .join('\n');
}

/**
 * Mount the pool, its tools, the command policy and the assistant API.
 * @param ctx - the plugin context (Host realm, so every agent sees the tools).
 * @param config - the bundle row's `config` mapping; `lib/config.js` lists the keys actually read.
 */
export function apply(ctx, config = {}) {
  const normalized = normalizeConfig(config);
  const { hosts, warnings } = buildHostTable(normalized);
  const store = new MetadataStore({
    filePath: normalized.statePath,
    defaults: {
      settings: {
        idleTimeoutMs: normalized.idleTimeoutMs,
        maxOutputBytes: normalized.maxOutputBytes,
        transferTimeoutMs: normalized.transferTimeoutMs
      },
    }
  });
  const policy = createPolicy();
  const diagnostics = createDiagnostics();
  const analyzer = createAnalyzer(ctx, ctx.logger);
  const pool = new SshPool({ hosts, config: normalized, logger: ctx.logger, warnings, meta: store });
  for (const warning of warnings) ctx.logger?.warn?.(`ssh-pool: ${warning}`);
  ctx.logger?.info?.(
    `ssh-pool: ${hosts.size} host(s) available (${[...hosts.keys()].join(', ') || 'none'}), keepalive ${normalized.keepaliveIntervalMs}ms, idle timeout ${normalized.idleTimeoutMs === 0 ? 'never' : `${normalized.idleTimeoutMs}ms`}`
  );

  ctx.effect(() => {
    const tools = createTools(pool, normalized, { policy, analyzer, diagnostics });

    // The SSH visibility switch: when off, the tools are unregistered, so no
    // session can see or call them (a context-global `tools.restrict` is
    // rejected by the registry by design). The panel keeps working: it is the
    // human's surface and talks to the pool directly.
    let disposeTools = [];
    const applyVisibility = () => {
      const visible = store.settings().sshVisible !== false;
      if (visible && disposeTools.length === 0) {
        disposeTools = tools.map((tool) => ctx.tools.register(tool));
        ctx.logger?.info?.('ssh-pool: SSH tools registered for every session');
        return;
      }
      if (!visible && disposeTools.length > 0) {
        for (const dispose of disposeTools) {
          try {
            dispose();
          } catch {
            /* the tool was already unregistered */
          }
        }
        disposeTools = [];
        ctx.logger?.info?.('ssh-pool: SSH tools hidden from every session (visibility switch off)');
      }
    };
    applyVisibility();

    // The command policy runs as a guard: monotonic, synchronous, and applied
    // before any transport work, so no argument shape can slip past it.
    const unguard = ctx.tools.guard((execution) => {
      if (execution?.name !== 'ssh_run') return undefined;
      const args = execution.arguments;
      if (args === null || typeof args !== 'object') return undefined;
      const verdict = policy.evaluate({ alias: args.host, command: args.command, host: args.host });
      if (verdict.action === 'deny') {
        diagnostics.record({
          tool: 'ssh_run',
          host: typeof args.host === 'string' ? args.host : null,
          commandKind: typeof args.command === 'string' ? commandKind(args.command) : null,
          outcome: 'denied',
          reason: 'policy'
        });
        return denyMessage(verdict, args.host);
      }
      return undefined;
    });

    // The assistant panel: HTTP routes the browser surface reads and writes.
    // The web server initializes asynchronously, so wait for the service
    // instead of reading it once — a boot-time `ctx.get('webServer')` can still
    // be undefined, which left the panel showing HTTP 404 until the next reload.
    ctx.inject(['webServer'], (webCtx) => {
      webCtx.effect(() => {
        const api = createAssistantApi({
          pool,
          store,
          config: normalized,
          logger: ctx.logger,
          analysisStatus: () => analyzer.status(),
          diagnostics: () => diagnostics.snapshot(),
          onSettingsChanged: applyVisibility
        });
        const disposeRoute = webCtx.webServer.register(api.route);
        const disposeTap = webCtx.webServer.tapIndex((html) => html.replace(/<head(?:\s[^>]*)?>/i, (match) => `${match}${api.indexInjection}`));
        ctx.logger?.info?.('ssh-pool: SSH assistant API mounted at /ssh-pool/ (loopback, cookie-authorized writes)');
        return () => {
          for (const dispose of [disposeRoute, disposeTap]) {
            try {
              dispose();
            } catch {
              /* the route or tap was already removed */
            }
          }
        };
      });
    });

    // Prewarm the configured hosts so the first agent call is already warm.
    const prewarm = pool.autoConnectAliases();
    for (const alias of prewarm) {
      pool
        .connection(alias)
        .ensure()
        .then(() => ctx.logger?.info?.(`ssh-pool: prewarmed ${alias}`))
        .catch((error) => ctx.logger?.warn?.(`ssh-pool: prewarm of ${alias} failed: ${error instanceof Error ? error.message : String(error)}`));
    }

    return () => {
      unguard();
      for (const dispose of disposeTools) {
        try {
          dispose();
        } catch {
          /* the tool was already unregistered */
        }
      }
      disposeTools = [];
      pool.dispose();
    };
  });
}
