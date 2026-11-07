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
import { isDeleteCommand, isLocalSshDelete, isPlanActive } from './lib/plan-guard.js';
import { renameIdentityFile } from './lib/keyfile.js';
import { renameHostAlias } from './lib/hostalias.js';
import { editHostIdentity } from './lib/edit-host.js';

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

/** Denial for a delete attempted while plan mode is active or pending. */
export function planDeleteMessage(alias = '') {
  return [
    '[ssh-pool plan] 计划模式下禁止删除',
    `主机 ${alias || '?'}`,
    '请先把计划提交审批；退出计划模式后，用 ssh_run 执行经过连接池和策略检查的删除。'
  ].join('\n');
}

/** Denial for a local bash command that bypasses the pool with a raw ssh key. */
export function localSshDeleteMessage() {
  return [
    '[ssh-pool guard] 本地 bash 直接调用 ssh 执行删除已被拒绝',
    '这会绕过连接池、主机策略和诊断记录；请改用 ssh_run。',
    '本地 ssh 的只读探查仍然允许，只有删除类操作被拦截。'
  ].join('\n');
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
  /**
   * Rebuild the host table from OpenSSH config. Called by the panel on every
   * state read so a host/key added locally appears without reloading the plugin.
   * A missing or unreadable config is treated as "keep what we have": a
   * transient read failure must never silently remove every host.
   */
  const refreshHosts = () => {
    const next = buildHostTable(normalized);
    const unreadable = next.warnings.some((warning) => warning.startsWith('cannot read') || warning.startsWith('ssh config not found'));
    if (unreadable && pool.aliases.length > 0) {
      pool.warnings = [...next.warnings];
      return { added: [], changed: [], removed: [], skipped: true };
    }
    const diff = pool.refreshHosts(next.hosts, next.warnings);
    if (diff.added.length > 0 || diff.changed.length > 0 || diff.removed.length > 0) {
      ctx.logger?.info?.(
        `ssh-pool: host table refreshed (added=${diff.added.length}, changed=${diff.changed.length}, removed=${diff.removed.length})`
      );
    }
    return diff;
  };
  /**
   * Rename the actual key file and update ~/.ssh/config, then rebuild the host
   * table so the panel and future connections use the new path.
   */
  const renameKey = ({ alias, keyName }) => {
    const spec = pool.spec(alias);
    if (spec === undefined) throw new Error(`unknown host "${alias}"`);
    if (spec.source !== 'ssh-config') {
      throw new Error('this host comes from plugin config, not ~/.ssh/config; rename its IdentityFile in the bundle config instead');
    }
    const result = renameIdentityFile({
      configPath: normalized.sshConfigPath,
      identityFile: spec.identityFile,
      newName: keyName
    });
    refreshHosts();
    ctx.logger?.info?.(`ssh-pool: renamed key ${result.oldName} -> ${result.newName} for ${alias}`);
    return result;
  };
  const renameHost = ({ alias, newAlias }) => {
    const spec = pool.spec(alias);
    if (spec === undefined) throw new Error(`unknown host "${alias}"`);
    if (spec.source !== 'ssh-config') {
      throw new Error('this host comes from plugin config, not ~/.ssh/config; rename it in the bundle config instead');
    }
    const result = renameHostAlias({ configPath: normalized.sshConfigPath, oldAlias: alias, newAlias });
    store.renameHost(alias, result.newAlias);
    refreshHosts();
    ctx.logger?.info?.(`ssh-pool: renamed host ${result.oldAlias} -> ${result.newAlias}`);
    return result;
  };
  /** Atomic combined edit used by the single dialog. */
  const editHost = ({ alias, newAlias, keyName }) => {
    const spec = pool.spec(alias);
    if (spec === undefined) throw new Error(`unknown host "${alias}"`);
    if (spec.source !== 'ssh-config') {
      throw new Error('this host comes from plugin config, not ~/.ssh/config; edit it in the bundle config instead');
    }
    const result = editHostIdentity({
      configPath: normalized.sshConfigPath,
      oldAlias: alias,
      newAlias,
      oldKeyPath: spec.identityFile,
      newKeyName: keyName
    });
    if (result.aliasChanged) store.renameHost(alias, result.newAlias);
    refreshHosts();
    ctx.logger?.info?.(`ssh-pool: edited ${alias}${result.aliasChanged ? ` -> ${result.newAlias}` : ''}${result.keyChanged ? `; key ${result.oldKeyName} -> ${result.newKeyName}` : ''}`);
    return result;
  };
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
    //
    // Plan mode is collaboration, not enforcement (DSH keeps every tool
    // callable), so this guard adds the two SSH-specific limits:
    //   - plan active/pending: no delete-like ssh_run;
    //   - local bash + ssh + delete: always denied, even after plan approval,
    //     because a raw local key bypasses the pool and its policy.
    const planModeOf = () => {
      try {
        return typeof ctx.get === 'function' ? ctx.get('planMode') : ctx.planMode;
      } catch {
        return undefined;
      }
    };
    const unguard = ctx.tools.guard((execution) => {
      const toolName = execution?.name;
      const args = execution?.arguments;
      if (args === null || typeof args !== 'object') return undefined;

      if (toolName === 'bash') {
        if (isLocalSshDelete(args.command)) {
          diagnostics.record({
            tool: 'bash',
            host: null,
            commandKind: typeof args.command === 'string' ? commandKind(args.command) : null,
            outcome: 'denied',
            reason: 'local-ssh'
          });
          return localSshDeleteMessage();
        }
        return undefined;
      }

      if (toolName !== 'ssh_run') return undefined;
      if (isPlanActive(planModeOf(), execution.agent) && isDeleteCommand(args.command)) {
        diagnostics.record({
          tool: 'ssh_run',
          host: typeof args.host === 'string' ? args.host : null,
          commandKind: typeof args.command === 'string' ? commandKind(args.command) : null,
          outcome: 'denied',
          reason: 'plan'
        });
        return planDeleteMessage(args.host);
      }
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
          diagnostics: (options) => diagnostics.snapshot(options),
          onSettingsChanged: applyVisibility,
          refreshHosts,
          renameKey,
          renameHost,
          editHost
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
