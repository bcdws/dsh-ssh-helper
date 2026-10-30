/**
 * Client half of the SSH assistant.
 *
 * The sidebar row is host chrome: clicking it selects the `main` panel whose
 * key equals this entry's id, so the panel is the primary surface and the
 * entry renders nothing but the icon. The same body is also available as a
 * floating window in `shell.overlay`, opened from the panel.
 *
 * Layout follows the host's own plugin page: a fixed-column table so every
 * connection row aligns, switch rows for settings, and quiet inputs that only
 * show their border on hover or focus. Data comes from the Host half over
 * `/ssh-pool/*`; the write credential is the HttpOnly cookie the first read
 * hands out. No key material crosses this boundary.
 */
window.__ModuleLoader__.load({
  id: 'dsh-ssh-helper',
  factory(require) {
    const React = require('react');
    const h = React.createElement;

    const TEXT = {
      title: 'SSH 助手',
      subtitle: '常驻连接池：同一连接复用，无需重复握手',
      close: '关闭',
      float: '浮窗',
      refresh: '刷新',
      connections: '连接',
      connectionsHint: '「隐藏」后任何会话都看不到、也连不上它；这里仍可正常管理。',
      hidden: '隐藏',
      visible: '可见',
      hiddenHint: '隐藏后 agent 看不到也连不上该主机；面板仍可连接和管理。',
      hiddenCount: (count) => `${count} 台隐藏`,
      settings: '设置',
      groupOutput: '输出与上下文',
      groupConnection: '连接与空闲',
      policy: '命令护栏',
      idleTimeout: '空闲超时',
      idleTimeoutDesc: '秒；0 = 永不自动断开。未使用时不创建连接，只有会话真正用到该主机才首次建连。',
      sshVisible: 'SSH 工具对会话可见',
      sshVisibleShort: '会话可见',
      sshVisibleDesc: '总开关。关闭后 9 个 ssh_* 工具对任何会话（含子 agent）都不再存在，已建立的连接不受影响。',
      maxOutputBytes: '命令输出上限',
      maxOutputBytesDesc: '每条命令回传的每个流（stdout / stderr）的字节上限，单位 KB；默认 32 KB，超出时保留头尾并标注省略。调小更省上下文。',
      logAnalysis: '日志旁路分析',
      logAnalysisDesc: '开启后，较大的日志读取/搜索/日志类命令会交给一个没有工具的旁路模型分析，主会话只收到摘要；需要原文时在调用里传 analyze:false。默认关闭。日志会先脱敏，再发送到你配置的默认模型提供商；敏感日志请保持关闭。',
      transferTimeout: '文件传输超时',
      transferTimeoutDesc: '单位：秒。单次 SFTP 上传/下载的默认时限，默认 600 秒（10 分钟）；到点即取消传输，避免链路卡住时一直挂着。',
      open: '连接',
      closeConnection: '断开',
      connected: '已连接',
      connecting: '连接中',
      idle: '未连接',
      down: '已断开',
      retryPaused: '已暂停',
      retry: '重试',
      remarkPlaceholder: '备注…',
      sessionsUnit: '会话',
      commandsUnit: '命令',
      perHostIdle: '单独超时',
      perHostIdleShort: '超时',
      noHosts: '没有可用的 SSH 主机：检查 ~/.ssh/config 或插件配置。',
      loadFailed: '读取状态失败',
      saveFailed: '保存失败',
      policyText: '只拦会让整台机器报废的操作：递归/通配删除系统关键目录、mkfs/分区、dd 或 > 写块设备、覆写系统关键文件、递归 chmod/chown 系统目录。业务目录和普通维护不拦。',
      logExamples: '查日志要有界；数字只是写法示例，不是固定上限',
    };

    /** Floating-window state shared by the panel button and the overlay. */
    const listeners = new Set();
    let isFloating = false;
    const setFloating = (next) => {
      isFloating = next;
      for (const listener of [...listeners]) listener(next);
    };
    const useFloating = () => {
      const [value, setValue] = React.useState(isFloating);
      React.useEffect(() => {
        const listener = (next) => setValue(next);
        listeners.add(listener);
        setValue(isFloating);
        return () => listeners.delete(listener);
      }, []);
      return value;
    };

    /** The layout service, captured so the entry can select its own panel. */
    let layoutService;

    const CSS = `
.ssh-root{display:flex;flex-direction:column;flex:1 1 auto;height:100%;min-height:0;container-type:inline-size;background:var(--dsw-alias-bg-base);color:var(--dsw-alias-label-primary);font-size:13px;line-height:20px}
.ssh-top{display:flex;align-items:center;gap:10px;padding:14px 52px;border-bottom:1px solid var(--dsw-alias-border-l1);flex:0 0 auto}
.ssh-mark{display:flex;align-items:center;justify-content:center;width:28px;height:28px;border-radius:8px;background:var(--dsw-alias-bg-layer-2);color:var(--dsw-alias-brand-primary);flex:0 0 auto}
.ssh-title{font-size:14px;font-weight:600}
.ssh-sub{font-size:12px;color:var(--dsw-alias-label-secondary)}
.ssh-grow{flex:1 1 auto}
.ssh-content{overflow:auto;padding:26px 52px 36px;display:flex;flex-direction:column;gap:22px;min-height:0}
.ssh-sec{font-size:12px;font-weight:600;color:var(--dsw-alias-label-secondary);letter-spacing:.04em;margin-bottom:10px}
.ssh-note{font-size:12px;color:var(--dsw-alias-label-secondary);margin:-4px 0 10px}
.ssh-table{border:1px solid var(--dsw-alias-border-l1);border-radius:12px;background:var(--dsw-alias-bg-layer-1);overflow:hidden}
/* One connection per row: identity, state and key first, then the controls, and
   the note field last so it absorbs the remaining width instead of leaving a
   dead strip on the right. Fixed bases keep every row aligned. */
.ssh-row{display:flex;flex-wrap:wrap;align-items:center;gap:9px 16px;padding:11px 16px}
.ssh-row + .ssh-row{border-top:1px solid var(--dsw-alias-border-l1)}
.ssh-row:hover{background:var(--dsw-alias-bg-layer-2)}
.ssh-id{display:flex;align-items:center;gap:8px;flex:0 0 250px;min-width:0}
.ssh-state{flex:0 0 104px;font-size:12.5px}
.ssh-key{flex:0 0 88px;font-size:12px}
.ssh-remark{width:auto;flex:1 1 220px;min-width:160px;max-width:none}
.ssh-controls{display:flex;align-items:center;gap:12px;flex:0 0 auto;margin-right:6px}
.ssh-mini{display:inline-flex;align-items:center;gap:6px;font-size:11.5px;color:var(--dsw-alias-label-secondary);white-space:nowrap}
/* One neutral switch with the two states spelled out on either side: the knob
   shows which side is active and the fixed labels keep the row width stable. */
.ssh-hidden-toggle{display:inline-flex;align-items:center;gap:6px;height:26px;font-size:11.5px;color:var(--dsw-alias-label-secondary);white-space:nowrap}
.ssh-hidden-label{opacity:.55;transition:opacity .12s ease}
.ssh-hidden-label.is-on{opacity:1;color:var(--dsw-alias-label-primary)}
.ssh-timeout{width:62px}
.ssh-sec-row{flex-wrap:wrap;row-gap:8px}
/* Narrow panel: the control cluster takes its own line under the identity. */
@container (max-width: 900px){
  .ssh-id{flex:1 1 100%}
  .ssh-state{flex:0 0 96px}
  .ssh-remark{flex:1 1 130px}
}
.ssh-ell{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ssh-name{font-weight:600}
.ssh-muted{color:var(--dsw-alias-label-secondary)}
.ssh-dot{width:9px;height:9px;border-radius:50%;flex:0 0 auto}
.ssh-quiet{width:100%;height:26px;padding:0 8px;border:1px solid transparent;border-radius:7px;background:transparent;color:var(--dsw-alias-label-primary);font:inherit;font-size:12.5px}
.ssh-quiet:hover{border-color:var(--dsw-alias-border-l1)}
.ssh-quiet:focus{outline:none;background:var(--dsw-alias-bg-base);border-color:var(--dsw-alias-border-l2)}
.ssh-num{width:100%;height:26px;padding:0 6px;text-align:center;border:1px solid var(--dsw-alias-border-l1);border-radius:7px;background:var(--dsw-alias-bg-base);color:var(--dsw-alias-label-primary);font:inherit;font-size:12.5px}
.ssh-num:focus{outline:none;border-color:var(--dsw-alias-border-l2)}
.ssh-btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;height:28px;padding:0 12px;border:1px solid var(--dsw-alias-border-l1);border-radius:8px;background:var(--dsw-alias-bg-layer-1);color:var(--dsw-alias-label-primary);font:inherit;font-size:12.5px;cursor:pointer;white-space:nowrap}
.ssh-btn:hover{background:var(--dsw-alias-bg-layer-2);border-color:var(--dsw-alias-border-l2)}
.ssh-btn[disabled]{opacity:.5;cursor:default}
.ssh-btn svg{flex:0 0 auto}
.ssh-btn-primary{background:var(--dsw-alias-brand-primary);border-color:transparent;color:var(--dsw-alias-bg-base)}
.ssh-btn-primary:hover{background:var(--dsw-alias-brand-primary);filter:brightness(1.08)}
.ssh-ico-connect{color:var(--dsw-alias-brand-primary)}
.ssh-ico-stop{color:var(--dsw-alias-state-error-primary)}
.ssh-btn-primary .ssh-ico-connect{color:inherit}
.ssh-switch{position:relative;width:36px;height:20px;padding:0;border:1px solid var(--dsw-alias-border-l2);border-radius:999px;background:var(--dsw-alias-bg-layer-2);cursor:pointer;flex:0 0 auto;transition:background .14s ease,border-color .14s ease}
/* Off: layer-2 track with the primary label colour as the knob. On: the
   success colour, which stays legible whichever way the theme's brand colour
   leans (it is near-white here) — geometry is identical in both states, only
   the colours and the knob's travel change. */
.ssh-switch[aria-checked="true"]{background:var(--dsw-alias-state-success-primary);border-color:var(--dsw-alias-state-success-primary)}
/* The hidden switch is a state readout, not a success signal: keep it neutral
   so "hidden" is not painted green. The knob travel and the labels carry the
   state, with no colour change that could shift the perceived layout. */
.ssh-switch-neutral[aria-checked="true"]{background:var(--dsw-alias-label-primary);border-color:var(--dsw-alias-label-primary)}
.ssh-switch-neutral[aria-checked="true"] .ssh-knob{background:var(--dsw-alias-bg-base)}
.ssh-switch[disabled]{opacity:.5;cursor:default}
/* Off: the track is layer-2 and the knob is the primary label colour; On: the
   track is the success colour with a white knob. Both pairs stay high-contrast
   in the light and the dark theme. */
.ssh-knob{position:absolute;top:2px;left:2px;width:14px;height:14px;border-radius:50%;background:var(--dsw-alias-label-primary);transition:left .14s ease,background .14s ease}
.ssh-switch[aria-checked="true"] .ssh-knob{left:18px;background:#fff}
.ssh-card{border:1px solid var(--dsw-alias-border-l1);border-radius:12px;background:var(--dsw-alias-bg-layer-1);padding:6px 18px}
/* Settings row: the control — switch or number box — is centred in its own
   fixed column, so every control shares one vertical axis, and a clear margin
   separates that column from the text. */
.ssh-setrow{display:grid;grid-template-columns:88px minmax(0,1fr);align-items:start;gap:6px 18px;padding:12px 0}
.ssh-setrow + .ssh-setrow{border-top:1px solid var(--dsw-alias-border-l1)}
.ssh-setctl{grid-column:1;grid-row:1;display:flex;align-items:center;justify-content:center;min-height:20px}
.ssh-settext{grid-column:2;grid-row:1;min-width:0}
.ssh-setrow-title{font-size:13px;line-height:20px}
.ssh-setrow-desc{font-size:12px;color:var(--dsw-alias-label-secondary);line-height:17px;max-width:78ch}
/* A settings group: a quiet caption, then its card. Splitting the long list keeps
   the panel readable instead of one wall of identical rows. */
.ssh-group + .ssh-group{margin-top:18px}
.ssh-group-title{font-size:11.5px;font-weight:600;letter-spacing:.04em;color:var(--dsw-alias-label-secondary);margin:0 2px 8px}
/* Centred in the column like the switch, with the digits centred inside. */
.ssh-setctl .ssh-num{width:70px;text-align:center}
.ssh-code{display:block;width:100%;box-sizing:border-box;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;background:var(--dsw-alias-bg-layer-2);border-radius:8px;padding:10px 12px;white-space:pre-wrap;margin-top:8px}
/* Free-form text block (the policy explanation): fills the card, no grid indent. */
.ssh-prose{padding:14px 2px 16px}
.ssh-prose-desc{font-size:12.5px;color:var(--dsw-alias-label-secondary);line-height:20px}
.ssh-prose-title{font-size:13px;font-weight:600;margin-top:14px}
.ssh-err{border:1px solid var(--dsw-alias-state-error-primary);color:var(--dsw-alias-state-error-primary);border-radius:10px;padding:8px 12px;font-size:12.5px}
.ssh-warn{border:1px solid var(--dsw-alias-state-warn-primary);color:var(--dsw-alias-state-warn-primary);border-radius:10px;padding:7px 12px;font-size:12.5px}
.ssh-foot{font-size:12px;color:var(--dsw-alias-label-secondary);padding-top:2px}
.ssh-mask{position:fixed;inset:0;z-index:60;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,.5);padding:40px}
.ssh-modal{display:flex;flex-direction:column;width:min(1000px,100%);max-height:min(780px,100%);border:1px solid var(--dsw-alias-border-l1);border-radius:14px;background:var(--dsw-alias-bg-overlay);box-shadow:0 24px 64px rgba(0,0,0,.45);overflow:hidden}
.ssh-icon{display:flex;align-items:center;justify-content:center;width:100%;height:100%;color:inherit}
`;

    const panelIcon = h(
      'svg',
      { viewBox: '0 0 24 24', width: 16, height: 16, 'aria-hidden': true, fill: 'none', stroke: 'currentColor', strokeWidth: 1.7, strokeLinecap: 'round' },
      h('rect', { x: 3, y: 4, width: 18, height: 13, rx: 2 }),
      h('path', { d: 'M8 20h8M12 17v3' }),
      h('path', { d: 'M7 9.5l2 1.5-2 1.5M12.5 12.5h3.5' })
    );

    /** Small action glyphs, so the controls read at a glance. */
    const icon = (paths, size = 14) =>
      h(
        'svg',
        { viewBox: '0 0 24 24', width: size, height: size, 'aria-hidden': true, fill: 'none', stroke: 'currentColor', strokeWidth: 1.8, strokeLinecap: 'round', strokeLinejoin: 'round' },
        paths.map((d, index) => h('path', { key: index, d }))
      );
    const ICONS = {
      connect: (extra) => icon(['M9 3v6', 'M15 3v6', 'M6 9h12v3a6 6 0 0 1-6 6 6 6 0 0 1-6-6z', 'M12 18v3'], 14),
      stop: () => icon(['M12 4v8', 'M7.5 6.6a7 7 0 1 0 9 0'], 14),
      refresh: () => icon(['M20 12a8 8 0 1 1-2.3-5.6', 'M20 4v5h-5'], 14),
      float: () => icon(['M14 4h6v6', 'M20 4l-8 8', 'M18 14v4a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4'], 14),
      close: () => icon(['M6 6l12 12', 'M18 6L6 18'], 14)
    };

    const statusColor = (state) => {
      if (state === 'ready') return 'var(--dsw-alias-state-success-primary)';
      if (state === 'connecting' || state === 'paused') return 'var(--dsw-alias-state-warn-primary)';
      return 'var(--dsw-alias-state-idle-primary)';
    };
    /** The panel title used outside React. */
    const titleText = () => TEXT.title;
    const seconds = (value) => (value === null || value === undefined ? '' : String(Math.round(value)));

    /** The host's own switch look: a pill with a knob. */
    function Switch({ checked, onChange, label, disabled, neutral }) {
      const on = checked === true;
      return h(
        'button',
        {
          type: 'button',
          className: `ssh-switch${neutral === true ? ' ssh-switch-neutral' : ''}`,
          role: 'switch',
          'aria-checked': on ? 'true' : 'false',
          'aria-label': label,
          title: label,
          disabled: disabled === true,
          onClick: () => onChange(!on)
        },
        h('span', { className: 'ssh-knob' })
      );
    }

    /**
     * One settings row: the control — switch or number box — in a fixed left
     * column, then the title and description sharing one left edge.
     */
    function SetRow({ title, desc, control }) {
      return h(
        'div',
        { className: 'ssh-setrow' },
        h('div', { className: 'ssh-setctl' }, control ?? null),
        h('div', { className: 'ssh-settext' }, h('div', { className: 'ssh-setrow-title' }, title), h('div', { className: 'ssh-setrow-desc' }, desc))
      );
    }

    /** The bound translator shared by every component. */
    function useT() {
      return (key, ...args) => {
        const value = TEXT[key] ?? key;
        return typeof value === 'function' ? value(...args) : value;
      };
    }

    /**
     * Survives a remount of the panel or window (the host may re-render the
     * slot around it), so the surface never blanks and refills — which reads as
     * a page refresh — and an in-progress note edit is not thrown away.
     */
    const cache = { state: null, settings: null, draft: {} };

    /** Shared data: state, mutations, and polling while `active`. */
    function useAssistant(active) {
      const credential = React.useRef(globalThis.__DSH_SSH_ASSISTANT__?.token);
      const consecutiveFailures = React.useRef(0);
      const [state, setState] = React.useState(cache.state);
      const [error, setError] = React.useState(null);
      const [notice, setNotice] = React.useState(null);
      const [busy, setBusy] = React.useState(false);
      const [settings, setSettings] = React.useState(cache.settings);
      const [draft, setDraftState] = React.useState(cache.draft);
      // Numeric settings are typed locally and saved on blur. While at least
      // one such input is focused, a background poll must not overwrite the
      // editing value with the server's last snapshot.
      const editingRef = React.useRef(0);
      const beginEdit = React.useCallback(() => { editingRef.current += 1; }, []);
      const endEdit = React.useCallback(() => { editingRef.current = Math.max(0, editingRef.current - 1); }, []);
      const setDraft = React.useCallback((next) => {
        const value = typeof next === 'function' ? next(cache.draft) : next;
        cache.draft = value;
        setDraftState(value);
      }, []);

      const call = React.useCallback(async (path, body, options = {}) => {
        const isWrite = body !== undefined;
        const retry = options.retry !== false;
        // A background poll must not touch `busy`: toggling it disabled every
        // control twice per interval, which flickered the whole table.
        const silent = options.silent === true;
        if (!silent) setBusy(true);
        try {
          const token = credential.current;
          const response = await fetch(`/ssh-pool/${path}`, {
            method: isWrite ? 'POST' : 'GET',
            headers: isWrite
              ? { 'content-type': 'application/json', ...(token === undefined ? {} : { 'x-dsh-ssh-pool-token': token }) }
              : { accept: 'application/json', ...(token === undefined ? {} : { 'x-dsh-ssh-pool-token': token }) },
            credentials: 'same-origin',
            ...(isWrite ? { body: JSON.stringify(body) } : {})
          });
          const payload = await response.json().catch(() => null);
          // Every read refreshes the write credential.
          if (typeof payload?.token === 'string' && payload.token.length > 0) credential.current = payload.token;
          if (!response.ok || payload === null || payload.ok !== true) {
            throw new Error(payload?.error ?? `HTTP ${response.status}`);
          }
          if (payload.state) {
            cache.state = payload.state;
            cache.settings = payload.state.settings;
            setState(payload.state);
            if (!(silent && editingRef.current > 0)) setSettings(payload.state.settings);
          }
          consecutiveFailures.current = 0;
          setError(null);
          if (isWrite) setNotice(null);
          return true;
        } catch (cause) {
          const message = cause instanceof Error ? cause.message : String(cause);
          if (isWrite) {
            setNotice(message);
            if (retry) {
              // A stale credential is the usual cause: re-read (which also
              // refreshes it) and try the write exactly once more.
              await call('state', undefined, { retry: false, silent: true });
              const retried = await call(path, body, { retry: false });
              if (!retried && cache.settings !== null) setSettings(cache.settings);
              return retried;
            }
            if (cache.settings !== null) setSettings(cache.settings);
            return false;
          }
          consecutiveFailures.current += 1;
          // One dropped poll is not worth a banner; keep showing the last state.
          if (consecutiveFailures.current >= 2 || cache.state === null) setError(message);
          return false;
        } finally {
          if (!silent) setBusy(false);
        }
      }, []);

      React.useEffect(() => {
        if (!active) return undefined;
        call('state', undefined, { silent: true });
        const timer = setInterval(() => call('state', undefined, { silent: true }), 4000);
        return () => clearInterval(timer);
      }, [active, call]);

      return { state, error, notice, busy, settings, setSettings, draft, setDraft, call, beginEdit, endEdit };
    }

    /** The panel/window body: the connection table, settings and the policy. */
    function AssistantBody({ t, data }) {
      const { state, error, notice, busy, settings, setSettings, draft, setDraft, call, beginEdit, endEdit } = data;
      const hosts = state?.hosts ?? [];
      const settingsView = settings ?? state?.settings ?? { idleTimeoutMs: 0, maxOutputBytes: 32768, transferTimeoutMs: 600000, sshVisible: true, logAnalysis: false };
      const hiddenCount = hosts.filter((host) => host.hidden === true).length;

      const row = (host) => {
        const remark = draft[`remark:${host.alias}`] ?? host.remark ?? '';
        const idleDraft = draft[`idle:${host.alias}`] ?? seconds(host.idleTimeoutMs);
        const stateLabel = host.retryPaused === true ? t('retryPaused') : host.state === 'ready' ? t('connected') : host.state === 'connecting' ? t('connecting') : host.state === 'down' ? t('down') : t('idle');
        // Compact in the row, complete in the tooltip. A stateless command leaves
        // no session behind, so the command count is what shows the host was used.
        const stats = [
          stateLabel,
          host.sessions.length > 0 ? `${host.sessions.length} ${t('sessionsUnit')}` : null,
          (host.commands ?? 0) > 0 ? `${host.commands} ${t('commandsUnit')}` : null
        ].filter(Boolean).join(' · ');
        return h(
          'div',
          { className: 'ssh-row', key: host.alias },
          h('span', { className: 'ssh-id' },
            h('span', { className: 'ssh-dot', style: { background: statusColor(host.retryPaused === true ? 'paused' : host.state) }, title: host.lastError ?? stateLabel }),
            h('span', { className: 'ssh-name ssh-ell', title: host.alias }, host.alias),
            h('span', { className: 'ssh-muted ssh-ell', title: `${host.user}@${host.host}:${host.port}` }, `${host.user}@${host.host}:${host.port}`)
          ),
          h('span', { className: 'ssh-state ssh-muted ssh-ell', title: host.lastError ?? stats }, stats),
          h('span', { className: 'ssh-key ssh-muted ssh-ell', title: host.keyName ?? 'agent' }, host.keyName ?? 'agent'),
          h('span', { className: 'ssh-controls' },
            h('span', { className: 'ssh-hidden-toggle', title: t('hiddenHint') },
              h('span', { className: `ssh-hidden-label${host.hidden === true ? '' : ' is-on'}` }, t('visible')),
              h(Switch, {
                checked: host.hidden === true,
                neutral: true,
                label: t('hiddenHint'),
                onChange: (next) => call('meta', { alias: host.alias, hidden: next })
              }),
              h('span', { className: `ssh-hidden-label${host.hidden === true ? ' is-on' : ''}` }, t('hidden'))
            ),
            h('span', { className: 'ssh-mini' },
              h('span', null, t('perHostIdleShort')),
              h('input', {
                className: 'ssh-num ssh-timeout',
                inputMode: 'numeric',
                title: t('perHostIdle'),
                placeholder: '—',
                value: idleDraft,
                onFocus: beginEdit,
                onChange: (event) => setDraft((current) => ({ ...current, [`idle:${host.alias}`]: event.target.value })),
                onBlur: (event) => {
                  const raw = String(event.target.value ?? '').trim();
                  setDraft((current) => ({ ...current, [`idle:${host.alias}`]: raw }));
                  if (raw === seconds(host.idleTimeoutMs)) {
                    endEdit();
                    return;
                  }
                  if (raw !== '' && !Number.isFinite(Number(raw))) {
                    endEdit();
                    return;
                  }
                  const idleTimeoutMs = raw === '' ? null : Math.max(0, Math.round(Number(raw) * 1000));
                  Promise.resolve(call('meta', { alias: host.alias, idleTimeoutMs }))
                    .then((ok) => {
                      if (ok) return;
                      setDraft((current) => {
                        const next = { ...current };
                        delete next[`idle:${host.alias}`];
                        return next;
                      });
                    })
                    .finally(endEdit);
                },
                onKeyDown: (event) => { if (event.key === 'Enter') event.currentTarget.blur(); }
              })
            ),
            h('button', {
              className: `ssh-btn${host.state === 'ready' ? '' : ' ssh-btn-primary'}`,
              title: host.state === 'ready' ? t('closeConnection') : host.retryPaused === true ? t('retry') : t('open'),
              onClick: () => call('action', { action: host.state === 'ready' ? 'close' : 'open', alias: host.alias })
            },
              h('span', { className: host.state === 'ready' ? 'ssh-ico-stop' : 'ssh-ico-connect', style: { display: 'flex' } }, host.state === 'ready' ? ICONS.stop() : ICONS.connect()),
              host.state === 'ready' ? t('closeConnection') : host.retryPaused === true ? t('retry') : t('open')
            )
          ),
          h('input', {
            className: 'ssh-quiet ssh-remark',
            placeholder: t('remarkPlaceholder'),
            value: remark,
            onChange: (event) => setDraft({ ...draft, [`remark:${host.alias}`]: event.target.value }),
            // Focus in and out without a change must not send anything.
            onBlur: () => {
              if (remark !== (host.remark ?? '')) call('meta', { alias: host.alias, remark });
            },
            onKeyDown: (event) => {
              if (event.key === 'Enter') event.currentTarget.blur();
            }
          })
        );
      };

      /** A captioned card: the settings list is long, so it ships in topics. */
      const group = (title, rows) =>
        h(
          'div',
          { className: 'ssh-group' },
          h('div', { className: 'ssh-group-title' }, title),
          h('div', { className: 'ssh-card' }, rows)
        );

      return h(
        React.Fragment,
        null,
        error !== null ? h('div', { className: 'ssh-err' }, `${t('loadFailed')}: ${error}`) : null,
        notice !== null ? h('div', { className: 'ssh-warn' }, `${t('saveFailed')}: ${notice}`) : null,

        h(
          'div',
          null,
          h(
            'div',
            { className: 'ssh-sec ssh-sec-row', style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px' } },
            h('span', null, t('connections')),
            h(
              'span',
              { className: 'ssh-mini', title: t('sshVisibleDesc') },
              h(Switch, { checked: settingsView.sshVisible !== false, label: t('sshVisible'), onChange: (next) => call('settings', { sshVisible: next }) }),
              h('span', { className: 'ssh-muted' }, t('sshVisibleShort'))
            )
          ),
          h('div', { className: 'ssh-note' }, t('connectionsHint')),
          hosts.length === 0
            ? h('div', { className: 'ssh-note' }, t('noHosts'))
            : h('div', { className: 'ssh-table' }, hosts.map(row))
        ),

        h(
          'div',
          null,
          h('div', { className: 'ssh-sec' }, t('settings')),
          group(t('groupOutput'), [
            h(SetRow, {
              title: t('maxOutputBytes'),
              desc: t('maxOutputBytesDesc'),
              control: h('input', {
                className: 'ssh-num',
                inputMode: 'numeric',
                value: String(Math.max(1, Math.round((settingsView.maxOutputBytes ?? 32768) / 1024))),
                onFocus: beginEdit,
                onChange: (event) => {
                  const kb = Math.max(1, Math.round(Number(event.target.value || '32')));
                  setSettings((current) => ({ ...(current ?? settingsView), maxOutputBytes: kb * 1024 }));
                },
                onBlur: (event) => {
                  const kb = Math.max(1, Math.round(Number(event.target.value || '32')));
                  const maxOutputBytes = kb * 1024;
                  setSettings((current) => ({ ...(current ?? settingsView), maxOutputBytes }));
                  Promise.resolve(call('settings', { maxOutputBytes })).finally(endEdit);
                },
                onKeyDown: (event) => { if (event.key === 'Enter') event.currentTarget.blur(); }
              })
            }),
            h(SetRow, {
              title: t('logAnalysis'),
              desc:
                state?.analysis?.available === false
                  ? `${t('logAnalysisDesc')}（不可用：${state.analysis.reason ?? '?'}）`
                  : t('logAnalysisDesc'),
              control: h(Switch, {
                checked: settingsView.logAnalysis === true,
                label: t('logAnalysisDesc'),
                onChange: (next) => call('settings', { logAnalysis: next })
              })
            })
          ]),
          group(t('groupConnection'), [
            h(SetRow, {
              title: t('idleTimeout'),
              desc: t('idleTimeoutDesc'),
              control: h('input', {
                className: 'ssh-num',
                inputMode: 'numeric',
                value: seconds(settingsView.idleTimeoutMs / 1000),
                onFocus: beginEdit,
                onChange: (event) => {
                  const secondsValue = Math.max(0, Math.round(Number(event.target.value || '0')));
                  setSettings((current) => ({ ...(current ?? settingsView), idleTimeoutMs: secondsValue * 1000 }));
                },
                onBlur: (event) => {
                  const secondsValue = Math.max(0, Math.round(Number(event.target.value || '0')));
                  const idleTimeoutMs = secondsValue * 1000;
                  setSettings((current) => ({ ...(current ?? settingsView), idleTimeoutMs }));
                  Promise.resolve(call('settings', { idleTimeoutMs })).finally(endEdit);
                },
                onKeyDown: (event) => { if (event.key === 'Enter') event.currentTarget.blur(); }
              })
            }),
            h(SetRow, {
              title: t('transferTimeout'),
              desc: t('transferTimeoutDesc'),
              control: h('input', {
                className: 'ssh-num',
                inputMode: 'numeric',
                value: String(Math.max(1, Math.round((settingsView.transferTimeoutMs ?? 600000) / 1000))),
                onFocus: beginEdit,
                onChange: (event) => {
                  const secondsValue = Math.max(1, Math.round(Number(event.target.value || '600')));
                  setSettings((current) => ({ ...(current ?? settingsView), transferTimeoutMs: secondsValue * 1000 }));
                },
                onBlur: (event) => {
                  const secondsValue = Math.max(1, Math.round(Number(event.target.value || '600')));
                  const transferTimeoutMs = secondsValue * 1000;
                  setSettings((current) => ({ ...(current ?? settingsView), transferTimeoutMs }));
                  Promise.resolve(call('settings', { transferTimeoutMs })).finally(endEdit);
                },
                onKeyDown: (event) => { if (event.key === 'Enter') event.currentTarget.blur(); }
              })
            })
          ])
        ),

        h(
          'div',
          null,
          h('div', { className: 'ssh-sec' }, t('policy')),
          h(
            'div',
            { className: 'ssh-card' },
            h(
              'div',
              { className: 'ssh-prose' },
              h('div', { className: 'ssh-prose-desc' }, t('policyText')),
              h('div', { className: 'ssh-prose-title' }, t('logExamples')),
              h('div', { className: 'ssh-code' }, 'journalctl -u <unit> --since "<time>" -n <lines>\ntail -n <lines> <file>\ngrep -m <matches> -n <pattern> <file>\nsed -n "<start>,<end>p" <file>\nawk "NR>=<start> && NR<=<end>" <file>')
            )
          )
        ),

        h(
          'div',
          { className: 'ssh-foot' },
          state === null
            ? t('loadFailed')
            : `${state.totals.hosts} hosts · ${state.totals.connected} connected · ${state.totals.sessions} sessions${hiddenCount > 0 ? ` · ${t('hiddenCount', hiddenCount)}` : ''}${settingsView.sshVisible === false ? ` · ${t('sshVisible')}: off` : ''}`
        )
      );
    }

    /** The shell shared by the docked panel and the floating window. */
    function AssistantShell({ t, data, actions }) {
      return h(
        'div',
        { className: 'ssh-root' },
        h('style', null, CSS),
        h(
          'div',
          { className: 'ssh-top' },
          h('span', { className: 'ssh-mark' }, panelIcon),
          h('div', null, h('div', { className: 'ssh-title' }, t('title')), h('div', { className: 'ssh-sub' }, t('subtitle'))),
          h('div', { className: 'ssh-grow' }),
          actions
        ),
        h('div', { className: 'ssh-content' }, h(AssistantBody, { t, data }))
      );
    }

    /** The docked panel the sidebar row selects. */
    function SshAssistantPanel() {
      const t = useT();
      const data = useAssistant(true);
      return h(AssistantShell, {
        t,
        data,
        actions: h(
          React.Fragment,
          null,
          h('button', { className: 'ssh-btn', onClick: () => setFloating(true) }, h('span', { style: { display: 'flex' } }, ICONS.float()), t('float')),
          h('button', { className: 'ssh-btn', disabled: data.busy, onClick: () => data.call('state') }, h('span', { style: { display: 'flex' } }, ICONS.refresh()), t('refresh'))
        )
      });
    }

    /** The optional floating window, opened from the panel. */
    function SshAssistantOverlay() {
      const floating = useFloating();
      const t = useT();
      const data = useAssistant(floating);
      const boxRef = React.useRef(null);

      React.useEffect(() => {
        if (!floating) return undefined;
        const onKey = (event) => {
          if (event.key === 'Escape') setFloating(false);
        };
        window.addEventListener('keydown', onKey);
        const focus = setTimeout(() => boxRef.current?.focus(), 0);
        return () => {
          window.removeEventListener('keydown', onKey);
          clearTimeout(focus);
        };
      }, [floating]);

      if (!floating) return null;
      return h(
        React.Fragment,
        null,
        h('style', null, CSS),
        h(
          'div',
          { className: 'ssh-mask', onMouseDown: (event) => { if (event.target === event.currentTarget) setFloating(false); } },
          h(
            'div',
            { className: 'ssh-modal', role: 'dialog', 'aria-modal': 'true', 'aria-label': t('title'), tabIndex: -1, ref: boxRef },
            h(AssistantShell, {
              t,
              data,
              actions: h(
                React.Fragment,
                null,
                h('button', { className: 'ssh-btn', disabled: data.busy, onClick: () => data.call('state') }, h('span', { style: { display: 'flex' } }, ICONS.refresh()), t('refresh')),
                h('button', { className: 'ssh-btn ssh-btn-primary', onClick: () => setFloating(false) }, h('span', { style: { display: 'flex' } }, ICONS.close()), t('close'))
              )
            })
          )
        )
      );
    }

    /** The sidebar entry: the icon only, because the host row owns the chrome. */
    function SshAssistantIcon() {
      const activate = () => {
        if (typeof layoutService?.selectPanel === 'function') layoutService.selectPanel('ssh-assistant');
        else setFloating(true);
      };
      return h(
        React.Fragment,
        null,
        h('style', null, CSS),
        h(
          'span',
          {
            className: 'ssh-icon',
            role: 'button',
            tabIndex: 0,
            'aria-label': titleText(),
            onClick: activate,
            onKeyDown: (event) => {
              if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                activate();
              }
            }
          },
          panelIcon
        )
      );
    }

    return {
      inject: ['slots'],
      apply(ctx) {
        layoutService = ctx.get('layout');
        const label = () => titleText();
        // The sidebar row selects the `main` panel whose key is this entry id.
        ctx.slots.inject('sidebar.panellist', () => ctx.slots.register({ name: 'sidebar.panellist', id: 'ssh-assistant', order: 60, label }, SshAssistantIcon));
        ctx.slots.inject('main', () => ctx.slots.register({ name: 'main', key: 'ssh-assistant' }, SshAssistantPanel));
        ctx.slots.inject('shell.overlay', () => ctx.slots.register({ name: 'shell.overlay', id: 'ssh-assistant', order: 60 }, SshAssistantOverlay));
      }
    };
  }
});
