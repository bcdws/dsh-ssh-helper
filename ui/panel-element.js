/**
 * `<ssh-helper-panel>` — the one SSH assistant UI, as a dependency-free custom
 * element with its own shadow DOM.
 *
 *   <ssh-helper-panel api-base="/ssh-pool" mode="dsh" floatable></ssh-helper-panel>   DSH sidebar
 *   <ssh-helper-panel api-base="/api" mode="mcp"></ssh-helper-panel>                  MCP page
 *
 * Attributes: `api-base` (route prefix of `lib/assistant-api.js`), `mode`
 * (`dsh` shows the sshVisible master switch; `mcp` adds the process tab and
 * routes opens to a chosen server), `floatable` / `closable` (header buttons
 * that dispatch `ssh-helper-float` / `ssh-helper-close`, composed events the
 * host page handles). Property `token`: an initial write credential (DSH
 * injects one); every state read refreshes it anyway.
 *
 * Theme: DSH's `--dsw-alias-*` variables pierce the shadow root, so inside DSH
 * the panel uses the host theme; standalone it falls back to its own light /
 * dark palette.
 *
 * @module dsh-ssh-helper/ui/panel-element
 */
import {
  TEXT,
  renderBanners,
  renderDrawer,
  renderEditDialog,
  renderFooter,
  renderHeader,
  renderTab,
  renderTabs,
  tabsFor
} from './panel-view.js';

const STYLES = `
:host{
  --bg:var(--dsw-alias-bg-base,#f7f7f8);--l1:var(--dsw-alias-bg-layer-1,#fff);--l2:var(--dsw-alias-bg-layer-2,#f0f0f3);
  --overlay:var(--dsw-alias-bg-overlay,#fff);--b1:var(--dsw-alias-border-l1,#e4e4e8);--b2:var(--dsw-alias-border-l2,#cacad1);
  --fg:var(--dsw-alias-label-primary,#1c1c1f);--fg2:var(--dsw-alias-label-secondary,#6d6d76);--brand:var(--dsw-alias-brand-primary,#3b6cf6);
  --ok:var(--dsw-alias-state-success-primary,#1f9d55);--warn:var(--dsw-alias-state-warn-primary,#c98a00);
  --err:var(--dsw-alias-state-error-primary,#d64545);--idle:var(--dsw-alias-state-idle-primary,#b4b4bc);
  display:flex;flex-direction:column;position:relative;height:100%;min-height:0;overflow:hidden;container-type:inline-size;
  background:var(--bg);color:var(--fg);font:13px/20px system-ui,-apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;color-scheme:light dark
}
@media (prefers-color-scheme:dark){:host{
  --bg:var(--dsw-alias-bg-base,#141416);--l1:var(--dsw-alias-bg-layer-1,#1b1b1f);--l2:var(--dsw-alias-bg-layer-2,#25252a);
  --overlay:var(--dsw-alias-bg-overlay,#1f1f24);--b1:var(--dsw-alias-border-l1,#2d2d33);--b2:var(--dsw-alias-border-l2,#3e3e46);
  --fg:var(--dsw-alias-label-primary,#ececf1);--fg2:var(--dsw-alias-label-secondary,#9a9aa4);--brand:var(--dsw-alias-brand-primary,#7c9cff);
  --ok:var(--dsw-alias-state-success-primary,#3ccf7c);--warn:var(--dsw-alias-state-warn-primary,#e0a83a);
  --err:var(--dsw-alias-state-error-primary,#ef6b6b);--idle:var(--dsw-alias-state-idle-primary,#5a5a63)
}}
*{box-sizing:border-box}
button,input{font:inherit;color:inherit}
.top{display:flex;align-items:center;gap:10px;padding:14px 24px 10px;flex:0 0 auto}
.mark{display:flex;align-items:center;justify-content:center;width:30px;height:30px;border-radius:9px;background:var(--l2);color:var(--brand);flex:0 0 auto}
.title{font-size:14px;font-weight:600;display:flex;align-items:center;gap:6px}
.title-tag{font-size:10.5px;font-weight:600;padding:0 6px;border-radius:5px;background:var(--l2);color:var(--fg2);letter-spacing:.04em}
.sub{font-size:12px;color:var(--fg2)}
.row .sub{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.grow{flex:1}
.actions{display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end}
.tabs{display:flex;gap:2px;padding:0 20px;border-bottom:1px solid var(--b1);flex:0 0 auto;overflow-x:auto}
.tab{display:inline-flex;align-items:center;gap:6px;height:36px;padding:0 12px;border:0;border-bottom:2px solid transparent;background:none;color:var(--fg2);cursor:pointer;white-space:nowrap;margin-bottom:-1px}
.tab:hover{color:var(--fg)}
.tab.on{color:var(--fg);border-bottom-color:var(--brand);font-weight:600}
.count{display:inline-flex;align-items:center;justify-content:center;min-width:18px;height:17px;padding:0 5px;border-radius:9px;background:var(--l2);color:var(--fg2);font-size:10.5px;font-weight:600}
.count.warn{background:color-mix(in srgb,var(--err) 16%,transparent);color:var(--err)}
.body{flex:1 1 auto;min-height:0;overflow:auto}
.pane{padding:16px 24px 24px;display:flex;flex-direction:column;gap:14px;max-width:1100px}
.note{font-size:12px;color:var(--fg2);line-height:18px}
.chips{display:inline-flex;gap:6px;margin-left:4px;vertical-align:middle}
.empty{padding:28px 16px;text-align:center;color:var(--fg2);border:1px dashed var(--b1);border-radius:12px}
.list{border:1px solid var(--b1);border-radius:12px;background:var(--l1);overflow:hidden}
.row{display:flex;align-items:center;gap:12px;padding:10px 14px;cursor:pointer;outline:none;min-height:56px}
.row+.row{border-top:1px solid var(--b1)}
.row:hover,.row:focus-visible{background:var(--l2)}
.row.selected{background:color-mix(in srgb,var(--brand) 9%,var(--l1));box-shadow:inset 3px 0 0 var(--brand)}
.row.static{cursor:default}
.who{flex:0 0 210px;min-width:0}
.row.static .who{flex:0 1 auto;max-width:46%}
.what{flex:1 1 auto;min-width:0;color:var(--fg2);font-size:12px;line-height:18px}
.act{flex:0 0 auto}
.chev{flex:0 0 auto;color:var(--fg2);display:flex;opacity:.6}
.name{display:flex;align-items:center;gap:6px;font-weight:600;min-width:0}
.ell{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0}
.remark{color:var(--fg)}
.fail{color:var(--err)}
.muted{color:var(--fg2)}
.small{font-size:11.5px}
.dot{width:9px;height:9px;border-radius:50%;flex:0 0 auto;background:var(--idle)}
.dot.ready{background:var(--ok);box-shadow:0 0 0 3px color-mix(in srgb,var(--ok) 18%,transparent)}
.dot.connecting,.dot.paused{background:var(--warn)}
.dot.down{background:var(--err)}
.badge{display:inline-flex;align-items:center;height:18px;padding:0 6px;border-radius:5px;font-size:10.5px;font-weight:600;letter-spacing:.03em;border:1px solid var(--b2);color:var(--fg2);flex:0 0 auto;white-space:nowrap}
.badge.prod{color:var(--err);border-color:color-mix(in srgb,var(--err) 55%,transparent);background:color-mix(in srgb,var(--err) 9%,transparent)}
.badge.warn{color:var(--warn);border-color:var(--warn)}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;height:30px;padding:0 12px;border:1px solid var(--b1);border-radius:8px;background:var(--l1);cursor:pointer;white-space:nowrap;font-size:12.5px}
.btn:hover{background:var(--l2);border-color:var(--b2)}
.btn[disabled]{opacity:.5;cursor:default}
.btn.sm{height:26px;padding:0 10px;font-size:12px}
.btn.primary{background:var(--brand);border-color:transparent;color:var(--bg)}
.btn.primary:hover{filter:brightness(1.08);background:var(--brand)}
.btn.ghost{background:transparent;border-color:transparent;color:var(--fg2)}
.btn.ghost:hover{background:var(--l2);color:var(--fg)}
.btn.danger{color:var(--err)}
.btn.icon{width:30px;padding:0}
.switch{position:relative;width:36px;height:20px;padding:0;border:1px solid var(--b2);border-radius:999px;background:var(--l2);cursor:pointer;flex:0 0 auto;transition:background .14s ease,border-color .14s ease}
.knob{position:absolute;top:2px;left:2px;width:14px;height:14px;border-radius:50%;background:var(--fg2);transition:transform .14s ease,background .14s ease}
.switch[aria-checked="true"]{background:var(--ok);border-color:var(--ok)}
.switch[aria-checked="true"] .knob{transform:translateX(16px);background:#fff}
.switch.neutral[aria-checked="true"]{background:var(--l2);border-color:var(--b2)}
.switch.neutral[aria-checked="true"] .knob{background:var(--fg)}
.switch.danger[aria-checked="true"]{background:var(--err);border-color:var(--err)}
.toggle-label{font-size:12px;color:var(--fg2);opacity:.6}
.toggle-label.on{opacity:1;color:var(--fg)}
.toggle-label.prod.on{color:var(--err);font-weight:600}
.hint{font-size:11.5px;color:var(--fg2)}
.num{width:84px;height:30px;padding:0 8px;text-align:center;border:1px solid var(--b1);border-radius:8px;background:var(--bg)}
.text{width:100%;height:32px;padding:0 10px;border:1px solid var(--b1);border-radius:8px;background:var(--bg)}
.num:focus,.text:focus{outline:none;border-color:var(--brand)}
.field{display:flex;flex-direction:column;gap:6px}
.field>span{font-size:12px;color:var(--fg2);display:flex;gap:8px;align-items:baseline;flex-wrap:wrap}
.field em{font-style:normal;font-size:11px;opacity:.8}
.drawer-scrim{position:absolute;inset:0;background:rgba(0,0,0,.18);z-index:20}
.drawer{position:absolute;top:0;right:0;bottom:0;width:min(400px,100%);z-index:21;display:flex;flex-direction:column;background:var(--overlay);border-left:1px solid var(--b1);box-shadow:-16px 0 40px rgba(0,0,0,.18);animation:slide .16s ease-out}
@keyframes slide{from{transform:translateX(24px);opacity:.4}to{transform:none;opacity:1}}
.drawer-head{display:flex;align-items:center;gap:10px;padding:14px 16px;border-bottom:1px solid var(--b1)}
.drawer-head .who{flex:1 1 auto}
.drawer-body{flex:1 1 auto;overflow:auto;padding:4px 16px 16px}
.drawer-foot{padding:12px 16px;border-top:1px solid var(--b1);display:flex;justify-content:flex-end}
.drawer-foot .btn{min-width:110px}
.drawer-foot.hint{justify-content:flex-start;color:var(--fg2);font-size:12px}
.block{display:flex;flex-direction:column;gap:10px;padding:14px 0}
.block+.block{border-top:1px solid var(--b1)}
.block-title{font-size:12px;font-weight:600;color:var(--fg2);display:flex;align-items:center;gap:6px}
.block>.btn{align-self:flex-start}
.kv{display:flex;gap:12px;font-size:12.5px}
.k{flex:0 0 64px;color:var(--fg2)}
.v{flex:1;min-width:0;overflow-wrap:anywhere}
.switch-row{display:flex;align-items:center;gap:8px}
.proc{display:flex;align-items:center;gap:8px;font-size:12.5px}
.proc .ell{flex:1}
.failure{font-size:12px;color:var(--err)}
.failure .msg{color:var(--fg2);margin-top:2px;overflow-wrap:anywhere}
.cmd{display:block;padding:8px 10px;border-radius:8px;background:var(--l2);font:11.5px/17px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;overflow-wrap:anywhere}
.group{display:flex;flex-direction:column;gap:8px}
.group-title{font-size:12px;font-weight:600;color:var(--fg2);letter-spacing:.03em}
.card{border:1px solid var(--b1);border-radius:12px;background:var(--l1);padding:2px 16px}
.card.flush{padding:0;overflow:auto}
.card.prose{padding:12px 16px;font-size:12.5px;color:var(--fg2);line-height:19px}
.card.prose p{margin:0 0 10px}
.set{display:flex;align-items:center;gap:16px;padding:12px 0}
.set+.set{border-top:1px solid var(--b1)}
.set-text{flex:1;min-width:0}
.set-title{font-weight:500;color:var(--fg)}
.set-desc{font-size:12px;color:var(--fg2);line-height:18px;margin-top:2px}
.set-ctl{flex:0 0 auto}
.set-ctl code{font:12px/20px ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--l2);border:1px solid var(--b1);border-radius:6px;padding:2px 8px;color:var(--fg)}
.code{margin:6px 0 0;padding:10px 12px;border-radius:8px;background:var(--l2);color:var(--fg);font:11.5px/18px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;white-space:pre-wrap}
code{font:11.5px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:10px}
.tile{border:1px solid var(--b1);border-radius:12px;background:var(--l1);padding:12px 14px}
.tile-num{font-size:22px;font-weight:600;line-height:28px;font-variant-numeric:tabular-nums}
.tile-label{font-size:12px;color:var(--fg2)}
.tile.warn .tile-num{color:var(--err)}
.events{width:100%;border-collapse:collapse;font-size:12px}
.events th{text-align:left;font-weight:500;color:var(--fg2);background:var(--l2);padding:7px 12px;white-space:nowrap}
.events td{padding:7px 12px;border-top:1px solid var(--b1);white-space:nowrap}
.events tr.bad td{color:var(--err)}
.events .r{text-align:right;font-variant-numeric:tabular-nums}
.banner{margin:10px 24px 0;padding:9px 14px;border-radius:10px;font-size:12.5px}
.banner.err{border:1px solid var(--err);color:var(--err)}
.banner.warn{border:1px solid var(--warn);color:var(--warn)}
.status{flex:0 0 auto;padding:7px 24px;border-top:1px solid var(--b1);font-size:11.5px;color:var(--fg2)}
.foot{font-size:11.5px;color:var(--fg2);display:flex;flex-direction:column;gap:3px}
.backdrop{position:absolute;inset:0;z-index:40;display:flex;align-items:center;justify-content:center;padding:20px;background:rgba(0,0,0,.45)}
.dialog{width:min(420px,100%);display:flex;flex-direction:column;gap:12px;border:1px solid var(--b1);border-radius:14px;background:var(--overlay);box-shadow:0 24px 64px rgba(0,0,0,.35);padding:18px}
.dialog-title{font-size:15px;font-weight:600}
.dialog-desc{font-size:12px;line-height:18px;color:var(--fg2)}
.dialog-host{padding:7px 10px;border:1px solid var(--b1);border-radius:8px;background:var(--bg);font-size:12px;color:var(--fg2)}
.dialog-actions{display:flex;justify-content:flex-end;gap:8px}
.loading{padding:40px;text-align:center;color:var(--fg2)}
@container (max-width:720px){
  .who{flex-basis:150px}
  .row.static .who{max-width:64%}
  .top{padding:12px 16px 8px}.tabs{padding:0 12px}.pane{padding:14px 16px 20px}
  .actions .label{display:none}.actions .btn{width:30px;padding:0}
}
@container (max-width:520px){
  .row{flex-wrap:wrap}.what{flex-basis:100%;order:3;padding-left:21px}.who{flex:1 1 auto}
}
`;

const POLL_MS = 4000;

class SshHelperPanel extends HTMLElement {
  static get observedAttributes() {
    return ['api-base', 'mode', 'floatable', 'closable'];
  }

  constructor() {
    super();
    this.attachShadow({ mode: 'open' });
    this.state = null;
    this.tab = 'hosts';
    this.selected = null;
    this.error = null;
    this.notice = null;
    this.busy = false;
    this.dialog = null;
    this.failures = 0;
    this.timer = undefined;
    this.credential = undefined;
    this.shadowRoot.innerHTML = `<style>${STYLES}</style><div class="frame" style="display:contents"></div>`;
    this.frame = this.shadowRoot.querySelector('.frame');
    this.onVisibility = () => {
      if (!document.hidden) void this.load(true);
    };
    this.wire();
  }

  /** Initial write credential (DSH injects one); state reads refresh it. */
  set token(value) {
    if (typeof value === 'string' && value.length > 0) this.credential = value;
  }

  get apiBase() {
    return (this.getAttribute('api-base') ?? '/ssh-pool').replace(/\/+$/, '');
  }

  get mode() {
    return this.getAttribute('mode') === 'mcp' ? 'mcp' : 'dsh';
  }

  connectedCallback() {
    this.render(true);
    void this.load(true);
    this.timer = setInterval(() => {
      if (!document.hidden) void this.load(true);
    }, POLL_MS);
    document.addEventListener('visibilitychange', this.onVisibility);
  }

  disconnectedCallback() {
    clearInterval(this.timer);
    this.timer = undefined;
    document.removeEventListener('visibilitychange', this.onVisibility);
  }

  attributeChangedCallback() {
    if (this.isConnected) this.render(true);
  }

  // ── data ────────────────────────────────────────────────────────────────

  async call(path, body, { silent = false, retry = true } = {}) {
    const write = body !== undefined;
    if (!silent) this.setBusy(true);
    try {
      const headers = { accept: 'application/json' };
      if (this.credential) headers['x-dsh-ssh-pool-token'] = this.credential;
      if (write) headers['content-type'] = 'application/json';
      const response = await fetch(`${this.apiBase}/${path}`, {
        method: write ? 'POST' : 'GET',
        headers,
        credentials: 'same-origin',
        ...(write ? { body: JSON.stringify(body) } : {})
      });
      const payload = await response.json().catch(() => null);
      if (typeof payload?.token === 'string' && payload.token.length > 0) this.credential = payload.token;
      if (!response.ok || payload === null || payload.ok !== true) throw new Error(payload?.error ?? `HTTP ${response.status}`);
      if (payload.state) this.state = payload.state;
      this.failures = 0;
      this.error = null;
      if (write) this.notice = null;
      return payload;
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : String(cause);
      if (write) {
        if (retry) {
          // A stale credential is the usual cause: re-read (which refreshes
          // it) and try the write exactly once more.
          await this.call('state', undefined, { silent: true, retry: false }).catch(() => undefined);
          return this.call(path, body, { silent, retry: false });
        }
        this.notice = message;
        throw cause;
      }
      this.failures += 1;
      // One dropped poll is not worth a banner; keep showing the last state.
      if (this.failures >= 2 || this.state === null) this.error = message;
      throw cause;
    } finally {
      if (!silent) this.setBusy(false);
      this.render();
    }
  }

  load(silent) {
    return this.call('state', undefined, { silent }).catch(() => undefined);
  }

  post(path, body) {
    return this.call(path, body).catch(() => undefined);
  }

  setBusy(value) {
    this.busy = value;
    for (const element of this.shadowRoot.querySelectorAll('[data-action],[data-refresh]')) element.toggleAttribute('disabled', value);
  }

  // ── rendering ───────────────────────────────────────────────────────────

  /** Never redraw under the cursor: a poll would eat a half-typed remark. */
  editing() {
    const active = this.shadowRoot.activeElement;
    return active !== null && (active.tagName === 'INPUT' || active.tagName === 'TEXTAREA' || active.tagName === 'SELECT');
  }

  render(force = false) {
    if (!force && this.editing()) return;
    const options = { mode: this.mode, selected: this.selected };
    if (!tabsFor(this.mode).includes(this.tab)) this.tab = 'hosts';
    const host = this.selected === null ? null : (this.state?.hosts ?? []).find((candidate) => candidate.alias === this.selected) ?? null;
    if (this.selected !== null && host === null && this.state !== null) this.selected = null;
    const bodyScroll = this.shadowRoot.querySelector('.body')?.scrollTop ?? 0;
    const drawerScroll = this.shadowRoot.querySelector('.drawer-body')?.scrollTop ?? 0;
    this.frame.innerHTML = [
      renderHeader({ mode: this.mode, floatable: this.hasAttribute('floatable'), closable: this.hasAttribute('closable'), busy: this.busy }),
      renderTabs({ mode: this.mode, tab: this.tab, state: this.state }),
      renderBanners({ error: this.error, notice: this.notice }),
      `<div class="body">${this.state === null ? `<div class="loading">${this.error ? '' : TEXT.loading}</div>` : renderTab(this.tab, this.state, options)}</div>`,
      renderFooter(this.state, { mode: this.mode }),
      host && this.tab === 'hosts' ? `<div class="drawer-scrim" data-close-drawer></div>${renderDrawer(host, { state: this.state, mode: this.mode })}` : '',
      this.dialog ? renderEditDialog(this.dialog.host, this.dialog) : ''
    ].join('');
    const body = this.shadowRoot.querySelector('.body');
    if (body) body.scrollTop = bodyScroll;
    const drawer = this.shadowRoot.querySelector('.drawer-body');
    if (drawer) drawer.scrollTop = drawerScroll;
  }

  // ── interaction ─────────────────────────────────────────────────────────

  hostByAlias(alias) {
    return (this.state?.hosts ?? []).find((host) => host.alias === alias);
  }

  emit(name) {
    this.dispatchEvent(new CustomEvent(name, { bubbles: true, composed: true }));
  }

  wire() {
    const root = this.shadowRoot;
    root.addEventListener('click', (event) => {
      const target = event.target instanceof Element ? event.target : null;
      if (target === null) return;
      const button = target.closest('button,[data-select],[data-close-drawer]');
      if (button === null || button.hasAttribute('disabled')) return;
      const d = button.dataset;
      if (d.tab !== undefined) {
        this.tab = d.tab;
        this.render(true);
      } else if (d.refresh !== undefined) void this.load(false);
      else if (d.closeAll !== undefined) {
        if (window.confirm(TEXT.confirmCloseAll)) void this.post('action', { action: 'close_all' });
      } else if (d.float !== undefined) this.emit('ssh-helper-float');
      else if (d.closePanel !== undefined) this.emit('ssh-helper-close');
      else if (d.closeDrawer !== undefined) {
        this.selected = null;
        this.render(true);
      } else if (d.action !== undefined) {
        event.stopPropagation();
        const body = { action: d.action, ...(d.alias ? { alias: d.alias } : {}), ...(d.pid ? { pid: Number(d.pid) } : {}) };
        void this.post('action', body);
      } else if (d.toggle !== undefined) {
        const host = this.hostByAlias(d.alias);
        if (host) void this.post('meta', { alias: d.alias, [d.field]: !(host[d.field] === true) }).then(() => this.mode === 'mcp' && setTimeout(() => this.load(true), 1500));
      } else if (d.settingToggle !== undefined) {
        void this.post('settings', { [d.settingToggle]: !(this.state?.settings?.[d.settingToggle] === true || (d.settingToggle === 'sshVisible' && this.state?.settings?.sshVisible !== false)) });
      } else if (d.edit !== undefined) {
        const host = this.hostByAlias(d.edit);
        if (host) this.openDialog(host);
      } else if (d.dialogCancel !== undefined) this.closeDialog();
      else if (d.select !== undefined) {
        this.selected = this.selected === d.select ? null : d.select;
        this.render(true);
      }
    });
    root.addEventListener('mousedown', (event) => {
      if (event.target instanceof Element && event.target.matches('[data-dialog-backdrop]') && !this.dialog?.saving) this.closeDialog();
    });
    root.addEventListener('change', (event) => {
      const input = event.target;
      if (!(input instanceof HTMLInputElement)) return;
      const d = input.dataset;
      if (d.metaInput !== undefined) {
        const host = this.hostByAlias(d.alias);
        if (!host) return;
        if (d.field === 'remark') {
          if (input.value !== (host.remark ?? '')) void this.post('meta', { alias: d.alias, remark: input.value });
        } else if (d.field === 'idleTimeoutMs') {
          const raw = input.value.trim();
          if (raw !== '' && !Number.isFinite(Number(raw))) return;
          void this.post('meta', { alias: d.alias, idleTimeoutMs: raw === '' ? null : Math.max(0, Math.round(Number(raw) * 1000)) });
        }
      } else if (d.settingInput !== undefined) {
        const value = Number(input.value);
        if (!Number.isFinite(value)) return;
        void this.post('settings', { [d.settingInput]: Math.max(0, Math.round(value)) * Number(d.scale ?? 1) });
      }
    });
    root.addEventListener('keydown', (event) => {
      const target = event.target;
      if (event.key === 'Escape') {
        if (this.dialog && !this.dialog.saving) this.closeDialog();
        else if (this.selected !== null) {
          this.selected = null;
          this.render(true);
        }
        return;
      }
      if (event.key === 'Enter' && target instanceof HTMLInputElement && target.form === null) target.blur();
      if ((event.key === 'Enter' || event.key === ' ') && target instanceof HTMLElement && target.matches('.row[data-select]')) {
        event.preventDefault();
        target.click();
      }
    });
    root.addEventListener('submit', (event) => {
      event.preventDefault();
      void this.submitDialog(event.target);
    });
    // Catch up on polls skipped while an input had focus.
    root.addEventListener('focusout', () => setTimeout(() => this.render(), 0));
  }

  openDialog(host) {
    this.dialog = { host, error: null, saving: false };
    this.render(true);
    const input = this.shadowRoot.querySelector('.dialog input[name="alias"]');
    input?.focus();
    input?.select();
  }

  closeDialog() {
    this.dialog = null;
    this.render(true);
  }

  async submitDialog(form) {
    if (!this.dialog || !(form instanceof HTMLFormElement)) return;
    const host = this.dialog.host;
    const newAlias = String(form.elements.namedItem('alias')?.value ?? '').trim();
    const keyInput = form.elements.namedItem('key');
    const keyName = keyInput && !keyInput.disabled ? String(keyInput.value ?? '').trim() : host.keyName;
    if (newAlias.length === 0) return;
    const body = { alias: host.alias };
    if (newAlias !== host.alias) body.newAlias = newAlias;
    if (keyName && keyName !== host.keyName) body.keyName = keyName;
    if (body.newAlias === undefined && body.keyName === undefined) {
      this.closeDialog();
      return;
    }
    this.dialog = { ...this.dialog, saving: true, error: null };
    this.render(true);
    try {
      await this.call('edit-host', body, { retry: false });
      if (this.selected === host.alias && body.newAlias) this.selected = body.newAlias;
      this.dialog = null;
      this.render(true);
    } catch (error) {
      this.dialog = { ...this.dialog, saving: false, error: error instanceof Error ? error.message : String(error) };
      this.render(true);
    }
  }
}

if (!customElements.get('ssh-helper-panel')) customElements.define('ssh-helper-panel', SshHelperPanel);

export { SshHelperPanel, STYLES };
