/**
 * `<ssh-helper-panel>` — the one SSH assistant UI, as a dependency-free custom
 * element with its own shadow DOM.
 *
 *   <ssh-helper-panel api-base="/ssh-pool" mode="dsh"></ssh-helper-panel>   DSH sidebar
 *   <ssh-helper-panel api-base="/api" mode="mcp"></ssh-helper-panel>      MCP page
 *
 * Attributes: `api-base` (route prefix of `lib/assistant-api.js`), `mode`
 * (`dsh` shows the sshVisible master switch; `mcp` adds the process tab and
 * routes opens to a chosen server). Property `token`: an initial write
 * credential (DSH injects one); every state read refreshes it anyway.
 *
 * Theme: DSH's `--dsw-alias-*` variables pierce the shadow root, so inside DSH
 * the panel uses the host theme; standalone it falls back to its own light /
 * dark palette.
 *
 * @module dsh-ssh-helper/ui/panel-element
 */
import {
  TEXT,
  moveAlias,
  sortTarget,
  renderBanners,
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
  --mosaic-a:#a3a3ad;--mosaic-b:#74747e;
  display:flex;flex-direction:column;position:relative;height:100%;min-height:0;overflow:hidden;container-type:inline-size;
  background:var(--bg);color:var(--fg);font:13px/20px system-ui,-apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;color-scheme:light dark
}
@media (prefers-color-scheme:dark){:host{
  --bg:var(--dsw-alias-bg-base,#141416);--l1:var(--dsw-alias-bg-layer-1,#1b1b1f);--l2:var(--dsw-alias-bg-layer-2,#25252a);
  --overlay:var(--dsw-alias-bg-overlay,#1f1f24);--b1:var(--dsw-alias-border-l1,#2d2d33);--b2:var(--dsw-alias-border-l2,#3e3e46);
  --fg:var(--dsw-alias-label-primary,#ececf1);--fg2:var(--dsw-alias-label-secondary,#9a9aa4);--brand:var(--dsw-alias-brand-primary,#7c9cff);
  --ok:var(--dsw-alias-state-success-primary,#3ccf7c);--warn:var(--dsw-alias-state-warn-primary,#e0a83a);
  --err:var(--dsw-alias-state-error-primary,#ef6b6b);--idle:var(--dsw-alias-state-idle-primary,#5a5a63);
  --mosaic-a:#55555f;--mosaic-b:#3a3a43
}}
*{box-sizing:border-box}
button,input{font:inherit;color:inherit}
button:focus-visible{outline:2px solid var(--brand);outline-offset:1px}
.top{display:flex;align-items:center;gap:10px;padding:14px 24px 10px;flex:0 0 auto}
.mark{display:flex;align-items:center;justify-content:center;width:30px;height:30px;border-radius:9px;background:var(--l2);color:var(--brand);flex:0 0 auto}
.title{font-size:14px;font-weight:600;display:flex;align-items:center;gap:6px}
.title-tag{font-size:10.5px;font-weight:600;padding:0 6px;border-radius:5px;background:var(--l2);color:var(--fg2);letter-spacing:.04em}
.sub{font-size:12px;color:var(--fg2)}
.row .sub{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.grow{flex:1}
.actions{display:flex;gap:6px;flex-wrap:nowrap;justify-content:flex-end}
.titles{min-width:0}
.titles .sub{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.tabs{display:flex;gap:2px;padding:0 20px;border-bottom:1px solid var(--b1);flex:0 0 auto;overflow-x:auto}
.tab{display:inline-flex;align-items:center;gap:6px;height:36px;padding:0 12px;border:0;border-bottom:2px solid transparent;background:none;color:var(--fg2);cursor:pointer;white-space:nowrap;margin-bottom:-1px}
.tab:hover{color:var(--fg)}
.tab.on{color:var(--fg);border-bottom-color:var(--brand);font-weight:600}
.count{display:inline-flex;align-items:center;justify-content:center;min-width:18px;height:17px;padding:0 5px;border-radius:9px;background:var(--l2);color:var(--fg2);font-size:10.5px;font-weight:600}
.count.warn{background:color-mix(in srgb,var(--err) 16%,transparent);color:var(--err)}
.body{flex:1 1 auto;min-height:0;overflow:auto}
.pane{padding:16px 24px 24px;display:flex;flex-direction:column;gap:14px;max-width:920px}
.note{font-size:12px;color:var(--fg2);line-height:18px}
.chips{display:inline-flex;gap:6px;margin-left:4px;vertical-align:middle}
.empty{padding:28px 16px;text-align:center;color:var(--fg2);border:1px dashed var(--b1);border-radius:12px}
.list{border:1px solid var(--b1);border-radius:12px;background:var(--l1);overflow:hidden}
.row{display:flex;align-items:center;gap:12px;padding:10px 14px;min-height:56px}
.row+.row{border-top:1px solid var(--b1)}
.who{flex:0 0 210px;min-width:0}
.row.static .who{flex:0 1 auto;max-width:46%}
.what{flex:1 1 auto;min-width:0;color:var(--fg2);font-size:12px;line-height:18px}
.act{flex:0 0 auto}
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
.badge.warn{color:var(--warn);border-color:var(--warn)}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;height:30px;padding:0 12px;border:1px solid var(--b1);border-radius:8px;background:var(--l1);cursor:pointer;white-space:nowrap;font-size:12.5px;transition:background .12s ease,border-color .12s ease,color .12s ease}
.btn:hover{background:var(--l2);border-color:var(--b2)}
.btn[disabled]{opacity:.5;cursor:default}
.btn.sm{height:26px;padding:0 10px;font-size:12px}
.btn.primary{background:var(--brand);border-color:transparent;color:var(--bg)}
.btn.primary:hover{filter:brightness(1.08);background:var(--brand)}
.btn.ghost{background:transparent;border-color:transparent;color:var(--fg2)}
.btn.ghost.on{color:var(--brand);background:var(--l2)}
.btn.ghost:hover{background:var(--l2);color:var(--fg)}
.btn.danger{color:var(--err)}
.btn.ghost.danger:hover{color:var(--err);background:color-mix(in srgb,var(--err) 10%,transparent)}
.btn.icon{width:30px;padding:0}
.switch{position:relative;width:36px;height:20px;padding:0;border:1px solid var(--b2);border-radius:999px;background:var(--l2);cursor:pointer;flex:0 0 auto;transition:background .14s ease,border-color .14s ease}
.knob{position:absolute;top:2px;left:2px;width:14px;height:14px;border-radius:50%;background:var(--fg2);transition:transform .14s ease,background .14s ease}
.switch[aria-checked="true"]{background:var(--ok);border-color:var(--ok)}
.switch[aria-checked="true"] .knob{transform:translateX(16px);background:#fff}
.switch.neutral[aria-checked="true"]{background:var(--l2);border-color:var(--b2)}
.switch.neutral[aria-checked="true"] .knob{background:var(--fg)}
.toggle-label{font-size:12px;color:var(--fg2);opacity:.6}
.toggle-label.on{opacity:1;color:var(--fg)}
.num{width:84px;height:30px;padding:0 8px;text-align:center;border:1px solid var(--b1);border-radius:8px;background:var(--bg)}
.text{width:100%;height:32px;padding:0 10px;border:1px solid var(--b1);border-radius:8px;background:var(--bg)}
.num{-moz-appearance:textfield;appearance:textfield;font-variant-numeric:tabular-nums}
.num::-webkit-inner-spin-button,.num::-webkit-outer-spin-button{-webkit-appearance:none;margin:0}
.num::placeholder,.text::placeholder{color:var(--fg2);opacity:.7}
.num:focus,.text:focus{outline:none;border-color:var(--brand);box-shadow:0 0 0 3px color-mix(in srgb,var(--brand) 20%,transparent)}
.field{display:flex;flex-direction:column;gap:6px}
.field>span{font-size:12px;color:var(--fg2);display:flex;gap:8px;align-items:baseline;flex-wrap:wrap}
.pane.wide{max-width:none}
.host-table{border:1px solid var(--b1);border-radius:12px;background:var(--l1);overflow:hidden}
.host-cols{display:grid;grid-template-columns:28px minmax(110px,1fr) minmax(170px,1.1fr) minmax(0,1.3fr) auto;grid-template-areas:"grip name addr state act" ". meta meta meta meta";column-gap:12px;row-gap:8px;align-items:center;padding:10px 12px 12px 8px}
.host-header{display:none}
.hosts{position:relative}
.host{position:relative;background:var(--l1);border-top:1px solid var(--b1)}
.host:first-child{border-top:0}
.host-line{font-size:12.5px}
.host:hover .host-line{background:color-mix(in srgb,var(--l2) 45%,transparent)}
.host.is-hidden .host-name .name{color:var(--fg2)}
.host.is-hidden .c-addr,.host.is-hidden .c-key,.host.is-hidden .c-state{opacity:.6}
.grip{grid-area:grip}
.host-name{grid-area:name}
.c-addr{grid-area:addr}
.c-key{grid-area:key}
.c-hk{grid-area:hk}
.c-state{grid-area:state}
.c-vis{grid-area:vis}
.c-idle{grid-area:idle}
.c-remark{grid-area:remark}
.c-act{grid-area:act}
.host-meta{grid-area:meta;display:flex;flex-wrap:wrap;align-items:center;gap:8px 16px}
.host-meta .cell{display:flex;align-items:center;gap:8px}
.host-meta .c-key{flex:0 0 176px}
.host-meta .c-hk{flex:0 0 176px}
.host-meta .c-vis{flex:0 0 92px}
.host-meta .c-idle{flex:0 0 196px}
.host-meta .c-remark{flex:1 1 220px;min-width:180px}
.host-meta .c-remark .text{flex:1;width:auto;min-width:0}
.lbl{flex:0 0 auto;font-size:11.5px;color:var(--fg2)}
.cell{min-width:0}
.cell.ell{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.cell.inline{display:flex;align-items:center;gap:6px}
.cell .num{width:76px;height:28px}
.cell .text{height:28px;font-size:12px}
.host-name{display:flex;align-items:center;gap:8px;min-width:0}
.host-name .name{font-weight:600;font-size:13px}
.state-cell{display:flex;align-items:center;flex-wrap:wrap;gap:4px 8px;min-width:0}
.state-text{min-width:0;white-space:normal}
.hk.fail{color:var(--err);font-weight:600}
.hk.warnish{color:var(--warn)}
.chip{flex:0 0 auto;display:inline-flex;align-items:center;height:20px;padding:0 7px;border-radius:999px;border:1px solid transparent;font-size:11px;font-weight:600;cursor:pointer;background:none}
.chip.err{color:var(--err);border-color:color-mix(in srgb,var(--err) 45%,transparent);background:color-mix(in srgb,var(--err) 8%,transparent)}
.chip.err:hover{background:color-mix(in srgb,var(--err) 16%,transparent)}
.row-actions{display:grid;grid-template-columns:56px 44px 26px;gap:4px;justify-content:end;align-items:center}
.row-actions .btn{width:100%;padding:0}
.row-actions .slot{display:block}
.expand svg{transition:transform .16s ease}
.host.open .expand svg{transform:rotate(90deg)}
.mono{font:12px/18px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.grip{display:inline-flex;align-items:center;justify-content:center;width:24px;height:30px;padding:0;border:0;border-radius:6px;background:none;color:var(--fg2);cursor:grab;touch-action:none;opacity:.45}
.host:hover .grip,.grip:focus-visible{opacity:1}
.grip:hover{background:var(--l2);color:var(--fg)}
.grip:focus-visible{outline:2px solid var(--brand);outline-offset:1px}
.host-detail{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px 24px;padding:12px 16px 16px 48px;border-top:1px dashed var(--b1);background:color-mix(in srgb,var(--l2) 35%,transparent)}
.detail-block{display:flex;flex-direction:column;gap:6px;min-width:0}
.cmd-line{display:flex;align-items:center;gap:8px;min-width:0}
.cmd-inline{flex:1;min-width:0;padding:5px 8px;border-radius:7px;background:var(--l2);font:11.5px/16px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.hosts.sorting{user-select:none;cursor:grabbing}
.hosts.sorting .grip{cursor:grabbing}
.hosts.sorting .host{transition:transform .2s cubic-bezier(.2,.8,.2,1)}
.hosts.sorting .host.dragging{transition:none;z-index:3;box-shadow:0 10px 28px rgba(0,0,0,.18),0 0 0 1px var(--brand);border-radius:8px}
.hosts.sorting .host.dragging .host-line{background:var(--l1)}
.hosts .host.settling{transition:transform .16s cubic-bezier(.2,.8,.2,1);z-index:3}
.hosts.no-motion .host{transition:none!important}
.mosaic{display:inline-block;height:1.05em;min-width:4.5em;max-width:100%;vertical-align:-.18em;border-radius:4px;background-color:var(--mosaic-a);background-image:linear-gradient(45deg,var(--mosaic-b) 25%,transparent 25%,transparent 75%,var(--mosaic-b) 75%),linear-gradient(45deg,var(--mosaic-b) 25%,transparent 25%,transparent 75%,var(--mosaic-b) 75%);background-size:7px 7px;background-position:0 0,3.5px 3.5px;box-shadow:inset 0 0 0 1px color-mix(in srgb,var(--fg) 8%,transparent)}
.block-title{font-size:12px;font-weight:600;color:var(--fg2);display:flex;align-items:center;gap:6px}
.proc{display:flex;align-items:center;gap:8px;font-size:12.5px}
.proc .ell{flex:1}
.failure{font-size:12px;color:var(--err)}
.failure .msg{color:var(--fg2);margin-top:2px;overflow-wrap:anywhere}
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
@container (min-width:1320px){
  .host-cols{grid-template-columns:28px minmax(110px,1fr) 170px 100px 112px minmax(170px,1.4fr) 56px 116px minmax(120px,1.3fr) 140px;grid-template-areas:"grip name addr key hk state vis idle remark act";row-gap:0;padding:0 12px 0 8px}
  .host-header{display:grid;height:34px;font-size:11.5px;font-weight:500;color:var(--fg2);background:var(--l2);border-bottom:1px solid var(--b1);white-space:nowrap}
  .host-line{min-height:52px}
  .host-meta{display:contents}
  .host-meta .cell{display:block}
  .host-meta .cell.inline{display:flex;gap:6px}
  .host-meta .c-remark{min-width:0}
  .host-meta .c-remark .text{width:100%}
  .host-header>:nth-child(2){padding-left:17px}
  .lbl{display:none}
  .state-cell{flex-wrap:nowrap}
  .state-text{white-space:nowrap}
}
@container (max-width:760px){
  .host-cols{grid-template-columns:28px minmax(0,1fr) auto;grid-template-areas:"grip name act" ". addr addr" ". state state" ". meta meta";padding:10px 10px 12px 6px}
  .host-detail{padding-left:44px}
  .host-meta{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px 12px}
  .host-meta>.cell{grid-area:auto}
  .host-meta>.c-remark{grid-column:1/-1}
}
@container (max-width:720px){
  .who{flex-basis:150px}
  .row.static .who{max-width:64%}
  .top{padding:12px 16px 8px}.tabs{padding:0 12px}.pane{padding:14px 16px 20px}
  .actions .label{display:none}.actions .btn{width:30px;padding:0}
}
@container (max-width:400px){
  .host-meta{grid-template-columns:minmax(0,1fr)}
  .host-meta .lbl{flex:0 0 64px}
}
@container (max-width:520px){
  .row{flex-wrap:wrap}.what{flex-basis:100%;order:3;padding-left:21px}.who{flex:1 1 auto}
}
`;

const POLL_MS = 4000;

class SshHelperPanel extends HTMLElement {
  static get observedAttributes() {
    return ['api-base', 'mode'];
  }

  constructor() {
    super();
    this.attachShadow({ mode: 'open' });
    this.state = null;
    this.tab = 'hosts';
    this.error = null;
    this.notice = null;
    this.busy = false;
    this.dialog = null;
    this.failures = 0;
    this.timer = undefined;
    this.credential = undefined;
    /** The row being dragged (see `startDrag`), or null. */
    this.drag = null;
    /** Aliases whose detail strip is open. */
    this.expanded = new Set();
    /** The alias whose drag handle gets focus back after the next redraw. */
    this.focusHandle = null;
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
    for (const element of this.shadowRoot.querySelectorAll('[data-action],[data-refresh],[data-mask]')) element.toggleAttribute('disabled', value);
  }

  // ── rendering ───────────────────────────────────────────────────────────

  /** Never redraw under the cursor: a poll would eat a half-typed remark. */
  editing() {
    const active = this.shadowRoot.activeElement;
    return active !== null && (active.tagName === 'INPUT' || active.tagName === 'TEXTAREA' || active.tagName === 'SELECT');
  }

  render(force = false) {
    // While the edit dialog is open, only its own transitions redraw: a poll
    // or the focusout catch-up would rebuild the form between the Save
    // button's mousedown and mouseup, dropping both the click and the typed
    // names.
    // A drag moves cards in the DOM itself; a redraw mid-drag would undo it.
    if (!force && (this.editing() || this.dialog || this.drag)) return;
    const options = { mode: this.mode, expanded: [...(this.expanded ?? [])] };
    if (!tabsFor(this.mode).includes(this.tab)) this.tab = 'hosts';
    const bodyScroll = this.shadowRoot.querySelector('.body')?.scrollTop ?? 0;
    // A redraw replaces every node: keep a focused drag handle focused, so a
    // poll never yanks keyboard reordering out from under the user.
    const active = this.shadowRoot.activeElement;
    const focusAlias = this.focusHandle ?? (typeof active?.matches === 'function' && active.matches('[data-drag-handle]') ? active.dataset.alias : null);
    this.focusHandle = null;
    this.frame.innerHTML = [
      renderHeader({ mode: this.mode, busy: this.busy, masked: this.state?.settings?.maskAddresses === true }),
      renderTabs({ mode: this.mode, tab: this.tab, state: this.state }),
      renderBanners({ error: this.error, notice: this.notice }),
      `<div class="body">${this.state === null ? `<div class="loading">${this.error ? '' : TEXT.loading}</div>` : renderTab(this.tab, this.state, options)}</div>`,
      renderFooter(this.state, { mode: this.mode }),
      this.dialog ? renderEditDialog(this.dialog.host, { ...this.dialog, masked: this.state?.settings?.maskAddresses === true }) : ''
    ].join('');
    const body = this.shadowRoot.querySelector('.body');
    if (body) body.scrollTop = bodyScroll;
    if (focusAlias !== null) [...this.shadowRoot.querySelectorAll('[data-drag-handle]')].find((handle) => handle.dataset.alias === focusAlias)?.focus();
  }

  // ── row order ───────────────────────────────────────────────────────────

  /**
   * Save a new row order: reorder the local state at once (so the next redraw
   * already shows it), then persist it; the answer is the stored state.
   */
  saveOrder(order) {
    const hosts = this.state?.hosts ?? [];
    if (this.state && hosts.length > 0) {
      const rank = new Map(order.map((alias, index) => [alias, index]));
      this.state = { ...this.state, hosts: [...hosts].sort((a, b) => (rank.get(a.alias) ?? Infinity) - (rank.get(b.alias) ?? Infinity)) };
    }
    this.render(true);
    return this.post('order', { order });
  }

  /**
   * Pointer drag on a row's handle (mouse, pen and touch alike). The dragged
   * row follows the pointer; the rows it passes slide out of the way (CSS
   * transitions on `transform`); on release it glides into its slot and only
   * then is the DOM reordered and the order saved. Row geometry is measured
   * once at the start, so moving never forces a layout.
   */
  startDrag(event, handle) {
    const row = handle.closest('.host');
    const list = row?.parentElement;
    const body = this.shadowRoot.querySelector('.body');
    if (!row || !list || !body || event.button !== 0 || this.drag) return;
    event.preventDefault();
    try {
      handle.setPointerCapture?.(event.pointerId);
    } catch {
      /* drag without capture */
    }
    const rows = [...list.children].filter((child) => child.classList.contains('host'));
    const boxes = rows.map((child) => {
      const box = child.getBoundingClientRect();
      return { top: box.top, height: box.height };
    });
    const from = rows.indexOf(row);
    this.drag = { row, list, body, rows, boxes, from, index: from, pointerId: event.pointerId, startY: event.clientY, y: event.clientY, scroll0: body.scrollTop, scrolling: false, settling: false };
    list.classList.add('sorting');
    row.classList.add('dragging');
  }

  moveDrag(event) {
    const drag = this.drag;
    if (!drag || drag.settling || event.pointerId !== drag.pointerId) return;
    drag.y = event.clientY;
    this.layoutDrag();
    this.autoScroll();
  }

  /** Place the dragged row under the pointer and slide the rows it has passed. */
  layoutDrag() {
    const drag = this.drag;
    if (!drag) return;
    const first = drag.boxes[0];
    const last = drag.boxes.at(-1);
    const own = drag.boxes[drag.from];
    const raw = drag.y - drag.startY + (drag.body.scrollTop - drag.scroll0);
    // Keep the row inside the table.
    const dy = Math.max(first.top - own.top, Math.min(last.top + last.height - own.top - own.height, raw));
    drag.row.style.transform = `translate3d(0, ${dy}px, 0)`;
    const { index, shifts } = sortTarget(drag.boxes, drag.from, dy);
    drag.rows.forEach((row, i) => {
      if (i !== drag.from) row.style.transform = shifts[i] ? `translate3d(0, ${shifts[i]}px, 0)` : '';
    });
    drag.index = index;
  }

  /**
   * Near the top or bottom edge of the scroll area the list scrolls by itself
   * (and keeps scrolling while the pointer rests there), so a row can be
   * dragged past what is on screen.
   */
  autoScroll() {
    const drag = this.drag;
    if (!drag || drag.scrolling) return;
    const step = () => {
      const current = this.drag;
      if (current !== drag || current.settling) return;
      const box = current.body.getBoundingClientRect();
      const edge = 56;
      const speed = current.y < box.top + edge ? -Math.ceil((box.top + edge - current.y) / 3) : current.y > box.bottom - edge ? Math.ceil((current.y - box.bottom + edge) / 3) : 0;
      const atEnd = speed < 0 ? current.body.scrollTop <= 0 : current.body.scrollTop + current.body.clientHeight >= current.body.scrollHeight;
      if (speed === 0 || atEnd) {
        current.scrolling = false;
        return;
      }
      current.body.scrollTop += speed;
      this.layoutDrag();
      setTimeout(step, 16);
    };
    drag.scrolling = true;
    setTimeout(step, 16);
  }

  /**
   * Release (or cancel): glide the row into its slot, then reorder the DOM and
   * clear every transform in one frame with transitions off, so nothing jumps.
   */
  endDrag(event, { cancel = false } = {}) {
    const drag = this.drag;
    if (!drag || drag.settling || (event && event.pointerId !== drag.pointerId)) return;
    const target = cancel || event?.type === 'pointercancel' ? drag.from : drag.index;
    drag.settling = true;
    const { boxes, from } = drag;
    const offset = target > from ? boxes[target].top + boxes[target].height - boxes[from].top - boxes[from].height : target < from ? boxes[target].top - boxes[from].top : 0;
    drag.row.classList.remove('dragging');
    drag.row.classList.add('settling');
    drag.row.style.transform = offset === 0 ? '' : `translate3d(0, ${offset}px, 0)`;
    if (target === from) for (const row of drag.rows) if (row !== drag.row) row.style.transform = '';
    const finish = () => {
      if (this.drag !== drag) return;
      drag.list.classList.add('no-motion');
      for (const row of drag.rows) row.style.transform = '';
      drag.row.classList.remove('settling');
      drag.list.classList.remove('sorting');
      if (target !== from) {
        const anchor = drag.rows[target];
        drag.list.insertBefore(drag.row, target > from ? anchor.nextSibling : anchor);
      }
      void drag.list.offsetHeight;
      drag.list.classList.remove('no-motion');
      this.drag = null;
      const order = [...drag.list.children].filter((child) => child.classList.contains('host')).map((child) => child.dataset.alias);
      if (target !== from) void this.saveOrder(order);
      else this.render(true);
    };
    setTimeout(finish, 170);
  }

  // ── interaction ─────────────────────────────────────────────────────────

  hostByAlias(alias) {
    return (this.state?.hosts ?? []).find((host) => host.alias === alias);
  }

  wire() {
    const root = this.shadowRoot;
    root.addEventListener('click', (event) => {
      const target = event.target instanceof Element ? event.target : null;
      if (target === null) return;
      const button = target.closest('button');
      if (button === null || button.hasAttribute('disabled')) return;
      const d = button.dataset;
      if (d.tab !== undefined) {
        this.tab = d.tab;
        this.render(true);
      } else if (d.refresh !== undefined) void this.load(false);
      else if (d.closeAll !== undefined) {
        if (window.confirm(TEXT.confirmCloseAll)) void this.post('action', { action: 'close_all' });
      } else if (d.mask !== undefined) {
        void this.post('settings', { maskAddresses: this.state?.settings?.maskAddresses !== true });
      } else if (d.action !== undefined) {
        event.stopPropagation();
        const body = { action: d.action, ...(d.alias ? { alias: d.alias } : {}), ...(d.pid ? { pid: Number(d.pid) } : {}) };
        void this.post('action', body);
      } else if (d.toggle !== undefined) {
        const host = this.hostByAlias(d.alias);
        if (host) void this.post('meta', { alias: d.alias, [d.field]: !(host[d.field] === true) }).then(() => this.mode === 'mcp' && setTimeout(() => this.load(true), 1500));
      } else if (d.settingToggle !== undefined) {
        void this.post('settings', { [d.settingToggle]: !(this.state?.settings?.[d.settingToggle] === true || (d.settingToggle === 'sshVisible' && this.state?.settings?.sshVisible !== false)) });
      } else if (d.expand !== undefined) {
        if (this.expanded.has(d.expand)) this.expanded.delete(d.expand);
        else this.expanded.add(d.expand);
        this.render(true);
      } else if (d.edit !== undefined) {
        const host = this.hostByAlias(d.edit);
        if (host) this.openDialog(host);
      } else if (d.dialogCancel !== undefined) this.closeDialog();
    });
    root.addEventListener('pointerdown', (event) => {
      const handle = event.target instanceof Element ? event.target.closest('[data-drag-handle]') : null;
      if (handle) this.startDrag(event, handle);
    });
    root.addEventListener('pointermove', (event) => this.moveDrag(event));
    root.addEventListener('pointerup', (event) => this.endDrag(event));
    root.addEventListener('pointercancel', (event) => this.endDrag(event));
    root.addEventListener('lostpointercapture', (event) => this.endDrag(event, { cancel: true }));
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
        if (this.drag) this.endDrag(null, { cancel: true });
        else if (this.dialog && !this.dialog.saving) this.closeDialog();
        return;
      }
      // A focused drag handle moves its card with the arrow keys.
      const handle = target instanceof Element ? target.closest('[data-drag-handle]') : null;
      if (handle && !this.drag) {
        const delta = { ArrowUp: -1, ArrowLeft: -1, ArrowDown: 1, ArrowRight: 1, Home: -Infinity, End: Infinity }[event.key];
        if (delta === undefined) return;
        event.preventDefault();
        const aliases = (this.state?.hosts ?? []).map((host) => host.alias);
        const order = moveAlias(aliases, handle.dataset.alias, Number.isFinite(delta) ? delta : delta < 0 ? -aliases.length : aliases.length);
        if (order.join('\n') === aliases.join('\n')) return;
        this.focusHandle = handle.dataset.alias;
        void this.saveOrder(order);
        return;
      }
      if (event.key === 'Enter' && target instanceof HTMLInputElement && target.form === null) target.blur();
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
    this.dialog = { ...this.dialog, saving: true, error: null, draft: { alias: newAlias, keyName } };
    this.render(true);
    try {
      await this.call('edit-host', body, { retry: false });
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
