/**
 * Client half of the SSH assistant in DSH.
 *
 * The UI itself is the shared `<ssh-helper-panel>` custom element
 * (`ui/panel-element.js`), the same one the MCP management page uses; the Host
 * half serves it under `/ssh-pool/ui/` and preloads it from the boot page. This
 * file only places it in DSH's chrome:
 *
 * - the sidebar row (icon only; the row selects the `main` panel whose key is
 *   this entry's id),
 * - the docked `main` panel.
 *
 * DSH's theme variables (`--dsw-alias-*`) pierce the element's shadow root, so
 * the panel follows the host theme without any bridging.
 */
window.__ModuleLoader__.load({
  id: 'dsh-ssh-helper',
  factory(require) {
    const React = require('react');
    const h = React.createElement;

    const TITLE = 'SSH 助手';
    const ELEMENT = 'ssh-helper-panel';
    const ELEMENT_URL = '/ssh-pool/ui/panel-element.js';
    const LOAD_FAILED = '加载 SSH 助手界面失败';

    /** The layout service, captured so the entry can select its own panel. */
    let layoutService;

    /**
     * The element is normally defined already (the boot page loads it); when
     * the injection did not run, load the same module on demand.
     */
    let loading = null;
    const ensureElement = () => {
      if (globalThis.customElements?.get(ELEMENT)) return Promise.resolve();
      loading ??= import(ELEMENT_URL).then(() => customElements.whenDefined(ELEMENT));
      return loading;
    };

    /**
     * Mount one `<ssh-helper-panel>` into a host div. React never renders the
     * element's children, so its own DOM is left alone across re-renders.
     */
    function PanelMount() {
      const hostRef = React.useRef(null);
      const [failure, setFailure] = React.useState(null);
      React.useEffect(() => {
        const host = hostRef.current;
        if (host === null) return undefined;
        let element = null;
        let cancelled = false;
        ensureElement()
          .then(() => {
            if (cancelled) return;
            element = document.createElement(ELEMENT);
            element.setAttribute('api-base', '/ssh-pool');
            element.setAttribute('mode', 'dsh');
            element.token = globalThis.__DSH_SSH_ASSISTANT__?.token;
            host.appendChild(element);
          })
          .catch((error) => {
            if (!cancelled) setFailure(error instanceof Error ? error.message : String(error));
          });
        return () => {
          cancelled = true;
          if (element !== null) element.remove();
        };
      }, []);
      return h(
        'div',
        { className: 'ssh-mount', ref: hostRef, style: { display: 'flex', flexDirection: 'column', flex: '1 1 auto', height: '100%', minHeight: 0 } },
        failure === null ? null : h('div', { className: 'ssh-load-error', style: { padding: '24px', color: 'var(--dsw-alias-state-error-primary)' } }, `${LOAD_FAILED}：${failure}`)
      );
    }

    /** The docked panel the sidebar row selects. */
    function SshAssistantPanel() {
      return h(PanelMount, {});
    }

    const panelIcon = h(
      'svg',
      { viewBox: '0 0 24 24', width: 16, height: 16, 'aria-hidden': true, fill: 'none', stroke: 'currentColor', strokeWidth: 1.7, strokeLinecap: 'round' },
      h('rect', { x: 3, y: 4, width: 18, height: 13, rx: 2 }),
      h('path', { d: 'M8 20h8M12 17v3' }),
      h('path', { d: 'M7 9.5l2 1.5-2 1.5M12.5 12.5h3.5' })
    );

    /** The sidebar entry: the icon only, because the host row owns the chrome. */
    function SshAssistantIcon() {
      const activate = () => {
        if (typeof layoutService?.selectPanel === 'function') layoutService.selectPanel('ssh-assistant');
      };
      return h(
        'span',
        {
          className: 'ssh-icon',
          role: 'button',
          tabIndex: 0,
          'aria-label': TITLE,
          style: { display: 'flex', alignItems: 'center', justifyContent: 'center', width: '100%', height: '100%', color: 'inherit' },
          onClick: activate,
          onKeyDown: (event) => {
            if (event.key === 'Enter' || event.key === ' ') {
              event.preventDefault();
              activate();
            }
          }
        },
        panelIcon
      );
    }

    return {
      inject: ['slots'],
      apply(ctx) {
        layoutService = ctx.get('layout');
        const label = () => TITLE;
        // The sidebar row selects the `main` panel whose key is this entry id.
        ctx.slots.inject('sidebar.panellist', () => ctx.slots.register({ name: 'sidebar.panellist', id: 'ssh-assistant', order: 60, label }, SshAssistantIcon));
        ctx.slots.inject('main', () => ctx.slots.register({ name: 'main', key: 'ssh-assistant' }, SshAssistantPanel));
      }
    };
  }
});
