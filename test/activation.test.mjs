/**
 * Activation behaviour: late web server, page token, command guard, and the
 * SSH visibility switch (which registers or unregisters the tools).
 *
 * Every case points the store at a temp file, so the test never reads or
 * writes the machine's real assistant state.
 */
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { apply } from '../index.js';

const dir = mkdtempSync(join(tmpdir(), 'dsh-inject-'));
const visiblePath = join(dir, 'visible.json');
const hiddenPath = join(dir, 'hidden.json');
writeFileSync(hiddenPath, JSON.stringify({ hosts: {}, settings: { sshVisible: false } }));

let pass = 0;
const failures = [];
const check = (name, ok, detail) => (ok ? (pass += 1) : failures.push(`${name}: ${detail}`));

/** A minimal Host context double. */
function makeContext(plan = { active: false, pending: false }) {
  const tools = [];
  const guards = [];
  const routes = [];
  const taps = [];
  const injections = new Map();
  const ctx = {
    logger: { info: () => {}, warn: () => {} },
    get: (name) => (name === 'planMode' ? { get: () => plan } : undefined),
    tools: {
      register: (tool) => {
        tools.push(tool.name);
        return () => {
          const at = tools.indexOf(tool.name);
          if (at >= 0) tools.splice(at, 1);
        };
      },
      guard: (fn) => {
        guards.push(fn);
        return () => {};
      }
    },
    effect: (callback) => {
      callback();
      return () => {};
    },
    inject: (deps, callback) => {
      for (const dep of deps) injections.set(dep, callback);
      return () => {};
    }
  };
  const provideWebServer = () => {
    injections.get('webServer')({
      ...ctx,
      webServer: {
        register: (route) => {
          routes.push(route);
          return () => {};
        },
        tapIndex: (transform) => {
          taps.push(transform);
          return () => {};
        }
      }
    });
  };
  return { ctx, tools, guards, routes, taps, injections, provideWebServer };
}

// 1. Visibility on (no state file): tools, guard, route and token are mounted.
const visible = makeContext();
apply(visible.ctx, { useSshConfig: true, statePath: visiblePath });
check('tools-registered', visible.tools.length === 8, JSON.stringify(visible.tools));
check('guard-registered', visible.guards.length === 1, `${visible.guards.length} guards`);
check('no-route-before-service', visible.routes.length === 0 && visible.injections.has('webServer'), `routes=${visible.routes.length}`);
visible.provideWebServer();
check('route-mounted', visible.routes.length === 1 && visible.routes[0].kind === 'prefix' && visible.routes[0].path === '/ssh-pool', JSON.stringify(visible.routes.map((route) => route.path)));
check('tap-mounted', visible.taps.length === 1, `${visible.taps.length} taps`);
const html = visible.taps[0]('<html><head><title>t</title></head><body></body></html>');
const tokenMatch = /__DSH_SSH_ASSISTANT__=\{"token":"([0-9a-f]{48})"\}/.exec(html);
check('page-token-injected', tokenMatch !== null && html.indexOf(tokenMatch[0]) < html.indexOf('</head>'), html.slice(0, 160));
check('route-handler-callable', typeof visible.routes[0].handler === 'function', typeof visible.routes[0].handler);

// 2. The guard denies a dangerous command anywhere and allows a bounded read.
const deny = visible.guards[0]({ name: 'ssh_run', arguments: { host: 'web-host', command: 'rm -rf /' } });
check('guard-denies-danger', typeof deny === 'string' && deny.includes('danger.rm-root'), String(deny));
const allow = visible.guards[0]({ name: 'ssh_run', arguments: { host: 'web-host', command: 'tail -n 20 /var/log/messages' } });
check('guard-allows-bounded', allow === undefined, String(allow));
check('guard-ignores-non-ssh-bash', visible.guards[0]({ name: 'bash', arguments: { command: 'rm -rf /tmp/x' } }) === undefined, 'guard leaked to local non-ssh bash');
const localDeny = visible.guards[0]({ name: 'bash', arguments: { command: 'ssh -i ~/.ssh/key root@host "rm -rf /data/x"' } });
check('guard-denies-local-ssh-delete', typeof localDeny === 'string' && localDeny.includes('本地 bash'), String(localDeny));
const localRead = visible.guards[0]({ name: 'bash', arguments: { command: 'ssh -i ~/.ssh/key root@host "ls -la /data"' } });
check('guard-allows-local-ssh-read', localRead === undefined, String(localRead));

// 2b. Plan mode is an explicit guard input: no delete-like ssh_run, reads allowed.
const planned = makeContext({ active: true, pending: false });
apply(planned.ctx, { useSshConfig: true, statePath: join(dir, 'planned.json') });
const planDeny = planned.guards[0]({ name: 'ssh_run', agent: {}, arguments: { host: 'web-host', command: 'rm -rf /data/x' } });
check('guard-denies-plan-delete', typeof planDeny === 'string' && planDeny.includes('计划模式'), String(planDeny));
const planRead = planned.guards[0]({ name: 'ssh_run', agent: {}, arguments: { host: 'web-host', command: 'tail -n 20 /var/log/messages' } });
check('guard-allows-plan-read', planRead === undefined, String(planRead));

// 3. Visibility off: the tools are not registered at all, so no session can
//    even see them; the panel's API still mounts.
const hidden = makeContext();
apply(hidden.ctx, { useSshConfig: true, statePath: hiddenPath });
check('hidden-registers-no-tools', hidden.tools.length === 0, JSON.stringify(hidden.tools));
hidden.provideWebServer();
check('hidden-still-serves-panel', hidden.routes.length === 1, `${hidden.routes.length} routes`);

rmSync(dir, { recursive: true, force: true });
console.log(`${pass}/${pass + failures.length} passed`);
for (const failure of failures) console.log(`FAIL ${failure}`);
process.exit(failures.length === 0 ? 0 : 2);
