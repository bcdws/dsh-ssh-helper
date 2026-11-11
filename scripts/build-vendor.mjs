/**
 * Bundle ssh2 into `vendor/ssh2.cjs`, a single CommonJS file with no
 * dependencies and no install script.
 *
 * Why: `npx -y github:bcdws/dsh-ssh-helper` installs straight from git. A plain
 * `dependencies: { ssh2 }` makes npm fetch 7 packages and run ssh2's
 * `node-gyp rebuild` postinstall, which needs a compiler (or at least `node` on
 * the PATH of npm's script shell — often missing when a desktop app such as
 * magpie launches npx). The MCP client's `initialize` budget is short (magpie:
 * 30 s for a command server), so a slow or failing install reads as
 * "initialize 无响应".
 *
 * A vendored bundle keeps the installed package at zero dependencies: npx
 * unpacks one tarball, runs no lifecycle scripts, and the server starts at once
 * on every platform.
 *
 * ssh2 is MIT; its licence text is copied to vendor/ssh2.LICENSE by this script.
 * Regenerate with `npm run build:vendor` after bumping the ssh2 devDependency.
 */
import { copyFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const root = fileURLToPath(new URL('..', import.meta.url));
const ssh2Dir = fileURLToPath(new URL('../node_modules/ssh2/', import.meta.url));
const pkg = JSON.parse(
  (await import('node:fs')).readFileSync(new URL('package.json', `file://${ssh2Dir}`), 'utf8')
);

mkdirSync(new URL('../vendor/', import.meta.url), { recursive: true });

await build({
  // The entry is a CommonJS require so the bundle exports ssh2's real
  // `module.exports`, the same object `require('ssh2')` gives.
  stdin: {
    contents: "module.exports = require('ssh2');",
    resolveDir: root,
    sourcefile: 'ssh2-entry.cjs',
    loader: 'js',
  },
  bundle: true,
  platform: 'node',
  format: 'cjs',
  target: 'node18',
  outfile: 'vendor/ssh2.cjs',
  // Both are optional native accelerators: ssh2 already wraps them in
  // try/catch and falls back to its pure-JS path.
  external: ['cpu-features', '*.node'],
  legalComments: 'none',
  banner: {
    js: [
      `/* ssh2 v${pkg.version} — MIT — bundled for dsh-ssh-helper.`,
      ' * Source: https://github.com/mscdex/ssh2',
      ' * Do not edit: regenerate with `npm run build:vendor`. */',
    ].join('\n'),
  },
  logLevel: 'info',
});

copyFileSync(new URL('LICENSE', `file://${ssh2Dir}`), new URL('../vendor/ssh2.LICENSE', import.meta.url));
