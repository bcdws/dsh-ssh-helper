/**
 * Packaging smoke test: what a client actually installs.
 *
 * `npm pack` → install the tarball into an empty directory → start the MCP
 * server with a temp ssh config (TEST-NET only, nothing connects) → require a
 * real `initialize` answer within a few seconds.
 *
 * This is the guarantee `npx -y github:bcdws/dsh-ssh-helper` relies on: one
 * package, no dependencies, no lifecycle scripts, an `initialize` answer well
 * inside the short budget desktop clients give a command server (about 30 s).
 *
 *   node scripts/pack-smoke.mjs
 */
import { execFileSync, spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
// `npm` is a shell script on POSIX and npm.cmd on Windows, which needs a shell.
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const npmShell = process.platform === 'win32' ? { shell: true } : {};
const started = Date.now();
const work = mkdtempSync(join(tmpdir(), 'dsh-pack-smoke-'));

/** Fail loudly with the reason, after cleaning up. */
function fail(message) {
  console.error(`✗ ${message}`);
  rmSync(work, { recursive: true, force: true });
  process.exit(1);
}

try {
  const packed = JSON.parse(execFileSync(npm, ['pack', '--json', '--pack-destination', work], { cwd: root, encoding: 'utf8', ...npmShell }))[0];
  const tarball = join(work, packed.filename);
  const files = packed.files.map((entry) => entry.path);
  if (!files.includes('vendor/ssh2.cjs')) fail('the tarball must ship vendor/ssh2.cjs');

  writeFileSync(join(work, 'package.json'), JSON.stringify({ name: 'pack-smoke', private: true }));
  execFileSync(npm, ['install', tarball, '--no-audit', '--no-fund', '--offline'], { cwd: work, stdio: 'pipe', ...npmShell });
  const installed = join(work, 'node_modules', 'dsh-ssh-helper');
  const manifest = JSON.parse(readFileSync(join(installed, 'package.json'), 'utf8'));
  if (Object.keys(manifest.dependencies ?? {}).length > 0) fail(`installed with runtime dependencies: ${JSON.stringify(manifest.dependencies)}`);
  const nested = join(installed, 'node_modules');
  if (existsSync(nested) && readdirSync(nested).length > 0) fail('installed package brought its own node_modules');

  const sshConfig = join(work, 'ssh_config');
  writeFileSync(sshConfig, ['Host probe', '  HostName 192.0.2.10', '  User root', ''].join('\n'));
  const bin = join(installed, 'bin', 'dsh-ssh-mcp.js');
  const child = spawn(process.execPath, [bin, '--ssh-config', sshConfig, '--quiet'], { stdio: ['pipe', 'pipe', 'pipe'] });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (chunk) => (stdout += chunk));
  child.stderr.on('data', (chunk) => (stderr += chunk));
  child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'pack-smoke', version: '0' } } })}\n`);
  child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' })}\n`);

  const deadline = Date.now() + 15_000;
  const answers = new Map();
  while (Date.now() < deadline && !(answers.has(1) && answers.has(2))) {
    await new Promise((resolve) => setTimeout(resolve, 50));
    for (const line of stdout.split('\n')) {
      if (!line.trim()) continue;
      const message = JSON.parse(line);
      if (message.id === 1 || message.id === 2) answers.set(message.id, message);
    }
  }
  child.kill();
  rmSync(work, { recursive: true, force: true });

  if (!answers.has(1) || !answers.has(2)) fail(`no initialize/tools answer within 15s${stderr ? `: ${stderr.slice(-300)}` : ''}`);
  const tools = answers.get(2).result?.tools ?? [];
  if (tools.length !== 8) fail(`tools/list returned ${tools.length} tools, expected 8`);
  if (answers.get(1).result?.serverInfo?.name !== 'dsh-ssh-helper') fail('initialize answer carries no serverInfo');

  console.log(`✓ packed ${(packed.size / 1024).toFixed(0)} KB, installed 1 package, initialize answered in ${Date.now() - started} ms`);
} catch (error) {
  fail(error instanceof Error ? error.message : String(error));
}
