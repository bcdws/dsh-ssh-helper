#!/usr/bin/env node
/**
 * dsh-ssh-mcp — the SSH pool as a stdio MCP server, for any MCP client
 * (Claude Code, Codex, Cursor, ...). No DSH needed.
 *
 *   dsh-ssh-mcp [--config <file.json>] [--ssh-config <path>] [--state <path>] [--quiet]
 *   dsh-ssh-mcp panel [--port <n>] [--open] [--config <file.json>] [--ssh-config <path>]
 */
import { readFileSync } from 'node:fs';
import { createStandaloneRuntime, PACKAGE, stderrLogger } from '../mcp/runtime.js';
import { serveStdio } from '../mcp/stdio.js';
import { servePanel } from '../mcp/panel.js';
import { spawn } from 'node:child_process';

/** Best effort: hand the URL to the desktop's opener. */
function openBrowser(url, logger) {
  // Inside WSL there is usually no Linux browser; hand the URL to Windows,
  // which reaches the WSL loopback through localhost forwarding / mirroring.
  const inWsl = process.platform === 'linux' && typeof process.env.WSL_DISTRO_NAME === 'string';
  const [command, args] =
    process.platform === 'win32' || inWsl
      ? ['cmd.exe', ['/c', 'start', '', url]]
      : process.platform === 'darwin'
        ? ['open', [url]]
        : ['xdg-open', [url]];
  try {
    const child = spawn(command, args, { stdio: 'ignore', detached: true });
    child.on('error', () => logger.warn?.(`cannot open a browser; visit ${url}`));
    child.unref();
  } catch {
    logger.warn?.(`cannot open a browser; visit ${url}`);
  }
}

const USAGE = `dsh-ssh-mcp ${PACKAGE.version} — SSH connection pool as a stdio MCP server

Usage: dsh-ssh-mcp [options]          run the stdio MCP server
       dsh-ssh-mcp panel [options]    serve the management page on 127.0.0.1

Options:
  --config <file>      JSON file with plugin config keys (hosts, exclude,
                       hostKeyPolicy, maxOutputBytes, ...). Env: DSH_SSH_MCP_CONFIG
  --ssh-config <path>  OpenSSH config to read (default ~/.ssh/config)
  --state <path>       Follow another panel state file read-only (hidden
                       hosts, output limit), e.g. ~/.dsh/ssh-pool/state.json.
                       Default: the MCP panel's own ~/.dsh-ssh-mcp/state.json
  --no-control         Do not open the loopback control port the panel uses
  --quiet              Only log warnings and errors (stderr)
  -h, --help           Show this help
  -v, --version        Show the version

Panel options:
  --port <n>           Loopback port (default 7318; when it is busy the next
                       free one is used, or a running panel is reused)
  --open               Open the page in the default browser
  --config, --ssh-config, --quiet as above
`;

function parseArgs(input) {
  let argv = input;
  const options = { config: process.env.DSH_SSH_MCP_CONFIG, sshConfig: undefined, state: undefined, quiet: false, control: true, panel: false, port: undefined, open: false };
  if (argv[0] === 'panel') {
    options.panel = true;
    argv = argv.slice(1);
  }
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    const value = () => {
      const next = argv[index + 1];
      if (next === undefined || next.startsWith('--')) throw new Error(`${arg} needs a value`);
      index += 1;
      return next;
    };
    if (arg === '-h' || arg === '--help') options.help = true;
    else if (arg === '-v' || arg === '--version') options.version = true;
    else if (arg === '--config') options.config = value();
    else if (arg === '--ssh-config') options.sshConfig = value();
    else if (arg === '--state' && !options.panel) options.state = value();
    else if (arg === '--quiet') options.quiet = true;
    else if (arg === '--no-control' && !options.panel) options.control = false;
    else if (arg === '--port' && options.panel) {
      const port = Number(value());
      if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('--port must be 0-65535');
      options.port = port;
    } else if (arg === '--open' && options.panel) options.open = true;
    else throw new Error(`unknown option ${arg}`);
  }
  return options;
}

let options;
try {
  options = parseArgs(process.argv.slice(2));
} catch (error) {
  process.stderr.write(`${error.message}\n\n${USAGE}`);
  process.exit(2);
}
if (options.help) {
  process.stdout.write(USAGE);
  process.exit(0);
}
if (options.version) {
  process.stdout.write(`${PACKAGE.version}\n`);
  process.exit(0);
}

let config = {};
if (options.config) {
  try {
    config = JSON.parse(readFileSync(options.config, 'utf8'));
  } catch (error) {
    process.stderr.write(`cannot read --config ${options.config}: ${error.message}\n`);
    process.exit(2);
  }
}
if (options.sshConfig !== undefined) config.sshConfigPath = options.sshConfig;
if (options.state !== undefined) config.statePath = options.state;

const logger = stderrLogger({ quiet: options.quiet });

if (options.panel) {
  let served;
  try {
    served = await servePanel({ port: options.port, config, logger });
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(1);
  }
  for (const { port, holder } of served.skipped) {
    logger.warn?.(`port ${port} is taken by ${holder === 'other' ? 'another program' : `a different ${holder}`}; skipped`);
  }
  if (served.existing) {
    process.stdout.write(`dsh-ssh-mcp panel: already running at ${served.url}\n`);
    if (options.open) openBrowser(served.url, logger);
    process.exit(0);
  }
  process.stdout.write(`dsh-ssh-mcp panel: ${served.url}\n`);
  if (options.open) openBrowser(served.url, logger);
  const stop = () => {
    served.server.close();
    served.panel.dispose();
    process.exit(0);
  };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
} else {
  const runtime = createStandaloneRuntime({ config, logger });
  const { done } = serveStdio({ createSession: runtime.createSession });
  // After the transport is up, so the port never delays `initialize`.
  if (options.control) setImmediate(() => void runtime.startControl());
  // `autoConnect` hosts (from --config) connect in the background, also after
  // the transport is up so `initialize` is never delayed by a handshake.
  setImmediate(() => runtime.prewarm());

  let exiting = false;
  const shutdown = (code) => {
    if (exiting) return;
    exiting = true;
    try {
      runtime.dispose();
    } finally {
      process.exit(code);
    }
  };
  process.on('SIGINT', () => shutdown(130));
  process.on('SIGTERM', () => shutdown(143));
  done.then(() => shutdown(0));
}
