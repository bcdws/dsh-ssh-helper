#!/usr/bin/env node
/**
 * dsh-ssh-mcp — the SSH pool as a stdio MCP server, for any MCP client
 * (Claude Code, Codex, Cursor, ...). No DSH needed.
 *
 *   dsh-ssh-mcp [--config <file.json>] [--ssh-config <path>] [--state <path>] [--quiet]
 */
import { readFileSync } from 'node:fs';
import { createStandaloneRuntime, PACKAGE, stderrLogger } from '../mcp/runtime.js';
import { serveStdio } from '../mcp/stdio.js';

const USAGE = `dsh-ssh-mcp ${PACKAGE.version} — SSH connection pool as a stdio MCP server

Usage: dsh-ssh-mcp [options]

Options:
  --config <file>      JSON file with plugin config keys (hosts, exclude,
                       hostKeyPolicy, maxOutputBytes, ...). Env: DSH_SSH_MCP_CONFIG
  --ssh-config <path>  OpenSSH config to read (default ~/.ssh/config)
  --state <path>       Follow a DSH panel state file read-only (hidden hosts,
                       output limit), e.g. ~/.dsh/ssh-pool/state.json.
                       Default: not read, independent of DSH
  --quiet              Only log warnings and errors (stderr)
  -h, --help           Show this help
  -v, --version        Show the version
`;

function parseArgs(argv) {
  const options = { config: process.env.DSH_SSH_MCP_CONFIG, sshConfig: undefined, state: undefined, quiet: false };
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
    else if (arg === '--state') options.state = value();
    else if (arg === '--quiet') options.quiet = true;
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
const runtime = createStandaloneRuntime({ config, logger });
const { done } = serveStdio({ createSession: runtime.createSession });

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
