/**
 * Where the MCP side keeps its own files, separate from DSH's `~/.dsh`:
 *
 *   $DSH_SSH_MCP_HOME (default ~/.dsh-ssh-mcp)
 *     state.json     panel-owned metadata (hidden hosts, remarks, settings);
 *                    written only by `dsh-ssh-mcp panel`, read by every server
 *     run/<pid>.json one per running MCP server: its control port and token
 *
 * @module dsh-ssh-helper/mcp/home
 */
import { homedir } from 'node:os';
import { join } from 'node:path';

export function mcpHome() {
  const override = process.env.DSH_SSH_MCP_HOME;
  return typeof override === 'string' && override.length > 0 ? override : join(homedir(), '.dsh-ssh-mcp');
}

export const mcpStatePath = () => join(mcpHome(), 'state.json');
export const mcpRunDir = () => join(mcpHome(), 'run');
