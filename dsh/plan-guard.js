/**
 * Plan-mode and local-SSH deletion guards.
 *
 * Plan mode in DSH is collaborative: every tool remains available. This helper
 * supplies the small enforcement layer the SSH plugin needs:
 *  - while plan mode is active/pending, delete-like ssh_run commands are denied;
 *  - a local `bash` command that invokes ssh and deletes is denied even after
 *    the plan is approved, so a raw local key cannot bypass the pooled tools.
 *
 * The match is a seatbelt over shell text, not a sandbox: a command hidden in a
 * script or built from variables is outside its view.
 *
 * @module dsh-ssh-helper/dsh/plan-guard
 */

/**
 * A delete command at a shell command position (start, `;`, `&&`, a pipe, or
 * after a wrapper such as sudo/xargs). Deliberately does not match a bare
 * argument: `grep rm file` is a read, not a deletion.
 */
const DELETE = /(?:^|[;&|()\n\r])\s*(?:(?:sudo|doas|command|builtin|env|nice|ionice|nohup|time|stdbuf|setsid|chrt|taskset|xargs)(?:\s+-{0,2}[\w=,.:-]+|\s+\d+)*\s+)*(?:rm|rmdir|unlink|shred|truncate)\b|\bfind\b[^;&|]*(?:-delete|-exec\s+(?:rm|shred|unlink|rmdir))\b|\brsync\b[^;&|]*--delete\b|\bgit\s+clean\b/i;

/**
 * A quoted remote command (`ssh host 'rm -rf …'`) is not at a shell command
 * position from the local shell's point of view, so this wider fallback is
 * used only after the command is known to invoke ssh.
 */
const DELETE_ANYWHERE = /\b(?:rm|rmdir|unlink|shred|truncate)\b|\bfind\b[^;&|]*(?:-delete|-exec\s+(?:rm|shred|unlink|rmdir))\b|\brsync\b[^;&|]*--delete\b|\bgit\s+clean\b/i;

/** A local shell command that invokes a remote SSH transport. */
const REMOTE_SSH = /(?:^|[\s;&|()])(?:ssh|scp|sftp|rsync)(?:[\s;&|()]|$)/i;

/** Pull the command text out of `sh -c '…'` / `bash -c "…"`. */
function nestedShellCommands(command) {
  const found = [];
  const re = /\b(?:sh|bash|zsh|dash|ksh)\s+-c\s+(['"])([\s\S]*?)\1/gi;
  let match;
  while ((match = re.exec(command)) !== null) found.push(match[2]);
  return found;
}

/** True when the command contains a delete-like operation at a command position. */
export function isDeleteCommand(command) {
  if (typeof command !== 'string') return false;
  return DELETE.test(command) || nestedShellCommands(command).some((nested) => DELETE.test(nested));
}

/** True when a local bash command combines ssh with a delete operation. */
export function isLocalSshDelete(command) {
  return typeof command === 'string' && REMOTE_SSH.test(command) && DELETE_ANYWHERE.test(command);
}

/**
 * Read the plan state for one agent. A pending user selection blocks too: the
 * user has asked for planning and the next accepted step will commit it.
 */
export function isPlanActive(planMode, agent) {
  if (planMode === undefined || planMode === null || typeof planMode.get !== 'function' || agent === undefined) return false;
  try {
    const state = planMode.get(agent);
    return state?.active === true || state?.pending === true;
  } catch {
    return false;
  }
}
