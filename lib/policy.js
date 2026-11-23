/**
 * The command guard: one policy for every host.
 *
 * It refuses only what scraps the machine: removing `/`, a system tree root or
 * a directory the system needs to boot and log in (as a whole or by wildcard);
 * removing, overwriting or truncating the account files, fstab, the core
 * binaries or the C library; formatting, partitioning or wiping a disk;
 * writing an image to a block device; recursive permission changes on those
 * directories; and forcing the package manager to remove essential packages.
 *
 * Everything else is ordinary work: application config under `/etc/<app>`,
 * `/usr/local`, business directories, runtime tunables under `/proc/sys`.
 * A false positive is worse than a gap — it pushes the caller to find another
 * spelling instead of asking — so the protected set is a short list of paths
 * whose loss actually breaks the machine, never whole trees.
 *
 * The guard reads normalized shell text together with what it can know about
 * the shell: the session's working directory and exported variables, `cd`
 * steps, assignments and `for` lists in the same command. A variable it
 * cannot see counts as empty, which is what the shell does with it. It is a
 * seatbelt, not a sandbox: a command hidden in a script file or inside an
 * interpreter is outside its view.
 *
 * Every model-facing string is an abstract description plus the safe next step.
 * It must never contain a copyable dangerous command: after context compression
 * an agent can mistake an example for an instruction and run it in reverse.
 *
 * @module dsh-ssh-pool/policy
 */

/** Strip a leading wrapper command plus its own options, repeatedly. */
const WRAPPERS =
  /^(?:sudo|doas|nice|ionice|nohup|time|command|builtin|exec|env|stdbuf|setsid|chrt|taskset|timeout|busybox)(?:\s+-{1,2}[\w=,.:-]+|\s+\d+(?:\.\d+)?[smhd]?)*\s+/;

// ── the protected set ───────────────────────────────────────────────────────

/**
 * Directories whose loss leaves the machine unable to boot, log in or run
 * anything. Their ancestors are protected too (computed below), so `/usr` and
 * `/var/lib` follow from their children. Application directories such as
 * `/etc/nginx`, `/usr/local` or `/usr/share/nginx` are deliberately absent.
 */
const CRITICAL_DIRS = [
  '/etc',
  '/etc/ssh',
  '/etc/pam.d',
  '/etc/security',
  '/etc/systemd',
  '/etc/sudoers.d',
  '/etc/ld.so.conf.d',
  '/etc/selinux',
  '/etc/alternatives',
  '/usr',
  '/usr/bin',
  '/usr/sbin',
  '/usr/lib',
  '/usr/lib32',
  '/usr/lib64',
  '/usr/libx32',
  '/usr/libexec',
  '/usr/share',
  '/usr/lib/systemd',
  '/usr/lib/modules',
  '/bin',
  '/sbin',
  '/lib',
  '/lib32',
  '/lib64',
  '/libx32',
  '/lib/systemd',
  '/lib/modules',
  '/var/lib/dpkg',
  '/var/lib/rpm'
];

/**
 * Removed only as a whole or by a bare `*` over their contents: `/var/log/*.gz`
 * or `/root/*.tar` are ordinary cleanup, the directory itself is not.
 */
const WHOLE_ONLY = new Set(['/var', '/var/lib', '/root']);

/** Trees where every path counts: boot loader and kernels, device nodes, kernel interfaces. */
const WHOLE_TREE_ROOTS = ['/boot', '/dev', '/proc', '/sys'];

/** Multiarch library directories (`/usr/lib/x86_64-linux-gnu`, `/lib/aarch64-linux-gnu`). */
const MULTIARCH_DIR = /^\/(?:usr\/)?lib(?:32|64|x32)?\/[a-z0-9_]+-linux-gnu[a-z0-9_]*$/;
const LIB_DIR = /^\/(?:usr\/)?lib(?:32|64|x32)?$/;
const MULTIARCH_SAMPLES = ['x86_64-linux-gnu', 'aarch64-linux-gnu', 'arm-linux-gnueabihf', 'i386-linux-gnu'];

const PROTECTED_DIRS = (() => {
  const set = new Set(['/']);
  for (const dir of [...CRITICAL_DIRS, ...WHOLE_ONLY, ...WHOLE_TREE_ROOTS]) {
    for (let current = dir; current.length > 1; current = current.slice(0, current.lastIndexOf('/')) || '/') set.add(current);
  }
  return set;
})();

/** The account database: removing or rewriting it locks every login out. */
const ACCOUNT_FILE = /^\/etc\/(?:passwd|shadow|group|gshadow|sudoers)$/;
/** fstab: edited line by line routinely, but emptying or replacing it breaks the boot. */
const FSTAB = /^\/etc\/fstab$/;
/** The login shells, init and sshd: without them nothing starts and nobody gets in. */
const CORE_BINARY = /^\/(?:usr\/)?(?:bin\/(?:sh|bash|dash)|sbin\/(?:init|sshd)|lib\/systemd\/systemd)$/;
/** The dynamic loader and the C library: every dynamically linked program dies with them. */
const CORE_LIBRARY =
  /^\/(?:usr\/)?lib(?:32|64|x32)?(?:\/[a-z0-9_]+-linux-gnu[a-z0-9_]*)?\/(?:ld-linux[^/]*|ld-musl[^/]*|libc\.so(?:\.\d+)?|libc-[\d.]+\.so)$/;

/** `/dev/shm` is scratch space (tmpfs), not a device: deleting a file there is ordinary work. */
const DEV_SCRATCH = /^\/dev\/shm(?:\/|$)/;

/**
 * A `/dev` node whose contents are the disk itself, as opposed to a harmless
 * character device (`/dev/null`, `/dev/stdout`, a pty, `/dev/shm`). Writing a
 * redirect or `dd` target here overwrites a filesystem or a whole disk.
 *
 * `/dev/tcp` and `/dev/udp` are excluded because they are not device nodes at
 * all: bash opens a TCP/UDP connection to `<host>/<port>` and writes go over
 * that socket, never to a disk. Treating them as devices made `echo > /dev/tcp`
 * a false positive, and a false positive is worse than a gap — it pushes the
 * caller to find another spelling instead of asking. Note the tradeoff: the
 * same pseudo-paths are a classic reverse-shell primitive, but `ssh_run` is a
 * full shell that already has `nc`/`python`/`curl`, so blocking this spelling
 * contains nothing; egress control belongs in a firewall, not here.
 */
const WRITABLE_DEVICE =
  /^\/dev\/(?!null(?:\/|$)|zero(?:\/|$)|stdout(?:\/|$)|stderr(?:\/|$)|stdin(?:\/|$)|full(?:\/|$)|random(?:\/|$)|urandom(?:\/|$)|tty(?:\/|$)|ptmx(?:\/|$)|fd(?:\/|$)|pts(?:\/|$)|shm(?:\/|$)|tcp(?:\/|$)|udp(?:\/|$))/;

const isProtectedDir = (path) => PROTECTED_DIRS.has(path) || MULTIARCH_DIR.test(path);

/** Inside one of the whole trees (below its root), `/dev/shm` excepted. */
const underWholeTree = (path) => !DEV_SCRATCH.test(path) && /^\/(?:boot|dev|proc|sys)\/./.test(path);

const isCriticalFile = (path, { edit = false } = {}) =>
  ACCOUNT_FILE.test(path) || CORE_BINARY.test(path) || CORE_LIBRARY.test(path) || (!edit && FSTAB.test(path));

/** Names of the protected directories directly inside `dir`. */
function protectedChildren(dir) {
  const prefix = dir === '/' ? '/' : `${dir}/`;
  const names = [];
  for (const path of PROTECTED_DIRS) {
    if (path !== dir && path.startsWith(prefix) && !path.slice(prefix.length).includes('/')) names.push(path.slice(prefix.length));
  }
  if (LIB_DIR.test(dir)) names.push(...MULTIARCH_SAMPLES);
  return names;
}

/** Names of the critical files directly inside `dir`, for matching a wildcard against them. */
function criticalNames(dir, { edit = false } = {}) {
  if (dir === '/etc') return ['passwd', 'shadow', 'group', 'gshadow', 'sudoers', ...(edit ? [] : ['fstab'])];
  if (/^\/(?:usr\/)?bin$/.test(dir)) return ['sh', 'bash', 'dash'];
  if (/^\/(?:usr\/)?sbin$/.test(dir)) return ['init', 'sshd'];
  if (/^\/(?:usr\/)?lib\/systemd$/.test(dir)) return ['systemd'];
  if (LIB_DIR.test(dir) || MULTIARCH_DIR.test(dir)) return ['ld-linux-x86-64.so.2', 'ld-linux-aarch64.so.1', 'ld-musl-x86_64.so.1', 'libc.so.6'];
  return [];
}

// ── wildcards ───────────────────────────────────────────────────────────────

const hasGlob = (text) => /[*?[]/.test(text);

/** A shell glob for one path segment as an anchored regex. */
function globRegex(pattern) {
  let source = '';
  for (let index = 0; index < pattern.length; index += 1) {
    const char = pattern[index];
    if (char === '*') source += '[^/]*';
    else if (char === '?') source += '[^/]';
    else if (char === '[') {
      const end = pattern.indexOf(']', index + 2);
      if (end < 0) {
        source += '\\[';
        continue;
      }
      let body = pattern.slice(index + 1, end);
      if (body.startsWith('!')) body = `^${body.slice(1)}`;
      source += `[${body.replace(/\\/g, '\\\\')}]`;
      index = end;
    } else source += char.replace(/[.+^${}()|\\]/g, '\\$&');
  }
  try {
    return new RegExp(`^${source}$`);
  } catch {
    return /^.*$/;
  }
}

/** A glob with fewer than three literal characters (`*`, `e?c`, `*.*`) sweeps a directory. */
const isBroadGlob = (pattern) => pattern.replace(/\[[^\]]*\]/g, '').replace(/[*?]/g, '').length < 3;

const trimSlash = (path) => (path.length > 1 ? path.replace(/\/+$/, '') || '/' : path);

/**
 * Judge a wildcard path by what it could match: a protected directory or
 * critical file it names, or a broad sweep of a protected directory's contents.
 * `/etc/nginx/conf.d/*.conf` and `/usr/local/*` stay ordinary work.
 */
function wildcardIsFatal(path, judge, { files = true } = {}) {
  const parts = path.split('/').filter((part) => part.length > 0);
  const index = parts.findIndex(hasGlob);
  if (index < 0) return judge(path);
  const dir = `/${parts.slice(0, index).join('/')}`;
  const pattern = parts[index];
  const rest = parts.slice(index + 1);
  if (WHOLE_TREE_ROOTS.includes(dir) || underWholeTree(dir)) return true;
  const regex = globRegex(pattern);
  const candidates = [...protectedChildren(dir), ...(rest.length === 0 && files ? criticalNames(dir) : [])];
  for (const name of candidates) {
    if (!regex.test(name)) continue;
    if (rest.length === 0) return true;
    if (judge(`${dir === '/' ? '' : dir}/${name}/${rest.join('/')}`)) return true;
  }
  if (dir !== '/' && !WHOLE_ONLY.has(dir) && isProtectedDir(dir) && isBroadGlob(pattern)) return true;
  if ((dir === '/' || WHOLE_ONLY.has(dir)) && rest.length === 0 && /^\*+$/.test(pattern)) return true;
  return false;
}

/** Does removing (or moving away) this path scrap the machine? */
function removalIsFatal(path) {
  if (hasGlob(path)) return wildcardIsFatal(path, removalIsFatal);
  const clean = trimSlash(path);
  return clean === '/' || underWholeTree(clean) || isProtectedDir(clean) || isCriticalFile(clean);
}

/**
 * Does a recursive chmod/chown of this path scrap the machine? The protected
 * directories, except `/root`: tightening it is routine hardening.
 */
function permissionIsFatal(path) {
  if (hasGlob(path)) return wildcardIsFatal(path, permissionIsFatal, { files: false });
  const clean = trimSlash(path);
  if (clean === '/root') return false;
  return clean === '/' || underWholeTree(clean) || isProtectedDir(clean);
}

/**
 * Does writing to this path scrap the machine?
 *
 * - `overwrite` (`>`, `tee`, `truncate`, a copy from /dev/null, `dd of=`):
 *   block devices, `/boot`, the account files, fstab, core binaries, libc.
 * - `edit` (`sed -i`): the same minus fstab, which is edited line by line.
 * - `append` (`>>`, `tee -a`) and `device` (cp/mv/rsync destination): block
 *   devices only.
 */
function writeIsFatal(path, kind) {
  const clean = trimSlash(path);
  if (WRITABLE_DEVICE.test(clean)) return true;
  if (clean.startsWith('/dev/') || kind === 'append' || kind === 'device') return false;
  if (/^\/boot\//.test(clean)) return true;
  if (hasGlob(clean)) {
    const slash = clean.lastIndexOf('/');
    const dir = clean.slice(0, slash) || '/';
    if (hasGlob(dir)) return false;
    const regex = globRegex(clean.slice(slash + 1));
    return criticalNames(dir, { edit: kind === 'edit' }).some((name) => regex.test(name));
  }
  return isCriticalFile(clean, { edit: kind === 'edit' });
}

// ── words → paths ───────────────────────────────────────────────────────────

/** Drop the shell noise a target token may carry (`$(ls /backup)` → `/backup`). */
function cleanTarget(token) {
  return String(token).replace(/^[('"]+/, '').replace(/[)'";&|]+$/, '');
}

/**
 * Resolve the shell-level path noise a target token may carry: quoting, a
 * leading `~` and — crucially — `.`/`..` segments and duplicate slashes.
 * Without this, `/var/log/../etc/passwd` would dodge the rules that judge the
 * path as written.
 */
function normalizeTargetPath(token, home = '/root') {
  let text = cleanTarget(token);
  if (text === '~') text = home;
  else if (text.startsWith('~/')) text = `${home}/${text.slice(2)}`;
  if (!text.startsWith('/')) return text;
  const tail = /\/$/.test(text);
  const parts = [];
  for (const part of text.split('/')) {
    if (part === '' || part === '.') continue;
    if (part === '..') {
      parts.pop();
      continue;
    }
    parts.push(part);
  }
  const resolved = `/${parts.join('/')}`;
  return tail && resolved !== '/' ? `${resolved}/` : resolved;
}

/** A variable whose value the guard cannot know (set from a command substitution, `$?`, …). */
const UNKNOWN = Symbol('unknown');

const VARIABLE_REFERENCE = /\$\{([a-z_][a-z0-9_]*|[0-9]+|[@*#?$!-])(?:(:?[-=+?])([^}]*))?\}|\$([a-z_][a-z0-9_]*|[0-9]|[@*#?$!-])/g;

/** The possible values of one variable: a list, UNKNOWN, or null when it is unset. */
function variableValues(name, context) {
  if (context.vars.has(name)) return context.vars.get(name);
  if (name === 'home') return [context.home];
  if (name === 'pwd') return context.cwd ? [context.cwd] : UNKNOWN;
  if (/^[?$!#-]$/.test(name)) return UNKNOWN;
  // Positional parameters are unset in a fresh shell: `$1` expands to nothing.
  return null;
}

/**
 * Every value a word can take after variable expansion, each flagged when it
 * relied on an unset variable being empty; null when it cannot be known (an
 * UNKNOWN variable, or a `${VAR:?}` guard that makes the shell stop instead).
 */
function expandWord(word, context, depth = 0) {
  let results = [{ text: '', unset: false }];
  let last = 0;
  const combine = (literal, values) => {
    const next = [];
    for (const result of results) {
      for (const value of values) {
        next.push({ text: `${result.text}${literal}${value.text}`, unset: result.unset || value.unset });
        if (next.length >= 16) break;
      }
    }
    results = next;
  };
  for (const match of word.matchAll(VARIABLE_REFERENCE)) {
    const literal = word.slice(last, match.index);
    last = match.index + match[0].length;
    const name = match[1] ?? match[4];
    const op = match[2];
    const raw = variableValues(name, context);
    if (raw === UNKNOWN) return null;
    const empty = raw === null || raw.every((value) => value === '');
    let values;
    if (op === undefined) {
      values = raw === null ? [{ text: '', unset: true }] : raw.map((value) => ({ text: value, unset: false }));
    } else if (op.endsWith('?')) {
      // The shell stops with an error instead of expanding an unset `${X:?}`.
      if (raw === null || (op === ':?' && empty)) return null;
      values = raw.map((value) => ({ text: value, unset: false }));
    } else if (op.endsWith('-') || op.endsWith('=')) {
      if (raw === null || (op.startsWith(':') && empty)) {
        const fallback = depth < 2 ? expandWord(match[3] ?? '', context, depth + 1) : null;
        if (fallback === null) return null;
        values = fallback;
      } else values = raw.map((value) => ({ text: value, unset: false }));
    } else {
      values = raw === null || (op.startsWith(':') && empty) ? [{ text: '', unset: false }] : [{ text: match[3] ?? '', unset: false }];
    }
    // A value may itself reference variables (`APP=$HOME/app`).
    const expanded = [];
    for (const value of values) {
      if (!value.text.includes('$')) {
        expanded.push(value);
        continue;
      }
      if (depth >= 2) return null;
      const inner = expandWord(value.text, context, depth + 1);
      if (inner === null) return null;
      for (const piece of inner) expanded.push({ text: piece.text, unset: value.unset || piece.unset });
    }
    combine(literal, expanded);
  }
  combine(word.slice(last), [{ text: '', unset: false }]);
  return results;
}

/** Shell brace expansion: `{a,b}` becomes both words, `{1..9}` a wildcard. */
function expandBraces(word, limit = 32) {
  const done = [];
  const queue = [word];
  while (queue.length > 0 && done.length < limit) {
    const current = queue.shift();
    const match = /\{([^{}]*(?:,|\.\.)[^{}]*)\}/.exec(current);
    if (match === null) {
      done.push(current);
      continue;
    }
    const head = current.slice(0, match.index);
    const tail = current.slice(match.index + match[0].length);
    if (match[1].includes(',')) for (const alternative of match[1].split(',')) queue.push(`${head}${alternative}${tail}`);
    else queue.push(`${head}*${tail}`);
  }
  return done;
}

/**
 * The absolute paths one word can name, after variables, braces, `~` and the
 * working directory. A relative word with no known working directory, or a
 * word built from a command substitution, names nothing the guard can judge.
 */
function resolveTargets(word, context) {
  const text = cleanTarget(word);
  if (text.length === 0 || /\$\(|`/.test(text)) return [];
  const expanded = expandWord(text, context);
  if (expanded === null) return [];
  const targets = [];
  for (const { text: value, unset } of expanded) {
    for (const piece of expandBraces(value)) {
      let path = piece;
      if (path.length === 0) continue;
      if (path === '~' || path.startsWith('~/')) path = `${context.home}${path.slice(1)}`;
      else if (path.startsWith('~')) continue;
      if (!path.startsWith('/')) {
        if (typeof context.cwd !== 'string') continue;
        path = `${context.cwd}/${path}`;
      }
      targets.push({ path: normalizeTargetPath(path, context.home), unset });
    }
  }
  return targets;
}

// ── tokens ──────────────────────────────────────────────────────────────────

const tokensOf = (segment) => segment.split(' ').filter((token) => token.length > 0);

/** The command name of a token: `/bin/rm`, `system(rm` and `rm` are all `rm`. */
function baseName(token) {
  const clean = cleanTarget(token);
  return clean.slice(clean.lastIndexOf('(') + 1).split('/').pop();
}

/** Index of the first token that runs one of `names`, or -1. */
function commandAt(tokens, names) {
  return tokens.findIndex((token) => !token.startsWith('-') && names.has(baseName(token)));
}

/** Index of the segment's own command, past leading `VAR=value` assignments. */
function headIndex(tokens) {
  let index = 0;
  while (index < tokens.length && /^[a-z_][a-z0-9_]*=/.test(tokens[index])) index += 1;
  return index;
}

const REDIRECT_OPERATOR = /^\d*(?:&>>?|>>?[&|]?|<<?<?|<>)$/;
const REDIRECT_ATTACHED = /^\d*(?:&>|>|<)/;

/**
 * The operands after `start`: options, redirections and their targets
 * skipped, `--` honored. `valueOptions` take the next token as their value.
 */
function operands(tokens, start, valueOptions = []) {
  const found = [];
  let options = true;
  for (let index = start; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (REDIRECT_OPERATOR.test(token)) {
      index += 1;
      continue;
    }
    if (REDIRECT_ATTACHED.test(token) || /^[;&|(){}]+$/.test(token)) continue;
    if (options && token === '--') {
      options = false;
      continue;
    }
    if (options && token.startsWith('-') && token.length > 1) {
      if (valueOptions.includes(token)) index += 1;
      continue;
    }
    found.push(token);
  }
  return found;
}

/**
 * Whether a token list carries a short-flag cluster with `letter` (or the
 * named long flag). `-rf`, `-R` and `-vf` all need to be recognized.
 */
function hasFlag(tokens, letter, long = '') {
  for (const token of tokens) {
    if (/^-[A-Za-z]+$/.test(token) && token.slice(1).toLowerCase().includes(letter)) return true;
    if (long.length > 0 && token === `--${long}`) return true;
  }
  return false;
}

// ── what a segment removes, overwrites or formats ───────────────────────────

const REMOVERS = new Set(['rm', 'shred', 'unlink', 'rmdir', 'mv']);
const FIND = new Set(['find']);
const XARGS = new Set(['xargs']);
const RSYNC = new Set(['rsync']);
const FIND_DELETES = /(?:^|\s)-(?:delete\b|(?:exec|execdir|ok|okdir)\s+(?:\S*\/)?(?:rm|shred|unlink|rmdir)\b)/;

/** The starting points of a `find` (default `.`). */
function findRoots(tokens, at) {
  const roots = [];
  let index = at + 1;
  while (index < tokens.length && /^-(?:[hlp]|d|o\d)$/.test(tokens[index])) index += tokens[index] === '-d' ? 2 : 1;
  for (; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (token.startsWith('-') || token.startsWith('(') || token.startsWith('!') || token.startsWith('\\')) break;
    roots.push(token);
  }
  return roots.length > 0 ? roots : ['.'];
}

/** Every path this segment would remove that scraps the machine, with how it was resolved. */
function removalHits(segment, context) {
  const tokens = tokensOf(segment);
  const hits = [];
  const judge = (word) => {
    for (const target of resolveTargets(word, context)) if (removalIsFatal(target.path)) hits.push(target);
  };

  const at = commandAt(tokens, REMOVERS);
  if (at >= 0) {
    const args = operands(tokens, at + 1);
    // `mv` destroys what it moves, not the place it lands.
    if (baseName(tokens[at]) === 'mv' && args.length > 1 && !hasFlag(tokens.slice(at + 1), 't', 'target-directory')) args.pop();
    for (const word of args) judge(word);
  }

  // `find <dir> -delete` (or `-exec rm`) sweeps everything below each root.
  const findAt = commandAt(tokens, FIND);
  if (findAt >= 0 && FIND_DELETES.test(segment)) for (const word of findRoots(tokens, findAt)) judge(word);

  // `rsync --delete <src> <dst>` empties whatever the source lacks; the source
  // is only read, unless `--remove-source-files` deletes it after copying.
  const rsyncAt = commandAt(tokens, RSYNC);
  if (rsyncAt >= 0) {
    const options = tokens.slice(rsyncAt + 1);
    const dryRun = options.some((token) => token === '--dry-run' || /^-[a-z]*n[a-z]*$/.test(token));
    const local = operands(tokens, rsyncAt + 1, ['-e', '--rsh']).filter((word) => !/^[^/]*:/.test(word));
    if (!dryRun && local.length > 0) {
      if (options.some((token) => /^--del(?:ete[a-z-]*)?$/.test(token)) && local.length >= 2) judge(local.at(-1));
      if (options.includes('--remove-source-files')) for (const word of local.slice(0, -1)) judge(word);
    }
  }

  // `… | xargs rm`: the paths come from the producer in the same pipeline.
  const xargsAt = commandAt(tokens, XARGS);
  if (xargsAt >= 0 && commandAt(tokens.slice(xargsAt + 1), REMOVERS) >= 0) {
    for (const producer of context.prev ?? []) {
      const producerTokens = tokensOf(producer.lower);
      const producerFind = commandAt(producerTokens, FIND);
      if (producerFind >= 0) {
        for (const word of findRoots(producerTokens, producerFind)) judge(word);
        continue;
      }
      const start = headIndex(producerTokens);
      const head = baseName(producerTokens[start] ?? '');
      // echo/printf print their operands, and so does `ls -d`.
      const literal = head === 'echo' || head === 'printf' || (head === 'ls' && hasFlag(producerTokens.slice(start + 1), 'd', 'directory'));
      if (literal) for (const word of operands(producerTokens, start + 1)) judge(word);
    }
  }
  return hits;
}

/** /dev/null, /dev/zero and `:`: a copy from one of these only ever erases. */
const VOID_SOURCE = /^(?:\/dev\/(?:null|zero)|:)$/;

const REDIRECT = /(?:^|[\s;&|()])(\d*(?:&>>?|>>?)[&|]?|:>)\s*(\S+)/g;

/** Every write in this segment that scraps the machine. */
function overwriteHits(segment, context) {
  const hits = [];
  const judge = (word, kind) => {
    for (const target of resolveTargets(word, context)) if (writeIsFatal(target.path, kind)) hits.push(target);
  };
  // Judge every redirect, not just the first: a second `>` must not smuggle a
  // system file in behind an innocent `/tmp` target.
  for (const match of segment.matchAll(REDIRECT)) judge(match[2], match[1].includes('>>') ? 'append' : 'overwrite');
  for (const match of segment.matchAll(/(?:^|\s)of=(\S+)/g)) judge(match[1], 'overwrite');

  const tokens = tokensOf(segment);
  const head = headIndex(tokens);
  const name = baseName(tokens[head] ?? '');
  const args = (valueOptions = []) => operands(tokens, head + 1, valueOptions);
  if (name === 'tee') {
    const kind = hasFlag(tokens.slice(head + 1), 'a', 'append') ? 'append' : 'overwrite';
    for (const word of args()) judge(word, kind);
  }
  if (name === 'truncate') for (const word of args(['-s', '--size', '-r', '--reference'])) judge(word, 'overwrite');
  if (name === 'cp' || name === 'install') {
    const words = args(['-m', '--mode', '-o', '--owner', '-g', '--group', '-S', '--suffix']);
    if (words.length >= 2) {
      // A copy from a void device only ever erases its destination.
      if (words.slice(0, -1).some((word) => VOID_SOURCE.test(cleanTarget(word)))) judge(words.at(-1), 'overwrite');
      judge(words.at(-1), 'device');
    }
  }
  if (name === 'mv' || name === 'rsync') {
    const words = args(['-e', '--rsh']);
    if (words.length >= 2) judge(words.at(-1), 'device');
  }
  if (name === 'ddrescue' || name === 'dcfldd') {
    const words = args();
    if (words.length >= 2) judge(words[1], 'device');
  }
  if ((name === 'sed' || name === 'perl') && tokens.slice(head + 1).some((token) => /^-[a-z]*i/.test(token) || token.startsWith('--in-place'))) {
    // sed -i <script> <file>…: the first operand is the script.
    const words = args(['-e', '--expression', '-f', '--file']);
    const scripted = tokens.slice(head + 1).some((token) => token === '-e' || token === '--expression' || token === '-f' || token === '--file');
    for (const word of scripted ? words : words.slice(1)) judge(word, 'edit');
  }
  return hits;
}

/** Tools that destroy whatever device they are pointed at. */
const DEVICE_TOOL = /^(?:mkfs(?:\.\w+)?|mke2fs|mkdosfs|mkntfs|mkswap|wipefs|fdisk|sfdisk|cfdisk|gdisk|sgdisk|cgdisk|parted|blkdiscard|sg_format)$/;

/**
 * Read-only partition-table listings: fdisk/sfdisk/gdisk list, sfdisk dump,
 * sgdisk print/info/verify/backup, parted's list or `print`. A partitioning
 * verb anywhere in the segment keeps it on the destructive side, and allowing
 * the listing never suppresses the overwrite rules that judge a redirect.
 */
const PARTED_WRITE_VERB = /\b(?:mklabel|mkpart|mkpartfs|mkfs|rm|delete|resize|resizepart|set|toggle|name|move|copy|rescue|disk_set|disk_toggle)\b/;

function isReadOnlyListing(name, options, operandWords, segment) {
  if (options.some((word) => word === '--help' || word === '--version')) return true;
  const lists = options.some((word) => word === '-l' || word === '--list');
  if (name === 'parted') return !PARTED_WRITE_VERB.test(segment) && (lists || operandWords.includes('print'));
  if (name === 'fdisk' || name === 'gdisk') return lists;
  if (name === 'sfdisk') return lists || options.some((word) => word === '-d' || word === '--dump' || word === '-j' || word === '--json');
  if (name === 'sgdisk') {
    return options.length > 0 && options.every((word) => /^(?:-p|--print|-i(?:=\d+)?|--info(?:=\d+)?|-v|--verify|-b(?:=\S+)?|--backup(?:=\S+)?)$/.test(word));
  }
  return false;
}

/** Whether any operand names a block device. */
function namesDevice(words, context) {
  return words.some((word) => resolveTargets(word, context).some((target) => WRITABLE_DEVICE.test(target.path)));
}

function formatsDisk(segment, context) {
  const tokens = tokensOf(segment);
  const head = headIndex(tokens);
  const name = baseName(tokens[head] ?? '');
  const rest = tokens.slice(head + 1);
  const words = operands(tokens, head + 1);
  if (DEVICE_TOOL.test(name)) {
    if (isReadOnlyListing(name, rest.filter((word) => word.startsWith('-')), words, segment)) return false;
    // An image or swap file is ordinary work; a device is the disk itself.
    return namesDevice(words, context);
  }
  if (name === 'badblocks') return hasFlag(rest, 'w') && namesDevice(words, context);
  if (name === 'nvme') return /^(?:format|sanitize)$/.test(words[0] ?? '') && namesDevice(words, context);
  if (name === 'cryptsetup') return /^(?:luksformat|erase|lukserase)$/.test(words[0] ?? '') && namesDevice(words, context);
  if (name === 'mdadm') return rest.includes('--zero-superblock') && namesDevice(words, context);
  if (name === 'hdparm') return rest.some((word) => word.startsWith('--security-erase')) && namesDevice(words, context);
  if (name === 'vgremove' || name === 'pvremove') return true;
  if (name === 'zpool') return /^(?:destroy|labelclear)$/.test(words[0] ?? '');
  // A whole pool, recursively; destroying a snapshot or one dataset is ordinary work.
  if (name === 'zfs') return words[0] === 'destroy' && hasFlag(rest, 'r') && words.slice(1).some((word) => !/[/@]/.test(word));
  return false;
}

const ESSENTIAL_PACKAGE = /^(?:glibc|bash|coreutils|systemd|filesystem|rpm|libc6|libc-bin|base-files|dpkg)$/;

function removesEssential(segment) {
  const tokens = tokensOf(segment);
  const head = headIndex(tokens);
  const name = baseName(tokens[head] ?? '');
  const rest = tokens.slice(head + 1);
  if (name === 'dpkg') {
    const removing = rest.some((word) => /^(?:-r|-p|--remove|--purge)$/.test(word));
    return removing && rest.some((word) => word === '--force-remove-essential' || word === '--force-all');
  }
  if (name === 'apt' || name === 'apt-get') return rest.includes('--allow-remove-essential');
  if (name === 'rpm') {
    const erasing = rest.some((word) => word === '--erase' || /^-[a-z]*e[a-z]*$/.test(word));
    return erasing && rest.includes('--nodeps') && rest.some((word) => ESSENTIAL_PACKAGE.test(word));
  }
  if (name === 'yum' || name === 'dnf') {
    return rest.some((word) => /^(?:remove|erase)$/.test(word)) && rest.some((word) => ESSENTIAL_PACKAGE.test(word));
  }
  return false;
}

// ── the rules ───────────────────────────────────────────────────────────────

/** The shapes that make the machine unbootable, unreachable or diskless. */
const RULES = [
  {
    id: 'danger.rm-root',
    title: '删除或移走系统关键目录或文件',
    test: (segment, context) => removalHits(segment, context).some((hit) => !hit.unset),
    reason: '这条命令会删除或移走根目录、系统目录树、启动与登录必需的目录、账户文件或核心程序与 C 库，系统将无法启动或无法登录，只能从备份或面板重建。',
    suggestion: '先 `ls -lh <path>` 确认目标，只删除业务目录或应用自己的目录（如 /etc/<app>、/usr/local/<app>）下的明确路径；系统目录的维护交给包管理器，或在维护窗口由人工执行。'
  },
  {
    id: 'danger.empty-var-delete',
    title: '删除目标含可能为空的变量',
    test: (segment, context) => removalHits(segment, context).some((hit) => hit.unset),
    reason: '目标里的变量在这条命令里没有赋值（不带 session 时每次调用都是新 shell，之前设置的变量已经不在了）；变量为空时，目标会展开成根目录或系统关键目录。',
    suggestion: '在同一条命令里先给变量赋值，或写成 ${VAR:?} 让变量为空时直接报错退出；也可以直接写绝对路径。'
  },
  {
    id: 'danger.fs-format',
    title: '格式化、分区或抹除磁盘',
    test: (segment, context) => formatsDisk(segment, context),
    reason: '格式化、重新分区或抹除会瞬间销毁磁盘上的文件系统，内容只能从备份或面板重建。',
    suggestion: '先确认设备与挂载状态：lsblk、findmnt <dev>、mount | grep <dev>；这类操作应在维护窗口由人工执行。对镜像文件或 swap 文件操作不受限制。'
  },
  {
    id: 'danger.dd-device',
    title: '把数据直接写入设备',
    test: (segment, context) => {
      if (!/\bdd\b/.test(segment)) return false;
      for (const match of segment.matchAll(/(?:^|\s)of=(\S+)/g)) {
        if (resolveTargets(match[1], context).some((target) => WRITABLE_DEVICE.test(target.path))) return true;
      }
      return false;
    },
    reason: '把镜像或数据直接写到设备会覆盖磁盘与文件系统，原内容只能从备份或面板重建。',
    suggestion: '只对具体文件做有界写入：dd if=… of=/tmp/probe bs=1M count=10；确认设备与挂载状态用 lsblk、findmnt <dev>。'
  },
  {
    id: 'danger.overwrite-device',
    title: '覆写块设备或账户/启动关键文件',
    test: (segment, context) => overwriteHits(segment, context).length > 0,
    reason: '覆写或截断块设备、/boot、账户文件、fstab 或核心程序与 C 库，会立刻破坏文件系统、启动或登录，系统通常只能从备份或面板重建。',
    suggestion: '应用配置（/etc/<app>/、/usr/local/、业务目录）可以直接写；账户用 useradd/usermod/passwd 维护，fstab 按行修改；先 `ls -lh <file>` 确认目标。不要覆写设备文件或系统关键文件。'
  },
  {
    id: 'danger.recursive-chmod-root',
    title: '递归修改系统目录权限',
    test: (segment, context) => {
      const tokens = tokensOf(segment);
      const at = commandAt(tokens, new Set(['chmod', 'chown', 'chgrp', 'setfacl']));
      if (at < 0 || !hasFlag(tokens.slice(at + 1), 'r', 'recursive')) return false;
      for (const word of operands(tokens, at + 1, ['-m', '-x', '-M', '-X', '--reference'])) {
        if (resolveTargets(word, context).some((target) => permissionIsFatal(target.path))) return true;
      }
      return false;
    },
    reason: '递归修改根目录、系统目录或启动与登录必需目录的权限，会让服务、登录与提权通道失效，系统通常只能从备份或面板重建。',
    suggestion: '只对需要的具体目录授权（应用目录、/usr/local/<app>、业务目录不受限制）；先 `ls -ld <dir>` 与 `namei -l <path>` 确认目标；批量修复系统权限用包管理器校验。'
  },
  {
    id: 'danger.remove-essential',
    title: '强制卸载系统必需的软件包',
    test: (segment) => removesEssential(segment),
    reason: '强制卸载 C 库、shell、systemd、coreutils 或包管理器本身，系统会立刻无法运行程序或无法启动，只能从备份或面板重建。',
    suggestion: '普通的安装、升级、卸载不受限制；必需软件包不要绕过包管理器的保护去卸载，需要替换时在维护窗口由人工执行。'
  }
];

// ── splitting ───────────────────────────────────────────────────────────────

const SHELL_C = /\b((?:ba|z|da|k)?sh\s+(?:-[a-z]+\s+)*-[a-z]*c[a-z]*\s+)(['"])([\s\S]*?)\2/gi;
const EVAL_BODY = /\b(eval\s+)(['"])([\s\S]*?)\2/gi;

/**
 * The command text and every nested command (`sh -c '…'`, `eval '…'`,
 * `$(…)`, backticks), each as its own chain. A nested shell's body is cut out
 * of the outer text so its `cd` steps are followed only inside it.
 */
function chainTexts(command) {
  const chains = [];
  const visit = (text, depth) => {
    if (depth > 4 || typeof text !== 'string' || text.length === 0) return;
    const nested = [];
    const outer = text
      .replace(SHELL_C, (_whole, head, _quote, body) => {
        nested.push(body);
        return `${head}__nested__`;
      })
      .replace(EVAL_BODY, (_whole, head, _quote, body) => {
        nested.push(body);
        return `${head}__nested__`;
      });
    for (const match of outer.matchAll(/\$\(([^()]*)\)/g)) nested.push(match[1]);
    for (const match of outer.matchAll(/`([^`]*)`/g)) nested.push(match[1]);
    chains.push(outer);
    for (const body of nested) visit(body, depth + 1);
  };
  visit(command, 0);
  return chains;
}

/** Split a command into independently checkable segments, following nesting. */
export function splitSegments(command) {
  const segments = [];
  for (const chain of chainTexts(command)) {
    for (const part of chain.split(/&&|\|\||;|\n/)) {
      for (const stage of part.split('|')) {
        if (stage.trim().length > 0) segments.push(normalizeSegment(stage));
      }
    }
  }
  return segments;
}

/** Collapse whitespace, drop quoting, and strip wrapper prefixes for matching. */
export function normalizeSegment(segment) {
  let text = String(segment).replace(/\\\r?\n/g, ' ').replace(/\s+/g, ' ').trim();
  for (let round = 0; round < 3; round += 1) {
    const stripped = text.replace(WRAPPERS, '');
    if (stripped === text) break;
    text = stripped;
  }
  const flat = text
    // `$'…'` and `$"…"` are just quoting: `$'/etc'` is `/etc`.
    .replace(/\$(?=['"])/g, '')
    .replace(/["']/g, '')
    .replace(/\\(?=\S)/g, '')
    .replace(/\s+/g, ' ')
    .trim();
  return { raw: text, flat, lower: flat.toLowerCase() };
}

/** The working directory after a `cd`/`pushd` segment, or `cwd` unchanged. */
function nextCwd(segment, cwd, context) {
  const match = /^[({\s]*(cd|pushd|popd)(?:\s+(.*))?$/.exec(segment.lower);
  if (match === null) return cwd;
  if (match[1] === 'popd') return null;
  const words = (match[2] ?? '').split(' ').filter((word) => word.length > 0 && word !== ')' && word !== '}');
  if (words.includes('-')) return null;
  const args = words.filter((word) => !/^-[a-z@]+$/.test(word) && word !== '--');
  if (args.length === 0) return context.home;
  const resolved = resolveTargets(args[0], { ...context, cwd });
  return resolved.length === 1 ? trimSlash(resolved[0].path) : null;
}

/**
 * Every segment with the working directory it runs in and the earlier stages
 * of its pipeline. `cd` steps are followed in order inside each chain.
 */
function walkSegments(command, startCwd, context) {
  const segments = [];
  for (const chain of chainTexts(command)) {
    let cwd = startCwd;
    for (const part of chain.split(/&&|\|\||;|\n/)) {
      const stages = part
        .split('|')
        .map((stage) => stage.trim())
        .filter((stage) => stage.length > 0);
      const earlier = [];
      for (const stage of stages) {
        const segment = { ...normalizeSegment(stage), cwd, prev: [...earlier] };
        segments.push(segment);
        earlier.push(segment);
      }
      if (earlier.length === 1) cwd = nextCwd(earlier[0], cwd, context);
    }
  }
  return segments;
}

const ASSIGNMENT = /(?:^|[\s;&|(])(?:export\s+|local\s+|readonly\s+|declare\s+(?:-[a-z]+\s+)*)?([a-z_][a-z0-9_]*)=([^\s;&|)]*)/g;
const FOR_LIST = /\bfor\s+([a-z_][a-z0-9_]*)\s+in\s+(.*?)\s*(?:;|\bdo\b|$)/g;

/**
 * What the guard knows about variables: the session's exports, then every
 * assignment and `for` list in the command (an assignment replaces the
 * exported value). A value from a command substitution is UNKNOWN.
 */
function collectVariables(command, env) {
  const vars = new Map();
  for (const [name, value] of Object.entries(env ?? {})) {
    if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(name) && typeof value === 'string') vars.set(name.toLowerCase(), [value.toLowerCase()]);
  }
  const assigned = new Set();
  const add = (name, value) => {
    if (vars.get(name) === UNKNOWN) return;
    const unknowable = /\$\(|`/.test(value);
    if (unknowable) {
      vars.set(name, UNKNOWN);
      return;
    }
    const current = assigned.has(name) ? vars.get(name) : [];
    assigned.add(name);
    vars.set(name, [...current, value.replace(/;+$/, '')]);
  };
  for (const match of command.matchAll(ASSIGNMENT)) add(match[1], match[2]);
  for (const match of command.matchAll(FOR_LIST)) {
    for (const value of match[2].split(' ').filter((word) => word.length > 0)) add(match[1], value);
  }
  return vars;
}

/** Match one rule against one normalized segment (rules are written lowercase). */
function matches(rule, segment, base) {
  try {
    return rule.test(segment.lower, { ...base, cwd: segment.cwd, prev: segment.prev }) === true;
  } catch {
    return false;
  }
}

/** A login's home directory: `/root` for root, `/home/<user>` otherwise. */
export function homeFor(user) {
  return typeof user !== 'string' || user.length === 0 || user === 'root' ? '/root' : `/home/${user}`;
}

/**
 * Build the policy engine.
 *
 * There is one host-independent list. `evaluate` takes the command and, when
 * the caller knows them, the working directory it runs in (`cwd`), the login's
 * home (`home`) and the session's exported variables (`env`). The result is
 * `{ action: 'allow' }` or a denial naming every rule that matched.
 */
export function createPolicy() {
  const evaluate = ({ command, cwd = null, home = '/root', env = {} } = {}) => {
    try {
      if (typeof command !== 'string' || command.trim().length === 0) return { action: 'allow' };
      const whole = normalizeSegment(command);
      const homeDir = typeof home === 'string' && home.startsWith('/') ? trimSlash(normalizeTargetPath(home.toLowerCase())) : '/root';
      const base = { command: whole.lower, home: homeDir, vars: collectVariables(whole.lower, env) };
      const startCwd = typeof cwd === 'string' && cwd.startsWith('/') ? trimSlash(normalizeTargetPath(cwd.toLowerCase(), homeDir)) : null;
      const segments = walkSegments(command, startCwd, base);
      const hits = RULES.filter((rule) => segments.some((segment) => matches(rule, segment, base)));
      if (hits.length === 0) return { action: 'allow' };
      const primary = hits[0];
      return {
        action: 'deny',
        rule: primary.id,
        title: primary.title,
        reason: primary.reason,
        suggestion: primary.suggestion,
        matches: hits.map((rule) => ({ rule: rule.id, title: rule.title }))
      };
    } catch {
      // A policy failure must never block ordinary work.
      return { action: 'allow' };
    }
  };

  const hints = () =>
    [
      '唯一门禁：会让整台机器报废的操作。包括删除或通配删除 /、系统目录树根和启动/登录必需的目录（/etc、/usr/bin、/usr/lib、/boot、/etc/ssh、/var/lib/dpkg 等）；删除或覆写账户文件、fstab、核心程序与 C 库；格式化/分区/抹除磁盘、dd 或写块设备；递归 chmod/chown 这些目录；强制卸载必需软件包。',
      '应用配置（/etc/<app>/、/usr/local/）、业务目录（/srv、/home、/opt、/var/www、/data）、写 /proc/sys、追加写和 sed -i 改配置都不在门禁内；先备份，再按明确路径操作。',
      '删除目标里的变量按空值判断：变量可能为空时，在同一条命令里赋值或写成 ${VAR:?}。相对路径按 session 的当前目录和命令里的 cd 解析。',
      '查日志用 journalctl --since/--until + -n、tail -n、grep -m、sed -n 等有界写法；数字只是示例，按日志密度和问题时间窗调整，不要把某个固定值当边界。',
      '被拒后不要换一种等价写法重试（例如把 /dev/tcp 探测换成 python 或 nc）。换写法只是绕过检查，不改结果；直接说明要做什么、对哪台机器、预期影响，由人决定。'
    ].join('\n');

  return { evaluate, hints };
}

/**
 * Whether an upload target (`ssh_transfer`) is one of the unrecoverable
 * destinations: a block device, a system boot/kernel path, the account files,
 * or a core binary or library. Config files under `/etc` (fstab included)
 * stay writable — that is ordinary maintenance.
 */
export function protectedWritePath(path) {
  const clean = normalizeTargetPath(path);
  if (clean.length === 0 || !clean.startsWith('/')) return null;
  if (WRITABLE_DEVICE.test(clean)) {
    return {
      rule: 'danger.write-device',
      title: '写入块设备',
      reason: '把文件写到块设备会覆盖磁盘与文件系统，原内容只能从备份或面板重建。',
      suggestion: '上传目标应是普通文件；镜像写入应在维护窗口用人工确认的设备路径执行。'
    };
  }
  if (/^\/(?:boot|proc|sys)(?:\/|$)/.test(clean)) {
    return {
      rule: 'danger.write-system',
      title: '写入系统关键路径',
      reason: '覆盖 /boot、/proc 或 /sys 下的内容会让系统无法启动或让内核状态失效。',
      suggestion: '这类文件由包管理器或维护窗口维护；请改到业务目录或普通配置文件。'
    };
  }
  if (isCriticalFile(trimSlash(clean), { edit: true })) {
    return {
      rule: 'danger.write-critical-file',
      title: '写入账户文件或核心程序',
      reason: '改写账户文件（passwd、shadow、group、sudoers）或核心程序与 C 库，会让登录、提权或所有程序立刻失效。',
      suggestion: '账户用 useradd/usermod/passwd/visudo 维护；核心程序与库由包管理器维护。'
    };
  }
  return null;
}

/**
 * The model-facing text for a command denial. Names EVERY rule that matched,
 * not just the first one: reporting one at a time is what made the agent guess
 * its way through three rules in a row.
 */
export function formatDenial(verdict, alias = '') {
  const others = (Array.isArray(verdict.matches) ? verdict.matches : []).filter((match) => match.rule !== verdict.rule);
  return [
    `[ssh-pool policy] 命令被拒绝（规则 ${verdict.rule}）: ${verdict.title}`,
    `主机 ${alias || '?'}`,
    others.length === 0 ? '' : `同时命中: ${others.map((match) => `${match.rule}（${match.title}）`).join('、')}`,
    `原因: ${verdict.reason}`,
    `建议: ${verdict.suggestion}`,
    '规则全表与合规写法: 调用 ssh_hosts 查看 [policy] 提示，或查看插件 README'
  ]
    .filter((line) => line.length > 0)
    .join('\n');
}

/**
 * A policy refusal raised from inside a tool. The message is the same text a
 * host guard would show; the fields let a non-DSH adapter (e.g. MCP) return a
 * structured error instead of parsing prose.
 */
export class PolicyDeniedError extends Error {
  /**
   * @param {object} denial - `{ rule, title, reason, suggestion, matches? }`.
   * @param {object} where - `{ host, target: 'command' | 'path', path? }`.
   * @param {string} message - the model-facing text.
   */
  constructor(denial, where, message) {
    super(message);
    this.name = 'PolicyDeniedError';
    this.code = 'POLICY_DENY';
    this.rule = denial.rule;
    this.title = denial.title;
    this.reason = denial.reason;
    this.suggestion = denial.suggestion;
    this.matches = Array.isArray(denial.matches) ? denial.matches : [{ rule: denial.rule, title: denial.title }];
    this.host = where.host ?? null;
    this.target = where.target;
    if (where.path !== undefined) this.path = where.path;
  }
}

/**
 * Throw a PolicyDeniedError when the policy refuses a remote command.
 * `cwd`, `home` and `env` are what the caller knows about the shell it runs in.
 */
export function assertCommandAllowed(policy, { host, command, cwd = null, home, env }) {
  const verdict = policy.evaluate({ alias: host, host, command, cwd, home, env });
  if (verdict.action !== 'deny') return;
  throw new PolicyDeniedError(verdict, { host, target: 'command' }, formatDenial(verdict, host));
}

/** Throw a PolicyDeniedError when an upload target is protected. */
export function assertWritePathAllowed({ host, path }) {
  const blocked = protectedWritePath(path);
  if (blocked === null) return;
  throw new PolicyDeniedError(
    blocked,
    { host, target: 'path', path },
    `[ssh-pool policy] ${blocked.title}：${path}\n${blocked.reason}\n建议: ${blocked.suggestion}`
  );
}

export { RULES };
