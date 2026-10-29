/**
 * The command guard: one policy for every host.
 *
 * It refuses only commands that would leave the machine unbootable or wipe a
 * system tree — recursive/glob removal of a critical tree, formatting or
 * partitioning a disk, writing an image to a block device, overwriting a system
 * file or device, and recursive permission changes on a system tree. Business
 * directories (`/srv`, `/home`, `/opt`, `/var/www`, `/data`, …) are not guarded;
 * ordinary maintenance, log cleanup and service work stay allowed.
 *
 * The guard is a seatbelt, not a sandbox. It matches normalized shell text, so a
 * command hidden inside a script file is outside its view; use a dedicated
 * account and backups when the boundary has to be real.
 *
 * Every model-facing string is an abstract description plus the safe next step.
 * It must never contain a copyable dangerous command: after context compression
 * an agent can mistake an example for an instruction and run it in reverse.
 *
 * @module dsh-ssh-pool/policy
 */

/** Strip a leading wrapper command plus its own options, repeatedly. */
const WRAPPERS = /^(?:sudo|doas|nice|ionice|nohup|time|command|builtin|exec|env|stdbuf|setsid|chrt|taskset)(?:\s+-{1,2}[\w=,.:-]+|\s+\d+)*\s+/;

/**
 * The only paths whose recursive/glob removal scraps the machine itself.
 * `/srv`, `/home`, `/opt`, `/var/www`, `/data` and every business directory are
 * deliberately absent. `/var` and `/root` are special — only the whole tree
 * counts (see `WHOLE_VAR`/`WHOLE_ROOT`).
 */
const SYSTEM_TREE = /^\/(?:etc|usr|bin|sbin|lib|lib64|boot|proc|sys|dev)(?:\/|$)/;

/** `/root` only as a whole: `/root`, `/root/`, `/root/*`. */
const WHOLE_ROOT = /^\/root\/?$|^\/root\/\*$/;

/** `/var` only as a whole: the directory itself or a wildcard over its contents. */
const WHOLE_VAR = /^\/var\/?$|^\/var\/\*+$/;

/**
 * The package/state database (`/var/lib` as a whole, plus dpkg and rpm): losing
 * it leaves the machine unable to install, upgrade or cleanly boot.
 */
const SYSTEM_STATE_WHOLE = /^\/var\/lib\/?$|^\/var\/lib\/\*+$/;
const PACKAGE_STATE = /^\/var\/lib\/(?:dpkg|rpm)(?:\/|$)/;

/** `/dev/shm` is scratch space (tmpfs), not a device: deleting a file there is ordinary work. */
const DEV_SCRATCH = /^\/dev\/shm(?:\/|$)/;

/**
 * A `/dev` node whose contents are the disk itself, as opposed to a harmless
 * character device (`/dev/null`, `/dev/stdout`, a pty, `/dev/shm`). Writing a
 * redirect or `dd` target here overwrites a filesystem or a whole disk.
 */
const WRITABLE_DEVICE = /^\/dev\/(?!null(?:\/|$)|zero(?:\/|$)|stdout(?:\/|$)|stderr(?:\/|$)|stdin(?:\/|$)|full(?:\/|$)|random(?:\/|$)|urandom(?:\/|$)|tty(?:\/|$)|ptmx(?:\/|$)|fd(?:\/|$)|pts(?:\/|$)|shm(?:\/|$))/;

/** Drop the shell noise a target token may carry (`$(ls /backup)` → `/backup`). */
function cleanTarget(token) {
  return String(token).replace(/^[('"]+/, '').replace(/[)'";&|]+$/, '');
}

/**
 * Resolve the shell-level path noise a target token may carry: quoting, a
 * leading `~` (the pool usually runs as root, so `~` is `/root`) and — crucially
 * — `.`/`..` segments and duplicate slashes. Without this, `/var/log/../etc/passwd`
 * would dodge the rules that judge the path as written.
 */
function normalizeTargetPath(token) {
  let text = cleanTarget(token);
  if (text === '~' || text === '$home' || text === '${home}') text = '/root';
  else if (text.startsWith('~/')) text = `/root/${text.slice(2)}`;
  else if (text.startsWith('${home}/')) text = `/root/${text.slice('${home}/'.length)}`;
  else if (text.startsWith('$home/')) text = `/root/${text.slice('$home/'.length)}`;
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

/** How many path levels sit below the tree root (`/etc` → 0, `/etc/passwd` → 1). */
function depthBelowTree(target) {
  return target.split('/').filter((part) => part.length > 0).length - 1;
}

/**
 * Does removing/overwriting this target scrap the system?
 *
 * A recursive or wildcard removal of a system tree is always fatal; a precise,
 * non-recursive removal of ONE file two or more levels down (`/etc/nginx/site.conf`)
 * is ordinary maintenance, while the tree root itself or a file directly in it
 * (`/etc/passwd`) is not.
 */
function isSystemDestruction(target, { recursive = false, sweep = false } = {}) {
  const clean = normalizeTargetPath(target);
  if (clean === '/' || clean === '/*') return true;
  if (!clean.startsWith('/')) return false;
  if (WHOLE_ROOT.test(clean) || WHOLE_VAR.test(clean)) return true;
  if (SYSTEM_STATE_WHOLE.test(clean) || PACKAGE_STATE.test(clean)) return true;
  if (DEV_SCRATCH.test(clean)) return false;
  if (!SYSTEM_TREE.test(clean)) return false;
  if (recursive || sweep) return true;
  if (clean.includes('*')) return true;
  return depthBelowTree(clean) < 2;
}

/**
 * Whether a recursive `chmod`/`chown` target can lock the operator out or break
 * the machine: the root directory, a system tree, the whole of `/var` or
 * `/root`, or the package state database. Business directories are not in here.
 */
function isPermissionCritical(target) {
  const clean = normalizeTargetPath(target);
  if (clean === '/' || clean === '/*') return true;
  if (!clean.startsWith('/')) return false;
  if (WHOLE_ROOT.test(clean) || WHOLE_VAR.test(clean)) return true;
  if (SYSTEM_STATE_WHOLE.test(clean) || PACKAGE_STATE.test(clean)) return true;
  return SYSTEM_TREE.test(clean);
}

/**
 * The targets a removal segment could destroy: arguments of `rm`/`shred`/`mv`
 * and the path arguments of a `find … -delete` (or `find … -exec rm`).
 * Only absolute (or `~`, or `*`-root) tokens are collected: a bare relative
 * name means something only in combination with a `cd`, which the chain rule
 * `danger.cd-bulk-delete` judges separately.
 */
function removalTargets(segment, { find = false, dropLast = false } = {}) {
  const targets = [];
  for (const word of segment.split(/\s+/).slice(1)) {
    if (word.startsWith('-') || /^\w+=/.test(word) || /^[;&|()]+$/.test(word)) continue;
    const clean = cleanTarget(word);
    // Rules match the lowercased segment, so `$HOME` arrives as `$home`.
    const home = clean === '~' || clean.startsWith('~/') || clean === '$home' || clean === '${home}'
      || clean.startsWith('$home/') || clean.startsWith('${home}/');
    const rooted = clean.startsWith('/') || home;
    // `find` takes only real paths; `rm`/`mv` also take the `*`/`/*` sweep forms.
    if (find ? !rooted : !(rooted || clean === '*' || clean === '/*')) continue;
    targets.push(clean);
  }
  // `mv` destroys the thing it moves, not the place it lands: drop the
  // destination so `mv /tmp/app.conf /etc/nginx/conf.d/` stays ordinary work.
  if (dropLast && targets.length > 0) targets.pop();
  return targets;
}

/**
 * Whether a segment carries a short-flag cluster (or the named long flag).
 * `-rf`, `-R`, `-vf` and `--force` all need to be recognized; a textual
 * `[a-z]*f` pattern would miss clustered flags such as `-fv`.
 */
function hasFlag(segment, letter, long = '') {
  for (const token of String(segment).split(/\s+/)) {
    if (/^-[A-Za-z]+$/.test(token) && token.slice(1).toLowerCase().includes(letter)) return true;
    if (long.length > 0 && token === `--${long}`) return true;
  }
  return false;
}

/** /dev/null and /dev/zero: a copy from one of these only ever erases. */
const VOID_SOURCE = /^(?:\/dev\/(?:null|zero)|:)$/;

/**
 * The concrete paths a segment overwrites with a destructive SHAPE.
 *
 * Conservative on purpose: copying a real file over another (a deploy, a
 * restore) is left to the ordinary rules, while a copy FROM a void device, a
 * tee, a raw dd of=, an in-place sed -i or a shell redirect only ever erases
 * or rewrites the target.
 */
function overwriteTargets(segment) {
  const targets = [];
  for (const match of segment.matchAll(/(?:^|[\s;&|()])(?:&>{1,2}|>{1,2}&?|:>)\s*(\S+)/g)) targets.push(match[1]);
  for (const match of segment.matchAll(/(?:^|\s)of=(\S+)/g)) targets.push(match[1]);
  const words = segment.split(/\s+/).filter((word) => word.length > 0 && !word.startsWith('-'));
  const head = words[0];
  if (head === 'tee') for (const word of words.slice(1)) targets.push(word);
  if ((head === 'sed' || head === 'perl') && hasFlag(segment, 'i', 'in-place')) {
    // sed -i <script> <file>: drop the command and the script, keep the files.
    for (const word of words.slice(2)) targets.push(word);
  }
  if (head === 'cp' || head === 'install') {
    // The void source may sit anywhere before the destination: skip a mode
    // operand such as the 644 in install -m 644 /dev/null X.
    const args = words.slice(1);
    const voidIndex = args.findIndex((word) => VOID_SOURCE.test(cleanTarget(word)));
    if (voidIndex >= 0 && voidIndex < args.length - 1) targets.push(args.at(-1));
  }
  return targets;
}

/** The six shapes that make the machine unbootable. */
const RULES = [
  {
    id: 'danger.rm-root',
    title: '删除或移走系统关键目录',
    test: (segment) => {
      const removing = /\b(?:rm|shred|mv|unlink|rmdir)\b/.test(segment);
      // `find <system tree> -delete` (or `-exec rm`) is the same wholesale
      // removal expressed without `rm`, so it must be recognized too.
      const finding = /\bfind\b[^;&|]*(?:-delete|-exec\s+(?:rm|shred|unlink|rmdir))\b/.test(segment);
      // `rsync --delete <src> <system tree>` empties everything the source does
      // not have — a recursive removal aimed at the destination (the source is
      // read, not destroyed, so it is never judged).
      const syncing = /\brsync\b/.test(segment)
        && /--delete\b/.test(segment)
        && !/--dry-run\b/.test(segment)
        && !/\s-[a-z]*n[a-z]*\b/.test(segment);
      if (!removing && !finding && !syncing) return false;
      if (syncing) {
        const absolute = segment.split(/\s+/).map(cleanTarget).filter((token) => token.startsWith('/') || token === '~' || token.startsWith('~/'));
        const destination = absolute.at(-1);
        return destination !== undefined && isSystemDestruction(destination, { recursive: true });
      }
      const recursive = /\s-{1,2}[a-z-]*[rR][a-z-]*/i.test(segment) || /\s--recursive\b/i.test(segment);
      // `mv` destroys what it moves, not where it lands.
      const moving = /\bmv\b/.test(segment) && !/\b(?:rm|shred)\b/.test(segment);
      const targets = [...removalTargets(segment, { dropLast: moving }), ...(finding ? removalTargets(segment, { find: true }) : [])];
      // `find` walks recursively by definition, so any system-tree target named
      // by it is a sweep; `rm`/`mv` only when asked to recurse.
      return targets.some((target) => isSystemDestruction(target, { recursive, sweep: finding }));
    },
    reason: '这条命令会递归或整目录删除系统关键目录，系统将无法启动，只能从备份或面板重建。',
    suggestion: '先 `ls -lh <dir>` 确认目标，再逐个删除明确路径下的单个文件，每次只删一个已确认的文件；日志轮转交给 logrotate -f /etc/logrotate.d/<name>。不要对系统目录做递归或通配删除。'
  },
  {
    id: 'danger.cd-bulk-delete',
    scope: 'command',
    title: '切换目录后批量删除',
    test: (segment) => {
      // Path rules judge a single segment on purpose, so a `cd` in one segment
      // and a relative bulk delete in the next would otherwise slip through
      // (`cd / && rm -rf *`). This chain-shaped rule covers it without making
      // the path rules match unrelated segments. Relative targets are resolved
      // against the `cd` directory so `cd / && rm -rf etc` gets the same verdict
      // as its absolute form.
      for (const cd of segment.matchAll(/(?:^|[;&|(]|\s)cd\s+(\/[^\s;&|)]*)/g)) {
        const dir = normalizeTargetPath(cd[1]);
        if (!dir.startsWith('/')) continue;
        const systemDir = dir === '/'
          || SYSTEM_TREE.test(dir)
          || WHOLE_ROOT.test(dir)
          || WHOLE_VAR.test(dir)
          || SYSTEM_STATE_WHOLE.test(dir)
          || PACKAGE_STATE.test(dir);
        if (!systemDir) continue;
        const rest = segment.slice(cd.index + cd[0].length);
        // `rm -rf x` and `mv x /tmp` both lose what `x` names; a move's
        // destination is where it lands, not what disappears.
        const mutation = /\b(rm|mv|unlink|rmdir)\b([^;&|]*)/.exec(rest);
        if (mutation !== null) {
          const recursive = hasFlag(mutation[2], 'r', 'recursive');
          const words = mutation[2].split(/\s+/).filter((word) => word.length > 0 && !word.startsWith('-') && !/^\w+=/.test(word) && !/^[;&|()]+$/.test(word));
          if (mutation[1] === 'mv' && words.length > 1) words.pop();
          for (const word of words) {
            const clean = cleanTarget(word);
            const resolved = clean.startsWith('/')
              ? normalizeTargetPath(clean)
              : normalizeTargetPath(`${dir.replace(/\/$/, '')}/${clean}`);
            if (isSystemDestruction(resolved, { recursive })) return true;
          }
        }
        // `find . -delete` after a `cd` into a system tree is the same sweep.
        if (/\bfind\b[^;&|]*(?:-delete|-exec\s+(?:rm|shred|unlink|rmdir))\b/.test(rest)) return true;
      }
      return false;
    },
    reason: '先切换进系统关键目录再整目录删除，等于删掉整个目录树，系统将无法启动。',
    suggestion: '不要先切换目录再用通配符删除；改用绝对路径，只删除确认过的具体目标，并先 `ls -lh <dir>` 看清内容；系统目录的维护交给包管理器或人工在维护窗口执行。'
  },
  {
    id: 'danger.fs-format',
    title: '格式化或分区设备',
    test: (segment) => /\b(?:mkfs(?:\.\w+)?|wipefs|mkswap|fdisk|sfdisk|parted|badblocks)\b/.test(segment),
    reason: '格式化或重新分区会瞬间销毁文件系统，磁盘上的内容只能从备份或面板重建。',
    suggestion: '先确认设备与挂载状态：lsblk、findmnt <dev>、mount | grep <dev>；这类操作应在维护窗口由人工执行。'
  },
  {
    id: 'danger.dd-device',
    title: '把数据直接写入设备',
    test: (segment) => {
      if (!/\bdd\b/.test(segment)) return false;
      for (const match of segment.matchAll(/(?:^|\s)of=(\S+)/g)) {
        if (WRITABLE_DEVICE.test(normalizeTargetPath(match[1]))) return true;
      }
      return false;
    },
    reason: '把镜像或数据直接写到设备会覆盖磁盘与文件系统，原内容只能从备份或面板重建。',
    suggestion: '只对具体文件做有界写入：dd if=… of=/tmp/probe bs=1M count=10；确认设备与挂载状态用 lsblk、findmnt <dev>。'
  },
  {
    id: 'danger.overwrite-device',
    title: '覆盖或截断设备与系统关键文件',
    test: (segment) => {
      const targets = [];
      // Judge every redirect in the segment, not just the first: a second `>`
      // must not smuggle a system file in behind an innocent `/tmp` target.
      // `&>`, `>&` and `:>` are the same overwrite spelled differently.
      for (const match of segment.matchAll(/(?:^|[\s;&|()])(?:&>{1,2}|>{1,2}&?|:>)\s*(\/\S+)/g)) targets.push(match[1]);
      // `truncate` is the same overwrite with zero bytes: truncating a device or
      // a system file is as fatal as redirecting over it.
      if (/\btruncate\b/.test(segment)) {
        for (const word of segment.split(/\s+/).slice(1)) {
          if (word.startsWith('-') || /^\w+=/.test(word)) continue;
          const clean = cleanTarget(word);
          if (clean.startsWith('/') || clean === '~' || clean.startsWith('~/')) targets.push(clean);
        }
      }
      // cp /dev/null X, tee X, dd of=X and an in-place sed -i X erase or
      // rewrite the target just like a redirect does; devices and system
      // trees are still the only targets this danger rule owns.
      for (const target of overwriteTargets(segment)) targets.push(target);
      if (targets.length === 0) return false;
      return targets.some((target) => {
        const clean = normalizeTargetPath(target);
        // A single log file (`: > /var/log/app.log`) keeps the inode and
        // permissions and stays ordinary space reclamation; devices and system
        // trees are hard wipes.
        if (WRITABLE_DEVICE.test(clean)) return true;
        // Any other `/dev` node (null, stdout, a pty, /dev/shm …) is not the disk.
        if (clean.startsWith('/dev/')) return false;
        return SYSTEM_TREE.test(clean) || clean === '/' || clean === '/*';
      });
    },
    reason: '覆写或截断设备/系统关键文件会立刻破坏文件系统或登录与提权通道，系统通常只能从备份或面板重建。',
    suggestion: '回收单个日志文件的空间请对那一个文件做截断，或交给 logrotate 按单份配置轮转：先 `ls -lh <file>` 确认目标，保留 inode 与文件权限；不要对设备文件、系统关键文件或通配符做覆写。'
  },
  {
    id: 'danger.recursive-chmod-root',
    title: '递归修改系统目录权限',
    test: (segment) => {
      if (!/\bch(?:mod|own|grp)\b/.test(segment)) return false;
      if (!hasFlag(segment, 'r', 'recursive')) return false;
      for (const word of segment.split(/\s+/).slice(1)) {
        if (word.startsWith('-') || /^\w+=/.test(word) || /^[;&|()]+$/.test(word)) continue;
        const clean = cleanTarget(word);
        const home = clean === '~' || clean.startsWith('~/');
        if (!clean.startsWith('/') && !home) continue;
        if (isPermissionCritical(home ? '~' : clean)) return true;
      }
      return false;
    },
    reason: '递归修改系统目录或根目录的权限会让服务、登录与提权通道失效，系统通常只能从备份或面板重建。',
    suggestion: '不建议对系统目录递归改权限：先 `ls -ld <dir>` 与 `namei -l <path>` 确认目标，再只对需要的具体子树授权；需要批量修复权限时用包管理器校验或按服务目录逐个处理。'
  }
];

/** Split a command into independently checkable segments, following nesting. */
export function splitSegments(command) {
  const segments = [];
  const visit = (text, depth) => {
    if (depth > 4 || typeof text !== 'string' || text.length === 0) return;
    for (const match of text.matchAll(/\b(?:ba|z|da|k)?sh\s+-c\s+(['"])([\s\S]*?)\1/g)) visit(match[2], depth + 1);
    for (const match of text.matchAll(/\$\(([^()]*)\)/g)) visit(match[1], depth + 1);
    for (const match of text.matchAll(/`([^`]*)`/g)) visit(match[1], depth + 1);
    for (const match of text.matchAll(/\beval\s+(['"])([\s\S]*?)\1/g)) visit(match[2], depth + 1);
    for (const part of text.split(/&&|\|\||;|\||\n/)) {
      const trimmed = part.trim();
      if (trimmed.length > 0) segments.push(trimmed);
    }
  };
  visit(command, 0);
  return segments.map(normalizeSegment);
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
    .replace(/["']/g, '')
    .replace(/\\(?=\S)/g, '')
    .replace(/\s+/g, ' ')
    .trim();
  return { raw: text, flat, lower: flat.toLowerCase() };
}

/** Match one rule against one normalized segment (rules are written lowercase). */
function matches(rule, segment, context) {
  try {
    return rule.test(segment.lower, context) === true;
  } catch {
    return false;
  }
}

/**
 * Build the policy engine.
 *
 * There is one host-independent list, so `evaluate` needs only the command. The
 * result is `{ action: 'allow' }` or a denial naming every rule that matched.
 */
export function createPolicy() {
  const evaluate = ({ command } = {}) => {
    try {
      if (typeof command !== 'string' || command.trim().length === 0) return { action: 'allow' };
      const whole = normalizeSegment(command);
      // Context carries the whole command for the two jobs a split segment
      // cannot do alone: a pipeline bound and the chain-shaped rules marked
      // `scope: 'command'`.
      const context = { command: whole.lower };
      const segments = splitSegments(command);
      // Path-shaped rules judge only their own segment: a `/var/log` reference
      // in a *different* segment must not poison a harmless `rm -f /tmp/…`.
      const hits = [];
      for (const rule of RULES) {
        const candidates = rule.scope === 'command' ? [whole, ...segments] : segments;
        if (candidates.some((segment) => matches(rule, segment, context))) hits.push(rule);
      }
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
      '唯一门禁：会让整台机器报废的操作。包括递归/通配删除系统关键目录（/、/etc、/usr、/boot、/var/lib 等）、mkfs/分区、dd 或 > 写块设备、覆写系统关键文件、递归 chmod/chown 系统目录。',
      '业务目录（/srv、/home、/opt、/var/www、/data）和普通数据删除不在门禁内；先备份，再按明确路径操作。',
      '查日志用 ssh_read/ssh_grep/ssh_check，或 journalctl --since/--until + -n、tail -n、grep -m 等有界写法；数字只是示例，按日志密度和问题时间窗调整，不要把某个固定值当边界。被拒时按提示改成单文件、绝对路径。'
    ].join('\n');

  return { evaluate, hints };
}

/**
 * Whether a file-tool write target is one of the unrecoverable destinations the
 * shell guard would refuse: a block device, or a system boot/kernel path.
 *
 * Config files under `/etc` stay writable through the file tools — that is
 * ordinary maintenance — while the shell guard still refuses a redirect over a
 * system tree.
 */
export function protectedWritePath(path) {
  const clean = normalizeTargetPath(path);
  if (clean.length === 0 || !clean.startsWith('/')) return null;
  if (WRITABLE_DEVICE.test(clean)) {
    return {
      rule: 'danger.write-device',
      title: '写入块设备',
      reason: '把文件写到块设备会覆盖磁盘与文件系统，原内容只能从备份或面板重建。',
      suggestion: '文件工具的写入目标是普通文件；镜像写入应在维护窗口用人工确认的设备路径执行。'
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
  return null;
}

export { RULES };
