/**
 * Safety acceptance for the single guard.
 *
 * Only the unrecoverable shapes are refused. Everything that used to be
 * `admin`/`data`/`advice` — shutdown, users, firewall changes, package work,
 * service restarts, business data deletion, log cleanup — must stay ordinary
 * work on every host.
 */
import { createPolicy, assertWritePathAllowed } from '../lib/policy.js';

const policy = createPolicy();
const verdict = (command) => policy.evaluate({ command });
const allowed = (command) => verdict(command).action === 'allow';
const denied = (command) => verdict(command).action === 'deny';

let pass = 0;
const failures = [];
const check = (name, ok, detail) => (ok ? (pass += 1) : failures.push(`${name}: ${detail}`));
const refused = [
  ['rm-root', 'rm -rf /'],
  ['rm-root-star', 'rm -rf /*'],
  ['rm-etc', 'rm -rf /etc'],
  ['rm-etc-slash', 'rm -rf /etc/'],
  ['rm-var', 'rm -rf /var'],
  ['rm-var-lib', 'rm -rf /var/lib'],
  ['rm-package-state', 'rm -rf /var/lib/dpkg'],
  ['rm-root-home', 'rm -rf /root'],
  ['rm-boot', 'rm -rf /boot'],
  ['find-root-delete', 'find / -delete'],
  ['find-etc-delete', "find /etc -name '*.conf' -delete"],
  ['cd-root-wildcard', 'cd / && rm -rf *'],
  ['cd-etc-ssh', 'cd /etc && rm -rf ssh'],
  ['cd-var-relative', 'cd /var && rm -rf lib'],
  ['mv-etc', 'mv /etc /tmp/backup'],
  ['sudo-wrapper', 'sudo rm -rf /usr'],
  ['shell-c', "bash -c 'rm -rf /etc'"],
  ['rsync-delete-etc', 'rsync --delete /tmp/empty/ /etc/'],
  ['mkfs', 'mkfs.ext4 /dev/sda1'],
  ['wipefs', 'wipefs -a /dev/sdb'],
  ['fdisk', 'fdisk /dev/sda'],
  ['parted', 'parted /dev/sda mklabel gpt'],
  // A listing flag must not become a foothold: the write modes stay refused.
  ['parted-rm', 'parted /dev/sda rm 1'],
  ['parted-script-mkpart', 'parted -s /dev/sda mkpart primary 0% 100%'],
  ['sfdisk-write-mode', 'sfdisk /dev/sdb'],
  ['fdisk-list-redirect-etc', 'fdisk -l > /etc/passwd'],
  ['mkfs-dry-run', 'mkfs.ext4 -n /dev/sda'],
  ['wipefs-dry-run', 'wipefs -n /dev/sda'],
  ['dd-device', 'dd if=/dev/zero of=/dev/sda bs=1M'],
  ['dd-nvme', 'dd if=image.iso of=/dev/nvme0n1'],
  ['redirect-device', 'echo x > /dev/sda'],
  ['truncate-etc', ': > /etc/passwd'],
  ['cp-void-etc', 'cp /dev/null /etc/shadow'],
  ['truncate-device', 'truncate -s 0 /dev/sda'],
  ['sed-in-place-etc', "sed -i 's/x/y/' /etc/passwd"],
  ['chmod-recursive-etc', 'chmod -R 000 /etc'],
  ['chown-recursive-root', 'chown -R nobody /'],
  // Wildcards and braces are judged by what they can match.
  ['glob-question', 'rm -rf /e?c'],
  ['glob-class', 'rm -rf /e[t]c'],
  ['glob-prefix', 'rm -rf /et*'],
  ['glob-short', 'rm -rf /u*'],
  ['glob-double-star', 'rm -rf /**'],
  ['glob-two-levels', 'rm -rf /*/*'],
  ['glob-etc-contents', 'rm -f /etc/*'],
  ['glob-etc-dot-d', 'rm -rf /etc/*.d'],
  ['glob-libc', 'rm -f /usr/lib/x86_64-linux-gnu/libc*'],
  ['glob-var-contents', 'rm -rf /var/*'],
  ['brace-roots', 'rm -rf /{etc,usr}'],
  ['brace-etc-children', 'rm -rf /etc/{nginx,ssh}'],
  ['ansi-c-quote', "rm -rf $'/etc'"],
  // Variables: assigned in the command, from a for list, or unset (empty).
  ['var-assigned', 'D=/etc; rm -rf $D'],
  ['var-for-list', 'for d in /srv/a /usr/lib; do rm -rf $d; done'],
  ['var-for-glob', 'for f in /etc/*; do rm -rf "$f"; done'],
  ['var-default', 'rm -rf ${TARGET:-/etc}'],
  ['var-home-parent', 'rm -rf $HOME/..'],
  // A chain or pipeline that resolves to a system tree.
  ['pushd-wildcard', 'pushd /etc && rm -rf *'],
  ['subshell-cd', '(cd /usr/lib && rm -rf *)'],
  ['nested-cd', "bash -lc 'cd /etc && rm -rf *'"],
  ['xargs-echo', 'echo /etc | xargs rm -rf'],
  ['xargs-ls-d', 'ls -d /usr/lib | xargs rm -rf'],
  ['xargs-find', 'find /etc -type f -print0 | xargs -0 rm -f'],
  ['find-execdir', 'find /usr/lib/x86_64-linux-gnu -execdir rm {} +'],
  ['find-exec-path', 'find /etc -exec /bin/rm -f {} +'],
  ['find-relative-root', 'cd /etc && find . -delete'],
  ['rsync-del-alias', 'rsync -a --del /tmp/empty/ /etc/'],
  ['rsync-remove-source', 'rsync -a --remove-source-files /etc/ /backup/etc/'],
  // Critical files, single and precise.
  ['rm-passwd', 'rm -f /etc/passwd'],
  ['mv-shadow', 'mv /etc/shadow /tmp/'],
  ['rm-libc', 'rm -f /usr/lib/x86_64-linux-gnu/libc.so.6'],
  ['rm-bash', 'rm -f /usr/bin/bash'],
  ['rm-sshd', 'rm -f /usr/sbin/sshd'],
  ['rm-etc-ssh', 'rm -rf /etc/ssh'],
  ['rm-systemd-lib', 'rm -rf /usr/lib/systemd'],
  ['rm-multiarch', 'rm -rf /lib/x86_64-linux-gnu'],
  ['rm-boot-file', 'rm -f /boot/vmlinuz'],
  ['tee-passwd', 'echo x | tee /etc/passwd'],
  ['tee-glob-etc', 'echo x | tee /etc/*'],
  ['truncate-fstab', 'truncate -s 0 /etc/fstab'],
  ['redirect-fstab', 'echo x > /etc/fstab'],
  ['redirect-fd-shadow', 'cmd 2>/etc/shadow'],
  ['redirect-libc', ': > /lib/x86_64-linux-gnu/libc.so.6'],
  ['sed-shadow', "sed -i.bak '/^root/d' /etc/shadow"],
  ['dd-of-passwd', 'dd if=/dev/zero of=/etc/passwd bs=1 count=1'],
  // Writing a disk without dd.
  ['cp-to-disk', 'cp disk.img /dev/sda'],
  ['ddrescue-to-disk', 'ddrescue disk.img /dev/nvme0n1'],
  ['tee-to-disk', 'cat disk.img | tee /dev/sdb'],
  ['blkdiscard', 'blkdiscard /dev/sda'],
  ['sgdisk-zap', 'sgdisk --zap-all /dev/sda'],
  ['gdisk', 'gdisk /dev/sda'],
  ['cfdisk', 'cfdisk /dev/sda'],
  ['mke2fs', 'mke2fs /dev/sda1'],
  ['mkdosfs', 'mkdosfs /dev/sdb1'],
  ['mkswap-device', 'mkswap /dev/sdb2'],
  ['nvme-format', 'nvme format /dev/nvme0n1'],
  ['luks-format', 'cryptsetup luksFormat /dev/sda2'],
  ['vgremove', 'vgremove -f vg0'],
  ['pvremove', 'pvremove -ff /dev/sda2'],
  ['zpool-destroy', 'zpool destroy tank'],
  ['zfs-destroy-pool', 'zfs destroy -r tank'],
  ['mdadm-zero', 'mdadm --zero-superblock /dev/sda1'],
  ['hdparm-erase', 'hdparm --security-erase p /dev/sda'],
  ['badblocks-write', 'badblocks -w /dev/sda'],
  ['format-via-wrapper', 'timeout 60s wipefs -a /dev/sdb'],
  // Forced removal of essential packages.
  ['dpkg-force-essential', 'dpkg --purge --force-remove-essential libc6'],
  ['apt-allow-essential', 'apt-get remove -y --allow-remove-essential systemd'],
  ['rpm-nodeps-glibc', 'rpm -e --nodeps glibc'],
  ['yum-remove-glibc', 'yum remove -y glibc']
];
for (const [name, command] of refused) check(`refuse-${name}`, denied(command), JSON.stringify(verdict(command)));

const ordinary = [
  ['rm-srv-cache', 'rm -rf /srv/app/cache'],
  ['rm-home-old', 'rm -rf /home/deploy/app/old'],
  ['rm-node-modules', 'rm -rf /opt/app/node_modules'],
  ['rm-www-old', 'rm -rf /var/www/html.old'],
  ['rm-data-archive', 'rm -rf /data/db-archive'],
  ['rm-log-file', 'rm -f /var/log/app.log'],
  ['rm-tmp-build', 'rm -rf /tmp/build'],
  ['rm-docker-volume', 'rm -rf /var/lib/docker/volumes/old'],
  ['rm-nginx-conf', 'rm -f /etc/nginx/conf.d/old.conf'],
  ['redirect-tmp', 'echo hi > /tmp/x'],
  ['dd-tmp', 'dd if=/dev/zero of=/tmp/img bs=1M count=10'],
  // Read-only partition-table listings are diagnostics, not formats.
  ['list-fdisk-l', 'fdisk -l'],
  ['list-fdisk-l-dev', 'fdisk -l /dev/sda'],
  ['list-fdisk-sudo', 'sudo fdisk -l'],
  ['list-sfdisk-l', 'sfdisk -l /dev/sda'],
  ['list-sfdisk-dump', 'sfdisk -d /dev/sda'],
  ['list-parted-l', 'parted -l'],
  ['list-parted-print', 'parted /dev/sda print'],
  ['list-parted-print-free', 'parted /dev/sda print free'],
  ['truncate-log', 'truncate -s 0 /var/log/app.log'],
  ['mv-into-etc', 'mv /tmp/app.conf /etc/nginx/conf.d/'],
  ['apt-install', 'apt-get install nginx'],
  ['systemctl-restart', 'systemctl restart nginx'],
  ['shutdown', 'shutdown -h now'],
  ['useradd', 'useradd deploy'],
  ['firewall-append', 'iptables -A INPUT -p tcp --dport 80 -j ACCEPT'],
  ['firewall-flush', 'iptables -F'],
  ['sql-delete', 'mysql -e "delete from t where id = 1"'],
  ['chmod-srv', 'chmod -R 755 /srv/app'],
  ['chown-www', 'chown -R www-data /var/www'],
  ['find-log-delete', "find /var/log -name '*.gz' -delete"],
  ['rsync-backup', 'rsync -a /srv/app/ /backup/app/'],
  // Application config under /etc and anything under /usr/local is ordinary work.
  ['append-sysctl', 'echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf'],
  ['append-hosts', "echo '192.0.2.10 db' >> /etc/hosts"],
  ['heredoc-unit', "cat > /etc/systemd/system/app.service <<'EOF'\n[Unit]\nDescription=app\nEOF"],
  ['heredoc-nginx', "cat > /etc/nginx/conf.d/app.conf <<'EOF'\nserver {}\nEOF"],
  ['tee-nginx', 'tee /etc/nginx/conf.d/app.conf < /tmp/app.conf'],
  ['sed-sshd-config', "sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config"],
  ['sed-fstab-swap', "sed -i '/ swap / s/^/#/' /etc/fstab"],
  ['append-fstab', "echo '/dev/vdb1 /data ext4 defaults 0 2' >> /etc/fstab"],
  ['redirect-motd', '> /etc/motd'],
  ['truncate-motd', 'truncate -s 0 /etc/motd'],
  ['rm-localtime', 'rm -f /etc/localtime && ln -s /usr/share/zoneinfo/Asia/Shanghai /etc/localtime'],
  ['rm-resolv', 'rm -f /etc/resolv.conf'],
  ['rm-nginx-sites', 'rm -f /etc/nginx/sites-enabled/*'],
  ['rm-nginx-conf-glob', 'rm -f /etc/nginx/conf.d/*.conf'],
  ['mv-yum-repos', 'mv /etc/yum.repos.d/*.repo /tmp/repo-bak/'],
  ['rm-letsencrypt', 'rm -rf /etc/letsencrypt/live/old.example.com'],
  ['cd-etc-nginx', 'cd /etc && rm -rf nginx'],
  ['mv-nginx-dir', 'mv /etc/nginx /etc/nginx.bak'],
  ['go-install', 'rm -rf /usr/local/go && tar -C /usr/local -xzf go1.22.linux-amd64.tar.gz'],
  ['usr-local-bin', "printf '#!/bin/sh\\necho hi\\n' > /usr/local/bin/hello"],
  ['usr-local-curl', 'curl -fsSL https://example.com/x.sh > /usr/local/bin/x'],
  ['usr-local-rm', 'rm -rf /usr/local/lib/node_modules/pm2'],
  ['usr-share-nginx', 'rm -rf /usr/share/nginx/html/*'],
  ['chown-usr-local', 'chown -R deploy:deploy /usr/local/app'],
  ['chmod-usr-local-bin', 'chmod -R 755 /usr/local/bin'],
  ['chown-nginx-conf', 'chown -R www-data /etc/nginx'],
  ['chmod-root-home', 'chmod -R go-rwx /root'],
  ['mv-python-link', 'mv /usr/bin/python /usr/bin/python.bak'],
  ['rm-old-modules', 'rm -rf /lib/modules/5.4.0-old-generic'],
  ['rm-dpkg-lock', 'rm -f /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock'],
  ['rm-dpkg-lock-glob', 'rm -f /var/lib/dpkg/lock*'],
  ['rm-var-log-glob', 'rm -f /var/log/*.gz'],
  ['rm-root-tarballs', 'rm -f /root/*.tar.gz'],
  // Runtime tunables are not the disk.
  ['drop-caches', 'echo 3 > /proc/sys/vm/drop_caches'],
  ['ip-forward', 'echo 1 > /proc/sys/net/ipv4/ip_forward'],
  ['thp', 'echo never > /sys/kernel/mm/transparent_hugepage/enabled'],
  // Images and swap files are files; listings and installs touch no disk.
  ['mkswap-file', 'fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile'],
  ['mkfs-image', 'mkfs.ext4 -F /srv/disk.img'],
  ['parted-image', 'parted -s /srv/disk.img mklabel gpt'],
  ['sgdisk-print', 'sgdisk -p /dev/sda'],
  ['gdisk-list', 'gdisk -l /dev/sda'],
  ['badblocks-read', 'badblocks -sv /dev/sda'],
  ['install-parted', 'apt-get install -y parted gdisk'],
  ['man-fdisk', 'man fdisk'],
  ['fdisk-help', 'fdisk --help'],
  ['zfs-snapshot', 'zfs destroy tank/data@2026-01-01'],
  ['lvremove-snapshot', 'lvremove -f /dev/vg0/backup-snap'],
  ['cp-disk-backup', 'cp /dev/sda /srv/backup/disk.img'],
  ['yum-remove-pkg', 'yum remove -y httpd'],
  ['rpm-nodeps-other', 'rpm -e --nodeps httpd'],
  // Shapes that only look like a removal.
  ['rm-quiet-redirect', 'rm -rf /srv/app/cache > /dev/null'],
  ['docker-rm-flag', 'docker run --rm -v /etc/nginx:/etc/nginx nginx'],
  ['grep-for-rm', 'grep -rn "rm -rf" /srv/app'],
  ['var-guarded', 'rm -rf "${APP_DIR:?}"/*'],
  ['var-assigned-business', 'APP=/srv/app; rm -rf $APP/*'],
  ['var-unset-business', 'rm -rf $BUILD/node_modules'],
  ['var-from-substitution', 'D=$(mktemp -d); rm -rf $D/*'],
  ['relative-no-cwd', 'rm -rf *'],
  ['nested-cd-business', "bash -c 'cd /srv/app && rm -rf *'"]
];
for (const [name, command] of ordinary) check(`allow-${name}`, allowed(command), JSON.stringify(verdict(command)));

// ── the shell context: session cwd, cwd argument, exports, home ─────────────
const inShell = (command, shell) => policy.evaluate({ command, ...shell });
check('cwd-system-wildcard', inShell('rm -rf *', { cwd: '/etc' }).action === 'deny', JSON.stringify(inShell('rm -rf *', { cwd: '/etc' })));
check('cwd-business-wildcard', inShell('rm -rf *', { cwd: '/srv/app' }).action === 'allow', JSON.stringify(inShell('rm -rf *', { cwd: '/srv/app' })));
check('cwd-relative-child', inShell('rm -rf ssh', { cwd: '/etc' }).action === 'deny' && inShell('rm -rf nginx', { cwd: '/etc' }).action === 'allow', 'relative names resolve against the session directory');
check('cwd-then-cd', inShell('cd /srv/app && rm -rf *', { cwd: '/etc' }).action === 'allow', JSON.stringify(inShell('cd /srv/app && rm -rf *', { cwd: '/etc' })));
check('cwd-dotdot', inShell('rm -rf ../*', { cwd: '/etc/nginx' }).action === 'deny', JSON.stringify(inShell('rm -rf ../*', { cwd: '/etc/nginx' })));
check('env-resolves', inShell('rm -rf $APP/*', { env: { APP: '/srv/app' } }).action === 'allow', JSON.stringify(inShell('rm -rf $APP/*', { env: { APP: '/srv/app' } })));
check('env-system', inShell('rm -rf $APP', { env: { APP: '/usr/lib' } }).action === 'deny', JSON.stringify(inShell('rm -rf $APP', { env: { APP: '/usr/lib' } })));
const unset = inShell('rm -rf "$APP_DIR"/*', {});
check('unset-var-rule', unset.action === 'deny' && unset.rule === 'danger.empty-var-delete' && /\$\{VAR:\?\}/.test(unset.suggestion), JSON.stringify(unset));
check('unset-var-root', inShell('rm -rf $BUILD/', {}).rule === 'danger.empty-var-delete', JSON.stringify(inShell('rm -rf $BUILD/', {})));
check('home-non-root', inShell('rm -rf ~', { home: '/home/deploy' }).action === 'allow' && inShell('rm -rf ~', {}).action === 'deny', 'only root\'s home is protected');
check('pwd-variable', inShell('rm -rf $PWD/*', { cwd: '/usr/lib' }).action === 'deny' && inShell('rm -rf $PWD/*', {}).action === 'allow', '$PWD follows the known directory');

// A command hidden in a script file is outside a text guard's view; a plain
// shell invocation is not, so the common wrapper shapes stay covered.
check('wrapped-sudo', denied('sudo rm -rf /etc'), JSON.stringify(verdict('sudo rm -rf /etc')));
check('wrapped-substitution', denied('echo $(rm -rf /etc)'), JSON.stringify(verdict('echo $(rm -rf /etc)')));

// The guard is intentionally absent from the old admin/data semantics.
check('no-admin-layer', allowed('reboot') && allowed('visudo') && allowed('crontab -r'), 'admin commands must stay ordinary work');
check('no-data-layer', allowed('rm -rf /var/lib/mysql') && allowed('psql -c "drop database app"'), 'data deletion is not a guard concern any more');

// ── upload targets (ssh_transfer) ───────────────────────────────────────────
// An upload replaces a whole file, so it refuses what would scrap the machine:
// block devices, /boot, /proc, /sys, the account files, core binaries, libc.
const writeRefused = [
  ['upload-block-device', '/dev/sda'],
  ['upload-boot', '/boot/grub/grub.cfg'],
  ['upload-proc', '/proc/sys/kernel/hostname'],
  ['upload-sys', '/sys/kernel/x'],
  ['upload-shadow', '/etc/shadow'],
  ['upload-sudoers', '/etc/sudoers'],
  ['upload-libc', '/usr/lib/x86_64-linux-gnu/libc.so.6'],
  ['upload-bash', '/bin/bash']
];
for (const [name, path] of writeRefused) {
  let blocked = null;
  try {
    assertWritePathAllowed({ host: 'h', path });
  } catch (error) {
    blocked = error;
  }
  check(name, blocked !== null && /\[ssh-pool policy\]/.test(blocked.message), String(blocked?.message ?? 'allowed'));
}

// Ordinary destinations stay ordinary work: business paths, app config, fstab.
const writeAllowed = [
  ['upload-var-log', '/var/log/app/app.log'],
  ['upload-srv', '/srv/app/release.tar.gz'],
  ['upload-nginx-conf', '/etc/nginx/conf.d/app.conf'],
  ['upload-fstab', '/etc/fstab'],
  ['upload-usr-local', '/usr/local/bin/app'],
  ['upload-home', '/home/deploy/app.log']
];
for (const [name, path] of writeAllowed) {
  let error = null;
  try {
    assertWritePathAllowed({ host: 'h', path });
  } catch (thrown) {
    error = thrown;
  }
  check(`allow-${name}`, error === null, String(error?.message ?? ''));
}

// A relative path carries no target to judge (SFTP resolves it against the
// login directory).
let relativeError = null;
try {
  assertWritePathAllowed({ host: 'h', path: 'logs/app.log' });
} catch (thrown) {
  relativeError = thrown;
}
check('allow-upload-relative', relativeError === null, String(relativeError?.message ?? ''));

console.log(`${pass}/${pass + failures.length} passed`);
for (const failure of failures) console.log(`FAIL ${failure}`);
process.exit(failures.length === 0 ? 0 : 2);
