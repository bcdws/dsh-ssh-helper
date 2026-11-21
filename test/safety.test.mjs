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
  ['cd-etc-relative', 'cd /etc && rm -rf nginx'],
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
  ['chown-recursive-root', 'chown -R nobody /']
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
  ['rsync-backup', 'rsync -a /srv/app/ /backup/app/']
];
for (const [name, command] of ordinary) check(`allow-${name}`, allowed(command), JSON.stringify(verdict(command)));

// A command hidden in a script file is outside a text guard's view; a plain
// shell invocation is not, so the common wrapper shapes stay covered.
check('wrapped-sudo', denied('sudo rm -rf /etc'), JSON.stringify(verdict('sudo rm -rf /etc')));
check('wrapped-substitution', denied('echo $(rm -rf /etc)'), JSON.stringify(verdict('echo $(rm -rf /etc)')));

// The guard is intentionally absent from the old admin/data semantics.
check('no-admin-layer', allowed('reboot') && allowed('visudo') && allowed('crontab -r'), 'admin commands must stay ordinary work');
check('no-data-layer', allowed('rm -rf /var/lib/mysql') && allowed('psql -c "drop database app"'), 'data deletion is not a guard concern any more');

// ── background logPath is a write target, guarded like the file tools ──────
// `ssh_run`'s background mode writes a log at a caller-chosen path. Without
// this check that path reached the remote shell unchecked, so a log could be
// aimed at a block device or a system tree that `ssh_write` refuses.
const writeRefused = [
  ['log-block-device', '/dev/sda'],
  ['log-boot', '/boot/grub/grub.cfg'],
  ['log-proc', '/proc/sys/kernel/hostname'],
  ['log-sys', '/sys/kernel/x']
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

// Ordinary log destinations stay ordinary work: business paths, /var/log, and
// the plugin's own default directory.
const writeAllowed = [
  ['log-var-log', '/var/log/app/app.log'],
  ['log-srv', '/srv/app/run.log'],
  ['log-default-dir', '/root/.local/state/dsh-ssh/logs/web-2026-01-01_00-00-00-abc.log'],
  ['log-home', '/home/deploy/app.log']
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

// A relative path carries no target to judge; the file tools let it through
// and so does this check (the remote shell resolves it).
let relativeError = null;
try {
  assertWritePathAllowed({ host: 'h', path: 'logs/app.log' });
} catch (thrown) {
  relativeError = thrown;
}
check('allow-log-relative', relativeError === null, String(relativeError?.message ?? ''));

console.log(`${pass}/${pass + failures.length} passed`);
for (const failure of failures) console.log(`FAIL ${failure}`);
process.exit(failures.length === 0 ? 0 : 2);
