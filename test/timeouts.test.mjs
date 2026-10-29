/**
 * Command deadlines are derived, not fixed: estimate × multiplier, clamped.
 *
 * These cases pin down the classifier buckets, the caller override, the
 * multiplier/floor/ceiling clamps, and the fact that nothing can end up without
 * a finite deadline.
 */
import { deadlineFor, estimateFor } from '../lib/timeouts.js';

let pass = 0;
const failures = [];
const check = (name, ok, detail) => (ok ? (pass += 1) : failures.push(`${name}: ${detail}`));

const estimate = (command) => estimateFor(command).estimateMs;
check('probe-bucket', estimate('ls -la /var/log') === 5000 && estimate('echo hi') === 5000 && estimate('systemctl status nginx') === 5000, `${estimate('ls -la /var/log')}/${estimate('echo hi')}`);
check('read-bucket', estimate('tail -n 200 /var/log/syslog') === 15000 && estimate('grep -m 20 err /var/log/app.log') === 15000, `${estimate('tail -n 200 /var/log/syslog')}`);
check('file-bucket', estimate('cp -r /srv/app /srv/app.bak') === 30000, `${estimate('cp -r /srv/app /srv/app.bak')}`);
check('service-bucket', estimate('systemctl restart nginx') === 60000, `${estimate('systemctl restart nginx')}`);
check('build-bucket', estimate('apt-get install -y nginx') === 600000 && estimate('npm ci') === 600000, `${estimate('apt-get install -y nginx')}`);
check('backup-bucket', estimate('mysqldump app > /backup/app.sql') === 900000 && estimate('rsync -a /a /b') === 900000, `${estimate('mysqldump app > /backup/app.sql')}`);
check('unknown-uses-fallback', estimate('frobnicate --everything') === 30000, `${estimate('frobnicate --everything')}`);
check('fallback-overridable', estimateFor('frobnicate', 12000).estimateMs === 12000, 'fallbackEstimateMs must be honoured');

// Multiplier and clamps.
const plain = deadlineFor({ command: 'frobnicate', fallbackEstimateMs: 30000 });
check('multiplier-applied', plain.timeoutMs === 90000 && plain.estimateMs === 30000 && plain.multiplier === 3, JSON.stringify(plain));
const custom = deadlineFor({ command: 'frobnicate', fallbackEstimateMs: 30000, multiplier: 3 });
check('custom-multiplier', custom.timeoutMs === 90000, JSON.stringify(custom));
const floored = deadlineFor({ command: 'echo hi', floorMs: 20000 });
check('floor-applies', floored.timeoutMs === 20000, JSON.stringify(floored));
const ceilinged = deadlineFor({ command: 'apt-get install -y x', ceilingMs: 120000 });
check('ceiling-applies', ceilinged.timeoutMs === 120000, JSON.stringify(ceilinged));
const weird = deadlineFor({ command: 'x', multiplier: 0, floorMs: -5, ceilingMs: 10 });
check('clamps-sane', weird.multiplier === 3 && weird.timeoutMs >= 1000 && Number.isFinite(weird.timeoutMs), JSON.stringify(weird));

// The caller's own estimate always wins over the classifier.
const caller = deadlineFor({ command: 'apt-get install -y x', expectedMs: 40000 });
check('expected-ms-wins', caller.estimateMs === 40000 && caller.timeoutMs === 120000 && caller.source === 'expectedMs', JSON.stringify(caller));
const callerFloored = deadlineFor({ command: 'ls', expectedMs: 100 });
check('expected-ms-floored', callerFloored.estimateMs === 100 && callerFloored.timeoutMs === 5000, JSON.stringify(callerFloored));

// Every input shape still yields a finite, positive deadline.
for (const input of [undefined, {}, { command: null }, { command: 'x', expectedMs: -1 }, { command: 'x', expectedMs: 'soon' }, { command: 'x', multiplier: 'fast' }]) {
  const result = deadlineFor(input);
  check(`finite@${JSON.stringify(input)}`, Number.isFinite(result.timeoutMs) && result.timeoutMs > 0, JSON.stringify(result));
}

// Network and certificate work is not a 5-second probe: it must survive a slow
// handshake or an ACME round trip, otherwise the agent sees timeouts it will
// work around by hand.
check('network-bucket', estimate('curl -sI https://example.com') === 120000 && estimate('dig +short example.com') === 120000 && estimate('git clone https://github.com/a/b') === 120000, `${estimate('curl -sI https://example.com')}`);
check('certificate-bucket', estimate('certbot renew --dry-run') === 300000 && estimate('caddy reload --config /etc/caddy/Caddyfile') === 300000 && estimate('sing-box check -c /etc/sing-box/config.json') === 300000, `${estimate('certbot renew --dry-run')}`);
check('docker-inspect-bucket', estimate('docker logs --tail 100 sing-box') === 60000 && estimate('docker ps -a') === 60000, `${estimate('docker logs --tail 100 sing-box')}`);

// Escalation: a fired deadline can be retried once with a longer one.

console.log(`${pass}/${pass + failures.length} passed`);
for (const failure of failures) console.log(`FAIL ${failure}`);
process.exit(failures.length === 0 ? 0 : 2);
