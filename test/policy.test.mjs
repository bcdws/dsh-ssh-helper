/**
 * The single guard: engine mechanics, the six rule ids, normalization and the
 * file-tool write target check.
 *
 * The acceptance table (what is refused / what stays ordinary work) lives in
 * safety.test.mjs; this suite pins the pieces around it.
 */
import { RULES, createPolicy, normalizeSegment, protectedWritePath, splitSegments } from '../lib/policy.js';

let pass = 0;
const failures = [];
const check = (name, ok, detail) => (ok ? (pass += 1) : failures.push(`${name}: ${detail}`));
const policy = createPolicy();
const verdict = (command) => policy.evaluate({ command });

// ── the rule set is exactly the six machine-destroying shapes ───────────────
const ids = RULES.map((rule) => rule.id).sort();
check(
  'rule-ids',
  JSON.stringify(ids) === JSON.stringify([
    'danger.cd-bulk-delete',
    'danger.dd-device',
    'danger.fs-format',
    'danger.overwrite-device',
    'danger.recursive-chmod-root',
    'danger.rm-root'
  ]),
  JSON.stringify(ids)
);
check('no-tier-field', RULES.every((rule) => !('tier' in rule)), JSON.stringify(RULES.map((rule) => Object.keys(rule))));

// ── evaluate ────────────────────────────────────────────────────────────────
check('empty-allows', verdict('').action === 'allow' && verdict('   ').action === 'allow', 'empty command');
check('non-string-allows', policy.evaluate({ command: undefined }).action === 'allow' && policy.evaluate({}).action === 'allow', 'missing command');
check('benign-allows', verdict('uptime && df -h /').action === 'allow', JSON.stringify(verdict('uptime && df -h /')));
check('danger-denies', verdict('rm -rf /etc').action === 'deny', JSON.stringify(verdict('rm -rf /etc')));
const multiple = verdict('rm -rf /etc && mkfs.ext4 /dev/sda');
check('denial-names-every-hit', multiple.action === 'deny' && multiple.matches.length >= 2, JSON.stringify(multiple.matches));
check('denial-shape', multiple.rule === 'danger.rm-root' && typeof multiple.title === 'string' && typeof multiple.reason === 'string' && typeof multiple.suggestion === 'string', JSON.stringify(multiple));
check('host-independent', JSON.stringify(policy.evaluate({ alias: 'a', command: 'rm -rf /etc' })) === JSON.stringify(policy.evaluate({ alias: 'b', command: 'rm -rf /etc' })), 'the guard has no per-host state');
check('hints-mention-system', /系统关键目录|mkfs|块设备/.test(policy.hints()), policy.hints());

// ── normalization ───────────────────────────────────────────────────────────
const plain = normalizeSegment('  sudo rm   -rf   "/etc"  ');
check('normalize-wrapper', plain.flat === 'rm -rf /etc' && plain.lower === 'rm -rf /etc', JSON.stringify(plain));
check('normalize-backslash', normalizeSegment('r\\m -rf /etc').flat === 'rm -rf /etc', JSON.stringify(normalizeSegment('r\\m -rf /etc')));
const segments = splitSegments('echo a && rm -rf /etc; tail -n 5 /var/log/x | grep y');
check('split-count', segments.length === 4, JSON.stringify(segments.map((part) => part.flat)));
check('split-nested', splitSegments("bash -c 'rm -rf /etc'").some((part) => part.flat === 'rm -rf /etc'), JSON.stringify(splitSegments("bash -c 'rm -rf /etc'")));
check('split-substitution', splitSegments('echo $(rm -rf /etc)').some((part) => part.flat.includes('rm -rf /etc')), JSON.stringify(splitSegments('echo $(rm -rf /etc)')));

// ── file-tool write targets ─────────────────────────────────────────────────
check('write-block-device', protectedWritePath('/dev/sda')?.rule === 'danger.write-device', JSON.stringify(protectedWritePath('/dev/sda')));
check('write-nvme', protectedWritePath('/dev/nvme0n1p1')?.rule === 'danger.write-device', JSON.stringify(protectedWritePath('/dev/nvme0n1p1')));
check('write-boot', protectedWritePath('/boot/vmlinuz')?.rule === 'danger.write-system', JSON.stringify(protectedWritePath('/boot/vmlinuz')));
check('write-proc', protectedWritePath('/proc/sys/kernel/panic')?.rule === 'danger.write-system', JSON.stringify(protectedWritePath('/proc/sys/kernel/panic')));
check('write-dev-null-allowed', protectedWritePath('/dev/null') === null, JSON.stringify(protectedWritePath('/dev/null')));
check('write-dev-shm-allowed', protectedWritePath('/dev/shm/x') === null, JSON.stringify(protectedWritePath('/dev/shm/x')));
check('write-config-allowed', protectedWritePath('/etc/nginx/nginx.conf') === null, JSON.stringify(protectedWritePath('/etc/nginx/nginx.conf')));
check('write-business-allowed', protectedWritePath('/srv/app/config.yml') === null, JSON.stringify(protectedWritePath('/srv/app/config.yml')));
check('write-traversal', protectedWritePath('/srv/../../boot/vmlinuz')?.rule === 'danger.write-system', JSON.stringify(protectedWritePath('/srv/../../boot/vmlinuz')));

console.log(`${pass}/${pass + failures.length} passed`);
for (const failure of failures) console.log(`FAIL ${failure}`);
process.exit(failures.length === 0 ? 0 : 2);
