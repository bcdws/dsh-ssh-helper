/** Plan-mode and raw-local-ssh deletion policy. */
import { isDeleteCommand, isLocalSshDelete, isPlanActive } from '../dsh/plan-guard.js';

let pass = 0;
const failures = [];
const check = (name, ok, detail) => (ok ? (pass += 1) : failures.push(`${name}: ${detail}`));

for (const command of ['rm -rf /data/x', 'sudo rm /data/x', 'find /data -delete', 'rsync --delete a b', 'git clean -fd', 'truncate -s 0 /data/x', "sh -c 'rm -rf /data/x'", 'bash -c "rm -rf /data/x"']) {
  check(`delete: ${command}`, isDeleteCommand(command) === true, command);
}
for (const command of ['ls -la /data', 'grep rm /data/file', 'grep "rm" /data/file', 'find /data -name x', 'rsync a b', 'echo done']) {
  check(`not-delete: ${command}`, isDeleteCommand(command) === false, command);
}
check('local-ssh-delete', isLocalSshDelete('timeout 20 ssh -i ~/.ssh/key root@host "rm -rf /data/x"') === true, 'ssh delete');
check('local-ssh-read', isLocalSshDelete('ssh -i ~/.ssh/key root@host "ls -la /data"') === false, 'ssh read');
check('local-rm-not-ssh', isLocalSshDelete('rm -rf /tmp/x') === false, 'local rm');

const fakePlan = (state) => ({ get: () => state });
check('plan-active', isPlanActive(fakePlan({ active: true, pending: false }), {}) === true, 'active');
check('plan-pending', isPlanActive(fakePlan({ active: false, pending: true }), {}) === true, 'pending');
check('plan-inactive', isPlanActive(fakePlan({ active: false, pending: false }), {}) === false, 'inactive');
check('plan-no-agent', isPlanActive(fakePlan({ active: true, pending: true }), undefined) === false, 'no agent');
check('plan-missing-service', isPlanActive(undefined, {}) === false, 'missing service');
check('plan-throws', isPlanActive({ get() { throw new Error('no projection'); } }, {}) === false, 'throw');

console.log(`${pass}/${pass + failures.length} passed`);
for (const failure of failures) console.log(`FAIL ${failure}`);
process.exit(failures.length === 0 ? 0 : 2);
