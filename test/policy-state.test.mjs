/**
 * The guard's own decision and its model-facing denial must agree.
 *
 * There is no per-host switch any more: `denyMessage` names the host and the
 * rule without a tier, and points at `ssh_hosts` for the policy hints.
 */
import { createPolicy } from '../lib/policy.js';
import { denyMessage } from '../index.js';

const policy = createPolicy();

let pass = 0;
const failures = [];
const check = (name, ok, detail) => (ok ? (pass += 1) : failures.push(`${name}: ${detail}`));

const denial = policy.evaluate({ alias: 'prod', command: 'rm -rf /etc' });
const text = denyMessage(denial, 'prod');
check('denial-names-host', /主机 prod/.test(text), text);
check('denial-names-rule', /danger\.rm-root/.test(text), text);
check('denial-no-tier', !/档位|完全档|生产档/.test(text), text);
check('denial-points-at-hosts', /ssh_hosts/.test(text) && /policy/.test(text), text);

// A hidden host gets the same verdict: the guard has no per-host state any
// more, and visibility is a tool-layer gate, not a policy tier.
const hiddenDenial = policy.evaluate({ alias: 'hidden', command: 'rm -rf /etc' });
check('same-verdict', hiddenDenial.action === 'deny' && hiddenDenial.rule === denial.rule, JSON.stringify(hiddenDenial));

// Ordinary admin/data work is allowed for every host.
for (const command of ['shutdown -h now', 'rm -rf /var/lib/mysql', 'iptables -F', 'dpkg -i x.deb']) {
  check(`allow:${command}`, policy.evaluate({ alias: 'prod', command }).action === 'allow', JSON.stringify(policy.evaluate({ alias: 'prod', command })));
}

console.log(`${pass}/${pass + failures.length} passed`);
for (const failure of failures) console.log(`FAIL ${failure}`);
process.exit(failures.length === 0 ? 0 : 2);
