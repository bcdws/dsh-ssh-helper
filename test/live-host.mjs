/**
 * Resolve the live test host.
 *
 * The live suites (smoke / race / errors) drive a real SSH server, so they only
 * run when `DSH_SSH_TEST_HOST` names a host from `~/.ssh/config` — a test run
 * must never go off and connect to whatever host happens to be configured
 * first. Without that variable the suites skip cleanly (exit 0), so
 * `npm test` is safe on any machine.
 */
import { buildHostTable, normalizeConfig } from '../lib/config.js';

export function liveHost() {
  const wanted = process.env.DSH_SSH_TEST_HOST ?? '';
  if (wanted.length === 0) {
    console.log('SKIP: the live suite needs a target host.');
    console.log('      Set DSH_SSH_TEST_HOST=<alias from ~/.ssh/config> to run it.');
    process.exit(0);
  }
  const config = normalizeConfig({ useSshConfig: true, hostKeyPolicy: 'warn' });
  const { hosts, warnings } = buildHostTable(config);
  if (!hosts.has(wanted)) {
    console.log(`SKIP: host "${wanted}" is not in ~/.ssh/config (known: ${[...hosts.keys()].join(', ') || 'none'}).`);
    process.exit(0);
  }
  if (warnings.length > 0) console.log('host table warnings:', JSON.stringify(warnings));
  const spec = hosts.get(wanted);
  console.log(`live host: ${wanted} (${spec.user}@${spec.host}:${spec.port})`);
  return { config, alias: wanted, spec, hosts };
}
