#!/usr/bin/env node
/**
 * Test runner.
 *
 * Offline suites run everywhere and need no network. Live suites drive a real
 * SSH host: they skip cleanly when none is configured, and take the alias from
 * `DSH_SSH_TEST_HOST` (default: the first host in ~/.ssh/config).
 *
 *   node test/run.mjs            # everything (live suites skip without a host)
 *   node test/run.mjs --offline  # only suites that need no network
 *   node test/run.mjs --live     # only the suites that need a real host
 */
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const OFFLINE = ['schema.test.mjs', 'tools.test.mjs', 'policy-state.test.mjs', 'store.test.mjs', 'timeouts.test.mjs', 'permissions.test.mjs', 'files.test.mjs', 'hostmeta.test.mjs', 'safety.test.mjs', 'api.test.mjs', 'activation.test.mjs', 'pool.test.mjs', 'backoff.test.mjs', 'diagnostics.test.mjs', 'analysis.test.mjs', 'client-render.test.mjs', 'policy.test.mjs', 'redact.test.mjs'];
const LIVE = ['smoke.mjs', 'race.mjs', 'errors.mjs'];

const mode = process.argv.includes('--offline') ? 'offline' : process.argv.includes('--live') ? 'live' : 'all';
const suites = [...(mode === 'live' ? [] : OFFLINE), ...(mode === 'offline' ? [] : LIVE)];

let failed = 0;
for (const suite of suites) {
  console.log(`\n── ${suite} ─────────────────────────────────────────`);
  const result = spawnSync(process.execPath, [join(here, suite)], { stdio: 'inherit', env: process.env });
  const ok = result.status === 0;
  if (!ok) failed += 1;
  console.log(`${ok ? '✓' : '✗'} ${suite}${ok ? '' : ` (exit ${result.status})`}`);
}

console.log(`\n${failed === 0 ? `all ${suites.length} suites passed` : `${failed}/${suites.length} suites failed`}`);
process.exit(failed === 0 ? 0 : 1);
