/**
 * Command deadlines.
 *
 * A fixed timeout is wrong in both directions: it kills a deploy that was
 * always going to take four minutes, and it makes `ls` sit there for a minute
 * before giving up. So each command gets a deadline derived from an estimate of
 * how long it should take, multiplied by a safety factor, then clamped:
 *
 *   estimate = expectedMs (caller's own estimate) ?? classify(command) ?? fallback
 *   deadline = clamp(estimate × multiplier, floorMs, ceilingMs)
 *
 * The classifier is deliberately coarse: it only has to land within an order of
 * magnitude, because the multiplier (3 by default) covers the rest. Callers
 * override everything by passing `timeoutMs` explicitly.
 *
 * @module dsh-ssh-helper/timeouts
 */

/** Estimate buckets, most specific first: the first matching rule wins. */
const BUCKETS = [
  // Network work: a fetch, a lookup or a handshake is not a probe.
  { ms: 120_000, label: 'network', test: /\b(?:curl|wget|git\s+(?:clone|fetch|pull)|dig|nslookup|host\s|ping|traceroute|mtr|openssl\s+s_client|nc\s|ncat|telnet|ncclient)\b/ },
  // Certificate issuance and reverse-proxy reconfiguration can block on the ACME
  // round trip, so they get minutes rather than the fallback.
  { ms: 300_000, label: 'certificate/proxy', test: /\b(?:certbot|acme\.sh|acme|lego\s|sing-box\s+(?:run|check|format|merge)|caddy\s+(?:reload|run|validate)|nginx\s+-t|haproxy\s+-c)\b/ },
  // Docker inspection is quick; pulling and bringing a stack up is not.
  { ms: 60_000, label: 'docker inspect', test: /\bdocker\s+(?:logs|ps|inspect|stats|top|images|version|info)\b/ },
  // Long copies, dumps and archives: minutes, not seconds.
  { ms: 900_000, label: 'transfer/backup', test: /\b(?:rsync|scp|sftp|mysqldump|pg_dump|pg_basebackup|mongodump|mongorestore|tar\s+-?[a-z]*c[a-z]*f|tar\s+czf|zip\s+-r|unzip|restic|rclone|aws\s+s3)\b/ },
  // Builds and package operations.
  { ms: 600_000, label: 'build/install', test: /\b(?:apt|apt-get|yum|dnf|zypper|apk\s+add|pacman|npm|pnpm|yarn|pip|pip3|uv\s+pip|make|cmake|cargo|go\s+build|mvn|gradle|docker\s+build|docker\s+compose\s+up|composer|bundle\s+install)\b/ },
  // Service lifecycle changes.
  { ms: 60_000, label: 'service restart', test: /\b(?:systemctl\s+(?:restart|start|stop|reload|daemon-reload)|service\s+\S+\s+(?:restart|start|stop)|docker\s+(?:restart|stop|start)|supervisorctl\s+(?:restart|start|stop)|nginx\s+-s\s+reload)\b/ },
  // Filesystem work over a directory tree.
  { ms: 30_000, label: 'file operation', test: /\b(?:cp|mv|rm|mkdir|chmod|chown|ln|touch|gzip|gunzip|7z|find|locate|updatedb)\b/ },
  // Reading and filtering text.
  { ms: 15_000, label: 'read/filter', test: /\b(?:cat|head|tail|grep|egrep|zgrep|sed|awk|sort|uniq|wc|md5sum|sha256sum|stat|file|less|jq|diff)\b/ },
  // Instant probes.
  { ms: 5_000, label: 'probe', test: /(?:^|[;&|]\s*)(?:ls|pwd|whoami|id|date|uptime|hostname|uname|df|du\s+-sh|free|ps|top\s+-b|ss|netstat|echo|printf|which|type|env|printenv|systemctl\s+(?:status|is-active)|journalctl[^|]*-n\s+\d+)\b/ }
];

/** Estimate how long one command should take, in milliseconds. */
export function estimateFor(command, fallbackMs = 30_000) {
  const text = String(command ?? '').toLowerCase();
  for (const bucket of BUCKETS) {
    if (bucket.test.test(text)) return { estimateMs: bucket.ms, label: bucket.label };
  }
  const fallback = Number.isFinite(fallbackMs) && fallbackMs > 0 ? fallbackMs : 30_000;
  return { estimateMs: fallback, label: null };
}

const clamp = (value, min, max) => Math.min(max, Math.max(min, value));

/**
 * Resolve the deadline for one command.
 * @param command - the command text, used when the caller gave no estimate.
 * @param expectedMs - the caller's own estimate of the run time.
 * @param multiplier - safety factor applied to the estimate (1–10).
 * @param floorMs / ceilingMs - hard bounds for the resulting deadline.
 * @param fallbackEstimateMs - estimate used when the command matches no bucket.
 */
export function deadlineFor({ command, expectedMs, multiplier = 3, floorMs = 5_000, ceilingMs = 1_800_000, fallbackEstimateMs = 30_000 } = {}) {
  const factor = clamp(Number.isFinite(Number(multiplier)) && Number(multiplier) > 0 ? Number(multiplier) : 3, 1, 10);
  const floor = clamp(Number.isFinite(Number(floorMs)) ? Number(floorMs) : 5_000, 1_000, 600_000);
  const ceiling = clamp(Number.isFinite(Number(ceilingMs)) ? Number(ceilingMs) : 1_800_000, floor, 86_400_000);
  const requested = Number(expectedMs);
  const fromCaller = Number.isFinite(requested) && requested > 0;
  const { estimateMs, label } = fromCaller ? { estimateMs: requested, label: 'caller estimate' } : estimateFor(command, fallbackEstimateMs);
  const timeoutMs = Math.round(clamp(estimateMs * factor, floor, ceiling));
  return { estimateMs: Math.round(estimateMs), multiplier: factor, timeoutMs, source: fromCaller ? 'expectedMs' : (label ?? 'fallback') };
}
