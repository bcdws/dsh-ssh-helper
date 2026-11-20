/**
 * "Did you mean …" for a mistyped host alias.
 *
 * Agents often drop the separator (`dbmain` for `db_main`), use only the
 * distinctive part (`replica` for `db_replica`), or make a one-letter typo. Each miss
 * costs a whole extra round trip through ssh_hosts, so the unknown-host error
 * names the likely alias instead.
 *
 * Nothing is fixed here: callers pass the aliases the agent may see *now*
 * (re-read from ~/.ssh/config), so a renamed host is suggested under its new
 * name and a hidden host can never surface.
 *
 * @module dsh-ssh-helper/alias-suggest
 */

/** Lower-case and drop separators: `DB_Main` and `db-main` both become `dbmain`. */
function squash(value) {
  return String(value).toLowerCase().replace(/[-_.\s]/g, '');
}

/** Plain Levenshtein distance; aliases are short, so O(n·m) is fine. */
function distance(a, b) {
  if (a === b) return 0;
  let previous = Array.from({ length: b.length + 1 }, (_, index) => index);
  for (let i = 1; i <= a.length; i += 1) {
    const current = [i];
    for (let j = 1; j <= b.length; j += 1) {
      current[j] = Math.min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    previous = current;
  }
  return previous[b.length];
}

/** Lower is better; `null` means "not similar enough to suggest". */
function score(input, candidate) {
  const wanted = squash(input);
  const target = squash(candidate);
  if (wanted.length === 0) return null;
  if (wanted === target) return 0;
  const segments = String(candidate).toLowerCase().split(/[-_.]/).filter(Boolean);
  if (wanted.length >= 2 && segments.includes(wanted)) return 1;
  if (wanted.length >= 3 && target.startsWith(wanted)) return 2;
  const allowed = wanted.length <= 4 ? 1 : 2;
  const edits = distance(wanted, target);
  return edits <= allowed ? 2 + edits : null;
}

/**
 * @param input - the alias the caller asked for.
 * @param candidates - aliases the caller may see, in table order.
 * @param limit - at most this many suggestions.
 * @returns the likely aliases, best first (ties keep table order).
 */
export function suggestAliases(input, candidates, limit = 3) {
  return candidates
    .map((alias, order) => ({ alias, order, score: alias === input ? null : score(input, alias) }))
    .filter((entry) => entry.score !== null)
    .sort((a, b) => a.score - b.score || a.order - b.order)
    .slice(0, limit)
    .map((entry) => entry.alias);
}

/** The unknown-host message: suggestion first (when any), then every visible alias. */
export function unknownHostMessage(alias, known) {
  const suggestions = suggestAliases(alias, known);
  const hint = suggestions.length > 0 ? `; did you mean ${suggestions.map((name) => `"${name}"`).join(' or ')}?` : '';
  return `unknown ssh host "${alias}"${hint}; known hosts: ${known.length > 0 ? known.join(', ') : '(none available)'}`;
}
