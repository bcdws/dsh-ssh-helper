/**
 * Tool schema contract: every tool the plugin registers must carry a real
 * JSON Schema object in `parameters`, and its `output.schema` must stay within
 * the subset the host enforces.
 *
 * Regression guard for a real outage: the tools used to be registered bare
 * with the author-friendly flat parameter table (`required: true` on each
 * property). A bare registration passes `parameters` through untouched, so the
 * provider received `type: null` and rejected the *whole conversation* with
 * "Invalid schema for function '<tool>'". Tolerant providers hid it.
 */
import { createTools } from '../lib/tools.js';

const pool = {
  aliases: ['h1'],
  warnings: [],
  logger: undefined,
  has: (alias) => alias === 'h1',
  hostVisible: () => true,
  outputLimit: () => 16000,
  connection: () => ({ connected: false, ensure: async () => {}, session: () => ({ run: async () => ({}) }), exec: async () => ({}) }),
  status: () => [],
  releaseForOwner: () => ({}),
  releaseAllForOwner: () => [],
  connections: () => []
};

const tools = createTools(pool, { defaultTimeoutMs: 60000 }, {});
let pass = 0;
const failures = [];
const check = (name, ok, detail) => (ok ? (pass += 1) : failures.push(`${name}: ${detail}`));

check('tool-count', tools.length === 9, JSON.stringify(tools.map((tool) => tool.name)));
check(
  'file-tools-present',
  ['ssh_read', 'ssh_write', 'ssh_edit', 'ssh_glob', 'ssh_grep'].every((name) => tools.some((tool) => tool.name === name)),
  JSON.stringify(tools.map((tool) => tool.name))
);

const isPlainObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value ?? undefined);

for (const tool of tools) {
  const parameters = tool.parameters;
  check(`${tool.name}-object`, isPlainObject(parameters) && parameters.type === 'object', JSON.stringify(parameters)?.slice(0, 120));
  check(`${tool.name}-properties`, isPlainObject(parameters?.properties), JSON.stringify(Object.keys(parameters?.properties ?? {})));
  const required = parameters?.required;
  check(`${tool.name}-required-array`, required === undefined || (Array.isArray(required) && required.every((name) => typeof name === 'string')), JSON.stringify(required));
  const propertyLevelRequired = Object.entries(parameters?.properties ?? {}).filter(([, schema]) => schema?.required !== undefined);
  check(`${tool.name}-no-property-required`, propertyLevelRequired.length === 0, JSON.stringify(propertyLevelRequired.map(([name]) => name)));
  for (const [name, schema] of Object.entries(parameters?.properties ?? {})) {
    check(`${tool.name}.${name}-typed`, typeof schema?.type === 'string' || Array.isArray(schema?.oneOf) || Array.isArray(schema?.enum), JSON.stringify(schema)?.slice(0, 100));
  }
  // The output schema must stay inside the host's enforced subset: object-level
  // `required` arrays only (property-level `required: true` was rejected at
  // activation with a JsonSchemaError).
  const output = tool.output?.schema;
  check(`${tool.name}-output-object`, isPlainObject(output) && (output.type === 'object' || output.type === 'array'), JSON.stringify(output?.type));
  const walk = (node, path) => {
    if (node === null || typeof node !== 'object') return;
    if (node.type === 'object' && node.required !== undefined) {
      check(`${tool.name}-output-required@${path}`, Array.isArray(node.required), JSON.stringify(node.required));
    }
    for (const [key, child] of Object.entries(node.properties ?? {})) walk(child, `${path}.${key}`);
    if (node.items) walk(node.items, `${path}[]`);
  };
  walk(output, 'output');
}

const byName = new Map(tools.map((tool) => [tool.name, tool]));
check('hosts-required', byName.get('ssh_hosts').parameters.required === undefined, 'ssh_hosts takes only an optional host');
check('run-required', JSON.stringify(byName.get('ssh_run').parameters.required) === '["host","command"]', JSON.stringify(byName.get('ssh_run').parameters.required));
check('transfer-required', JSON.stringify(byName.get('ssh_transfer').parameters.required) === '["direction","host","localPath","remotePath"]', JSON.stringify(byName.get('ssh_transfer').parameters.required));
check('session-one-of', JSON.stringify(byName.get('ssh_run').parameters.properties.session.oneOf) === '[{"type":"string"},{"type":"boolean"}]', JSON.stringify(byName.get('ssh_run').parameters.properties.session));
check('read-required', JSON.stringify(byName.get('ssh_read').parameters.required) === '["host","path"]', JSON.stringify(byName.get('ssh_read').parameters.required));
check('write-required', JSON.stringify(byName.get('ssh_write').parameters.required) === '["host","path","content"]', JSON.stringify(byName.get('ssh_write').parameters.required));
check('edit-required', JSON.stringify(byName.get('ssh_edit').parameters.required) === '["host","path"]', JSON.stringify(byName.get('ssh_edit').parameters.required));
check('glob-required', JSON.stringify(byName.get('ssh_glob').parameters.required) === '["host","pattern"]', JSON.stringify(byName.get('ssh_glob').parameters.required));
check('grep-required', JSON.stringify(byName.get('ssh_grep').parameters.required) === '["host","pattern"]', JSON.stringify(byName.get('ssh_grep').parameters.required));
check('direction-enum', JSON.stringify(byName.get('ssh_transfer').parameters.properties.direction.enum) === '["upload","download"]', JSON.stringify(byName.get('ssh_transfer').parameters.properties.direction));

// Every schema must survive JSON round-trip unchanged (no cycles, no functions).
for (const tool of tools) {
  const round = JSON.parse(JSON.stringify(tool.parameters));
  check(`${tool.name}-json-safe`, JSON.stringify(round) === JSON.stringify(tool.parameters), 'parameters must be plain JSON');
}

// ── every render() actually runs on a schema-shaped value ───────────────────
// Regression guard for a real outage: a missing comma between two template
// literals in a render array made the first one a *tag function*, so the
// tool failed with "is not a function". Nothing here executed a render, so no
// suite caught it.
const sample = (schema, depth = 0) => {
  if (schema === null || typeof schema !== 'object' || depth > 4) return 'x';
  if (Array.isArray(schema.oneOf) && schema.oneOf.length > 0) return sample(schema.oneOf[0], depth + 1);
  switch (schema.type) {
    case 'object': {
      const shaped = {};
      for (const [key, sub] of Object.entries(schema.properties ?? {})) shaped[key] = sample(sub, depth + 1);
      return shaped;
    }
    case 'array':
      return [];
    case 'number':
    case 'integer':
      return 1;
    case 'boolean':
      return false;
    default:
      return 'x';
  }
};
for (const tool of tools) {
  const render = tool.output?.render;
  if (typeof render !== 'function') continue;
  try {
    render({ host: 'h1', action: 'list', pattern: '*', path: '/tmp/x', command: 'true' }, sample(tool.output?.schema));
    check(`${tool.name}-render-runs`, true, '');
  } catch (error) {
    check(`${tool.name}-render-runs`, false, error instanceof Error ? error.message : String(error));
  }
}

console.log(`${pass}/${pass + failures.length} passed`);
for (const failure of failures) console.log(`FAIL ${failure}`);
process.exit(failures.length === 0 ? 0 : 2);
