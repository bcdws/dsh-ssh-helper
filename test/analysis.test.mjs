/**
 * Optional side analysis: one tool-less LLM call, never a subagent with SSH
 * tools. These checks use a fake LLM and fake connection, so they are offline.
 */
import { createAnalyzer } from '../lib/analysis.js';
import { createTools } from '../lib/tools.js';

let pass = 0;
const failures = [];
const check = (name, ok, detail) => (ok ? (pass += 1) : failures.push(`${name}: ${detail}`));

// ── the analyzer itself ─────────────────────────────────────────────────────
let captured;
const ctx = {
  get: (name) => {
    if (name === 'llm') {
      return {
        stream: async function* (options) {
          captured = options;
          yield { type: 'text-delta', text: '第一个错误：' };
          yield { type: 'text-delta', text: '连接超时' };
          yield { type: 'finish', reason: { kind: 'stop' } };
        }
      };
    }
    if (name === 'agentDefaultModel') return { currentSelection: () => ({ provider: 'fake', model: 'analyst', reasoningEffort: 'low' }) };
    return undefined;
  }
};
const analyzer = createAnalyzer(ctx, { warn: () => {} });
check('status-available', analyzer.status().available === true && analyzer.status().model === 'fake/analyst', JSON.stringify(analyzer.status()));
const result = await analyzer.run({ tool: 'ssh_run', target: 'journalctl -u app', text: 'ERROR token=abcdef123456', bytes: 26, signal: new AbortController().signal });
check('summary-returned', result?.summary === '第一个错误：连接超时', JSON.stringify(result));
check('model-returned', result?.model === 'fake/analyst' && result?.source === 'ssh_run', JSON.stringify(result));
check('system-is-read-only', /只读|没有工具/.test(captured?.system ?? ''), String(captured?.system).slice(0, 80));
check('prompt-redacted', /<redacted:token>/.test(captured?.messages?.[0]?.content?.[0]?.text ?? '') && !/abcdef123456/.test(captured?.messages?.[0]?.content?.[0]?.text ?? ''), String(captured?.messages?.[0]?.content?.[0]?.text));
check('selection-forwarded', captured?.provider === 'fake' && captured?.model === 'analyst', JSON.stringify({ provider: captured?.provider, model: captured?.model }));
check('no-tools-in-call', captured?.tools === undefined && captured?.toolHistory === undefined, JSON.stringify({ tools: captured?.tools, toolHistory: captured?.toolHistory }));
check('minimal-options', captured?.temperature === undefined && captured?.reasoningEffort === 'low', JSON.stringify({ temperature: captured?.temperature, reasoningEffort: captured?.reasoningEffort }));
check('route-session', captured?.sessionId === 'dsh-ssh-side-analysis', String(captured?.sessionId));
check('coverage-not-truncated', result?.truncated === false && result?.analyzedBytes === Buffer.byteLength('ERROR token=abcdef123456') && result?.inputLines === 1 && result?.analyzedLines === 1, JSON.stringify({ truncated: result?.truncated, analyzedBytes: result?.analyzedBytes, inputBytes: result?.inputBytes, lines: [result?.inputLines, result?.analyzedLines] }));
check('no-command-suggestion-request', /不要输出可直接执行的命令/.test(captured?.system ?? ''), String(captured?.system).slice(-120));

const missing = createAnalyzer({ get: () => undefined }, { warn: () => {} });
check('missing-llm-status', missing.status().available === false && /LLM/.test(missing.status().reason), JSON.stringify(missing.status()));
const missingResult = await missing.run({ tool: 'x', target: 'x', text: 'x', bytes: 1 });
check('missing-llm-error', /LLM/.test(missingResult.error ?? ''), JSON.stringify(missingResult));
const failing = createAnalyzer(
  { get: (name) => (name === 'llm' ? { stream: async function* () { throw new Error('boom'); } } : { currentSelection: () => ({ provider: 'p', model: 'm' }) }) },
  { warn: () => {} }
);
check('llm-failure-error', /boom/.test((await failing.run({ tool: 'x', target: 'x', text: 'xxx', bytes: 3 })).error ?? ''), 'a failed call must report the reason');
let longCaptured;
const longAnalyzer = createAnalyzer({
  get: (name) =>
    name === 'llm'
      ? {
          stream: async function* (options) {
            longCaptured = options;
            yield { type: 'text-delta', text: 'ok' };
            yield { type: 'finish', reason: { kind: 'stop' } };
          }
        }
      : { currentSelection: () => ({ provider: 'p', model: 'm' }) }
}, { warn: () => {} });
const longText = 'x'.repeat(70_000);
const longResult = await longAnalyzer.run({ tool: 'ssh_run', target: 'big', text: longText, bytes: Buffer.byteLength(longText) });
check('coverage-truncated', longResult?.truncated === true && longResult?.analyzedBytes === 65_536 && longResult?.inputBytes === 70_000, JSON.stringify({ truncated: longResult?.truncated, analyzedBytes: longResult?.analyzedBytes, inputBytes: longResult?.inputBytes }));
check('truncation-guard-in-prompt', /是否截断: 是/.test(longCaptured?.messages?.[0]?.content?.[0]?.text ?? '') && /不要声称总条数/.test(longCaptured?.system ?? ''), 'truncated input must be declared to the model');

const capped = createAnalyzer({
  get: (name) =>
    name === 'llm'
      ? {
          stream: async function* () {
            yield { type: 'text-delta', text: '部分摘要' };
            yield { type: 'finish', reason: { kind: 'max-tokens' } };
          }
        }
      : { currentSelection: () => ({ provider: 'p', model: 'm' }) }
}, { warn: () => {} });
const cappedResult = await capped.run({ tool: 'ssh_run', target: 'big', text: 'x'.repeat(10), bytes: 10 });
check('max-tokens-marked', /部分摘要/.test(cappedResult.summary ?? '') && /输出上限/.test(cappedResult.summary ?? ''), JSON.stringify(cappedResult));

const providerError = createAnalyzer(
  {
    get: (name) =>
      name === 'llm'
        ? {
            stream: async function* () {
              yield { type: 'finish', reason: { kind: 'error', failure: { code: 'INVALID_REQUEST', message: 'MissingSessionID', status: 400 } } };
            }
          }
        : { currentSelection: () => ({ provider: 'p', model: 'm' }) }
  },
  { warn: () => {} }
);
const providerFailure = await providerError.run({ tool: 'x', target: 'x', text: 'xxx', bytes: 3 });
check('provider-error-detail', /INVALID_REQUEST/.test(providerFailure.error ?? '') && /MissingSessionID/.test(providerFailure.error ?? '') && /400/.test(providerFailure.error ?? ''), JSON.stringify(providerFailure));

// ── tool integration ────────────────────────────────────────────────────────
const calls = [];
const big = 'x'.repeat(6000);
const pool = {
  aliases: ['h'],
  warnings: [],
  logger: undefined,
  has: () => true,
  hostVisible: () => true,
  timeoutPolicy: () => ({ multiplier: 3, floorMs: 1000, ceilingMs: 1800000, fallbackEstimateMs: 30000 }),
  transferTimeout: () => 600000,
  logAnalysis: () => true,
  recordActivity: () => {},
  status: () => [],
  connections: () => [],
  connection: () => ({
    connected: true,
    ensure: async () => {},
    session: () => ({ run: async () => ({ stdout: big, stderr: '', exitCode: 0 }) }),
    exec: async (command) => {
      calls.push(command);
      if (command.includes('grep')) return { stdout: Array.from({ length: 40 }, (_, i) => `/var/log/app.log:${i + 1}: ERROR line ${i} ${'x'.repeat(80)}`).join('\n'), stderr: '', exitCode: 0, signal: null, timedOut: false };
      return { stdout: big, stderr: '', exitCode: 0, signal: null, timedOut: false };
    }
  })
};
const analyzed = [];
const tools = createTools(pool, { maxOutputBytes: 32768, defaultTimeoutMs: 30000 }, {
  analyzer: async ({ tool, target, text }) => {
    analyzed.push({ tool, target, bytes: Buffer.byteLength(text) });
    return {
      summary: `summary:${tool}`,
      model: 'fake/model',
      inputBytes: Buffer.byteLength(text),
      analyzedBytes: Buffer.byteLength(text),
      inputLines: text.split('\n').length,
      analyzedLines: text.split('\n').length,
      truncated: false,
      source: tool
    };
  }
});
const byName = new Map(tools.map((tool) => [tool.name, tool]));

const run = await byName.get('ssh_run').execute({ host: 'h', command: 'tail -n 100 /var/log/app.log' }, {});
check('run-analyzed', run.analysis?.summary === 'summary:ssh_run' && run.stdout.text === '' && run.stderr.text === '', JSON.stringify({ analysis: run.analysis, stdout: run.stdout }));
check('run-analysis-source', analyzed.at(-1)?.tool === 'ssh_run' && analyzed.at(-1)?.target.includes('tail'), JSON.stringify(analyzed.at(-1)));

const raw = await byName.get('ssh_run').execute({ host: 'h', command: 'tail -n 100 /var/log/app.log', analyze: false }, {});
check('run-veto-returns-raw', raw.analysis === null && raw.stdout.text.length > 0, JSON.stringify({ analysis: raw.analysis, bytes: raw.stdout.text.length }));

const mentioned = await byName.get('ssh_run').execute({ host: 'h', command: 'uptime' }, {});
check('small-output-not-analyzed', mentioned.analysis === null && mentioned.stdout.text.length > 0, JSON.stringify(mentioned.analysis));

const grep = await byName.get('ssh_grep').execute({ host: 'h', pattern: 'ERROR', path: '/var/log', analyze: true }, {});
check('grep-analyzed', grep.analysis?.summary === 'summary:ssh_grep' && grep.matches.length === 0, JSON.stringify({ analysis: grep.analysis, matches: grep.matches.length }));
check('grep-called-grep', calls.some((command) => command.includes("grep -")) || calls.some((command) => command.includes('grep')), JSON.stringify(calls.slice(-2)));

// A failed side call must not dump the whole log back into the main context.
const fallbackTools = createTools(pool, { maxOutputBytes: 32768, defaultTimeoutMs: 30000 }, { analyzer: async () => null });
const fallback = await fallbackTools.find((tool) => tool.name === 'ssh_run').execute({ host: 'h', command: 'tail -n 100 /var/log/app.log' }, {});
check('fallback-analysis-null', fallback.analysis === null && typeof fallback.analysisError === 'string', JSON.stringify({ analysis: fallback.analysis, error: fallback.analysisError }));
check('fallback-preview-bounded', fallback.stdout.text.length < 5000, JSON.stringify({ bytes: fallback.stdout.text.length, hint: fallback.hint }));

// ── concurrency and empty-response retry ───────────────────────────────────
let releaseGate;
const gate = new Promise((resolve) => { releaseGate = resolve; });
const concurrent = createAnalyzer(
  {
    get: (name) =>
      name === 'llm'
        ? {
            stream: async function* () {
              await gate;
              yield { type: 'text-delta', text: 'first' };
              yield { type: 'finish', reason: { kind: 'stop' } };
            }
          }
        : { currentSelection: () => ({ provider: 'p', model: 'm' }) }
  },
  { warn: () => {} }
);
const firstRun = concurrent.run({ tool: 'ssh_run', target: 'first', text: 'first', bytes: 5 });
await new Promise((resolve) => setTimeout(resolve, 0));
const secondRun = await concurrent.run({ tool: 'ssh_run', target: 'second', text: 'second', bytes: 6 });
check('single-flight-busy', /正忙/.test(secondRun.error ?? ''), JSON.stringify(secondRun));
releaseGate();
const firstResult = await firstRun;
check('single-flight-first-ok', firstResult.summary === 'first', JSON.stringify(firstResult));

let retryAttempts = 0;
const retrying = createAnalyzer(
  {
    get: (name) =>
      name === 'llm'
        ? {
            stream: async function* () {
              retryAttempts += 1;
              if (retryAttempts === 1) {
                yield { type: 'finish', reason: { kind: 'stop' } };
                return;
              }
              yield { type: 'text-delta', text: 'recovered' };
              yield { type: 'finish', reason: { kind: 'stop' } };
            }
          }
        : { currentSelection: () => ({ provider: 'p', model: 'm' }) }
  },
  { warn: () => {} }
);
const retryResult = await retrying.run({ tool: 'ssh_run', target: 'retry', text: 'retry', bytes: 5 });
check('empty-retry-recovers', retryResult.summary === 'recovered' && retryAttempts === 2, JSON.stringify({ result: retryResult, attempts: retryAttempts }));

let emptyAttempts = 0;
const empty = createAnalyzer(
  {
    get: (name) =>
      name === 'llm'
        ? {
            stream: async function* () {
              emptyAttempts += 1;
              yield { type: 'finish', reason: { kind: 'stop' } };
            }
          }
        : { currentSelection: () => ({ provider: 'p', model: 'm' }) }
  },
  { warn: () => {} }
);
const emptyResult = await empty.run({ tool: 'ssh_run', target: 'empty', text: 'empty', bytes: 5 });
check('empty-retry-once-only', /没有返回摘要/.test(emptyResult.error ?? '') && emptyAttempts === 2, JSON.stringify({ result: emptyResult, attempts: emptyAttempts }));

console.log(`${pass}/${pass + failures.length} passed`);
for (const failure of failures) console.log(`FAIL ${failure}`);
process.exit(failures.length === 0 ? 0 : 2);
