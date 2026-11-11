/**
 * DSH side-analysis backend: the Harness `llm` service on the current default
 * model, plugged into the host-neutral analyzer from `lib/analysis.js`.
 *
 * @module dsh-ssh-helper/dsh/llm-backend
 */
import { createSideAnalyzer, errorText } from '../lib/analysis.js';

/**
 * The DSH backend: the Harness `llm` service on the current default model.
 *
 * @param ctx - the plugin context, used to resolve `llm` and `agentDefaultModel`.
 */
export function createDshLlmBackend(ctx) {
  let llm;
  let modelService;

  // Capture the services when they exist instead of relying on a later
  // `ctx.get` that may run in a scope where they are not visible yet.
  try {
    ctx.inject?.(['llm', 'agentDefaultModel'], (serviceCtx) => {
      llm = serviceCtx.get('llm');
      modelService = serviceCtx.get('agentDefaultModel');
    });
  } catch {
    /* the lazy fallback below reports the reason */
  }

  const resolve = () => {
    // Injection may not have run yet (or the services may be absent); the lazy
    // lookup keeps `status()` honest either way.
    llm ??= ctx.get?.('llm');
    modelService ??= ctx.get?.('agentDefaultModel');
    if (!llm) return { error: 'LLM 服务不可用' };
    if (typeof llm.stream !== 'function') return { error: 'LLM 服务没有 stream 接口' };
    let selection;
    try {
      selection = modelService?.currentSelection?.();
    } catch (error) {
      return { error: `读取默认模型失败: ${errorText(error)}` };
    }
    if (!selection?.provider || !selection?.model) return { error: '默认模型未配置' };
    return { llm, selection };
  };

  const status = () => {
    const resolved = resolve();
    if (resolved.error) return { available: false, reason: resolved.error, model: null };
    return { available: true, reason: null, model: `${resolved.selection.provider}/${resolved.selection.model}` };
  };

  const complete = async ({ system, prompt, sessionId, signal, maxTokens, maxChars }) => {
    const resolved = resolve();
    if (resolved.error) return { error: resolved.error };
    const { llm: service, selection } = resolved;
    let text = '';
    let hitMaxTokens = false;
    const stream = service.stream({
      provider: selection.provider,
      model: selection.model,
      system,
      messages: [{ role: 'user', content: [{ type: 'text', text: prompt }] }],
      // Minimal request: no tools, no tool history, no optional knobs that a
      // provider adapter might reject. Absence of `tools` is the no-tool
      // contract; an empty array is not sent. The opencode-go route requires
      // an x-opencode-session header, so a session id is always sent.
      sessionId,
      // Side analysis is a summary task; high reasoning on a 64 KB log can
      // spend the whole completion budget before any text is emitted.
      reasoningEffort: 'low',
      maxTokens,
      signal
    });
    for await (const chunk of stream) {
      if (chunk?.type === 'text-delta' && typeof chunk.text === 'string') {
        text += chunk.text;
        if (text.length >= maxChars) break;
      } else if (chunk?.type === 'block-end' && chunk.block?.type === 'text' && text.length === 0) {
        // Some non-streaming fallbacks only expose the assembled text block.
        text = chunk.block.text ?? '';
      } else if (chunk?.type === 'finish' && chunk.reason?.kind === 'max-tokens') {
        hitMaxTokens = true;
      } else if (chunk?.type === 'finish' && chunk.reason?.kind === 'error') {
        const failure = chunk.reason.failure;
        const detail = failure?.message ? `${failure.code ? `${failure.code}: ` : ''}${failure.message}` : '旁路模型返回错误';
        const httpStatus = failure?.status === undefined ? '' : ` (HTTP ${failure.status})`;
        return { error: `${detail}${httpStatus}` };
      } else if (chunk?.type === 'finish' && chunk.reason?.kind === 'aborted') {
        return { error: '旁路模型调用被取消' };
      }
    }
    return { text, hitMaxTokens, model: `${selection.provider}/${selection.model}` };
  };

  return { status, complete };
}

/**
 * The DSH analyzer: the neutral analyzer over the Harness default model.
 * @param ctx - the plugin context.
 * @param logger - optional logger for a failed side call.
 */
export function createAnalyzer(ctx, logger) {
  return createSideAnalyzer({ backend: createDshLlmBackend(ctx), logger });
}
