/**
 * Side-analysis backend over MCP sampling: the client's own model writes the
 * log summary, so the server needs no model credentials.
 *
 * The request carries no tools and `includeContext: "none"`, matching the
 * analyzer's no-tool contract. A client that did not declare `sampling` simply
 * reports the analyzer as unavailable; the tools then return bounded raw output.
 *
 * @module dsh-ssh-helper/mcp/sampling
 */

/** Join the text of a sampling result (`content` may be one block or an array). */
function resultText(content) {
  const blocks = Array.isArray(content) ? content : [content];
  return blocks
    .filter((block) => block?.type === 'text' && typeof block.text === 'string')
    .map((block) => block.text)
    .join('');
}

/**
 * @param session - an MCP session from `createMcpSession`.
 * @returns an analyzer backend (`{ status, complete }`, see `lib/analysis.js`).
 */
export function createSamplingBackend(session) {
  const status = () =>
    session.supports('sampling')
      ? { available: true, reason: null, model: 'mcp-sampling' }
      : { available: false, reason: 'MCP 客户端未声明 sampling 能力，旁路分析不可用', model: null };

  const complete = async ({ system, prompt, signal, maxTokens }) => {
    const result = await session.request(
      'sampling/createMessage',
      {
        messages: [{ role: 'user', content: { type: 'text', text: prompt } }],
        systemPrompt: system,
        includeContext: 'none',
        maxTokens,
        // A summary, not a reasoning task: prefer a fast, cheap model.
        modelPreferences: { speedPriority: 0.8, costPriority: 0.7, intelligencePriority: 0.3 }
      },
      { signal }
    );
    return {
      text: resultText(result?.content),
      hitMaxTokens: result?.stopReason === 'maxTokens',
      ...(typeof result?.model === 'string' && result.model.length > 0 ? { model: `mcp/${result.model}` } : {})
    };
  };

  return { status, complete };
}
