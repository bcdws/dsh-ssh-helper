/**
 * MCP stdio transport: one JSON-RPC message per line on stdin/stdout.
 *
 * stdout carries protocol messages only; every log line goes to stderr.
 *
 * @module dsh-ssh-helper/mcp/stdio
 */
import { createInterface } from 'node:readline';

/**
 * Serve one MCP session over a pair of streams.
 *
 * @param input
 * @param input.createSession - `(send) => session` (see `createMcpSession`).
 * @param input.input - readable stream (default `process.stdin`).
 * @param input.output - writable stream (default `process.stdout`).
 * @returns `{ session, done }`; `done` resolves when the input ends.
 */
export function serveStdio({ createSession, input = process.stdin, output = process.stdout }) {
  const send = (message) => {
    // JSON.stringify escapes newlines inside strings, so one message is one line.
    output.write(`${JSON.stringify(message)}\n`);
  };
  const session = createSession(send);
  const lines = createInterface({ input, crlfDelay: Infinity });
  const work = new Set();

  lines.on('line', (line) => {
    if (line.trim().length === 0) return;
    let message;
    try {
      message = JSON.parse(line);
    } catch (error) {
      session.parseError(error instanceof Error ? error.message : String(error));
      return;
    }
    // Requests are handled concurrently: a long ssh_run must not block a ping
    // or a cancellation behind it.
    const task = session.receive(message).finally(() => work.delete(task));
    work.add(task);
  });

  const done = new Promise((resolve) => {
    lines.once('close', async () => {
      // stdin closing is the client's shutdown signal: abort running calls
      // instead of letting a long command keep the process alive.
      session.close();
      await Promise.allSettled([...work]);
      resolve();
    });
  });
  return { session, done };
}
