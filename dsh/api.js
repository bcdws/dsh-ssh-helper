/**
 * The DSH side of the SSH assistant API: the shared, host-neutral handler from
 * `lib/assistant-api.js`, mounted by `index.js` on the Harness web server under
 * `/ssh-pool/`. Kept as its own module so existing importers stay valid.
 *
 * @module dsh-ssh-helper/dsh/api
 */
export { createAssistantApi } from '../lib/assistant-api.js';
