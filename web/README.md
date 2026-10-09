# Shared remote client

`remote-client.ts` is the strictly checked source. Run `node web/build.mjs` from the repository root after changes; the generated `remote-client.js` is committed so Rust builds do not require Node. `node web/build.mjs --check` fails on type errors or stale output and is part of `pnpm check`. Types use the desktop DTO declarations without a runtime import.

`remote-client.js` is served by both HTTPS adapters at `/remote-client.js`. It has no runtime dependencies and runs under `script-src 'self'`; HTML and this script are embedded at compile time. Login uses a rejecting authorization request, refresh requests are canceled on session changes, and polling schedules the next request after the previous one finishes. API error parsing accepts both historical v1 envelopes and structured errors.

Run `node --test tests/remote-client.test.mjs` from the root for the browser-independent login/offline/session regression suite. Browser DOM validation uses headed `agent-browser`; no production token is needed for the test server. The desktop Svelte application has its separate pnpm build and check.
