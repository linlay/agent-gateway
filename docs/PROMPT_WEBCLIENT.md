# Prompt: modify agent-webclient only

Use the following prompt in the `agent-webclient` repository. Do not modify `agent-gateway` or `agent-platform`.

---

Convert the user conversation surface to run behind Agent Gateway while preserving composer drafts and the current `platform-ws` event semantics.

Requirements:

1. At application bootstrap call `GET /api/gateway/session` with same-origin credentials. Store tenant display data, authenticated user or anonymous state, CSRF token, login/logout URLs, and feature flags. Add `X-CSRF-Token` to every same-origin mutating HTTP request. Do not read or create tenant IDs client-side.
2. Implement one Auth Coordinator shared by HTTP JSON, SSE connection failures, WebSocket errors/close, and resource downloads:
   - after the final response is 401, navigate to `/auth/login?return_to=<current relative route>`;
   - accept WS error frames with `code:401`, type `auth.required`, or close code `4401` as the same signal;
   - enforce single-flight so concurrent 401s trigger one navigation;
   - `return_to` must be a relative same-Host path and must reject `//`, schemes, or foreign hosts;
   - do not redirect merely because the anonymous session exists or the public catalog is empty.
3. On login return, clear all identity-scoped query/API caches, refetch Gateway session and Agent catalog, rebuild `/ws`, resume the current route, and restore the local Composer draft. Never replay an already accepted mutation unless it carries the same request ID/idempotency key.
4. Connect the browser WebSocket only to same-origin Gateway `/ws`, with cookies. Preserve existing request/response/stream/push/error handling, sequence ordering, timestamps, `lastSeq`, and attach recovery. Anonymous users may connect normally.
5. Treat the Agent `key` returned by Gateway as the only Agent identifier. Never persist, display, infer, or send platform ID, channel ID, or a platform-local agent key. Two returned Agents with similar names or the same historical local key remain distinct.
6. Remove or feature-gate all first-release-inaccessible UI and calls: Agent management, Registry, Memory, Automation, Skill management, Terminal, workspace/file browsing, Teams, custom model selection/model override, non-default access level, and platform `/api/admin/*`. Conversation upload/download remains available only when the Gateway session feature flag and Agent policy allow it.
7. When fetching `/api/viewport`, send both the `viewportKey` and the bound `runId` from the event/timeline state. Gateway intentionally rejects a bare viewport key because the same key can exist on multiple platform channels.
8. Ensure protected Agent navigation/invocation distinguishes 401 (start login) from 403 (show permission denied), 429 (show retry/concurrency message), and 503 (show channel offline with attach/retry affordance). Do not hide these as generic network errors.
9. Cover 401 handling for all four paths: JSON API, SSE handshake, WS frame/close, and file download. Tests must prove a burst of mixed 401s causes one redirect and returns to the original in-app route. Also test anonymous public Agents, authenticated/restricted catalog refresh, cache clearing on identity transition, same-name Agents with different public keys, run-bound Viewport lookup, WS reconnect + attach lastSeq, and hidden forbidden features.

Run formatting, typecheck, unit/component tests, and the existing production build. Report files changed, routes hidden, Auth Coordinator behavior, and test/build results. Do not add Gateway authorization logic to the browser; the UI may guide users, but Gateway remains authoritative.

---
