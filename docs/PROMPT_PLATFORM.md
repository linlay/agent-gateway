# Prompt: modify agent-platform only

Use the following prompt in the `agent-platform` repository. Do not modify `agent-gateway` or `agent-webclient`.

---

Implement the Agent Gateway channel compatibility work in this repository while preserving direct/local platform behavior and the existing `platform-ws` frame envelope.

Requirements:

1. The platform remains the active WebSocket connector. Connect to `GET <gateway>/ws/agent?channelId=<channel-id>` with `Authorization: Bearer <platform-jwt>`. Treat the credential as channel identity, never as an end-user identity. Preserve the GatewayContext base URL/token/channel on all request contexts, including `/api/upload` pulls and `/api/resource` pushes.
2. Add atomic Agent Card reporting per channel:
   - send request `agent.catalog.begin {snapshotId,revision,cardCount}`;
   - send `agent.card.update` for every export with the same snapshot ID/revision, `agentKey` equal to the export external key, `operations {query,submit,steer,interrupt,fileTransfer}`, and sanitized `agentCard`;
   - send `agent.catalog.commit {snapshotId,revision,cardCount,digest?}` only after all card updates are acknowledged;
   - revisions increase monotonically per channel and a reconnect sends a full snapshot;
   - fall back to legacy card upserts only when an older Gateway explicitly rejects the snapshot frame type.
3. Extend trusted channel request rewriting so `/api/attach` and `/api/detach` accept `externalAgentKey`, resolve it only within the current Gateway channel export, enforce the corresponding exported operation, rewrite to the local key, and remove `externalAgentKey` before normal handlers. Do not trust a local `agentKey` sent by Gateway unless it resolves through that channel export.
4. Under a verified GatewayContext only, add a `chatIds` allowlist to `/api/chats`, `/api/archives`, `/api/chats/search`, and `/api/archives/search` (HTTP and WS forms). Apply the filter inside storage/search before materializing results; an empty list returns no items. Ignore/reject `chatIds` from ordinary direct users so it cannot become a generic authorization bypass. Preserve existing response shapes, ordering, timestamps, stream events, and error frames.
5. Ensure query/submit/steer/interrupt channel rewriting uses `externalAgentKey` and the export operation matrix. File transfer must remain tied to an existing exported chat and an export with `fileTransfer=true`.
6. Keep `/api/upload` compatible with the nested ticket shape `{requestId,chatId,upload:{id,type,name,mimeType,sizeBytes,sha256,url}}`; GET the absolute URL with the Gateway channel bearer token. Keep `/api/resource {file,pushURL}`; POST bytes to the absolute push URL with the same token and preserve MIME type.
7. Preserve `runId` together with `viewportKey` in run/awaiting stream events so Gateway can create an explicit run-bound Viewport binding. `/api/viewport` itself may keep its existing `{viewportKey}` platform handler; Gateway removes the browser-only run routing field before forwarding.
8. Never include platform secrets, local paths, model credentials, prompt/tool configuration secrets, platform ID, or local agent key in Agent Cards or result fields intended for the browser.
9. Add contract and integration tests for: uncommitted snapshots, atomic add/update/removal, reconnect full snapshot, duplicate external keys on different channels, attach/detach mapping, operation denial, chatIds filtering before materialization, upload auth, resource push auth, run-bound Viewport events, disconnect/reconnect, and backward-compatible legacy Gateway fallback.

Run the repository’s formatter, unit tests, race/concurrency tests relevant to channel code, and existing end-to-end tests. Report files changed, protocol compatibility decisions, and test results. Do not implement tenant/ACL/session logic in platform; that belongs to Gateway.

---
