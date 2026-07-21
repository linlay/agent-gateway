# Gateway protocol contract

## Trust and routing

The Host header selects a tenant. Browser-provided `tenantId`, platform `userId`, platform-local `agentKey`, `chatId`, and `runId` are never accepted as routing authority. Every stateful operation resolves a tenant-scoped Gateway binding first, checks current ownership and policy, then obtains the stored route.

Platform channel identity is the intersection of the verified JWT and URL:

```text
JWT: aud=agent-gateway-platform
     sub=platform:<platformId>
     tenant_id, platform_id, channel_id, jti, iat, exp
URL: /ws/agent?channelId=<same channel_id>
key: tenant_id + platform_id + channel_id
```

## Card synchronization

Platform sends request frames in this order:

```json
{"frame":"request","type":"agent.catalog.begin","id":"1","payload":{"snapshotId":"s1","revision":12,"cardCount":1}}
{"frame":"request","type":"agent.card.update","id":"2","payload":{"snapshotId":"s1","revision":12,"agentKey":"assistant","operations":{"query":true,"submit":true,"steer":true,"interrupt":true,"fileTransfer":true},"agentCard":{"name":"Assistant","skills":[],"tools":[]}}}
{"frame":"request","type":"agent.catalog.commit","id":"3","payload":{"snapshotId":"s1","revision":12,"cardCount":1}}
```

Gateway acknowledges each request. Only commit changes the visible projection. Revisions must increase for a channel. Missing cards become `removed`; their Gateway Agent and immutable public key remain stored for audit and existing bindings. A card without `snapshotId` is accepted as a legacy upsert, but legacy mode cannot signal deletion.

## Query identifiers

For a new query Gateway generates and persists bindings before relay:

```text
chatId = <channelId>#web#<HMAC ownerRef>#<ULID-like id>
runId, requestId = Gateway-generated IDs
```

Gateway injects `externalAgentKey`, `chatId`, `runId`, `requestId`, and `sourceUser`. It removes model/team overrides and forces `accessLevel=default`. A retry with the same request ID attaches to the existing run. HTTP `Idempotency-Key` is scoped to tenant and owner; reusing it with a different canonical request returns 409.

## File transfer

Upload:

1. Browser multipart-posts one file and `chatId` to `/api/upload`.
2. Gateway spools with mode `0600`, creates a short-lived single-use binding, then requests channel `/api/upload` with an absolute `upload.url`.
3. Platform GETs that URL using its channel bearer token.
4. Gateway verifies token, tenant/platform/channel/route, consumes the ticket, and deletes the spool after the upstream result.

Download:

1. Browser GETs `/api/resource?file=<chatId/path>`.
2. Gateway verifies `file → chat binding → principal`, creates a push ticket, and requests `/api/resource {file,pushURL}` on the bound channel.
3. Platform POSTs bytes to the absolute `pushURL` using its channel bearer token.
4. Gateway validates the same route, size-limits the stream, then streams the temporary file to the browser and deletes it.

## Explicit denials

Any endpoint not present in the server allowlist returns 404. In particular, Gateway does not relay `/api/admin/*`, `/api/file`, Terminal/workspace APIs, Memory, Automation, Registry, Skill management, Teams, or model/access-level changes.
