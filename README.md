# Agent Gateway

## 1. Project overview

`agent-gateway` is a single-active Go gateway for multiple `agent-platform` channel connections. It terminates tenant and user identity, enforces Agent ACLs, owns unforgeable chat/run/resource routing bindings, and relays the existing `platform-ws` protocol. It does not execute agents or persist conversation content.

This release runs on SQLite only. The domain and `store.Store` boundary are database-neutral so a PostgreSQL adapter can be added without changing router or API contracts; `AGW_DATABASE_DRIVER=postgres` is intentionally rejected until that adapter exists.

### Scope and boundaries

- Host-to-tenant resolution; browser OIDC Authorization Code + PKCE sessions; OIDC bearer JWTs; anonymous browser identities; CSRF and WebSocket Origin checks.
- Platform RS256 JWT authentication at `GET /ws/agent?channelId=...`, keyed by `(tenant, platform, channel)`, with newest-connection-wins behavior.
- Atomic `agent.catalog.begin` / `agent.card.update` / `agent.catalog.commit` snapshots plus legacy card upsert compatibility.
- Disabled-by-default Gateway Agent projection, immutable public keys, public/authenticated/restricted visibility, permission-specific user/role/group ACLs, and optimistic policy versions.
- Explicit browser API allowlist, HTTP/SSE/browser-WebSocket relay, per-chat route stickiness, request/run idempotency, history aggregation, local rate/concurrency limits, audit records, and filtered push delivery.
- Temporary multipart upload pull tickets and platform-to-gateway resource push tickets. File bytes remain in a `0700` spool directory and never enter SQLite.
- SQLite foreign keys, WAL, busy timeout, serialized writes, strict schema version, integrity check, consistent backup, expiry cleanup, health and Prometheus metrics.

The first release deliberately does not expose platform admin, Registry, Memory, Automation, Skill management, Terminal, workspace files, arbitrary `/api/*`, non-default access levels, model overrides, or Teams.

## 2. Quick start

Requirements: Go 1.26+, an RSA key pair for platform credentials, and a random HMAC/admin secret.

```bash
cp .env.example .env
openssl genrsa -out configs/platform-jwt-private.pem 3072
openssl rsa -in configs/platform-jwt-private.pem -pubout -out configs/platform-jwt-public.pem
set -a
source .env
set +a
make run
```

The service listens on `:11945` by default. `/healthz` checks SQLite; `/metrics` exposes aggregate operational metrics without tenant or user labels.

## 3. Configuration

Copy `.env.example` to `.env` and provide real values locally or on the deployment host. `.env` and PEM keys are ignored by Git and must never be committed. Environment variables are the only runtime configuration source; defaults and validation live in `internal/config/config.go`. [`configs/gateway.example.yml`](configs/gateway.example.yml) is documentation-only and is not parsed.

For production, use an HTTPS `AGW_PUBLIC_BASE_URL`, keep `AGW_COOKIE_SECURE=true`, set `AGW_BOOTSTRAP_HOSTS` to the public host, generate independent random HMAC/admin secrets, and mount the platform RSA key pair as runtime secrets. See `.env.example` for the complete variable contract.

### Bootstrap tenant and OIDC

The bootstrap environment creates only the initial tenant/Host mapping. It never overwrites a tenant later edited through the admin API. Use the bootstrap bearer token on the tenant Host to set OIDC references:

```bash
curl -sS -X POST http://localhost:11945/api/gateway/admin/tenants \
  -H 'Host: localhost' \
  -H "Authorization: Bearer $AGW_BOOTSTRAP_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "tenantId":"local",
    "name":"Local",
    "status":"active",
    "hosts":["localhost","127.0.0.1"],
    "oidcIssuer":"https://id.example.com",
    "oidcClientId":"agent-gateway",
    "oidcClientSecretEnv":"AGW_LOCAL_OIDC_CLIENT_SECRET",
    "rolesClaim":"roles",
    "groupsClaim":"groups"
  }'
```

`oidcClientSecretEnv` is an environment-variable name, not the secret itself. The secret is never returned by normal APIs or written to logs.

### Add a platform and issue a channel credential

```bash
curl -sS -X POST http://localhost:11945/api/gateway/admin/platforms \
  -H 'Host: localhost' \
  -H "Authorization: Bearer $AGW_BOOTSTRAP_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"platformId":"platform-a","name":"Platform A","enabled":true}'

curl -sS -X POST http://localhost:11945/api/gateway/admin/platforms/platform-a/credentials \
  -H 'Host: localhost' \
  -H "Authorization: Bearer $AGW_BOOTSTRAP_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"channelId":"web-public"}'
```

The second response contains the only plaintext channel token. Configure platform to connect actively to:

```text
ws://localhost:11945/ws/agent?channelId=web-public
Authorization: Bearer <issued token>
```

Discovered routes appear at `GET /api/gateway/admin/agents`. They remain disabled and restricted until a tenant administrator publishes them. Both Agent metadata updates and policy replacement require `policyVersion` or `If-Match`.

```bash
curl -sS -X PUT http://localhost:11945/api/gateway/admin/agents/AGENT_ID/policy \
  -H 'Host: localhost' \
  -H "Authorization: Bearer $AGW_BOOTSTRAP_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'If-Match: "1"' \
  -d '{
    "visibility":"public",
    "permissions":{"discover":true,"invoke":true,"history.read":true,"run.control":true,"file.transfer":true},
    "acl":[]
  }'
```

Publishing (`enabled:true`) is a separate `PATCH /api/gateway/admin/agents/{id}` using the new policy version.

## 4. Deployment

The committed Compose topology builds the service, binds it only to `127.0.0.1:11945`, stores SQLite and spool data in the persistent `agent-gateway-data` volume, and mounts the platform RSA keys as Compose secrets.

```bash
cp .env.example .env
openssl genrsa -out configs/platform-jwt-private.pem 3072
openssl rsa -in configs/platform-jwt-private.pem -pubout -out configs/platform-jwt-public.pem
# Edit .env, then:
make deploy
make health
```

For the production host `singapore02`, clone the repository into `/docker/agent-gateway`, set `AGW_PUBLIC_BASE_URL=https://agent.zenmind.cc`, `AGW_COOKIE_SECURE=true`, and `AGW_BOOTSTRAP_HOSTS=agent.zenmind.cc` in the untracked `.env`. For first-time TLS provisioning, install `deploy/nginx/agent.zenmind.cc.http.conf`, issue the certificate with Certbot, then replace it with `deploy/nginx/agent.zenmind.cc.conf` and reload Nginx.

## 5. Operations

```bash
make docker-ps       # Container and health state
make docker-logs     # Follow service logs
make health          # Local reverse-proxy upstream health
make check           # SQLite integrity check
make backup          # Consistent timestamped backup in the data volume
```

Keep exactly one active Gateway instance against a SQLite database. A normal `make deploy` preserves `agent-gateway-data`; do not use `docker compose down -v` in production. Confirm both `http://127.0.0.1:11945/healthz` on the host and `https://agent.zenmind.cc/healthz` after every deployment.

## 6. Public API

Gateway-local:

- `GET /api/gateway/session`
- `GET /api/agents`
- `GET /api/agent?agentKey=<publicKey>`
- `/api/gateway/admin/*`

Binding-filtered and routed:

- `/api/chats`, `/api/chat`, `/api/chats/search`
- `/api/archives`, `/api/archive`, `/api/archives/search`
- `/api/query`, `/api/attach`, `/api/detach`
- `/api/submit`, `/api/steer`, `/api/interrupt`
- `/api/read`, `/api/feedback`, rename/derive/archive/delete/restore
- `/api/upload`, `/api/resource`
- `/api/viewport` (requires both `runId` and an event-bound `viewportKey`)

The browser `/ws` accepts the same `request`, `response`, `stream`, `push`, and `error` frames. A 401 is emitted as an error frame with `code: 401` and `type: "auth.required"` where authentication is required.

## 7. SQLite maintenance

Data and spool must be separate paths. Stop the active service before restoring.

```bash
# Online, transactionally consistent backup (destination must not exist)
go run ./cmd/agent-gateway -backup /secure-backups/gateway-$(date +%Y%m%d).db

# Startup-compatible schema and integrity check
go run ./cmd/agent-gateway -check
```

To restore: stop Gateway, preserve the failed database and its `-wal`/`-shm` files, copy a verified backup to `AGW_SQLITE_PATH`, run `-check`, then start one Gateway instance. Do not place the spool under the SQLite directory and do not deploy two active Gateway processes against the same database.

## 8. Verification

```bash
make test
make vet
make build
```

Tests cover catalog atomicity/removal, cross-tenant isolation, duplicate external keys on different channels, ACL/action intersection, local limits, SQLite backup/integrity, and a real platform JWT/WebSocket catalog exchange.

The required upstream/frontend changes are intentionally not made in their repositories. Use [`docs/PROMPT_PLATFORM.md`](docs/PROMPT_PLATFORM.md) and [`docs/PROMPT_WEBCLIENT.md`](docs/PROMPT_WEBCLIENT.md) as implementation prompts.
