# AGENTS.md

These instructions apply to the entire repository.

## Project contract

- This is a Go backend service. Keep the gateway single-active: do not introduce multi-replica deployment against the same SQLite database.
- `cmd/agent-gateway` owns process startup. `internal/server` owns HTTP and WebSocket boundaries, `internal/channel` owns platform connections, `internal/policy` owns authorization decisions, and `internal/store` owns persistence interfaces and implementations.
- Preserve tenant isolation, immutable public agent keys, route bindings, idempotency, CSRF/Origin validation, and the explicit browser API allowlist when changing behavior.
- The environment-variable contract lives in `.env.example`; defaults and validation live in `internal/config/config.go`. Do not create a second configuration source.

## Change workflow

1. Read the affected package and its tests before editing.
2. Keep changes scoped and add or update tests for behavior changes.
3. Run `make fmt`, `make test`, `make vet`, and `make build` before handing off.
4. If container or deployment files change, also run `docker compose -f compose.yml config` and build the image when Docker is available.

## Security and data

- Never commit `.env`, SQLite files, backups, private keys, certificates, tokens, session data, or spool contents.
- Keep production secrets in the server-side `.env` or runtime secrets. Examples must use obvious placeholders.
- Do not log bearer tokens, OIDC secrets, cookies, resource contents, tenant/user identifiers as metric labels, or plaintext platform credentials.
- Database migrations are forward-only. Preserve existing data and verify SQLite integrity before and after operational restore work.

## Deployment

- The production checkout is `/docker/agent-gateway` on `singapore02` and is served as `https://agent.zenmind.cc` through host Nginx.
- Use `make deploy` from the server checkout. Keep the service bound to `127.0.0.1:11945`; only Nginx should expose it publicly.
- Preserve the Docker volume `agent-gateway-data` during redeployments. `make docker-down` must not be extended to delete volumes.
- Keep the runtime privilege drop in `deploy/docker-entrypoint.sh`: it copies mounted key files into tmpfs, restricts them to `gateway`, and then uses `su-exec` before starting the requested command.
- Validate with `make health`, `make check`, container health status, and the public HTTPS `/healthz` endpoint after deployment.
