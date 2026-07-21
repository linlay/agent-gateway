package sqlite

const schemaVersion = 1

const migrationV1 = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at INTEGER NOT NULL
);

CREATE TABLE tenants (
    tenant_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active','disabled')),
    oidc_issuer TEXT NOT NULL DEFAULT '',
    oidc_client_id TEXT NOT NULL DEFAULT '',
    oidc_client_secret_env TEXT NOT NULL DEFAULT '',
    roles_claim TEXT NOT NULL DEFAULT 'roles',
    groups_claim TEXT NOT NULL DEFAULT 'groups',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE tenant_hosts (
    tenant_id TEXT NOT NULL,
    host TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, host),
    UNIQUE (host),
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

CREATE TABLE platforms (
    tenant_id TEXT NOT NULL,
    platform_id TEXT NOT NULL,
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL CHECK (enabled IN (0,1)),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, platform_id),
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

CREATE TABLE platform_credentials (
    tenant_id TEXT NOT NULL,
    platform_id TEXT NOT NULL,
    jti_hash TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, platform_id, jti_hash),
    FOREIGN KEY (tenant_id, platform_id) REFERENCES platforms(tenant_id, platform_id) ON DELETE CASCADE
);

CREATE TABLE catalog_snapshots (
    tenant_id TEXT NOT NULL,
    platform_id TEXT NOT NULL,
    channel_id TEXT NOT NULL,
    snapshot_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    card_count INTEGER NOT NULL,
    status TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    committed_at INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, platform_id, channel_id, snapshot_id),
    FOREIGN KEY (tenant_id, platform_id) REFERENCES platforms(tenant_id, platform_id) ON DELETE CASCADE
);

CREATE TABLE channel_routes (
    route_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    platform_id TEXT NOT NULL,
    channel_id TEXT NOT NULL,
    external_agent_key TEXT NOT NULL,
    card_json TEXT NOT NULL,
    operations_json TEXT NOT NULL,
    protocol_mode TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('online','offline','removed')),
    revision INTEGER NOT NULL DEFAULT 0,
    snapshot_id TEXT NOT NULL DEFAULT '',
    last_seen_at INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (tenant_id, platform_id, channel_id, external_agent_key),
    FOREIGN KEY (tenant_id, platform_id) REFERENCES platforms(tenant_id, platform_id) ON DELETE CASCADE
);

CREATE INDEX idx_channel_routes_channel ON channel_routes(tenant_id, platform_id, channel_id, status);

CREATE TABLE gateway_agents (
    agent_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    route_id TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    enabled INTEGER NOT NULL CHECK (enabled IN (0,1)),
    visibility TEXT NOT NULL CHECK (visibility IN ('public','authenticated','restricted')),
    permissions_json TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    display_description TEXT NOT NULL DEFAULT '',
    sort_order INTEGER NOT NULL DEFAULT 0,
    policy_version INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE (tenant_id, public_key),
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    FOREIGN KEY (route_id) REFERENCES channel_routes(route_id) ON DELETE CASCADE
);

CREATE INDEX idx_gateway_agents_catalog ON gateway_agents(tenant_id, enabled, sort_order, public_key);

CREATE TABLE agent_acl (
    acl_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    subject_type TEXT NOT NULL CHECK (subject_type IN ('user','role','group')),
    subject_value TEXT NOT NULL,
    permission TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE (tenant_id, agent_id, subject_type, subject_value, permission),
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    FOREIGN KEY (agent_id) REFERENCES gateway_agents(agent_id) ON DELETE CASCADE
);

CREATE TABLE web_sessions (
    tenant_id TEXT NOT NULL,
    session_hash TEXT NOT NULL,
    subject TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    roles_json TEXT NOT NULL,
    groups_json TEXT NOT NULL,
    csrf_token TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, session_hash),
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

CREATE TABLE anonymous_sessions (
    tenant_id TEXT NOT NULL,
    session_hash TEXT NOT NULL,
    anonymous_id TEXT NOT NULL,
    csrf_token TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, session_hash),
    UNIQUE (tenant_id, anonymous_id),
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

CREATE TABLE oidc_flows (
    tenant_id TEXT NOT NULL,
    state_hash TEXT NOT NULL,
    verifier TEXT NOT NULL,
    nonce TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    return_to TEXT NOT NULL,
    anonymous_id TEXT NOT NULL DEFAULT '',
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, state_hash),
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

CREATE TABLE chat_bindings (
    tenant_id TEXT NOT NULL,
    chat_id TEXT NOT NULL,
    owner_kind TEXT NOT NULL CHECK (owner_kind IN ('user','anonymous')),
    owner_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    route_id TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, chat_id),
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    FOREIGN KEY (agent_id) REFERENCES gateway_agents(agent_id),
    FOREIGN KEY (route_id) REFERENCES channel_routes(route_id)
);

CREATE INDEX idx_chat_bindings_owner ON chat_bindings(tenant_id, owner_kind, owner_id, updated_at DESC);

CREATE TABLE run_bindings (
    tenant_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    chat_id TEXT NOT NULL,
    route_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    status TEXT NOT NULL,
    last_seq INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, run_id),
    UNIQUE (tenant_id, request_id),
    FOREIGN KEY (tenant_id, chat_id) REFERENCES chat_bindings(tenant_id, chat_id) ON DELETE CASCADE,
    FOREIGN KEY (route_id) REFERENCES channel_routes(route_id)
);

CREATE INDEX idx_run_bindings_chat ON run_bindings(tenant_id, chat_id, created_at DESC);

CREATE TABLE viewport_bindings (
    tenant_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    chat_id TEXT NOT NULL,
    route_id TEXT NOT NULL,
    viewport_key TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, run_id, viewport_key),
    FOREIGN KEY (tenant_id, run_id) REFERENCES run_bindings(tenant_id, run_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, chat_id) REFERENCES chat_bindings(tenant_id, chat_id) ON DELETE CASCADE,
    FOREIGN KEY (route_id) REFERENCES channel_routes(route_id)
);

CREATE TABLE resource_bindings (
    tenant_id TEXT NOT NULL,
    resource_key TEXT NOT NULL,
    chat_id TEXT NOT NULL,
    owner_kind TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    route_id TEXT NOT NULL,
	direction TEXT NOT NULL CHECK (direction IN ('pull','push')),
	token_hash TEXT NOT NULL,
	spool_path TEXT NOT NULL,
	file_name TEXT NOT NULL,
	mime_type TEXT NOT NULL,
	size_bytes INTEGER NOT NULL DEFAULT 0,
	sha256 TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL,
    expires_at INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, resource_key),
	UNIQUE (tenant_id, token_hash),
    FOREIGN KEY (tenant_id, chat_id) REFERENCES chat_bindings(tenant_id, chat_id) ON DELETE CASCADE,
    FOREIGN KEY (route_id) REFERENCES channel_routes(route_id)
);

CREATE INDEX idx_resource_bindings_expiry ON resource_bindings(tenant_id, expires_at, status);

CREATE TABLE idempotency_keys (
    tenant_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    owner_kind TEXT NOT NULL,
    owner_id TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    chat_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, idempotency_key),
    FOREIGN KEY (tenant_id, chat_id) REFERENCES chat_bindings(tenant_id, chat_id) ON DELETE CASCADE
);

CREATE TABLE audit_logs (
    audit_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    result TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

CREATE INDEX idx_audit_logs_tenant_time ON audit_logs(tenant_id, created_at DESC);
`
