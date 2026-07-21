#!/bin/sh
set -eu

runtime_secrets=/tmp/agent-gateway-secrets
mkdir -p "$runtime_secrets"
cp /run/secrets/platform_jwt_public "$runtime_secrets/platform-jwt-public.pem"
cp /run/secrets/platform_jwt_private "$runtime_secrets/platform-jwt-private.pem"
chown -R gateway:gateway "$runtime_secrets"
chmod 700 "$runtime_secrets"
chmod 400 "$runtime_secrets/platform-jwt-public.pem" "$runtime_secrets/platform-jwt-private.pem"

export AGW_PLATFORM_JWT_PUBLIC_KEY_FILE="$runtime_secrets/platform-jwt-public.pem"
export AGW_PLATFORM_JWT_PRIVATE_KEY_FILE="$runtime_secrets/platform-jwt-private.pem"

exec su-exec gateway "$@"
