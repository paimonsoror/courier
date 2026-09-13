#!/usr/bin/env bash
# Phase 1 integration tests against the homelab Authentik and Vault.
#
# Mints two short-lived Vault tokens (policy courier = writer, team-alpha =
# reader), pulls the Authentik API token and a team-alpha test service account
# from the cluster, then runs `go test -tags integration`. Tokens are revoked
# on exit. Nothing sensitive is printed or placed on a command line.
#
# Needs a Vault token allowed to create tokens: ROOT_TOKEN_FILE (default: the
# phase 0 init file). After the root token is revoked, point VAULT_ADMIN_TOKEN
# at a token from `vault operator generate-root` or an admin OIDC login.
set -euo pipefail
export PATH="$HOME/.local/go/bin:$PATH"

repo="$(cd "$(dirname "$0")/../.." && pwd)"
PORT="${PORT:-18201}"
KEYS_FILE="${KEYS_FILE:-$HOME/courier-vault-init.json}"

kubectl -n vault port-forward svc/vault-active "$PORT:8200" >/dev/null 2>&1 &
pf=$!
export VAULT_ADDR="http://127.0.0.1:$PORT"

revoke() {
  local tok="$1"
  [ -n "$tok" ] || return 0
  curl -s -o /dev/null -X POST -H @<(printf 'X-Vault-Token: %s' "$tok") "$VAULT_ADDR/v1/auth/token/revoke-self" || true
}
cleanup() {
  revoke "${VAULT_WRITER_TOKEN:-}"
  revoke "${VAULT_READER_TOKEN:-}"
  kill "$pf" 2>/dev/null || true
}
trap cleanup EXIT

for _ in $(seq 1 30); do curl -sf "$VAULT_ADDR/v1/sys/health" >/dev/null && break; sleep 0.5; done

admin="${VAULT_ADMIN_TOKEN:-}"
if [ -z "$admin" ]; then
  admin="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["root_token"])' "$KEYS_FILE")"
fi

mint() {
  curl -sf -X POST -H @<(printf 'X-Vault-Token: %s' "$admin") \
    -d "{\"policies\":[\"$1\"],\"ttl\":\"30m\",\"display_name\":\"courier-it-$1\"}" \
    "$VAULT_ADDR/v1/auth/token/create" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["auth"]["client_token"])'
}
VAULT_WRITER_TOKEN="$(mint courier)"
VAULT_READER_TOKEN="$(mint team-alpha)"
export VAULT_WRITER_TOKEN VAULT_READER_TOKEN
unset admin

sec() { kubectl -n "$1" get secret "$2" -o "jsonpath={.data.$3}" | base64 -d; }
export AUTHENTIK_URL="${AUTHENTIK_URL:-https://auth.sororlab.dev}"
AUTHENTIK_TOKEN="$(sec authentik authentik-bootstrap AUTHENTIK_BOOTSTRAP_TOKEN)"
TEST_SA_USERNAME="$(sec vault courier-phase0-testers alpha_username)"
TEST_SA_TOKEN="$(sec vault courier-phase0-testers alpha_token)"
export AUTHENTIK_TOKEN TEST_SA_USERNAME TEST_SA_TOKEN
export TEST_OWNER_GROUP=team-alpha

cd "$repo"
go test -tags integration -count=1 -v ./pkg/idp/authentik/ ./pkg/broker/ 2>&1
