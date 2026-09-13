#!/usr/bin/env bash
# Phase 0: initialize Vault (AWS KMS auto-unseal) and configure:
#   - KV v2 at kv/, file audit device
#   - OIDC auth (humans, browser/CLI) and JWT auth (machines) against Authentik
#   - policies: vault-admin, team-alpha, team-bravo, courier (write-only)
#   - external identity groups + aliases on both auth mounts
#   - one sample secret per team
# Idempotent. Requires: authentik-setup.sh has run (Secret vault/vault-oidc).
set -euo pipefail

NS=vault
POD=vault-0
VAULT_HOST="${VAULT_HOST:-vault.sororlab.dev}"
KEYS_FILE="${KEYS_FILE:-$HOME/courier-vault-init.json}"

v() { kubectl -n "$NS" exec -i "$POD" -- vault "$@"; }
json_get() { python3 -c "import sys,json; d=json.load(sys.stdin); print(eval('d'+sys.argv[1]))" "$1"; }

echo "==> waiting for $POD to be running"
kubectl -n "$NS" wait --for=jsonpath='{.status.phase}'=Running "pod/$POD" --timeout=300s

initialized="$(kubectl -n "$NS" exec "$POD" -- vault status -format=json 2>/dev/null | json_get '["initialized"]' || true)"
if [ "$initialized" != "True" ]; then
  echo "==> initializing (recovery keys, KMS auto-unseal)"
  [ -e "$KEYS_FILE" ] && { echo "refusing to overwrite existing $KEYS_FILE" >&2; exit 1; }
  (umask 077; kubectl -n "$NS" exec "$POD" -- vault operator init -recovery-shares=5 -recovery-threshold=3 -format=json > "$KEYS_FILE")
  echo "    recovery keys + root token written to $KEYS_FILE (mode 600)"
  echo "    PRINT/STORE OFFLINE, then delete the file."
fi

echo "==> waiting for unseal"
for _ in $(seq 1 60); do
  sealed="$(kubectl -n "$NS" exec "$POD" -- vault status -format=json 2>/dev/null | json_get '["sealed"]' || true)"
  [ "$sealed" = "False" ] && break
  sleep 2
done
[ "$sealed" = "False" ] || { echo "vault still sealed; check KMS creds in secret vault-awskms" >&2; exit 1; }

echo "==> logging in with root token (token file lives only inside the pod, removed at exit)"
if [ -r "$KEYS_FILE" ]; then
  json_get '["root_token"]' < "$KEYS_FILE" | v login -no-print -
else
  read -rsp "root token: " tok; echo
  printf '%s' "$tok" | v login -no-print -; unset tok
fi
trap 'kubectl -n "$NS" exec "$POD" -- sh -c "rm -f \$HOME/.vault-token" >/dev/null 2>&1 || true' EXIT

echo "==> secrets engine + audit"
v secrets list -format=json | grep -q '"kv/"' || v secrets enable -path=kv kv-v2
v audit list -format=json | grep -q '"file/"' || v audit enable file file_path=/vault/audit/audit.log

echo "==> auth methods"
v auth list -format=json | grep -q '"oidc/"' || v auth enable oidc
v auth list -format=json | grep -q '"jwt/"'  || v auth enable jwt

ISSUER="$(kubectl -n "$NS" get secret vault-oidc -o jsonpath='{.data.issuer}' | base64 -d)"
CLIENT_ID="$(kubectl -n "$NS" get secret vault-oidc -o jsonpath='{.data.client_id}' | base64 -d)"

kubectl -n "$NS" get secret vault-oidc -o jsonpath='{.data.client_secret}' | base64 -d \
  | v write auth/oidc/config \
      oidc_discovery_url="$ISSUER" \
      oidc_client_id="$CLIENT_ID" \
      oidc_client_secret=- \
      default_role=human

v write auth/oidc/role/human \
  role_type=oidc \
  user_claim=email \
  groups_claim=groups \
  oidc_scopes="profile,email,groups" \
  bound_audiences="$CLIENT_ID" \
  allowed_redirect_uris="https://$VAULT_HOST/ui/vault/auth/oidc/oidc/callback,http://localhost:8250/oidc/callback" \
  token_policies=default \
  token_ttl=1h

v write auth/jwt/config oidc_discovery_url="$ISSUER" bound_issuer="$ISSUER"
v write auth/jwt/role/machine \
  role_type=jwt \
  user_claim=preferred_username \
  groups_claim=groups \
  bound_audiences="$CLIENT_ID" \
  token_policies=default \
  token_ttl=15m

echo "==> policies"
v policy write vault-admin - <<'HCL'
# Phase 0 operator policy. Broad on purpose; narrow before anyone else joins.
path "*" {
  capabilities = ["create", "read", "update", "patch", "delete", "list", "sudo"]
}
HCL

for team in team-alpha team-bravo; do
  v policy write "$team" - <<HCL
# Members of the $team IdP group read their team's secrets, nothing else.
path "kv/data/teams/$team/*" {
  capabilities = ["read"]
}
path "kv/metadata/teams/$team/*" {
  capabilities = ["read", "list"]
}
path "kv/metadata/teams/$team" {
  capabilities = ["list"]
}
HCL
done

v policy write courier - <<'HCL'
# Courier controller: write client credentials, never read them back.
path "kv/data/teams/+/oauth-clients/*" {
  capabilities = ["create", "update"]
}
path "kv/metadata/teams/+/oauth-clients/*" {
  capabilities = ["delete"]
}
HCL

echo "==> identity groups and aliases"
accessor() { v auth list -format=json | json_get "[\"$1/\"][\"accessor\"]"; }
OIDC_ACC="$(accessor oidc)"
JWT_ACC="$(accessor jwt)"

for pair in vault-admins:vault-admin team-alpha:team-alpha team-bravo:team-bravo; do
  group="${pair%%:*}"; policy="${pair##*:}"
  v write identity/group name="$group" type=external policies="$policy" >/dev/null
  gid="$(v read -field=id "identity/group/name/$group")"
  for acc in "$OIDC_ACC" "$JWT_ACC"; do
    existing="$(v write -format=json identity/lookup/group alias_name="$group" alias_mount_accessor="$acc" 2>/dev/null || true)"
    if [ -z "$existing" ]; then
      v write identity/group-alias name="$group" mount_accessor="$acc" canonical_id="$gid" >/dev/null
      echo "    alias $group -> $acc"
    fi
  done
done

echo "==> sample secrets"
for team in team-alpha team-bravo; do
  v kv put "kv/teams/$team/oauth-clients/phase0-sample" \
    client_id="sample-$team" \
    client_secret="phase0-sample-not-a-real-secret" \
    client_type=confidential \
    state=sample \
    managed_by=phase0-bootstrap >/dev/null
  echo "    kv/teams/$team/oauth-clients/phase0-sample"
done

echo "==> done"
