#!/usr/bin/env bash
# Phase 2b: a Vault Kubernetes auth role per team, for External Secrets.
#
#   auth/kubernetes/role/<team>
#     bound SA: <team>/courier-secrets
#     policy:   <team>   (read kv/teams/<team>/*)
#
# Teams are the directories under requests/. The team policy must already
# exist (see vault-bootstrap.sh). Idempotent.
set -euo pipefail

repo="$(cd "$(dirname "$0")/../.." && pwd)"
NS=vault
POD=vault-0
KEYS_FILE="${KEYS_FILE:-$HOME/courier-vault-init.json}"
SA="${SA:-courier-secrets}"

v() { kubectl -n "$NS" exec -i "$POD" -- vault "$@"; }

if [ -n "${VAULT_ADMIN_TOKEN:-}" ]; then
  printf '%s' "$VAULT_ADMIN_TOKEN" | v login -no-print -
else
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["root_token"])' "$KEYS_FILE" | v login -no-print -
fi
trap 'kubectl -n "$NS" exec "$POD" -- sh -c "rm -f \$HOME/.vault-token" >/dev/null 2>&1 || true' EXIT

for dir in "$repo"/requests/*/; do
  team="$(basename "$dir")"
  if ! v policy read "$team" >/dev/null 2>&1; then
    echo "skip $team: vault policy $team does not exist (onboard the team first)"
    continue
  fi
  v write "auth/kubernetes/role/$team" \
    bound_service_account_names="$SA" \
    bound_service_account_namespaces="$team" \
    token_policies="$team" \
    token_ttl=1h \
    token_max_ttl=4h >/dev/null
  echo "role auth/kubernetes/role/$team -> $team/$SA (policy $team)"
done
