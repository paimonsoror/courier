#!/usr/bin/env bash
# Phase 1: let the in-cluster Courier controller log in to Vault with its
# service account and receive only the write-only `courier` policy.
#
#   auth/kubernetes/role/courier
#     bound SA: courier-system/courier-controller-manager
#     policy:   courier (create/update/patch/delete on kv/teams/+/oauth-clients/*, no read)
#
# Vault runs in the same cluster, so it reviews tokens with its own service
# account (the chart grants system:auth-delegator). Idempotent.
set -euo pipefail

NS=vault
POD=vault-0
KEYS_FILE="${KEYS_FILE:-$HOME/courier-vault-init.json}"
CONTROLLER_NS="${CONTROLLER_NS:-courier-system}"
CONTROLLER_SA="${CONTROLLER_SA:-courier-controller-manager}"

v() { kubectl -n "$NS" exec -i "$POD" -- vault "$@"; }

if [ -n "${VAULT_ADMIN_TOKEN:-}" ]; then
  printf '%s' "$VAULT_ADMIN_TOKEN" | v login -no-print -
else
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["root_token"])' "$KEYS_FILE" | v login -no-print -
fi
trap 'kubectl -n "$NS" exec "$POD" -- sh -c "rm -f \$HOME/.vault-token" >/dev/null 2>&1 || true' EXIT

v auth list -format=json | grep -q '"kubernetes/"' || v auth enable kubernetes
v write auth/kubernetes/config kubernetes_host="https://kubernetes.default.svc:443"
v write auth/kubernetes/role/courier \
  bound_service_account_names="$CONTROLLER_SA" \
  bound_service_account_namespaces="$CONTROLLER_NS" \
  token_policies=courier \
  token_no_default_policy=true \
  token_ttl=1h \
  token_max_ttl=4h

echo "role auth/kubernetes/role/courier -> $CONTROLLER_NS/$CONTROLLER_SA (policy courier)"
