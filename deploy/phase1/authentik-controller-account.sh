#!/usr/bin/env bash
# Phase 1: create the controller's scoped Authentik identity and store its API
# token as Secret courier-system/courier-authentik (key AUTHENTIK_TOKEN).
# The token is never printed or passed on a command line.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
NS="${CONTROLLER_NS:-courier-system}"

kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f - >/dev/null

out="$(kubectl -n authentik exec -i deploy/authentik-server -- python3 - < "$here/authentik-controller-account.py")"

printf '%s' "$out" | python3 -c '
import json, sys
tok = json.load(sys.stdin)["token"]
print(json.dumps({
    "apiVersion": "v1", "kind": "Secret", "type": "Opaque",
    "metadata": {"name": "courier-authentik", "namespace": sys.argv[1],
                 "labels": {"app.kubernetes.io/part-of": "courier"}},
    "stringData": {"AUTHENTIK_TOKEN": tok},
}))
' "$NS" | kubectl apply -f -
