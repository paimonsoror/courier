#!/usr/bin/env bash
# Phase 0: run authentik-setup.py inside the Authentik server pod and store the
# resulting credentials as Kubernetes Secrets in the vault namespace:
#   vault/vault-oidc               client_id, client_secret, issuer
#   vault/courier-phase0-testers   <team>_username, <team>_token
# Credentials are never printed or passed on a command line.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"

out="$(kubectl -n authentik exec -i deploy/authentik-server -- python3 - < "$here/authentik-setup.py")"

printf '%s' "$out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
testers = {}
for team, t in d["testers"].items():
    testers[f"{team}_username"] = t["username"]
    testers[f"{team}_token"] = t["token"]
secrets = [
    ("vault-oidc", {**d["oidc"], "issuer": d["issuer"]}),
    ("courier-phase0-testers", testers),
]
print(json.dumps({"apiVersion": "v1", "kind": "List", "items": [
    {"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
     "metadata": {"name": n, "namespace": "vault", "labels": {"app.kubernetes.io/part-of": "courier-phase0"}},
     "stringData": s}
    for n, s in secrets
]}))
' | kubectl apply -f -
