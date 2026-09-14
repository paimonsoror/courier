#!/usr/bin/env bash
# Phase 4 demo setup: create a hand-built client in Authentik (application
# legacy-crm) and keep its "emailed" credentials in Secret
# vault/courier-phase4-legacy, so the adoption check can later prove that the
# old secret stopped working. Then confirm the old secret works today.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"

out="$(kubectl -n authentik exec -i deploy/authentik-server -- python3 - < "$here/create-legacy-client.py")"
printf '%s' "$out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(json.dumps({"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
  "metadata": {"name": "courier-phase4-legacy", "namespace": "vault",
               "labels": {"app.kubernetes.io/part-of": "courier-phase4-demo"}},
  "stringData": d}))' | kubectl apply -f -

python3 - <<'PY'
import base64, json, subprocess, urllib.error, urllib.parse, urllib.request

def secret(ns, name):
    raw = subprocess.check_output(["kubectl", "-n", ns, "get", "secret", name, "-o", "json"])
    return {k: base64.b64decode(v).decode() for k, v in json.loads(raw)["data"].items()}

legacy = secret("vault", "courier-phase4-legacy")
testers = secret("vault", "courier-phase0-testers")
form = {"grant_type": "client_credentials", "client_id": legacy["client_id"], "client_secret": legacy["client_secret"],
        "username": testers["alpha_username"], "password": testers["alpha_token"], "scope": "openid profile"}
try:
    urllib.request.urlopen("https://auth.sororlab.dev/application/o/token/", data=urllib.parse.urlencode(form).encode())
    print(f"legacy-crm client_id={legacy['client_id']}: the emailed secret works today (HTTP 200)")
except urllib.error.HTTPError as e:
    raise SystemExit(f"legacy secret should work before adoption, got HTTP {e.code}")
PY
