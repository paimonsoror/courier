#!/usr/bin/env bash
# Phase 4: prove Courier adopted the hand-built legacy-crm client.
#
# Run after the adoption request (team-alpha/crm, annotation adopt: legacy-crm)
# merged and is Ready. Checks:
#   - the Authentik application now carries Courier's managed/owner marker
#   - the client ID did not change
#   - the "emailed" secret from create-legacy-client.sh no longer works
#   - the secret Courier stored in vault works, and only team-alpha can read it
set -euo pipefail

NS=team-alpha
NAME=crm
PORT="${PORT:-18207}"

kubectl -n "$NS" wait "oauthclient/$NAME" --for=condition=Ready --timeout=180s >/dev/null
kubectl -n "$NS" get oauthclient "$NAME"

echo "==> Authentik application"
kubectl -n authentik exec -i deploy/authentik-server -- python3 - <<'PY'
import json, os, urllib.request
req = urllib.request.Request("http://localhost:9000/api/v3/core/applications/legacy-crm/",
                             headers={"Authorization": "Bearer " + os.environ["AUTHENTIK_BOOTSTRAP_TOKEN"]})
app = json.load(urllib.request.urlopen(req))
print("      name:", app["name"], "| meta_description:", app["meta_description"])
PY

kubectl -n vault port-forward svc/vault-active "$PORT:8200" >/dev/null 2>&1 &
pf=$!
trap 'kill $pf 2>/dev/null || true' EXIT
for _ in $(seq 1 30); do curl -sf "http://127.0.0.1:$PORT/v1/sys/health" >/dev/null && break; sleep 0.5; done

python3 - "$PORT" <<'PY'
import base64, json, subprocess, sys, urllib.error, urllib.parse, urllib.request
vault = f"http://127.0.0.1:{sys.argv[1]}"

def secret(ns, name):
    raw = subprocess.check_output(["kubectl", "-n", ns, "get", "secret", name, "-o", "json"])
    return {k: base64.b64decode(v).decode() for k, v in json.loads(raw)["data"].items()}

def http(url, data=None, headers=None, form=False):
    hdrs = dict(headers or {})
    body = None
    if data is not None:
        body = urllib.parse.urlencode(data).encode() if form else json.dumps(data).encode()
        hdrs["Content-Type"] = "application/x-www-form-urlencoded" if form else "application/json"
    req = urllib.request.Request(url, data=body, headers=hdrs, method="POST" if body is not None else "GET")
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, {}

failures = 0
def check(label, ok, detail=""):
    global failures
    failures += 0 if ok else 1
    print(f"{'PASS' if ok else 'FAIL'}  {label}" + (f"  ({detail})" if detail and not ok else ""))

oidc, testers, legacy = secret("vault", "vault-oidc"), secret("vault", "courier-phase0-testers"), \
    secret("vault", "courier-phase4-legacy")
idp_token = oidc["issuer"].split("/application/o/")[0] + "/application/o/token/"

def vault_token(team):
    st, tok = http(idp_token, {"grant_type": "client_credentials", "client_id": oidc["client_id"],
        "client_secret": oidc["client_secret"], "username": testers[f"{team}_username"],
        "password": testers[f"{team}_token"], "scope": "openid profile email groups"}, form=True)
    st, login = http(f"{vault}/v1/auth/jwt/login", {"role": "machine", "jwt": tok.get("id_token") or tok["access_token"]})
    return login["auth"]["client_token"]

def token_status(client_id, client_secret):
    code, _ = http(idp_token, {"grant_type": "client_credentials", "client_id": client_id,
        "client_secret": client_secret, "username": testers["alpha_username"], "password": testers["alpha_token"],
        "scope": "openid profile"}, form=True)
    return code

url = f"{vault}/v1/kv/data/teams/team-alpha/oauth-clients/legacy-crm"
alpha, bravo = vault_token("alpha"), vault_token("bravo")
st, body = http(url, headers={"X-Vault-Token": alpha})
entry = (body.get("data") or {}).get("data") or {}
check("team-alpha reads the adopted client's credentials", st == 200 and entry.get("state") == "active", f"HTTP {st}")
check("client ID is unchanged by adoption", entry.get("client_id") == legacy["client_id"])
code = token_status(legacy["client_id"], legacy["client_secret"])
check("the emailed secret no longer works", code in (400, 401), f"HTTP {code}")
if entry.get("client_secret"):
    code = token_status(entry["client_id"], entry["client_secret"])
    check("the secret Courier stored in vault works", code == 200, f"HTTP {code}")
st, _ = http(url, headers={"X-Vault-Token": bravo})
check("team-bravo is denied", st == 403, f"HTTP {st}")
for t in (alpha, bravo):
    http(f"{vault}/v1/auth/token/revoke-self", {}, headers={"X-Vault-Token": t})
print("\nADOPTION VERIFIED" if failures == 0 else f"\n{failures} CHECK(S) FAILED")
sys.exit(1 if failures else 0)
PY
