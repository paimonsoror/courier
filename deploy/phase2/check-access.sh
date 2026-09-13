#!/usr/bin/env bash
# Phase 2: after a request merges, prove who can read its credentials.
#
#   deploy/phase2/check-access.sh <team> <name>
#
# Logs in to Vault's jwt/ mount as the phase 0 test service account of every
# team (alpha, bravo) and reads the request's secret path. The owning team must
# get an active record, and its credentials must mint a token from Authentik.
# Every other team must be denied. Never prints credentials.
set -euo pipefail

TEAM="${1:?usage: check-access.sh <team> <name>}"
NAME="${2:?usage: check-access.sh <team> <name>}"
PORT="${PORT:-18204}"

kubectl -n "$TEAM" wait "oauthclient/$NAME" --for=condition=Ready --timeout=180s >/dev/null
path="$(kubectl -n "$TEAM" get oauthclient "$NAME" -o jsonpath='{.status.secretPath}')"
echo "request $TEAM/$NAME is Ready; credentials at $path"

kubectl -n vault port-forward svc/vault-active "$PORT:8200" >/dev/null 2>&1 &
pf=$!
trap 'kill $pf 2>/dev/null || true' EXIT
for _ in $(seq 1 30); do curl -sf "http://127.0.0.1:$PORT/v1/sys/health" >/dev/null && break; sleep 0.5; done

python3 - "$PORT" "$path" "$TEAM" <<'PY'
import base64, json, subprocess, sys, urllib.error, urllib.parse, urllib.request

port, path, owner = sys.argv[1:4]
vault = f"http://127.0.0.1:{port}"

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
        try:
            return e.code, json.loads(e.read() or b"{}")
        except ValueError:
            return e.code, {}

oidc = secret("vault", "vault-oidc")
testers = secret("vault", "courier-phase0-testers")
idp_token = oidc["issuer"].split("/application/o/")[0] + "/application/o/token/"
teams = sorted(k[: -len("_username")] for k in testers if k.endswith("_username"))

failures = 0
def check(label, ok, detail=""):
    global failures
    failures += 0 if ok else 1
    print(f"{'PASS' if ok else 'FAIL'}  {label}" + (f"  ({detail})" if detail and not ok else ""))

mount, rest = path.split("/", 1)
url = f"{vault}/v1/{mount}/data/{rest}"

for short in teams:
    team = f"team-{short}"
    st, tok = http(idp_token, {
        "grant_type": "client_credentials", "client_id": oidc["client_id"], "client_secret": oidc["client_secret"],
        "username": testers[f"{short}_username"], "password": testers[f"{short}_token"],
        "scope": "openid profile email groups"}, form=True)
    jwt = tok.get("id_token") or tok.get("access_token")
    st, login = http(f"{vault}/v1/auth/jwt/login", {"role": "machine", "jwt": jwt}) if jwt else (st, {})
    vtok = (login.get("auth") or {}).get("client_token")
    if not vtok:
        check(f"{team} logs in to vault", False, f"HTTP {st}")
        continue
    st, body = http(url, headers={"X-Vault-Token": vtok})
    if team == owner:
        data = (body.get("data") or {}).get("data") or {}
        check(f"{team} (owner) reads the credentials", st == 200 and data.get("state") == "active"
              and bool(data.get("client_secret")), f"HTTP {st} state={data.get('state')}")
        if data.get("token_endpoint"):
            code, err = http(data["token_endpoint"], {
                "grant_type": "client_credentials", "client_id": data["client_id"],
                "client_secret": data["client_secret"], "username": testers[f"{short}_username"],
                "password": testers[f"{short}_token"], "scope": "openid profile groups"}, form=True)
            check(f"{team} credentials get a token from Authentik", code == 200, f"HTTP {code} {err.get('error', '')}")
    else:
        check(f"{team} is denied", st == 403, f"HTTP {st}")
    http(f"{vault}/v1/auth/token/revoke-self", {}, headers={"X-Vault-Token": vtok})

print("\nACCESS CHECK PASSED" if failures == 0 else f"\n{failures} CHECK(S) FAILED")
sys.exit(1 if failures else 0)
PY
