#!/usr/bin/env bash
# Phase 0 acceptance test: identity in IdP group X can read kv/teams/X/* and
# cannot read another team's path.
#
# For each test service account: get a token from Authentik (client_credentials),
# log in to Vault's jwt auth method, then try both teams' sample secrets.
# Prints PASS/FAIL per check. Never prints credentials or secret values.
set -euo pipefail

NS=vault
PORT="${PORT:-18200}"

kubectl -n "$NS" port-forward svc/vault-active "$PORT:8200" >/dev/null 2>&1 &
pf=$!
trap 'kill $pf 2>/dev/null || true' EXIT
for _ in $(seq 1 20); do curl -s "http://127.0.0.1:$PORT/v1/sys/health" >/dev/null && break; sleep 0.5; done

python3 - "$PORT" <<'PY'
import base64, json, subprocess, sys, urllib.error, urllib.parse, urllib.request

port = sys.argv[1]
vault = f"http://127.0.0.1:{port}"

def secret(name):
    raw = subprocess.check_output(["kubectl", "-n", "vault", "get", "secret", name, "-o", "json"])
    return {k: base64.b64decode(v).decode() for k, v in json.loads(raw)["data"].items()}

def http(url, data=None, headers=None, form=False):
    body = None
    hdrs = dict(headers or {})
    if data is not None:
        if form:
            body = urllib.parse.urlencode(data).encode()
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            body = json.dumps(data).encode()
            hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=hdrs, method="POST" if body else "GET")
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except ValueError:
            return e.code, {}

oidc = secret("vault-oidc")
testers = secret("courier-phase0-testers")
token_url = oidc["issuer"].split("/application/o/")[0] + "/application/o/token/"

failures = 0
def check(label, ok, detail=""):
    global failures
    failures += 0 if ok else 1
    print(f"{'PASS' if ok else 'FAIL'}  {label}{('  (' + detail + ')') if detail and not ok else ''}")

for team, other in (("alpha", "bravo"), ("bravo", "alpha")):
    status, tok = http(token_url, {
        "grant_type": "client_credentials",
        "client_id": oidc["client_id"],
        "client_secret": oidc["client_secret"],
        "username": testers[f"{team}_username"],
        "password": testers[f"{team}_token"],
        "scope": "openid profile email groups",
    }, form=True)
    jwt = tok.get("id_token") or tok.get("access_token")
    check(f"{team}: Authentik issues a token", status == 200 and bool(jwt), f"HTTP {status} {tok.get('error', '')}")
    if not jwt:
        continue

    claims = json.loads(base64.urlsafe_b64decode(jwt.split(".")[1] + "=="))
    check(f"{team}: token carries group team-{team}", f"team-{team}" in claims.get("groups", []), f"groups={claims.get('groups')}")

    status, login = http(f"{vault}/v1/auth/jwt/login", {"role": "machine", "jwt": jwt})
    vtok = (login.get("auth") or {}).get("client_token")
    check(f"{team}: Vault jwt login", status == 200 and bool(vtok), f"HTTP {status} {login.get('errors')}")
    if not vtok:
        continue
    policies = (login.get("auth") or {}).get("identity_policies") or []
    check(f"{team}: identity policy team-{team} attached", f"team-{team}" in policies, f"identity_policies={policies}")

    h = {"X-Vault-Token": vtok}
    status, _ = http(f"{vault}/v1/kv/data/teams/team-{team}/oauth-clients/phase0-sample", headers=h)
    check(f"{team}: CAN read kv/teams/team-{team}/...", status == 200, f"HTTP {status}")
    status, _ = http(f"{vault}/v1/kv/data/teams/team-{other}/oauth-clients/phase0-sample", headers=h)
    check(f"{team}: CANNOT read kv/teams/team-{other}/...", status == 403, f"HTTP {status}")

    http(f"{vault}/v1/auth/token/revoke-self", {}, headers=h)

print()
print("ALL CHECKS PASSED" if failures == 0 else f"{failures} CHECK(S) FAILED")
sys.exit(1 if failures else 0)
PY
