#!/usr/bin/env bash
# Phase 1 acceptance: request a client the Kubernetes way, then act as the teams.
#
#   1. kubectl apply an OAuthClient in namespace team-alpha; wait for Ready
#   2. as a team-alpha identity: read the delivered credentials from Vault and
#      confirm Authentik accepts that secret (and rejects a wrong one)
#   3. as a team-bravo identity: reading the same path is denied
#   4. delete the OAuthClient: the credentials are destroyed
#
# Identities are the phase 0 service accounts, logging in through Vault's jwt/
# mount exactly as a workload would. Never prints credentials.
# KEEP=1 skips step 4.
set -euo pipefail

repo="$(cd "$(dirname "$0")/../.." && pwd)"
NS=team-alpha
NAME=billing-sync
PORT="${PORT:-18203}"
cd "$repo"

echo "==> request"
kubectl apply -f deploy/phase1/examples/team-alpha-billing-sync.yaml
kubectl -n "$NS" wait "oauthclient/$NAME" --for=condition=Ready --timeout=180s
kubectl -n "$NS" get oauthclient "$NAME"
path="$(kubectl -n "$NS" get oauthclient "$NAME" -o jsonpath='{.status.secretPath}')"

kubectl -n vault port-forward svc/vault-active "$PORT:8200" >/dev/null 2>&1 &
pf=$!
trap 'kill $pf 2>/dev/null || true' EXIT
for _ in $(seq 1 30); do curl -sf "http://127.0.0.1:$PORT/v1/sys/health" >/dev/null && break; sleep 0.5; done

check_as_teams() {
python3 - "$PORT" "$path" "$1" <<'PY'
import base64, json, subprocess, sys, urllib.error, urllib.parse, urllib.request

port, path, mode = sys.argv[1:4]
vault = f"http://127.0.0.1:{port}"

def secret(ns, name):
    raw = subprocess.check_output(["kubectl", "-n", ns, "get", "secret", name, "-o", "json"])
    return {k: base64.b64decode(v).decode() for k, v in json.loads(raw)["data"].items()}

def http(url, data=None, headers=None, form=False):
    hdrs = dict(headers or {})
    body = None
    if data is not None:
        if form:
            body = urllib.parse.urlencode(data).encode()
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            body = json.dumps(data).encode()
            hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=hdrs, method="POST" if body is not None else "GET")
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except ValueError:
            return e.code, {}

failures = 0
def check(label, ok, detail=""):
    global failures
    failures += 0 if ok else 1
    print(f"{'PASS' if ok else 'FAIL'}  {label}" + (f"  ({detail})" if detail and not ok else ""))

oidc = secret("vault", "vault-oidc")
testers = secret("vault", "courier-phase0-testers")
idp_token_url = oidc["issuer"].split("/application/o/")[0] + "/application/o/token/"

def vault_token(team):
    st, tok = http(idp_token_url, {
        "grant_type": "client_credentials", "client_id": oidc["client_id"], "client_secret": oidc["client_secret"],
        "username": testers[f"{team}_username"], "password": testers[f"{team}_token"],
        "scope": "openid profile email groups",
    }, form=True)
    jwt = tok.get("id_token") or tok.get("access_token")
    if not jwt:
        sys.exit(f"cannot get an Authentik token for {team}: HTTP {st}")
    st, login = http(f"{vault}/v1/auth/jwt/login", {"role": "machine", "jwt": jwt})
    if st != 200:
        sys.exit(f"vault login for {team} failed: HTTP {st} {login.get('errors')}")
    return login["auth"]["client_token"]

mount, rest = path.split("/", 1)
url = f"{vault}/v1/{mount}/data/{rest}"
alpha, bravo = vault_token("alpha"), vault_token("bravo")

if mode == "present":
    st, body = http(url, headers={"X-Vault-Token": alpha})
    data = (body.get("data") or {}).get("data") or {}
    check(f"team-alpha reads {path}", st == 200 and data.get("state") == "active" and bool(data.get("client_secret")),
          f"HTTP {st} state={data.get('state')}")
    st, _ = http(url, headers={"X-Vault-Token": bravo})
    check("team-bravo is denied", st == 403, f"HTTP {st}")
    if data.get("token_endpoint") and data.get("client_secret"):
        # The revocation endpoint always authenticates the client (200 accepted,
        # 401 rejected). A client_credentials token request would not prove the
        # secret: Authentik ignores it when a service account signs in.
        revoke = data["token_endpoint"].replace("/token/", "/revoke/")
        for label, candidate, want in (("Authentik accepts the delivered secret", data["client_secret"], 200),
                                       ("Authentik rejects a wrong secret", "not-the-secret", 401)):
            auth = base64.b64encode(f"{data['client_id']}:{candidate}".encode()).decode()
            st, _ = http(revoke, {"token": "courier-probe-not-a-real-token"},
                         headers={"Authorization": "Basic " + auth}, form=True)
            check(label, st == want, f"HTTP {st}")
else:
    st, _ = http(url, headers={"X-Vault-Token": alpha})
    check("credentials destroyed after the request is deleted", st == 404, f"HTTP {st}")

for t in (alpha, bravo):
    http(f"{vault}/v1/auth/token/revoke-self", {}, headers={"X-Vault-Token": t})
sys.exit(1 if failures else 0)
PY
}

echo "==> act as the teams"
check_as_teams present

if [ "${KEEP:-0}" = "1" ]; then
  echo "KEEP=1: leaving $NS/$NAME in place"
  exit 0
fi

echo "==> delete the request"
kubectl -n "$NS" delete oauthclient "$NAME" --wait=true --timeout=180s
check_as_teams absent

echo
echo "PHASE 1 ACCEPTANCE PASSED"
