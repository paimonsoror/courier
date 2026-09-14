#!/usr/bin/env bash
# Phase 4: prove a rotation of team-bravo/report-exporter took effect.
#
# Run after the rotation request merged and the OAuthClient is Ready again.
# The External Secrets copy in team-bravo still holds the previous secret until
# its next refresh, which lets us prove the old secret is dead without ever
# writing a secret to disk:
#   1. vault holds a new secret; the Kubernetes Secret still holds the old one
#   2. Authentik rejects the old secret and accepts the new one
#   3. forcing External Secrets to refresh brings the new secret into the namespace
set -euo pipefail

NS=team-bravo
NAME=report-exporter
ES=report-exporter-oauth
PORT="${PORT:-18206}"

echo "==> request status"
kubectl -n "$NS" wait "oauthclient/$NAME" --for=condition=Ready --timeout=180s >/dev/null
kubectl -n "$NS" get oauthclient "$NAME" -o jsonpath='{"lastSecretIssued: "}{.status.lastSecretIssued}{"\nrotationHandled:  "}{.status.rotationHandled}{"\n"}'

kubectl -n vault port-forward svc/vault-active "$PORT:8200" >/dev/null 2>&1 &
pf=$!
trap 'kill $pf 2>/dev/null || true' EXIT
for _ in $(seq 1 30); do curl -sf "http://127.0.0.1:$PORT/v1/sys/health" >/dev/null && break; sleep 0.5; done

check() {
python3 - "$PORT" "$1" <<'PY'
import base64, hashlib, json, subprocess, sys, urllib.error, urllib.parse, urllib.request
port, phase = sys.argv[1], sys.argv[2]
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
        return e.code, {}

fp = lambda s: hashlib.sha256(s.encode()).hexdigest()[:12]
failures = 0
def check(label, ok, detail=""):
    global failures
    failures += 0 if ok else 1
    print(f"{'PASS' if ok else 'FAIL'}  {label}" + (f"  ({detail})" if detail and not ok else ""))

oidc, testers = secret("vault", "vault-oidc"), secret("vault", "courier-phase0-testers")
idp_token = oidc["issuer"].split("/application/o/")[0] + "/application/o/token/"
st, tok = http(idp_token, {"grant_type": "client_credentials", "client_id": oidc["client_id"],
    "client_secret": oidc["client_secret"], "username": testers["bravo_username"],
    "password": testers["bravo_token"], "scope": "openid profile email groups"}, form=True)
st, login = http(f"{vault}/v1/auth/jwt/login", {"role": "machine", "jwt": tok.get("id_token") or tok["access_token"]})
vtok = login["auth"]["client_token"]
st, body = http(f"{vault}/v1/kv/data/teams/team-bravo/oauth-clients/team-bravo-report-exporter",
                headers={"X-Vault-Token": vtok})
entry = body["data"]["data"]
version = body["data"]["metadata"]["version"]
k8s = secret("team-bravo", "report-exporter-oauth")

def token_status(client_secret):
    code, _ = http(entry["token_endpoint"], {"grant_type": "client_credentials", "client_id": entry["client_id"],
        "client_secret": client_secret, "username": testers["bravo_username"], "password": testers["bravo_token"],
        "scope": "openid profile groups"}, form=True)
    return code

print(f"      vault version {version}, state {entry['state']}, secret fingerprint {fp(entry['client_secret'])}")
print(f"      kubernetes Secret fingerprint {fp(k8s['client_secret'])} (client_id {'unchanged' if k8s['client_id'] == entry['client_id'] else 'CHANGED'})")

if phase == "before-sync":
    check("vault holds a new secret; the synced copy still holds the previous one",
          k8s["client_secret"] != entry["client_secret"])
    check("client ID is unchanged by rotation", k8s["client_id"] == entry["client_id"])
    code = token_status(k8s["client_secret"])
    check("Authentik rejects the previous secret", code in (400, 401), f"HTTP {code}")
    code = token_status(entry["client_secret"])
    check("Authentik accepts the new secret", code == 200, f"HTTP {code}")
else:
    check("External Secrets now holds the new secret", k8s["client_secret"] == entry["client_secret"])
    code = token_status(k8s["client_secret"])
    check("the synced copy works", code == 200, f"HTTP {code}")

http(f"{vault}/v1/auth/token/revoke-self", {}, headers={"X-Vault-Token": vtok})
sys.exit(1 if failures else 0)
PY
}

echo "==> before External Secrets refresh"
check before-sync

echo "==> force External Secrets to refresh"
kubectl -n "$NS" annotate externalsecret "$ES" force-sync="$(date +%s)" --overwrite >/dev/null
sleep 15
check after-sync

echo
echo "ROTATION VERIFIED"
