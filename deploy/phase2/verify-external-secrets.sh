#!/usr/bin/env bash
# Phase 2b: prove External Secrets delivers credentials to the owning team's
# namespace, and to no other.
#
#   1. team-bravo's SecretStore is Ready
#   2. an ExternalSecret in team-bravo syncs report-exporter's credentials into
#      a Kubernetes Secret, and Authentik accepts the synced secret
#   3. an ExternalSecret in team-alpha that points at team-bravo's path fails
#      with permission denied, and no Secret is created
#
# Never prints credentials.
set -euo pipefail

repo="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$repo"
fail=0
pass() { echo "PASS  $*"; }
bad() { echo "FAIL  $*"; fail=1; }

echo "==> stores"
kubectl -n team-bravo wait secretstore/courier-vault --for=condition=Ready --timeout=120s >/dev/null && pass "team-bravo SecretStore Ready" || bad "team-bravo SecretStore not Ready"
kubectl -n team-alpha wait secretstore/courier-vault --for=condition=Ready --timeout=120s >/dev/null && pass "team-alpha SecretStore Ready" || bad "team-alpha SecretStore not Ready"

echo "==> owner sync (team-bravo)"
kubectl apply -f deploy/phase2/examples/team-bravo-externalsecret.yaml >/dev/null
if kubectl -n team-bravo wait externalsecret/report-exporter-oauth --for=condition=Ready --timeout=120s >/dev/null; then
  pass "ExternalSecret team-bravo/report-exporter-oauth synced"
else
  bad "ExternalSecret did not sync: $(kubectl -n team-bravo get externalsecret report-exporter-oauth -o jsonpath='{.status.conditions[0].message}')"
fi

kubectl -n team-bravo get secret report-exporter-oauth -o json | python3 -c '
import base64, json, sys
d = {k: base64.b64decode(v).decode() for k, v in json.load(sys.stdin)["data"].items()}
print("      keys:", ", ".join(sorted(d)))
print("      state:", d.get("state"), " client_id:", d.get("client_id"), " client_secret: present (%d chars)" % len(d.get("client_secret", "")))
'

code="$(kubectl -n team-bravo get secret report-exporter-oauth -o json | python3 -c '
import base64, json, subprocess, sys, urllib.error, urllib.parse, urllib.request
def sec(ns, name):
    raw = subprocess.check_output(["kubectl", "-n", ns, "get", "secret", name, "-o", "json"])
    return {k: base64.b64decode(v).decode() for k, v in json.loads(raw)["data"].items()}
d = {k: base64.b64decode(v).decode() for k, v in json.load(sys.stdin)["data"].items()}
t = sec("vault", "courier-phase0-testers")
# The revocation endpoint authenticates the client: 200 = Authentik accepts
# the synced client_id/secret. (A client_credentials token request would not.)
auth = base64.b64encode((d["client_id"] + ":" + d["client_secret"]).encode()).decode()
req = urllib.request.Request(d["token_endpoint"].replace("/token/", "/revoke/"),
    data=urllib.parse.urlencode({"token": "courier-probe-not-a-real-token"}).encode(),
    headers={"Authorization": "Basic " + auth})
try:
    urllib.request.urlopen(req, timeout=30)
    print(200)
except urllib.error.HTTPError as e:
    print(e.code)
')"
[ "$code" = "200" ] && pass "Authentik accepts the synced secret" || bad "Authentik rejected the synced secret (HTTP $code)"

echo "==> cross-team attempt (team-alpha -> team-bravo path)"
kubectl apply -f - >/dev/null <<'YAML'
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: attempt-team-bravo
  namespace: team-alpha
spec:
  refreshInterval: 1m
  secretStoreRef:
    name: courier-vault
    kind: SecretStore
  target:
    name: attempt-team-bravo
  dataFrom:
    - extract:
        key: teams/team-bravo/oauth-clients/team-bravo-report-exporter
YAML
for _ in $(seq 1 24); do
  reason="$(kubectl -n team-alpha get externalsecret attempt-team-bravo -o jsonpath='{.status.conditions[0].reason}' 2>/dev/null || true)"
  [ -n "$reason" ] && break
  sleep 5
done
msg="$(kubectl -n team-alpha get externalsecret attempt-team-bravo -o jsonpath='{.status.conditions[0].message}' 2>/dev/null || true)"
echo "      reason: $reason"
echo "      message: ${msg:0:160}"
if [ "$reason" = "SecretSyncedError" ] && ! kubectl -n team-alpha get secret attempt-team-bravo >/dev/null 2>&1; then
  pass "team-alpha cannot sync team-bravo's credentials; no Secret created"
else
  bad "cross-team sync was not refused"
fi
kubectl -n team-alpha delete externalsecret attempt-team-bravo --ignore-not-found >/dev/null

echo
[ $fail -eq 0 ] && echo "EXTERNAL SECRETS VERIFIED" || { echo "EXTERNAL SECRETS CHECK FAILED"; exit 1; }
