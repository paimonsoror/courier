#!/usr/bin/env bash
# Run the Python sample against the reference environment as team-bravo's and
# team-alpha's test workloads (jwt/ log-in), exactly as a job outside
# Kubernetes would. Never prints credentials.
#
#   samples/python/verify.sh team-bravo report-exporter
set -euo pipefail

TEAM="${1:?usage: verify.sh <team> <name>}"
NAME="${2:?usage: verify.sh <team> <name>}"
PORT="${PORT:-18205}"
here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
chmod 700 "$work"

kubectl -n vault port-forward svc/vault-active "$PORT:8200" >/dev/null 2>&1 &
pf=$!
trap 'kill $pf 2>/dev/null || true; rm -rf "$work"' EXIT
for _ in $(seq 1 30); do curl -sf "http://127.0.0.1:$PORT/v1/sys/health" >/dev/null && break; sleep 0.5; done

if [ ! -x "$here/.venv/bin/python" ]; then
  python3 -m venv "$here/.venv"
  "$here/.venv/bin/pip" install -q -r "$here/requirements.txt"
fi
py="$here/.venv/bin/python"

sec() { kubectl -n "$1" get secret "$2" -o "jsonpath={.data.$3}" | base64 -d; }

# Get an identity-provider JWT for a test workload: the same token a real
# workload would obtain with its own service account.
jwt_for() {
  local short="$1"
  CID="$(sec vault vault-oidc client_id)" CSEC="$(sec vault vault-oidc client_secret)" \
  ISSUER="$(sec vault vault-oidc issuer)" \
  U="$(sec vault courier-phase0-testers "${short}_username")" P="$(sec vault courier-phase0-testers "${short}_token")" \
  "$py" -c '
import json, os, urllib.parse, urllib.request
url = os.environ["ISSUER"].split("/application/o/")[0] + "/application/o/token/"
form = {"grant_type": "client_credentials", "client_id": os.environ["CID"], "client_secret": os.environ["CSEC"],
        "username": os.environ["U"], "password": os.environ["P"], "scope": "openid profile email groups"}
tok = json.load(urllib.request.urlopen(url, data=urllib.parse.urlencode(form).encode()))
print(tok.get("id_token") or tok["access_token"])' > "$work/$short.jwt"
}

owner_short="${TEAM#team-}"
for short in alpha bravo; do
  jwt_for "$short"
  echo "--- as team-$short workload: python courier_credentials.py $TEAM $NAME"
  set +e
  (cd "$here" && VAULT_ADDR="http://127.0.0.1:$PORT" COURIER_VAULT_AUTH=jwt COURIER_JWT_FILE="$work/$short.jwt" \
    "$py" courier_credentials.py "$TEAM" "$NAME")
  rc=$?
  set -e
  if [ "$short" = "$owner_short" ] && [ $rc -ne 0 ]; then echo "FAIL: owner could not read"; exit 1; fi
  if [ "$short" != "$owner_short" ] && [ $rc -eq 0 ]; then echo "FAIL: other team could read"; exit 1; fi
done

echo "--- as team-$owner_short workload: python get_token.py $TEAM $NAME"
(cd "$here" && VAULT_ADDR="http://127.0.0.1:$PORT" COURIER_VAULT_AUTH=jwt COURIER_JWT_FILE="$work/$owner_short.jwt" \
  AUTHENTIK_USERNAME="$(sec vault courier-phase0-testers "${owner_short}_username")" \
  AUTHENTIK_PASSWORD="$(sec vault courier-phase0-testers "${owner_short}_token")" \
  "$py" get_token.py "$TEAM" "$NAME")

echo
echo "PYTHON SAMPLE VERIFIED"
