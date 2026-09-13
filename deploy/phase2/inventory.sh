#!/usr/bin/env bash
# Inventory everything a merged request created, straight from each platform:
# Kubernetes, ArgoCD, Authentik (including its event log) and Vault (entry
# metadata, fields with the secret redacted, access policy, audit log).
#
#   deploy/phase2/inventory.sh <team> <name>
#
# Needs: kubectl access; Authentik bootstrap token (read from the server pod);
# a Vault admin token in VAULT_ADMIN_TOKEN, or the phase 0 init file.
set -uo pipefail

TEAM="${1:?usage: inventory.sh <team> <name>}"
NAME="${2:?usage: inventory.sh <team> <name>}"
CLIENT="$TEAM-$NAME"
KVPATH="kv/teams/$TEAM/oauth-clients/$CLIENT"
KEYS_FILE="${KEYS_FILE:-$HOME/courier-vault-init.json}"

echo "=== KUBERNETES: namespace"
kubectl get ns "$TEAM" -o json | python3 -c '
import json,sys; d=json.load(sys.stdin)["metadata"]
print("created", d["creationTimestamp"]); print("labels", d.get("labels"))'

echo "=== KUBERNETES: OAuthClient"
kubectl -n "$TEAM" get oauthclient "$NAME" -o json | python3 -c '
import json,sys; d=json.load(sys.stdin); m=d["metadata"]
print("created", m["creationTimestamp"], "generation", m["generation"])
print("finalizers", m.get("finalizers")); print("labels", m.get("labels"))
print("spec", json.dumps(d["spec"]))
s=dict(d["status"]); conds=s.pop("conditions",[])
print("status", json.dumps(s))
for c in conds: print("condition", c["type"], c["status"], c["reason"], c["lastTransitionTime"], "-", c["message"])'
echo "--- objects in the namespace"
kubectl api-resources --verbs=list --namespaced -o name 2>/dev/null \
  | grep -v -e events -e endpointslices -e localsubjectaccessreviews | xargs -n 40 | tr " " "," \
  | xargs -I{} kubectl -n "$TEAM" get {} --no-headers --ignore-not-found -o custom-columns=KIND:.kind,NAME:.metadata.name 2>/dev/null

echo "=== ARGOCD: application"
kubectl -n argocd get application "courier-requests-$TEAM" -o json | python3 -c '
import json,sys; d=json.load(sys.stdin); m=d["metadata"]; sp=d["spec"]; st=d.get("status",{})
print("created", m["creationTimestamp"], "owner", [o["kind"]+"/"+o["name"] for o in m.get("ownerReferences",[])])
print("project", sp["project"]); print("source", json.dumps(sp["source"])); print("destination", json.dumps(sp["destination"]))
print("syncPolicy", json.dumps(sp.get("syncPolicy")))
print("sync", st.get("sync",{}).get("status"), st.get("sync",{}).get("revision"), "health", st.get("health",{}).get("status"))
for r in st.get("resources",[]): print("resource", r.get("group",""), r["kind"], r.get("namespace",""), r["name"], r.get("status"))
for h in st.get("history",[]): print("history", h.get("deployedAt"), h.get("revision"))'

echo "=== AUTHENTIK"
kubectl -n authentik exec -i deploy/authentik-server -- env CLIENT="$CLIENT" python3 - <<'PY'
import json, os, urllib.parse, urllib.request
tok = os.environ["AUTHENTIK_BOOTSTRAP_TOKEN"]; client = os.environ["CLIENT"]
def get(path):
    req = urllib.request.Request("http://localhost:9000/api/v3/" + path, headers={"Authorization": "Bearer " + tok})
    return json.load(urllib.request.urlopen(req))
prov = get("providers/oauth2/?name=" + urllib.parse.quote("courier-" + client))["results"][0]
maps = {m["pk"]: m["name"] for m in get("propertymappings/provider/scope/?page_size=500")["results"]}
keys = {k["pk"]: k["name"] for k in get("crypto/certificatekeypairs/?page_size=100")["results"]}
flows = {f["pk"]: f["slug"] for f in get("flows/instances/?page_size=200")["results"]}
print("provider pk", prov["pk"], "name", prov["name"])
for k in ("client_type", "client_id", "grant_types", "redirect_uris", "sub_mode", "include_claims_in_id_token",
          "access_token_validity", "refresh_token_validity", "assigned_application_slug"):
    print("  ", k, "=", prov.get(k))
print("   client_secret = <present, %d chars>" % len(prov.get("client_secret") or ""))
print("   authorization_flow =", flows.get(prov["authorization_flow"]))
print("   signing_key =", keys.get(prov.get("signing_key")))
print("   property_mappings =", [maps.get(p, p) for p in prov["property_mappings"]])
app = get("core/applications/" + client + "/")
print("application", {k: app.get(k) for k in ("name", "slug", "pk", "provider", "meta_description", "policy_engine_mode")})
for b in get("policies/bindings/?page_size=100&target=" + app["pk"])["results"]:
    print("binding group", (b.get("group_obj") or {}).get("name"), "order", b["order"], "enabled", b["enabled"])
ev = get("events/events/?page_size=40&ordering=-created&search=" + urllib.parse.quote(client))["results"]
for e in reversed(ev):
    model = (e.get("context") or {}).get("model") or {}
    print("event", e["created"], e["action"], "by", (e.get("user") or {}).get("username"), model.get("model_name"), model.get("name"))
PY

echo "=== VAULT"
if [ -n "${VAULT_ADMIN_TOKEN:-}" ]; then
  printf '%s' "$VAULT_ADMIN_TOKEN" | kubectl -n vault exec -i vault-0 -- vault login -no-print -
else
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["root_token"])' "$KEYS_FILE" \
    | kubectl -n vault exec -i vault-0 -- vault login -no-print -
fi
trap 'kubectl -n vault exec vault-0 -- sh -c "rm -f \$HOME/.vault-token" >/dev/null 2>&1 || true' EXIT

echo "--- metadata"
kubectl -n vault exec vault-0 -- vault kv metadata get -format=json "$KVPATH" | python3 -c '
import json,sys; d=json.load(sys.stdin)["data"]
print("created", d["created_time"], "current_version", d["current_version"])
for v,info in sorted(d["versions"].items(), key=lambda kv:int(kv[0])): print("version", v, "created", info["created_time"])'
echo "--- fields (secret redacted)"
kubectl -n vault exec vault-0 -- vault kv get -format=json "$KVPATH" | python3 -c '
import json,sys; d=json.load(sys.stdin)["data"]["data"]
for k in sorted(d): print(" ", k, "=", ("<present, %d chars>" % len(d[k])) if k=="client_secret" else d[k])'
echo "--- access"
kubectl -n vault exec vault-0 -- vault policy read "$TEAM"
for g in "$TEAM" "$TEAM-jwt"; do
  kubectl -n vault exec vault-0 -- vault read -format=json "identity/group/name/$g" | python3 -c '
import json,sys; d=json.load(sys.stdin)["data"]; a=d.get("alias") or {}
print("identity group", d["name"], "policies", d["policies"], "alias", a.get("name"), "on", a.get("mount_type"))'
done
echo "--- audit log (excluding root)"
kubectl -n vault exec vault-0 -- sh -c "grep -F '$CLIENT' /vault/audit/audit.log" | python3 -c '
import json,sys
for line in sys.stdin:
    try: e=json.loads(line)
    except ValueError: continue
    if e.get("type")!="response": continue
    a=e.get("auth") or {}; r=e.get("request") or {}
    if a.get("display_name")=="root": continue
    err=(e.get("error") or "").replace("\n"," ").strip()
    pol=sorted(set((a.get("policies") or [])+(a.get("identity_policies") or [])))
    print(e["time"][:19], r.get("operation"), r.get("path"), "by", a.get("display_name"), pol, "->", "DENIED" if err else "ok")'
