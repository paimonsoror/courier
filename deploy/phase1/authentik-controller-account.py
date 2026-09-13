"""Phase 1: a least-privilege Authentik identity for the Courier controller.

Runs inside the authentik-server pod with AUTHENTIK_BOOTSTRAP_TOKEN. Creates:
  - service account  courier-controller
  - role             courier-controller, with global permissions to manage
                     OAuth2 providers, applications and policy bindings, and to
                     view the flows, groups, keys and scope mappings they reference
  - group            courier-controllers (has the role; the account is a member)
  - API token        courier-controller-api (intent=api, non-expiring)

Prints {"token": ...} on stdout for the wrapper script. Progress on stderr.
Idempotent.
"""
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

API = "http://localhost:9000/api/v3/"
TOKEN = os.environ["AUTHENTIK_BOOTSTRAP_TOKEN"]

ACCOUNT = "courier-controller"
ROLE = "courier-controller"
GROUP = "courier-controllers"
TOKEN_ID = "courier-controller-api"

PERMISSIONS = [
    "authentik_providers_oauth2.add_oauth2provider",
    "authentik_providers_oauth2.change_oauth2provider",
    "authentik_providers_oauth2.delete_oauth2provider",
    "authentik_providers_oauth2.view_oauth2provider",
    "authentik_core.add_application",
    "authentik_core.change_application",
    "authentik_core.delete_application",
    "authentik_core.view_application",
    "authentik_policies.add_policybinding",
    "authentik_policies.change_policybinding",
    "authentik_policies.delete_policybinding",
    "authentik_policies.view_policybinding",
    "authentik_core.view_group",
    "authentik_flows.view_flow",
    "authentik_crypto.view_certificatekeypair",
    "authentik_providers_oauth2.view_scopemapping",
]


def log(msg):
    print(msg, file=sys.stderr)


def call(method, path, body=None, ok_missing=False):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method,
                                 headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as err:
        if ok_missing and err.code == 404:
            return None
        sys.exit(f"{method} {path} -> {err.code}: {err.read().decode()[:800]}")


def find(path, **query):
    results = call("GET", f"{path}?{urllib.parse.urlencode(query)}")["results"]
    return results[0] if results else None


def main():
    user = find("core/users/", username=ACCOUNT)
    if not user:
        call("POST", "core/users/service_account/", {"name": ACCOUNT, "create_group": False, "expiring": False})
        user = find("core/users/", username=ACCOUNT)
        log(f"service account {ACCOUNT}: created")

    role = next((r for r in call("GET", "rbac/roles/?page_size=200")["results"] if r["name"] == ROLE), None)
    if not role:
        role = call("POST", "rbac/roles/", {"name": ROLE})
        log(f"role {ROLE}: created")
    call("POST", f"rbac/permissions/assigned_by_roles/{role['pk']}/assign/", {"permissions": PERMISSIONS})
    log(f"role {ROLE}: {len(PERMISSIONS)} global permissions assigned")

    group = find("core/groups/", name=GROUP)
    if not group:
        group = call("POST", "core/groups/", {"name": GROUP, "roles": [role["pk"]]})
        log(f"group {GROUP}: created")
    elif role["pk"] not in group.get("roles", []):
        call("PATCH", f"core/groups/{group['pk']}/", {"roles": [*group.get("roles", []), role["pk"]]})
    call("POST", f"core/groups/{group['pk']}/add_user/", {"pk": user["pk"]})

    if not call("GET", f"core/tokens/{TOKEN_ID}/", ok_missing=True):
        call("POST", "core/tokens/", {
            "identifier": TOKEN_ID, "intent": "api", "user": user["pk"], "expiring": False,
            "description": "Courier controller: manages Courier OAuth clients",
        })
        log(f"token {TOKEN_ID}: created")
    key = call("GET", f"core/tokens/{TOKEN_ID}/view_key/")["key"]
    json.dump({"token": key}, sys.stdout)


main()
