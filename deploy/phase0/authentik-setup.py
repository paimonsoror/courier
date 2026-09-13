"""Phase 0: create the Vault OIDC client and test identities in Authentik.

Runs inside the authentik-server pod and calls the API on localhost with
AUTHENTIK_BOOTSTRAP_TOKEN. Idempotent: existing objects are reused.

Progress goes to stderr. One JSON object with credentials goes to stdout for
authentik-setup.sh to turn into Kubernetes Secrets. Never run this with stdout
attached to a terminal or log.
"""
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

API = "http://localhost:9000/api/v3/"
TOKEN = os.environ["AUTHENTIK_BOOTSTRAP_TOKEN"]
AUTH_HOST = os.environ.get("AUTH_HOST", "auth.sororlab.dev")
VAULT_HOST = os.environ.get("VAULT_HOST", "vault.sororlab.dev")
ADMIN_USER = os.environ.get("ADMIN_USER", "paimonsoror")

APP_SLUG = "vault"
TEAM_GROUPS = ["team-alpha", "team-bravo"]
ADMIN_GROUP = "vault-admins"
TESTERS = {"alpha": ("courier-svc-alpha", "team-alpha"), "bravo": ("courier-svc-bravo", "team-bravo")}


def log(msg):
    print(msg, file=sys.stderr)


def call(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        API + path,
        data=data,
        method=method,
        headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as err:
        sys.exit(f"{method} {path} -> {err.code}: {err.read().decode()[:800]}")


def get_or_none(path):
    req = urllib.request.Request(API + path, headers={"Authorization": f"Bearer {TOKEN}"})
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as err:
        if err.code == 404:
            return None
        sys.exit(f"GET {path} -> {err.code}: {err.read().decode()[:800]}")


def find(path, **query):
    results = call("GET", f"{path}?{urllib.parse.urlencode(query)}")["results"]
    return results[0] if results else None


def ensure_group(name):
    group = find("core/groups/", name=name)
    if group:
        log(f"group {name}: exists")
        return group
    log(f"group {name}: created")
    return call("POST", "core/groups/", {"name": name})


def add_user(group, user_pk):
    call("POST", f"core/groups/{group['pk']}/add_user/", {"pk": user_pk})


def ensure_service_account(username):
    user = find("core/users/", username=username)
    if not user:
        call("POST", "core/users/service_account/", {"name": username, "create_group": False, "expiring": False})
        user = find("core/users/", username=username)
        log(f"service account {username}: created")
    else:
        log(f"service account {username}: exists")
    identifier = f"service-account-{username}-password"
    key = call("GET", f"core/tokens/{identifier}/view_key/")["key"]
    return user, key


def scope_mapping(scope_name, name=None):
    results = call("GET", "propertymappings/provider/scope/?" + urllib.parse.urlencode({"scope_name": scope_name}))["results"]
    if name:
        results = [m for m in results if m["name"] == name]
    else:
        results = [m for m in results if m.get("managed")]
    if not results:
        sys.exit(f"scope mapping for '{scope_name}' not found")
    return results[0]["pk"]


def main():
    admin = find("core/users/", username=ADMIN_USER)
    if not admin:
        sys.exit(f"admin user {ADMIN_USER} not found")

    groups = {name: ensure_group(name) for name in [ADMIN_GROUP, *TEAM_GROUPS]}
    add_user(groups[ADMIN_GROUP], admin["pk"])
    add_user(groups["team-alpha"], admin["pk"])  # lets the admin exercise the team-alpha path in the UI

    testers = {}
    for key, (username, group_name) in TESTERS.items():
        user, token = ensure_service_account(username)
        add_user(groups[group_name], user["pk"])
        testers[key] = {"username": username, "token": token}

    authz_flow = find("flows/instances/", slug="default-provider-authorization-implicit-consent")["pk"]
    invalidation_flow = find("flows/instances/", slug="default-provider-invalidation-flow")["pk"]
    signing_key = find("crypto/certificatekeypairs/", name="authentik Self-signed Certificate")["pk"]

    provider_body = {
        "name": "vault",
        "authorization_flow": authz_flow,
        "invalidation_flow": invalidation_flow,
        "client_type": "confidential",
        # Authentik 2026.x enforces an explicit allow-list; an empty list
        # rejects client_credentials with "Invalid grant_type for provider".
        "grant_types": ["authorization_code", "refresh_token", "client_credentials"],
        "redirect_uris": [
            {"matching_mode": "strict", "url": f"https://{VAULT_HOST}/ui/vault/auth/oidc/oidc/callback"},
            {"matching_mode": "strict", "url": "http://localhost:8250/oidc/callback"},
        ],
        "property_mappings": [
            scope_mapping("openid"),
            scope_mapping("email"),
            scope_mapping("profile"),
            scope_mapping("groups", name="oauth-groups"),
        ],
        "signing_key": signing_key,
        "sub_mode": "user_email",
        "include_claims_in_id_token": True,
        "access_token_validity": "minutes=10",
    }
    provider = find("providers/oauth2/", name="vault")
    if provider:
        provider = call("PATCH", f"providers/oauth2/{provider['pk']}/", provider_body)
        log("provider vault: updated")
    else:
        provider = call("POST", "providers/oauth2/", provider_body)
        log("provider vault: created")

    # The list endpoint ignores ?slug=; the detail endpoint is keyed by slug.
    app = get_or_none(f"core/applications/{APP_SLUG}/")
    if not app:
        app = call("POST", "core/applications/", {
            "name": "Vault",
            "slug": APP_SLUG,
            "provider": provider["pk"],
            "meta_launch_url": f"https://{VAULT_HOST}/ui/vault/auth?with=oidc",
        })
        log("application vault: created")
    else:
        log("application vault: exists")

    bound = {b["group"] for b in call("GET", f"policies/bindings/?target={app['pk']}")["results"] if b.get("group")}
    for order, name in enumerate([ADMIN_GROUP, *TEAM_GROUPS]):
        if groups[name]["pk"] not in bound:
            call("POST", "policies/bindings/", {
                "target": app["pk"], "group": groups[name]["pk"], "order": order,
                "enabled": True, "negate": False, "timeout": 30,
            })
            log(f"binding {name} -> vault: created")

    json.dump({
        "issuer": f"https://{AUTH_HOST}/application/o/{APP_SLUG}/",
        "oidc": {"client_id": provider["client_id"], "client_secret": provider["client_secret"]},
        "testers": testers,
    }, sys.stdout)


main()
