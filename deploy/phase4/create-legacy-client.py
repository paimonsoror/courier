"""Phase 4 demo setup: a hand-built OAuth client, the way it was done before Courier.

Runs inside the authentik-server pod with AUTHENTIK_BOOTSTRAP_TOKEN. Creates a
confidential client_credentials provider and an application with slug
legacy-crm, bound to group team-alpha, WITHOUT Courier's managed marker. Prints
{"client_id", "client_secret"} on stdout: this stands in for the secret that
was emailed to a team. Idempotent.
"""
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

API = "http://localhost:9000/api/v3/"
TOKEN = os.environ["AUTHENTIK_BOOTSTRAP_TOKEN"]
SLUG = "legacy-crm"
GROUP = "team-alpha"


def call(method, path, body=None, missing_ok=False):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method,
                                 headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as err:
        if missing_ok and err.code == 404:
            return None
        sys.exit(f"{method} {path} -> {err.code}: {err.read().decode()[:600]}")


def first(path, **query):
    results = call("GET", f"{path}?{urllib.parse.urlencode(query)}")["results"]
    return results[0] if results else None


app = call("GET", f"core/applications/{SLUG}/", missing_ok=True)
if app:
    prov = call("GET", f"providers/oauth2/{app['provider']}/")
    print(f"application {SLUG}: exists (provider {prov['pk']})", file=sys.stderr)
else:
    mappings = {m["managed"]: m["pk"] for m in call("GET", "propertymappings/provider/scope/?page_size=500")["results"]
                if m.get("managed")}
    groups_mapping = first("propertymappings/provider/scope/", name="oauth-groups")
    prov = call("POST", "providers/oauth2/", {
        "name": "legacy-crm (hand-built)",
        "authorization_flow": call("GET", "flows/instances/default-provider-authorization-implicit-consent/")["pk"],
        "invalidation_flow": call("GET", "flows/instances/default-provider-invalidation-flow/")["pk"],
        "client_type": "confidential",
        "grant_types": ["client_credentials"],
        "redirect_uris": [],
        "property_mappings": [
            mappings["goauthentik.io/providers/oauth2/scope-openid"],
            mappings["goauthentik.io/providers/oauth2/scope-profile"],
            groups_mapping["pk"],
        ],
        "signing_key": first("crypto/certificatekeypairs/", name="authentik Self-signed Certificate")["pk"],
        "sub_mode": "user_email",
        "include_claims_in_id_token": True,
    })
    app = call("POST", "core/applications/", {
        "name": "Legacy CRM (hand-built)",
        "slug": SLUG,
        "provider": prov["pk"],
        "meta_description": "created by hand in the console, secret emailed to team-alpha",
    })
    group = first("core/groups/", name=GROUP)
    call("POST", "policies/bindings/", {"target": app["pk"], "group": group["pk"], "order": 0,
                                        "enabled": True, "negate": False, "timeout": 30})
    print(f"application {SLUG}: created (provider {prov['pk']})", file=sys.stderr)

json.dump({"client_id": prov["client_id"], "client_secret": prov["client_secret"]}, sys.stdout)
