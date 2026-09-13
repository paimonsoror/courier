# Courier

Self-service OAuth/OIDC client registration that gets credentials to the right
team without anyone emailing a `client_secret`.

A team requests a client, the request is reviewed as a pull request, and after
merge a controller:

1. creates the client in the identity provider (Authentik first, Okta next), and
2. writes `client_id`, `client_secret` and endpoint metadata to a Vault path that
   only the owning team's IdP group can read.

```
Backstage template ─► PR (merge = approval) ─► ArgoCD ─► Courier controller ─┬─► IdP (Authentik / Okta)
                                                                             └─► Vault kv/teams/<team>/oauth-clients/<app>
                                                                                   ▲
                             team humans (Vault OIDC login) / workloads (External Secrets) ┘
```

## Status

Early design / proof of value. See [docs/blueprint.md](docs/blueprint.md) for the
full design and [docs/adr](docs/adr) for decisions.

| Phase | Scope | State |
|---|---|---|
| 0 | Vault CE on k3s, OIDC login via Authentik, group-gated read proven | in progress |
| 1 | `OAuthClient` CRD + Authentik adapter + ordered secret write | not started |
| 2 | GitOps request repo, CI validation, per-team SecretStore + ESO | not started |
| 3 | Backstage Scaffolder template + status on Group pages | not started |
| 4 | Rotation, drift detection, adopt mode, audit → Loki | not started |
| 5 | Okta adapter, `private_key_jwt`, adapter conformance suite | not started |

## Repository layout

```
docs/          blueprint and ADRs
deploy/phase0/ Vault CE install values and bootstrap scripts for the proof of value
```

More directories (`api/`, `internal/`, `charts/`, `backstage/`, `policy/`) arrive
with the phases that need them.
