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

## Documentation

Published at **https://paimonsoror.github.io/courier/** (GitHub Pages, source `main` `/docs`), or open [`docs/site/index.html`](docs/site/index.html) locally:

| Page | For |
|---|---|
| [Overview](docs/site/index.html) | Identity and security leaders: the challenge, what changes, risks and controls |
| [How it works](docs/site/how-it-works.html) | Architects and security reviewers: components, lifecycle, trust model, failures |
| [Walkthrough](docs/site/walkthrough.html) | Anyone evaluating: PR #1 followed from policy gate to verified access, with evidence |
| [Case study: team-bravo](docs/site/case-study-team-bravo.html) | What PR #1 set out to do, what it created on every platform, what the team can do now |
| [Request a client](docs/site/request-a-client.html) | Application teams: write a request, open the PR, read credentials |
| [Use credentials](docs/site/use-credentials.html) | Teams: Vault CLI, Python sample, External Secrets, with verified results |
| [Implementation guide](docs/site/implementation.html) | Engineers: install, verify, operate, troubleshoot, harden |
| [Reference](docs/site/reference.html) | Fields, conditions, policy, flags, vault layout, created objects |

## Status

Early design / proof of value. See [docs/blueprint.md](docs/blueprint.md) for the
full design and [docs/adr](docs/adr) for decisions.

| Phase | Scope | State |
|---|---|---|
| 0 | Vault CE on k3s, OIDC login via Authentik, group-gated read proven | done ([deploy/phase0](deploy/phase0)) |
| 1 | Kubernetes-free core (IdP adapter, Vault writer, ordered broker) + `OAuthClient` controller wrapping it | done ([deploy/phase1](deploy/phase1), [ADR 0003](docs/adr/0003-core-library-thin-controller.md)) |
| 2 | Pull request flow: `requests/`, `courier validate` check, CODEOWNERS, ArgoCD ApplicationSet; docs site | done ([docs/site](docs/site/index.html)) |
| 2b | Per-team SecretStore + External Secrets, Python consumer sample, controller image on GHCR pinned by digest | done ([use credentials](docs/site/use-credentials.html)) |
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
