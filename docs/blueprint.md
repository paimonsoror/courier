# Courier blueprint

- Status: draft v0.1
- Updated: 2026-09-13
- Reference environment: Authentik · Vault Community Edition · k3s · ArgoCD · Backstage

Teams ask for an OAuth client. After approval, Courier creates it in the identity
provider and puts the credentials in a secrets manager path that only the owning
team's IdP group can read. Nobody emails a `client_secret` again.

## Problem

Every new integration with the IdP needs a client registration. MCP makes this
worse: each MCP server that sits behind OAuth, and each backend that calls one,
needs its own client. Today an admin creates the client, then copies the
`client_id`, `client_secret`, issuer and endpoints to the team over email or chat.

- **Doesn't scale.** Admin time grows with every integration.
- **Unsafe handoff.** Secrets stay in inboxes and chat history for good.
- **No clear owner.** Nobody knows which team owns a client, so rotation and cleanup don't happen.

## Goals and non-goals

**Goals**

- Requests are declarative, reviewable, and leave an audit trail
- Nothing is created in the IdP until a request is approved
- Only the owning group can read the secrets, and that group is managed in the IdP itself
- Workloads can pull credentials without a human in the loop
- Works with more than one IdP: Authentik first, Okta through an adapter
- Rotation, deletion and drift detection are built in

**Non-goals (v1)**

- Replacing the IdP's own user or group management
- Running a public Dynamic Client Registration endpoint
- SAML applications
- Brokering tokens at runtime; Courier only handles registration
- A custom approval UI; review happens in pull requests

## Client types

| Type | Typical use | Token endpoint auth | What goes to Vault |
|---|---|---|---|
| Public | MCP clients (IDEs, CLI agents, desktop apps), SPAs | PKCE, no secret | metadata only: `client_id`, issuer, redirect URIs |
| Confidential | MCP servers doing token exchange, web backends, M2M `client_credentials` | `client_secret_basic` / `_post` | `client_id` + `client_secret` + metadata |
| Key-bound | High-value M2M where the IdP supports it (strong on Okta) | `private_key_jwt` (RFC 7523) | metadata only; the team registers a public JWKS |

> **MCP note.** Recent revisions of the MCP authorization spec favor Client ID
> Metadata Documents and treat Dynamic Client Registration as optional. MCP
> *clients* often need no pre-registration and no secret. Courier's main value is
> with *confidential* clients, plus the ownership record for every client.

## Architecture

```
 Request            Approve              Reconcile                    Consume
┌──────────┐     ┌──────────────┐     ┌─────────────────────┐     ┌──────────────────────┐
│Backstage │ ──► │ PR to GitOps │ ──► │ Courier controller  │ ──► │ Humans: Vault OIDC   │
│Scaffolder│     │ repo         │     │  1. IdP adapter     │     │  login, group claim  │
│ template │     │ CODEOWNERS + │     │  2. write secret to │     │  → policy            │
└──────────┘     │ CI checks    │     │     Vault team path │     │ Workloads: External  │
                 └──────────────┘     │  3. status (no      │     │  Secrets per-team    │
                                      │     secret)         │     │  SecretStore         │
                                      └─────────────────────┘     └──────────────────────┘
```

Why this shape:

- **Merging the PR is the approval.** Reviewers, comments and history come for free.
- **A controller instead of Terraform.** Terraform state would hold the secret. See [ADR 0002](adr/0002-controller-not-terraform.md).
- **The same IdP controls Vault access.** IdP group membership is what grants read access.

## The OAuthClient resource

```yaml
apiVersion: courier.sororlab.dev/v1alpha1
kind: OAuthClient
metadata:
  name: payments-mcp-server
  namespace: team-payments
spec:
  idpRef: authentik-homelab            # ClusterIdentityProvider
  owner:
    group: team-payments               # must exist in the IdP
  displayName: Payments MCP Server
  clientType: confidential             # public | confidential | privateKeyJwt
  grantTypes: [authorization_code, refresh_token]
  redirectUris:
    - https://mcp-payments.sororlab.dev/oauth/callback
  scopes: [openid, profile, email, offline_access]
  accessPolicy:
    allowGroups: [team-payments, payments-users]
  secretDelivery:
    vaultRef: vault-homelab
    path: auto                         # kv/teams/team-payments/oauth-clients/payments-mcp-server
  rotation:
    maxAgeDays: 180
status:
  conditions:
    - type: Ready
      status: "True"
  clientId: 8f3c2a…                    # not sensitive
  idpObjectRefs: { providerPk: 42, applicationSlug: payments-mcp-server }
  vaultPath: kv/teams/team-payments/oauth-clients/payments-mcp-server
  secretVersion: 3
  lastRotated: 2026-09-13T15:02:11Z
```

Cluster-scoped companions: `ClusterIdentityProvider` (IdP type, URL, admin
credential ref) and `ClusterSecretBackend` (Vault address, auth role).

## Request lifecycle

1. **Requester → Backstage:** fills out the template; owner is picked from the requester's own catalog Groups.
2. **Backstage → GitHub:** renders `clients/<team>/<app>.yaml` and opens a PR.
3. **CI:** checks schema and policy: HTTPS redirect URIs on allowed domains, extra approver for `client_credentials`, owner group exists.
4. **Approver:** merges. ArgoCD syncs the CR into the team namespace.
5. **Controller:** adds a finalizer, generates the secret in memory, writes it to Vault with `state: pending`.
6. **Controller → IdP:** creates provider/client with that secret, then application and group binding; saves the IdP object IDs in status.
7. **Controller → Vault:** promotes the entry to `state: active`; sets `Ready=True`.
8. **Team:** reads via `vault login -method=oidc`, or an `ExternalSecret` syncs it into the namespace.

> **Failure rule.** If the IdP generates the secret itself, write it to Vault
> immediately; if that write fails, rotate right away. The controller must never
> hold a live secret that hasn't been stored.

## IdP adapters

```go
type IdentityProvider interface {
    EnsureClient(ctx, spec ClientSpec, secret *Secret) (ClientRef, error)
    EnsureAccess(ctx, ref ClientRef, groups []string) error
    RotateSecret(ctx, ref ClientRef, next *Secret) (overlap bool, err error)
    DeleteClient(ctx, ref ClientRef) error
    Observe(ctx, ref ClientRef) (ObservedClient, error)
    Discovery() Endpoints
}
```

| Operation | Authentik (API v3) | Okta |
|---|---|---|
| Create client | `POST /api/v3/providers/oauth2/` (caller-supplied `client_id`/`client_secret`) | `POST /api/v1/apps` (OIDC app) |
| Create app | `POST /api/v3/core/applications/` linked to provider pk | created with the client |
| Restrict sign-in | `POST /api/v3/policies/bindings/` group → application | app group assignments |
| Rotation | one secret per provider: hard cutover | two active secrets: overlap |
| `private_key_jwt` | limited (federated-source JWT validation) | native, per-client JWKS |
| Admin credential | service account, RBAC scoped to providers/apps/bindings | service app with `okta.apps.manage` |

Exact field shapes (for example Authentik's newer `redirect_uris` list of
`{matching_mode, url}`) are pinned in adapter tests against the running version.

Confirmed in Phase 0 (Authentik 2026.8.2): OAuth2 providers carry an explicit
`grant_types` allow-list. An empty list rejects `client_credentials` with
`Invalid grant_type for provider`, so the adapter must always set it from
`spec.grantTypes`.

## Vault layout and access

Backend: Vault Community Edition ([ADR 0001](adr/0001-vault-ce-for-proof-of-value.md)).
OpenBao remains a CI compatibility target.

```
kv/                                   # KV v2 mount
└── teams/<team>/oauth-clients/<app>
      client_id, client_secret, issuer, token_endpoint,
      client_type, state, managed_by
```

Team policy `team-payments`:

```hcl
path "kv/data/teams/team-payments/*"     { capabilities = ["read"] }
path "kv/metadata/teams/team-payments/*" { capabilities = ["read", "list"] }
```

Controller policy `courier` (write, never read):

```hcl
path "kv/data/teams/+/oauth-clients/*"     { capabilities = ["create", "update"] }
path "kv/metadata/teams/+/oauth-clients/*" { capabilities = ["delete"] }
```

Mapping groups to policies:

- Vault OIDC auth against the same IdP with `groups_claim="groups"`.
- Per team: an external identity group, a group alias matching the IdP group name, and the team policy.
- Workloads: one `SecretStore` per team namespace with a namespace-bound Kubernetes auth role. No cluster-wide store that could read every team's path.

## Security model

| Threat | Control |
|---|---|
| A team requests a client under another team's name | Owner picker limited to own groups; CODEOWNERS per `clients/<team>/`; admission requires owner = namespace |
| Controller compromise | Vault write-only policy; IdP token scoped to OAuth providers/apps |
| Secret leaks into etcd, logs or Git | Never in CR status; log redaction; only in memory until written to Vault |
| Someone edits the client in the IdP console | Drift detection via `Observe()`: revert or mark `Drifted` |
| Nobody can tell who read a secret | Vault audit device → Loki |
| Malicious redirect URI | Domain allow-list, no wildcards, localhost only for public clients |

## Day-2 operations

- **Rotation:** `rotation.maxAgeDays` or annotation `courier.sororlab.dev/rotate: "now"`. Overlap where the IdP supports two secrets; otherwise hard cutover bounded by ESO refresh interval.
- **Deletion:** removing the YAML prunes the CR; the finalizer deletes IdP objects and destroys all Vault versions.
- **Adopt mode:** match an existing client by `client_id`, rotate, and from then on only Vault holds it.
- **Visibility:** Backstage Kubernetes plugin shows CR status on the owning Group page.
- **Metrics:** `courier_clients{state}`, `courier_secret_age_days`, `courier_reconcile_errors_total`.

## Roadmap

| Phase | Scope |
|---|---|
| 0 | Vault CE on k3s via ArgoCD; OIDC login via Authentik; prove a group member can read their path and a non-member can't |
| 1 | CRDs + Authentik adapter; create/delete for confidential clients with ordered secret writes |
| 2 | `clients/` GitOps repo, CI validation, CODEOWNERS; per-team SecretStore + ESO into a sample workload |
| 3 | Backstage Scaffolder template; status on Group pages; public/metadata-only paths |
| 4 | Rotation, drift detection, adopt mode, audit → Loki, metrics and alerts |
| 5 | Okta adapter, `private_key_jwt`, adapter conformance suite |

## Open decisions

| Decision | Options | Recommendation |
|---|---|---|
| Secrets backend | Vault CE · OpenBao · Vault Enterprise | **Vault CE** for the proof of value; OpenBao in CI |
| Controller language | Go + kubebuilder · Python + kopf | **Go + kubebuilder** |
| Approval | PR merge · separate workflow | **PR merge** with label-gated extra approvers |
| Team → Vault policy objects | `Team` CR · Terraform/scripts | scripts/Terraform for phases 0–2 |
| Where manifests live | `homelab-charts` · dedicated repo | dedicated repo |
