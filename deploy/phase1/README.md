# Phase 1: the write side — requests become delivered credentials

Goal: a team requests an OAuth client with a Kubernetes manifest, and the
credentials show up in that team's Vault path with no human handling them.

Design: [ADR 0003](../../docs/adr/0003-core-library-thin-controller.md). All
IdP and Vault logic is in `pkg/` (no Kubernetes imports); the controller in
`internal/controller` only maps `OAuthClient` objects to broker calls.

## What gets built

| Piece | Where | Notes |
|---|---|---|
| `OAuthClient` CRD | `courier.sororlab.dev/v1alpha1` | status shows `clientId`, `secretPath`, `Ready`; never the secret |
| Controller | `courier-system/courier-controller-manager` | image built on the node and imported into k3s (no registry) |
| Vault login | `auth/kubernetes/role/courier` | bound to the controller service account; policy `courier` (write/patch/delete, **no read**) |
| Authentik identity | service account `courier-controller`, role `courier-controller` | manages OAuth2 providers, applications and bindings only; token in Secret `courier-system/courier-authentik` |

## Rules the controller enforces

- A request's owner group is its namespace. `team-alpha/billing-sync` can only
  deliver to `kv/teams/team-alpha/...`, and only IdP group `team-alpha` may
  sign in through it (unless `allowGroups` says otherwise).
- The IdP-side name is `<namespace>-<name>`, so teams can't collide.
- Apps in Authentik that Courier didn't create are never modified
  (`Ready=False, reason NameConflict`).
- The secret is stored as `state=pending` **before** the IdP accepts it, then
  promoted to `active`. A crash at any point is repaired on the next reconcile.
- Deleting the request deletes the IdP client first, then destroys every
  version of the stored credentials.

## Run order

On a host with `kubectl` access (the homelab node):

```bash
deploy/phase1/authentik-controller-account.sh   # scoped Authentik token → Secret
deploy/phase1/vault-kubernetes-auth.sh          # Vault role for the controller SA
deploy/phase1/deploy-controller.sh              # build, import, apply CRD + controller
deploy/phase1/acceptance.sh                     # end-to-end as the teams
```

Developer checks (no cluster needed for unit tests):

```bash
go test ./pkg/... ./internal/...                # unit + fake-client controller tests
deploy/phase1/integration-test.sh               # adapters + broker against real Authentik/Vault
```

## Acceptance criteria

`acceptance.sh` prints `PHASE 1 ACCEPTANCE PASSED`:

- the `OAuthClient` becomes `Ready`
- a team-alpha identity reads `state=active` credentials at `status.secretPath`
- a team-bravo identity gets 403 on the same path
- the delivered `client_id`/`client_secret` obtain a token from Authentik
- after `kubectl delete`, the path returns 404

## Known limits (tracked for later phases)

- Approval is whoever can `kubectl apply` in the team namespace; the PR-based
  request repo arrives in Phase 2.
- Changing `clientType` on an existing request is not handled specially.
- `integration-test.sh` and the phase 0 scripts still use the root token from
  the init file; move them to an admin OIDC login before revoking it.
- The controller image is imported by hand; a registry and an ArgoCD app come
  with Phase 2.
