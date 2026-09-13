# 0002: A Kubernetes controller creates clients, not Terraform

- Status: accepted
- Date: 2026-09-13

## Context

Both Authentik and Okta have Terraform providers that can create OAuth clients.
Terraform records every managed attribute in state, including `client_secret`,
which puts the secret in a second store (the state backend) with its own access
model, backups and leak surface.

## Decision

Client lifecycle is handled by a Kubernetes controller that reconciles an
`OAuthClient` custom resource. The secret is generated in memory, written to
Vault, and passed to the IdP. It is never written to CR status, logs, Git, or
any other store.

## Consequences

- Approval stays GitOps-shaped: a PR adds the CR, ArgoCD syncs it.
- The controller owns ordering (pending Vault write → IdP create → promote),
  finalizers for deletion, drift detection, and rotation.
- Objects that contain no secrets (Vault policies, identity groups, auth
  roles) may still be managed by Terraform or scripts during early phases.
