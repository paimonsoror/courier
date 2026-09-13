# 0003: Kubernetes-free core library, thin controller on top

- Status: accepted
- Date: 2026-09-13

## Context

Courier's value is the write side: creating an IdP client and delivering its
secret to the owning team's Vault path without a human handling it. The hard
parts are correctness under partial failure (ordered writes, idempotent
retries), deletion, drift detection and rotation.

A Kubernetes controller is a good way to run that logic: reconciliation loops,
finalizers, status, namespace-based ownership, and GitOps approval through
ArgoCD. But the organizations that might adopt Courier aren't guaranteed to be
Kubernetes-first. An IdP or security team may prefer a CLI, a CI job, or a
small service.

## Decision

Split the code into two layers:

1. **Core** (`pkg/`), with no Kubernetes imports:
   - `pkg/courier`: domain types (`ClientSpec`, `ClientRef`, `Credentials`) and
     the broker that does the ordered pending-write → IdP create → promote
     sequence, delete, and observe
   - `pkg/idp`: the `IdentityProvider` interface; `pkg/idp/authentik` first,
     `pkg/idp/okta` later
   - `pkg/secretstore`: the `SecretStore` interface; `pkg/secretstore/vault`
2. **Front ends**, each thin:
   - `internal/controller`: kubebuilder reconciler for `OAuthClient`; maps
     the CR to `ClientSpec`, calls the broker, writes status and finalizers
   - `cmd/courier` (later): CLI/CI mode that reads the same YAML from files

Rule: anything a CLI user would also need lives in `pkg/`. The controller only
translates between Kubernetes objects and core types.

## Consequences

- The core is unit-tested with fakes and integration-tested against the real
  Authentik and Vault, with no cluster required.
- The `OAuthClient` YAML doubles as the file format for non-Kubernetes mode.
- A little more code up front (type mapping between the CR and core types),
  in exchange for not locking adoption to Kubernetes.
