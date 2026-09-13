# 0001: Vault Community Edition for the proof of value

- Status: accepted
- Date: 2026-09-13

## Context

Courier needs a secrets backend that can gate reads by IdP group. The target
organization already runs HashiCorp Vault. HashiCorp moved Vault to the Business
Source License (BSL 1.1) in 2023; OpenBao is the MPL-2.0 fork of Vault 1.14 under
the Linux Foundation, with a compatible API for the features Courier needs.

## Decision

Use **HashiCorp Vault Community Edition** for the proof of value.

Courier uses only features present in Community Edition: KV v2, OIDC auth,
Kubernetes auth, ACL policies, identity groups with external aliases, and audit
devices. Nothing depends on Enterprise (namespaces, control groups, Sentinel).

## Consequences

- The proof of value runs on the same product as production, so it answers
  "will this work on our Vault?" directly.
- BSL allows internal use; Courier is not a competing hosted offering.
- OpenBao stays a compatibility target, to be run in CI once there is code to
  test, so the project remains usable by orgs that avoid BSL software.
- If Vault Enterprise is used, per-team namespaces may replace the
  `kv/teams/<team>/` path prefix. That is optional, not required.
