# Phase 0: Vault CE + Authentik, group-gated reads

Goal: prove that membership in an IdP group is the only thing that decides who
can read a team's secrets in Vault, for both humans (OIDC) and machines (JWT).

## What gets built

| Piece | Where | Notes |
|---|---|---|
| Vault Community Edition 2.0.4 | k3s `vault` ns, ArgoCD app `vault` in homelab-charts | chart 0.34.1, raft (1 replica), local-path PVCs, `https://vault.sororlab.dev` |
| AWS KMS auto-unseal | `alias/courier-vault-unseal`, us-east-1 | IAM user `courier-vault-unseal`: Encrypt/Decrypt/DescribeKey on that key only |
| Authentik provider + app `vault` | auth.sororlab.dev | confidential; grants: authorization_code, refresh_token, client_credentials |
| IdP groups | Authentik | `vault-admins`, `team-alpha`, `team-bravo` |
| Test identities | Authentik service accounts | `courier-svc-alpha` (team-alpha), `courier-svc-bravo` (team-bravo) |
| Vault auth | `oidc/` role `human`, `jwt/` role `machine` | `groups` claim → external identity groups |
| Vault policies | `vault-admin`, `team-alpha`, `team-bravo`, `courier` | `courier` is write-only (no read) |
| Sample secrets | `kv/teams/<team>/oauth-clients/phase0-sample` | fake values |

## Prerequisites (out of band, never in git)

- Secret `vault/vault-awskms` with `AWS_REGION`, `VAULT_AWSKMS_SEAL_KEY_ID`,
  `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`
- DNS: `vault.sororlab.dev` CNAME `cilium.sororlab.dev` in Technitium

## Run order

All scripts run on a host with `kubectl` access to the cluster.

```bash
# 1. Deploy Vault (ArgoCD app in homelab-charts, values = vault-values.yaml)
# 2. Authentik objects + credentials into Secrets vault/vault-oidc, vault/courier-phase0-testers
./authentik-setup.sh
# 3. Init (recovery keys + root token → ~/courier-vault-init.json, mode 600) and configure Vault
./vault-bootstrap.sh
# 4. Acceptance test
./verify.sh
```

Every script is idempotent. `vault-bootstrap.sh` refuses to overwrite an
existing keys file.

## Acceptance criteria

`verify.sh` must print `ALL CHECKS PASSED`. For each test identity it checks:

- Authentik issues a token that carries the identity's team group
- Vault `jwt` login succeeds and attaches the matching identity policy
- the identity **can** read its own team's sample secret (HTTP 200)
- the identity **cannot** read the other team's sample secret (HTTP 403)

Manual check for humans: sign in at `https://vault.sororlab.dev` with method
OIDC as a member of `team-alpha`, then open `kv/teams/team-alpha/`.

## After the run

1. Store `~/courier-vault-init.json` offline, then `shred -u` it.
2. Confirm OIDC admin login works, then revoke the root token:
   `vault token revoke <root_token>`. Use `vault operator generate-root`
   with the recovery keys if a root token is ever needed again.
3. Auto-unseal check: `kubectl -n vault delete pod vault-0`; it must come back
   `Sealed false` with nobody entering keys.

## Findings

- **Authentik 2026.x requires an explicit `grant_types` list on OAuth2
  providers.** An empty list rejects `client_credentials` with
  `Invalid grant_type for provider`. The Courier adapter must map
  `spec.grantTypes` onto this field.
- Service-account app passwords live under token identifier
  `service-account-<username>-password` and expire after about a year by
  default, even with `expiring: false` on the account.
