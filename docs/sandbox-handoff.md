# Handoff: a portable Courier sandbox

**For:** an engineering agent (or person) with **podman** available.
**Goal:** one command that stands up a working Courier lab on a laptop, so
anyone can see the whole flow without the author's homelab: request a client →
client created in the IdP → secret delivered to a group-gated vault path →
only the owning team can read it, and the lifecycle operations (rotate, adopt)
work.

Everything in this repository was built and verified on a single-node k3s
homelab. This document tells you what exists, what is homelab-specific, the
order things must happen in, the traps we already fell into, and how to know
you are done. Read it fully before writing code.

---

## 1. What "done" looks like

A new directory `sandbox/` containing:

| File | Purpose |
|---|---|
| `sandbox/README.md` | Prerequisites, `up`, `demo`, `down`, troubleshooting |
| `sandbox/up.sh` | Idempotent. Creates the cluster and installs everything below. Re-running it on a working sandbox changes nothing. |
| `sandbox/demo.sh` | Applies the sample requests and runs the verification scripts (section 6) |
| `sandbox/down.sh` | Deletes the cluster and any local state |
| `sandbox/values/*.yaml` | Helm values for the sandbox (never edit `deploy/phase0/vault-values.yaml`; that is the homelab's) |
| `sandbox/sandbox.env` | Every tunable in one place: hostnames, ports, versions, image digest |

Acceptance: on a clean machine with podman, `sandbox/up.sh && sandbox/demo.sh`
ends with every check in section 6 printing PASS, and a second run of `up.sh` is
a no-op. Time budget for `up.sh`: under 15 minutes on a laptop.

Do not print or log any secret (client secrets, vault tokens, Authentik
tokens, app passwords). Existing scripts are careful about this; keep it that
way. Screen output may show lengths and fingerprints only.

## 2. Recommended shape

**Kubernetes via kind on podman** (`KIND_EXPERIMENTAL_PROVIDER=podman kind create cluster`).
The controller is a Kubernetes operator and all verification scripts use
`kubectl`, so a Kubernetes-less compose setup would mean rewriting most of the
proof. k3d on podman is an acceptable alternative if kind gives you trouble;
say which you picked and why.

Build it in tiers, and make each tier independently usable (`up.sh --tier 1`):

| Tier | Contents | Proves |
|---|---|---|
| **1. Core** | Authentik, Vault CE, the Courier controller; requests applied with `kubectl apply` | Delivery, group-gated access, rotation, adoption |
| **2. GitOps** | An in-cluster Git server (Gitea recommended), ArgoCD, External Secrets Operator, the ApplicationSets from `deploy/argocd`, the `deploy/team-access` chart | Merge → sync → credentials; per-team SecretStore |
| **3. Portal** (optional) | Backstage with the template in `backstage/` | Form → pull request |

Tier 1 is the must-have. Tier 2 is strongly wanted. Tier 3 only if time
allows; Backstage needs a GitHub-compatible API for the "open a pull request"
step, so it pairs with Gitea's GitHub-like API only partially. Document the gap
rather than faking it.

GitHub Actions (`.github/workflows/requests.yml`) cannot run locally in a
meaningful way. Instead, `demo.sh` should run the same command CI runs,
`go run ./cmd/courier validate requests --policy requests/.policy.yaml`
(or a container built from the repo), and show one failing and one passing
case.

## 3. Inventory of what already exists

### Versions verified in the homelab

| Component | Version |
|---|---|
| Kubernetes | k3s v1.36.4 |
| Vault Community Edition | 2.0.4, Helm chart `hashicorp/vault` 0.34.1 |
| Authentik | 2026.8.2 (Helm chart `authentik/authentik`, pick the chart version shipping this app version) |
| External Secrets Operator | chart 2.10.0 |
| ArgoCD | whatever current stable is; nothing version-specific is used |
| Controller image | `ghcr.io/paimonsoror/courier-controller@sha256:34023d6eeb14ba1efe231bb6f2b8442665a810e3a2de04680e8aba2485a3fc44` (tag `sha-8e454ad`, public). Check `deploy/phase1/controller/kustomization.yaml` for the current pin. |
| Go (to run `courier validate`) | 1.27.1 |
| Python (scripts, sample) | 3.x, `hvac==2.4.0` for `samples/python` |

### Scripts, in the order they run in the homelab

| # | Script | What it does | Needs |
|---|---|---|---|
| 1 | Helm install Vault with `deploy/phase0/vault-values.yaml` | Raft, 1 replica, awskms seal | Secret `vault/vault-awskms` |
| 2 | Helm install Authentik | IdP | env `AUTHENTIK_BOOTSTRAP_TOKEN` in the server pod (scripts exec into `deploy/authentik-server` and use it) |
| 3 | `deploy/phase0/authentik-setup.sh` (+ `.py`) | Groups `vault-admins`, `team-alpha`, `team-bravo`; service accounts `courier-svc-alpha`/`-bravo`; OIDC provider+app `vault`; bindings. Writes Secrets `vault/vault-oidc` and `vault/courier-phase0-testers` | Authentik running; scope mapping named `oauth-groups` for the `groups` scope (**not created by the script**, see 4.4) |
| 4 | `deploy/phase0/vault-bootstrap.sh` | Init (writes keys file), KV v2 `kv/`, audit, `oidc/` and `jwt/` auth, policies, one external group per IdP group per mount | Step 3 |
| 5 | `deploy/phase0/verify.sh` | Team service accounts read own path (200), other team's (403) | |
| 6 | `deploy/phase1/authentik-controller-account.sh` (+ `.py`) | Service account `courier-controller`, role with 16 permissions, API token → Secret `courier-system/courier-authentik` | |
| 7 | `deploy/phase1/vault-kubernetes-auth.sh` | `kubernetes/` auth, role `courier` → write-only policy | |
| 8 | `kubectl apply -k deploy/phase1/controller` (CRD, RBAC, manager, wiring patch) | Controller | Steps 6–7 |
| 9 | `deploy/phase1/acceptance.sh` | Apply `team-alpha/billing-sync`, read as owner, denied for other team, delete destroys | |
| 10 | Tier 2: `deploy/argocd/*` applied by an app-of-apps; ESO; `deploy/phase2/vault-team-roles.sh` | Requests from Git; per-team `courier-secrets` SA + `courier-vault` SecretStore | Git server URL |
| 11 | `deploy/phase2/check-access.sh <team> <name>`, `verify-external-secrets.sh`, `samples/python/verify.sh <team> <name>` | Access proofs | |
| 12 | `deploy/phase4/create-legacy-client.sh`, then a request with the adopt annotation, then `verify-adoption.sh`; rotate annotation then `verify-rotation.sh` | Lifecycle | |

Read `deploy/phase*/README.md`, `docs/site/implementation.html` and
`docs/site/reference.html` for the full detail; `cmd/main.go` lists every
controller flag and environment variable.

## 4. What is homelab-specific and must change

### 4.1 Vault unseal
The homelab uses AWS KMS auto-unseal. The sandbox has no AWS. Use **Shamir
with one key share** (`vault operator init -key-shares=1 -key-threshold=1`) and
have `up.sh` unseal from a keys file kept under `sandbox/.state/` (git-ignored,
mode 600). Do not use `-dev` mode: it is in-memory and changes the auth and
KV behavior we rely on. Mark the Shamir shortcut loudly as sandbox-only.

`vault-bootstrap.sh` hardcodes `-recovery-shares` (only valid with auto-unseal)
and `KEYS_FILE=$HOME/courier-vault-init.json`. Make the init arguments and the
keys path parameters rather than forking the script. Most later scripts accept
`VAULT_ADMIN_TOKEN` or `KEYS_FILE`; keep that contract.

### 4.2 Hostnames and TLS — the hard part
Authentik's issuer URL must be **the same string** for:
- browsers (Vault UI OIDC login, Backstage),
- Vault (OIDC discovery from inside the cluster),
- the controller (`AUTHENTIK_URL`),
- the verification scripts, which run on the host and read `token_endpoint`
  from the vault entry the controller wrote.

In the homelab that is `https://auth.sororlab.dev` via a real ingress and
certificate. Recommended sandbox approach: one wildcard name that resolves
everywhere, e.g. `auth.127.0.0.1.nip.io` / `vault.127.0.0.1.nip.io` with a kind
`extraPortMappings` ingress, **plus** a CoreDNS rewrite so the same names
resolve to the ingress controller from inside pods. Self-signed TLS is fine if
every client trusts the CA (Vault's `oidc_discovery_ca_pem`, the controller
container, Python's `SSL_CERT_FILE`); plain HTTP is simpler and acceptable for
a sandbox if Authentik and Vault both allow it. Decide early; everything else
depends on it.

Hardcoded `sororlab.dev` values to parameterize (grep for `sororlab.dev`):
- `deploy/phase0/authentik-setup.py` (`AUTH_HOST`, `VAULT_HOST`, `ADMIN_USER=paimonsoror`)
- `deploy/phase0/vault-bootstrap.sh` (`VAULT_HOST`)
- `deploy/phase1/controller/manager-wiring.yaml` (`AUTHENTIK_URL`) — use a sandbox kustomize overlay
- `deploy/phase4/create-legacy-client.sh` (revocation URL)
- `requests/.policy.yaml` (`allowedRedirectHosts`) and `requests/team-alpha/orders-portal.yaml` (redirect URI)
- `deploy/argocd/*` (repo URL `github.com/paimonsoror/courier`)
- the API group `courier.sororlab.dev` is **not** a hostname — leave it alone.

Prefer environment variables with the current values as defaults, so the
homelab keeps working unchanged.

### 4.3 Storage and ingress
Homelab: `local-path` storage class, Cilium ingress, cert-manager. kind ships
`standard` (local-path) storage; use ingress-nginx for kind. Put these in
`sandbox/values/`, not in the homelab files.

### 4.4 Authentik objects that were created by hand
- The custom scope mapping **`oauth-groups`** (scope name `groups`, expression
  returning the user's group names) was created in the Authentik UI before
  this project. `authentik-setup.py` looks it up and exits if missing. The
  sandbox must create it (API: `propertymappings/provider/scope/`). The
  homelab's expression, verbatim: `return {"groups": [g.name for g in user.ak_groups.all()]}`.
- The admin user `paimonsoror` → use `akadmin` (the bootstrap admin) in the sandbox.

### 4.5 Git hosting (tier 2)
ArgoCD needs a Git URL. Run Gitea in the cluster, push this repository to it
from `up.sh`, and point the ApplicationSets at it (sandbox overlay). ArgoCD
polls every ~3 minutes; either lower `timeout.reconciliation` or annotate the
ApplicationSet with `argocd.argoproj.io/application-set-refresh=true` in
`demo.sh`.

## 5. Traps we already hit (do not rediscover them)

1. **Authentik providers need an explicit `grant_types` list.** Created via API
   without it, the list is empty and every grant fails with `invalid_grant`.
2. **`core/applications/?slug=` ignores the filter.** Use `core/applications/<slug>/`.
3. **A Vault external group holds one alias.** Aliasing the same IdP group on
   both `oidc/` and `jwt/` silently replaces the first. Use a group per mount
   (`team-alpha` and `team-alpha-jwt`), as `vault-bootstrap.sh` does.
4. **One JWT/OIDC mount cannot serve both humans and machines.** A mount with
   `oidc_client_id` rejects jwt-role logins ("unsupported config type").
5. **Proving a client secret:** Authentik's `client_credentials` grant with a
   service account's username + app password returns a token **whatever
   `client_secret` is sent**. Never use "got a token" as proof. The scripts
   POST to `/application/o/revoke/` with HTTP Basic `client_id:secret` and a
   made-up token: 200 = secret accepted, 401 = rejected. Keep it that way, and
   keep the negative check.
6. **Redirect URI shape:** Authentik adds `redirect_uri_type: authorization`;
   controllers before `8e454ad` rewrote auth-code clients every resync. Use the
   pinned image or newer.
7. **External Secrets webhook readiness:** applying `SecretStore`s before the
   ESO webhook is ready fails, and ArgoCD does not retry the same revision.
   Wait for the ESO deployments (including the webhook) before creating the
   team-access applications.
8. **Scripts exec into pods** (`deploy/authentik-server`, `vault-0`). Keep those
   names, or parameterize them consistently.
9. **Heredoc quoting:** several scripts embed Python in single-quoted bash.
   Python f-strings with `'` inside break them silently. Use heredocs (`<<'PY'`).
10. **Docker credential helpers** can break anonymous pulls in non-interactive
    shells; for image builds use an empty `DOCKER_CONFIG`. With podman, check
    the equivalent (`REGISTRY_AUTH_FILE`).
11. **Rotation and cached copies:** after a rotation, External Secrets copies keep
    the old (now rejected) secret until `refreshInterval`. `verify-rotation.sh`
    forces a refresh; the demo should explain the window.

## 6. Verification the sandbox must pass

Run from `sandbox/demo.sh`, in this order, each must end with its PASS banner:

| Check | Command | Banner |
|---|---|---|
| Access model | `deploy/phase0/verify.sh` | `ALL CHECKS PASSED` |
| Controller delivery | `KEEP=1 deploy/phase1/acceptance.sh` | `PHASE 1 ACCEPTANCE PASSED` |
| Policy gate | `courier validate` on a request with `client_credentials` and no label (must fail), then with `--labels security-approved` (must pass) | exit codes 1, then 0 |
| Owner-only access | `deploy/phase2/check-access.sh team-bravo report-exporter` | `ACCESS CHECK PASSED` |
| External Secrets (tier 2) | `deploy/phase2/verify-external-secrets.sh` | `EXTERNAL SECRETS VERIFIED` |
| Python sample | `samples/python/verify.sh team-bravo report-exporter` | `PYTHON SAMPLE VERIFIED` |
| Rotation | set the rotate annotation, wait Ready, `deploy/phase4/verify-rotation.sh` | `ROTATION VERIFIED` |
| Adoption | `deploy/phase4/create-legacy-client.sh`, apply `requests/team-alpha/crm.yaml`, `deploy/phase4/verify-adoption.sh` | `ADOPTION VERIFIED` |
| Quiet resync | after 25 minutes idle, no Authentik `model_updated` events for unchanged clients | 0 events |

If a check needs a change to make it portable, change the script (with
defaults that keep the homelab working), not the expectation.

## 7. How to report back

- What works per tier, with the actual output of section 6.
- Every deviation from this document and why.
- Anything you had to change outside `sandbox/`, as a separate commit with a
  clear message.
- Known gaps (for example Backstage pull requests against Gitea).

Background reading, in order: `README.md`, `docs/site/index.html`,
`docs/site/how-it-works.html`, `docs/site/walkthrough.html`,
`docs/site/implementation.html`, `docs/adr/`.
