#!/usr/bin/env bash
# Phase 1: build the controller image on the k3s node, import it into k3s
# containerd (no registry needed), and apply CRD + RBAC + manager.
#
# Prerequisites:
#   deploy/phase1/authentik-controller-account.sh   (Secret courier-system/courier-authentik)
#   deploy/phase1/vault-kubernetes-auth.sh          (Vault role courier)
set -euo pipefail
export PATH="$HOME/.local/go/bin:$HOME/.local/bin:$PATH"

repo="$(cd "$(dirname "$0")/../.." && pwd)"
IMG="courier-controller:dev"
cd "$repo"

echo "==> build $IMG"
# The node's ~/.docker/config.json uses a gpg-backed credential store that
# cannot unlock in non-interactive sessions, which breaks even anonymous
# public pulls. Build with a throwaway empty config instead.
DOCKER_CONFIG="$(mktemp -d)"
export DOCKER_CONFIG
trap 'rm -rf "$DOCKER_CONFIG"' EXIT
make docker-build IMG="$IMG"

echo "==> import into k3s containerd"
docker save "$IMG" | sudo k3s ctr images import - >/dev/null
sudo k3s ctr images ls -q | grep -F "courier-controller:dev"

echo "==> apply"
kubectl apply --server-side -k deploy/phase1/controller

echo "==> restart and wait"
kubectl -n courier-system rollout restart deploy/courier-controller-manager
kubectl -n courier-system rollout status deploy/courier-controller-manager --timeout=180s
kubectl get crd oauthclients.courier.sororlab.dev
