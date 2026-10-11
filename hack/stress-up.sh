#!/usr/bin/env bash
# Brings up the stress-test cluster: kind with 1 control plane and 5 workers
# (test/stress/kind/cluster.yaml), KWOK for fake nodes, the kubesentry stack,
# the stress harness image and the metrics simulator. Safe to re-run.
#
# kubesentry itself is deployed by hack/kind-up.sh only when it is not there
# yet (or FORCE_KIND_UP=1), because kind-up.sh rebuilds the images from this
# working tree and restarts them. To run a specific version, set
# KUBESENTRY_SRC to a checkout; its images are built, kind-loaded and rolled out:
#
#   KUBESENTRY_SRC=../kunion-baseline hack/stress-up.sh   # baseline (git tag "baseline")
#   KUBESENTRY_SRC=. hack/stress-up.sh                    # this tree ("after")
set -euo pipefail
cd "$(dirname "$0")/.."
source hack/stress-lib.sh

for tool in docker kind kubectl helm go; do
  command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 1; }
done

hack/stress-guard.sh --once || { echo "not enough free memory to start" >&2; exit 1; }

if ! kind get clusters 2>/dev/null | grep -qx "$STRESS_CLUSTER"; then
  log "creating kind cluster $STRESS_CLUSTER (1 control plane + 5 workers)"
  mkdir -p .kind
  sed "s#__REPO__#$PWD#g" test/stress/kind/cluster.yaml >.kind/stress-cluster.yaml
  kind create cluster --config .kind/stress-cluster.yaml
fi

log "KWOK v0.8.0"
k apply -f test/stress/kind/kwok-v0.8.0/kwok.yaml >/dev/null
k apply -f test/stress/kind/kwok-v0.8.0/stage-fast.yaml >/dev/null
k -n kube-system rollout status deployment/kwok-controller --timeout 3m

if [ "${FORCE_KIND_UP:-0}" = 1 ] || ! k -n kubesentry get deployment kubesentry >/dev/null 2>&1; then
  log "kubesentry stack (hack/kind-up.sh with test/stress/kind/kps-values.yaml)"
  KPS_VALUES=test/stress/kind/kps-values.yaml hack/kind-up.sh
else
  log "kubesentry already deployed: not running hack/kind-up.sh (FORCE_KIND_UP=1 to redeploy)"
fi

if [ -n "${KUBESENTRY_SRC:-}" ]; then
  log "building kubesentry images from $KUBESENTRY_SRC"
  docker build -t kubesentry:dev --build-arg CMD=server "$KUBESENTRY_SRC"
  docker build -t kubesentry-agent:dev --build-arg CMD=agent "$KUBESENTRY_SRC"
  kind load docker-image --name "$STRESS_CLUSTER" kubesentry:dev kubesentry-agent:dev
  k -n kubesentry rollout restart deployment/kubesentry daemonset/kubesentry-agent
  k -n kubesentry rollout status deployment/kubesentry --timeout 3m
  k -n kubesentry rollout status daemonset/kubesentry-agent --timeout 5m || true
fi

log "harness images (busybox and agnhost for real-node cases, kubesentry-stress)"
for img in busybox:1.36 registry.k8s.io/e2e-test-images/agnhost:2.53; do
  docker image inspect "$img" >/dev/null 2>&1 || docker pull "$img"
done
kind load docker-image --name "$STRESS_CLUSTER" busybox:1.36 registry.k8s.io/e2e-test-images/agnhost:2.53
docker build -t kubesentry-stress:dev test/stress
kind load docker-image --name "$STRESS_CLUSTER" --nodes "$LOADGEN_NODE" kubesentry-stress:dev
build_stress_bin

log "load-generator namespace and metrics simulator"
k apply -f test/stress/deploy/runner.yaml >/dev/null
k apply -f test/stress/deploy/metrics-sim.yaml >/dev/null
k -n stress-load rollout restart deployment/metrics-sim >/dev/null
k -n stress-load rollout status deployment/metrics-sim --timeout 3m

cat <<'EOF'

Stress cluster ready. Next:
  hack/stress-run.sh L1 baseline       # one level
  hack/stress-run.sh all baseline      # L1 → L2 → L3 (TOP_LEVEL=L4 to go further)
EOF
