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
#
# The "after" variant installs this tree's build through the Helm chart in the
# enterprise configuration under test (test/stress/deploy/values-after.yaml):
# two replicas, 1Gi, Postgres audit store, SSO through the oauth2-proxy
# sidecar with JWTs from the harness's test issuer, CloudWatch from cwfake.
#
#   VARIANT=after hack/stress-up.sh            # BUILD_IMAGES=0 to keep the loaded images
#
# It switches a cluster deployed from the kustomize manifests to the chart
# (deploy/kind/values-kind.yaml header), deploys Postgres 17, the OIDC issuer
# and cwfake, applies the persona RBAC, and re-applies kube-prometheus-stack
# with test/stress/kind/kps-values.yaml at the pinned chart version.
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

VARIANT=${VARIANT:-baseline}
KPS_VERSION=${KPS_VERSION:-92.3.0}

if [ "${FORCE_KIND_UP:-0}" = 1 ] || ! k -n kubesentry get deployment kubesentry >/dev/null 2>&1; then
  log "kubesentry stack (hack/kind-up.sh with test/stress/kind/kps-values.yaml)"
  KPS_VALUES=test/stress/kind/kps-values.yaml hack/kind-up.sh
else
  log "kubesentry already deployed: not running hack/kind-up.sh (FORCE_KIND_UP=1 to redeploy)"
fi

log "harness image (kubesentry-stress) and binary"
docker build -t kubesentry-stress:dev -f test/stress/Dockerfile .
kind load docker-image --name "$STRESS_CLUSTER" --nodes "$LOADGEN_NODE" kubesentry-stress:dev
build_stress_bin

if [ "$VARIANT" = after ]; then
  log "kube-prometheus-stack $KPS_VERSION with test/stress/kind/kps-values.yaml"
  helm upgrade --install kps prometheus-community/kube-prometheus-stack --kube-context "$CTX" -n monitoring \
    --version "$KPS_VERSION" -f test/stress/kind/kps-values.yaml --wait --timeout 10m >/dev/null

  log "Postgres 17 for the audit store (stress-pg, on $STRESS_CLUSTER-worker2)"
  docker image inspect postgres:17 >/dev/null 2>&1 || docker pull postgres:17
  kind load docker-image --name "$STRESS_CLUSTER" --nodes "$STRESS_CLUSTER-worker2" postgres:17
  k apply -f test/stress/deploy/postgres.yaml >/dev/null
  if ! k -n stress-pg get secret postgres >/dev/null 2>&1; then
    k -n stress-pg create secret generic postgres --from-literal=password="$(openssl rand -hex 16)" >/dev/null
    k -n stress-pg label secret postgres kubesentry.io/stress=true >/dev/null
  fi
  pgpw=$(k -n stress-pg get secret postgres -o jsonpath='{.data.password}' | base64 -d)
  k -n kubesentry create secret generic kubesentry-pg \
    --from-literal=dsn="postgres://kubesentry:${pgpw}@postgres.stress-pg.svc.cluster.local:5432/kubesentry?sslmode=disable" \
    --dry-run=client -o yaml | k apply -f - >/dev/null
  k -n stress-pg rollout status statefulset/postgres --timeout 5m

  log "test OIDC issuer (stress-oidc) and the oauth2-proxy secrets"
  k apply -f test/stress/deploy/oidc.yaml >/dev/null
  "$STRESS_BIN" oidc-key --context "$CTX"
  k -n stress-oidc rollout restart deployment/oidc >/dev/null
  k -n stress-oidc rollout status deployment/oidc --timeout 3m
  k -n kubesentry get secret kubesentry-oauth2-proxy >/dev/null 2>&1 ||
    k -n kubesentry create secret generic kubesentry-oauth2-proxy --from-literal=client-secret="$(openssl rand -hex 16)" \
      --from-literal=cookie-secret="$(openssl rand -base64 32 | tr -- '+/' '-_' | head -c 32)" >/dev/null

  log "cwfake: a live CloudWatch tail from now (stress-cw)"
  docker image inspect quay.io/oauth2-proxy/oauth2-proxy:v7.15.5 >/dev/null 2>&1 || docker pull quay.io/oauth2-proxy/oauth2-proxy:v7.15.5
  kind load docker-image --name "$STRESS_CLUSTER" --nodes "$CONTROL_PLANE" quay.io/oauth2-proxy/oauth2-proxy:v7.15.5
  # Re-applying the manifest would reset START and restart the tail: only
  # create cwfake when it is not there.
  k -n stress-cw get deploy cwfake >/dev/null 2>&1 || k apply -f test/stress/deploy/cwfake.yaml >/dev/null
  if [ "$(k -n stress-cw get deploy cwfake -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="START")].value}')" = 2026-10-11T00:00:00Z ]; then
    k -n stress-cw set env deployment/cwfake START="$(date -u +%Y-%m-%dT%H:%M:%SZ)" EVENTS=0 RATE=300 SEED=2027 >/dev/null
  fi
  k -n stress-cw rollout status deployment/cwfake --timeout 3m

  if [ "${BUILD_IMAGES:-1}" = 1 ]; then
    log "kubesentry images from this tree"
    nice -n 19 hack/build-images.sh --kind --go-jobs 4
  fi

  if ! k -n kubesentry get deployment kubesentry -o jsonpath='{.metadata.labels.app\.kubernetes\.io/managed-by}' 2>/dev/null | grep -qx Helm; then
    log "switching kubesentry from the kustomize manifests to the chart"
    k -n kubesentry delete --ignore-not-found deployment/kubesentry service/kubesentry \
      serviceaccount/kubesentry daemonset/kubesentry-agent serviceaccount/kubesentry-agent
    k delete --ignore-not-found clusterrole/kubesentry clusterrolebinding/kubesentry
    for s in kubesentry-api kubesentry-agent kubesentry-audit; do
      k -n kubesentry label secret "$s" app.kubernetes.io/managed-by=Helm --overwrite >/dev/null
      k -n kubesentry annotate secret "$s" --overwrite meta.helm.sh/release-name=kubesentry meta.helm.sh/release-namespace=kubesentry >/dev/null
    done
  fi
  log "kubesentry (Helm, values-kind + values-after)"
  helm upgrade --install kubesentry charts/kubesentry --kube-context "$CTX" -n kubesentry \
    -f deploy/kind/values-kind.yaml -f test/stress/deploy/values-after.yaml --wait --timeout 10m
  if [ "${BUILD_IMAGES:-1}" = 1 ]; then
    # The tag stays "dev": restart to pick up the rebuilt images.
    k -n kubesentry rollout restart deployment/kubesentry daemonset/kubesentry-agent >/dev/null
    k -n kubesentry rollout status deployment/kubesentry --timeout 10m
    k -n kubesentry rollout status daemonset/kubesentry-agent --timeout 5m || true
  fi

  log "persona RBAC for JWT users"
  "$STRESS_BIN" personas --context "$CTX" --level "${PERSONA_LEVEL:-L3}" --n 100 --apply
fi

if [ "$VARIANT" != after ] && [ -n "${KUBESENTRY_SRC:-}" ]; then
  log "building kubesentry images from $KUBESENTRY_SRC"
  docker build -t kubesentry:dev --build-arg CMD=server "$KUBESENTRY_SRC"
  docker build -t kubesentry-agent:dev --build-arg CMD=agent "$KUBESENTRY_SRC"
  kind load docker-image --name "$STRESS_CLUSTER" kubesentry:dev kubesentry-agent:dev
  k -n kubesentry rollout restart deployment/kubesentry daemonset/kubesentry-agent
  k -n kubesentry rollout status deployment/kubesentry --timeout 3m
  k -n kubesentry rollout status daemonset/kubesentry-agent --timeout 5m || true
fi

log "images for the real-node cases (busybox, agnhost)"
for img in busybox:1.36 registry.k8s.io/e2e-test-images/agnhost:2.53; do
  docker image inspect "$img" >/dev/null 2>&1 || docker pull "$img"
done
kind load docker-image --name "$STRESS_CLUSTER" busybox:1.36 registry.k8s.io/e2e-test-images/agnhost:2.53

log "load-generator namespace and metrics simulator"
k apply -f test/stress/deploy/runner.yaml >/dev/null
k apply -f test/stress/deploy/metrics-sim.yaml >/dev/null
k -n stress-load rollout restart deployment/metrics-sim >/dev/null
k -n stress-load rollout status deployment/metrics-sim --timeout 3m

cat <<'EOF'

Stress cluster ready. Next:
  hack/stress-run.sh L1 baseline       # one level
  hack/stress-run.sh all baseline      # L1 → L2 → L3 (TOP_LEVEL=L4 to go further)
  hack/stress-run.sh L3 after          # the after build (after VARIANT=after hack/stress-up.sh)
EOF
