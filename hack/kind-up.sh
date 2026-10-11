#!/usr/bin/env bash
# Brings up a local kind cluster on Kubernetes 1.36.4 with kubesentry, Prometheus
# (kube-prometheus-stack), cert-manager, API server audit logging, the node agent
# and demo workloads. Safe to re-run: it rebuilds the images and restarts kubesentry.
set -euo pipefail
cd "$(dirname "$0")/.."

CLUSTER=kubesentry
CTX=kind-$CLUSTER
k() { kubectl --context "$CTX" "$@"; }

for tool in docker kind kubectl helm openssl; do
  command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 1; }
done

if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  echo "==> creating kind cluster $CLUSTER"
  mkdir -p .kind
  sed "s#__REPO__#$PWD#g" deploy/kind/cluster.yaml > .kind/cluster.yaml
  kind create cluster --config .kind/cluster.yaml
fi

echo "==> Prometheus (kube-prometheus-stack)"
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts >/dev/null 2>&1 || true
helm repo update prometheus-community >/dev/null
# KPS_VALUES replaces these defaults, e.g. test/stress/kind/kps-values.yaml for the stress cluster.
kps_values=(--set grafana.enabled=false --set alertmanager.enabled=false --set prometheus.prometheusSpec.retention=3d)
if [ -n "${KPS_VALUES:-}" ]; then kps_values=(-f "$KPS_VALUES"); fi
helm upgrade --install kps prometheus-community/kube-prometheus-stack \
  --kube-context "$CTX" --namespace monitoring --create-namespace \
  "${kps_values[@]}" \
  --wait --timeout 10m

echo "==> cert-manager"
helm repo add jetstack https://charts.jetstack.io >/dev/null 2>&1 || true
helm repo update jetstack >/dev/null
helm upgrade --install cert-manager jetstack/cert-manager \
  --kube-context "$CTX" --namespace cert-manager --create-namespace \
  --set crds.enabled=true \
  --wait --timeout 10m

echo "==> building images"
docker build -t kubesentry:dev --build-arg CMD=server .
docker build -t kubesentry-agent:dev --build-arg CMD=agent .
kind load docker-image --name "$CLUSTER" kubesentry:dev kubesentry-agent:dev

echo "==> kubesentry"
k create namespace kubesentry --dry-run=client -o yaml | k apply -f - >/dev/null
for secret in kubesentry-api kubesentry-agent kubesentry-audit; do
  k -n kubesentry get secret "$secret" >/dev/null 2>&1 ||
    k -n kubesentry create secret generic "$secret" --from-literal=token="$(openssl rand -hex 32)"
done
kubectl kustomize --load-restrictor LoadRestrictionsNone deploy/kind | k apply -f -
# The image tag stays "dev", so restart to pick up a rebuilt image.
k -n kubesentry rollout restart deployment/kubesentry daemonset/kubesentry-agent
k -n kubesentry rollout status deployment/kubesentry --timeout 3m
k -n kubesentry rollout status daemonset/kubesentry-agent --timeout 3m

echo "==> demo workloads and certificates"
k apply -f deploy/kind/scenarios.yaml
k apply -f deploy/kind/cert-manager.yaml

cat <<'EOF'

Ready. Next:
  hack/audit-scenarios.sh   # generate example audit activity
  hack/dashboard.sh         # UI at http://localhost:8080 (prints the API token)
EOF
