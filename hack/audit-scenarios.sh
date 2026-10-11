#!/usr/bin/env bash
# Generates one example of each kind of audit activity kubesentry highlights,
# against the kind cluster from hack/kind-up.sh. Safe to re-run.
set -euo pipefail

CTX=kind-kubesentry
NS=demo-apps
k() { kubectl --context "$CTX" "$@"; }

POD=$(k -n "$NS" get pod -l app=steady -o jsonpath='{.items[0].metadata.name}')

echo "exec into $POD"
k -n "$NS" exec "$POD" -c app -- python -c 'print("hello from exec")'

echo "secret write and read"
k -n "$NS" create secret generic demo-db-credentials --from-literal=password=not-a-real-password \
  --dry-run=client -o yaml | k apply -f - >/dev/null
k -n "$NS" get secret demo-db-credentials -o name

echo "RBAC change and delete"
k create clusterrolebinding demo-tmp-view --clusterrole=view --user=mallory
k delete clusterrolebinding demo-tmp-view

echo "impersonation (denied: the default service account cannot list pods)"
k --as="system:serviceaccount:$NS:default" -n "$NS" get pods 2>&1 | head -1 || true

echo "service account token request"
k -n "$NS" create token default --duration=10m >/dev/null && echo "token created"

echo "kubectl debug (ephemeral container)"
k -n "$NS" debug "$POD" --profile=general --image=python:3.13-alpine --target=app -- true

echo "anonymous request (denied)"
SERVER=$(kubectl config view --context "$CTX" --minify -o jsonpath='{.clusters[0].cluster.server}')
curl -sk -o /dev/null -w 'HTTP %{http_code}\n' "$SERVER/api/v1/namespaces/$NS/secrets"
