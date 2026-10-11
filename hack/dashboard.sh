#!/usr/bin/env bash
# Port-forwards the kubesentry UI on the kind cluster to http://localhost:8080
# (override with PORT=...) and prints the API token the UI asks for.
set -euo pipefail

CTX=kind-kubesentry
PORT=${PORT:-8080}

TOKEN=$(kubectl --context "$CTX" -n kubesentry get secret kubesentry-api -o jsonpath='{.data.token}' | base64 -d)
echo "Open http://localhost:$PORT and paste this API token when asked:"
echo "  $TOKEN"
exec kubectl --context "$CTX" -n kubesentry port-forward svc/kubesentry "$PORT:8080"
