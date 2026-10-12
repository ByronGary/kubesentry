#!/usr/bin/env bash
# Tests for charts/kubesentry: helm lint for each profile, golden `helm template`
# renders, and guardrails or schema rules that must refuse a configuration.
#
#   hack/helm-test.sh            compare against charts/kubesentry/testdata
#   hack/helm-test.sh --update   rewrite the golden files after an intended change
#
# Renders use a fixed Kubernetes version and declare the prometheus-operator
# APIs, so the output does not depend on the machine or a cluster. Generated
# tokens are random on every render and are masked as <generated>.
set -euo pipefail
cd "$(dirname "$0")/.."

CHART=charts/kubesentry
TESTDATA=$CHART/testdata
RELEASE=kubesentry
NAMESPACE=kubesentry
KUBE_VERSION=1.33.0

update=false
case "${1:-}" in
  --update) update=true ;;
  "") ;;
  *) echo "usage: $0 [--update]" >&2; exit 2 ;;
esac

command -v helm >/dev/null || { echo "missing tool: helm" >&2; exit 1; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
failed=0

render() {
  helm template "$RELEASE" "$CHART" --namespace "$NAMESPACE" --kube-version "$KUBE_VERSION" \
    --api-versions monitoring.coreos.com/v1/ServiceMonitor \
    --api-versions monitoring.coreos.com/v1/PrometheusRule \
    "$@"
}

# Masks the values of generated token Secrets (data.<key>: <base64>).
mask_tokens() {
  awk '
    /^kind: Secret$/ { secret = 1 }
    /^---/           { secret = 0; data = 0 }
    secret && /^data:$/ { data = 1; print; next }
    secret && data && /^  [A-Za-z0-9_.-]+: / { sub(/: .*/, ": <generated>"); print; next }
    { print }
  '
}

compare() { # name got-file golden-file
  local name=$1 got=$2 want=$3
  if $update; then
    cp "$got" "$want"
    echo "updated $want"
    return
  fi
  if [ ! -f "$want" ]; then
    echo "FAIL $name: no golden file $want (run $0 --update)"
    failed=1
  elif diff -u "$want" "$got" >"$tmp/diff"; then
    echo "ok   $name"
  else
    echo "FAIL $name: render differs from $want"
    cat "$tmp/diff"
    failed=1
  fi
}

lint() { # name values-args...
  local name=$1; shift
  if helm lint --strict "$CHART" --namespace "$NAMESPACE" "$@" >"$tmp/lint" 2>&1; then
    echo "ok   lint $name"
  else
    echo "FAIL lint $name"
    cat "$tmp/lint"
    failed=1
  fi
}

golden() { # name values-args...
  local name=$1; shift
  if ! render "$@" >"$tmp/raw" 2>"$tmp/err"; then
    echo "FAIL $name: render failed"
    cat "$tmp/err"
    failed=1
    return
  fi
  mask_tokens <"$tmp/raw" >"$tmp/$name.yaml"
  compare "$name" "$tmp/$name.yaml" "$TESTDATA/$name.golden.yaml"
}

refuses() { # name values-args...: the render must fail; the error is the golden file
  local name=$1; shift
  if render "$@" >/dev/null 2>"$tmp/err"; then
    echo "FAIL $name: rendered, but should have been refused"
    failed=1
    return
  fi
  compare "$name" "$tmp/err" "$TESTDATA/$name.golden.txt"
}

echo "== helm lint"
lint default
lint kind -f deploy/kind/values-kind.yaml
lint eks -f "$CHART/examples/values-eks.yaml"

echo "== golden renders"
golden default
golden kind -f deploy/kind/values-kind.yaml
golden eks -f "$CHART/examples/values-eks.yaml"

echo "== refused configurations"
# Two replicas would each keep a partial, different audit history.
refuses guardrail-memory-replicas --set replicas=2 --set audit.sources.webhook.enabled=true
# Proxy mode must know which addresses may send identity headers.
refuses guardrail-proxy-cidrs --set auth.mode=proxy
# ...and not every address, unless the operator says the network ensures it.
refuses guardrail-proxy-any-cidr --set auth.mode=proxy --set 'auth.trustedProxyCIDRs={10.0.0.0/8,0.0.0.0/0}'
# Identity headers must be ones oauth2-proxy sets and strips, unless explicitly allowed.
refuses schema-custom-user-header --set auth.userHeader=X-Remote-User
# The CloudWatch reader needs a log group, from the cluster name or explicitly.
refuses guardrail-cloudwatch-group --set audit.sources.cloudwatch.enabled=true
# The schema rejects values the server would not understand.
refuses schema-auth-mode --set auth.mode=sso
refuses schema-production-label --set 'alerts.production.labelKey=bad key'

if [ "$failed" -ne 0 ]; then
  echo "helm tests FAILED"
  exit 1
fi
$update || echo "helm tests passed"
