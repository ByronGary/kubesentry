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
lint dashboards --set metrics.grafanaDashboards.enabled=true
lint alerts -f "$TESTDATA/alerts.values.yaml"
lint incidents -f "$TESTDATA/incidents.values.yaml"
lint investigator -f "$TESTDATA/investigator.values.yaml"
lint investigator-bedrock -f "$TESTDATA/incidents.values.yaml" --set incidents.investigator.enabled=true \
  --set incidents.investigator.provider=bedrock --set incidents.investigator.acknowledgeDataEgress=true

echo "== golden renders"
golden default
golden kind -f deploy/kind/values-kind.yaml
golden eks -f "$CHART/examples/values-eks.yaml"
# Grafana dashboard ConfigMaps, with the budget and queue lines filled from values.
golden dashboards --set metrics.grafanaDashboards.enabled=true \
  --set metrics.grafanaDashboards.annotations.grafana_folder=kubesentry --set auth.authzQPS=300
# Alerts to an in-cluster Alertmanager pair: token Secret, CA, egress, the alerting rules.
golden alerts -f "$TESTDATA/alerts.values.yaml"
# Incidents with every value set: CloudWatch logs then pods/log, CloudTrail
# lookup, a request profile ConfigMap, the read-only RBAC and the rules.
golden incidents -f "$TESTDATA/incidents.values.yaml"
# The AI investigator on the Anthropic API: the key from a Secret, every
# value set, the investigator role aggregated into admin.
golden investigator -f "$TESTDATA/investigator.values.yaml"

echo "== refused configurations"
# Two replicas would each keep a partial, different audit history.
refuses guardrail-memory-replicas --set replicas=2 --set audit.sources.webhook.enabled=true
# Two replicas would each notify on their own: the alerts lock needs Postgres.
refuses guardrail-alerts-replicas --set replicas=2 --set alerts.enabled=true
# The agent check watches the chart's own agent DaemonSet.
refuses guardrail-alerts-agents-on --set alerts.enabled=true --set alerts.agents=on --set agent.enabled=false
# AMP's alert manager takes SigV4 from the pod's role, not a token.
refuses guardrail-alerts-sigv4-secret --set alerts.enabled=true --set alerts.alertmanager.existingSecret=am \
  --set 'alerts.alertmanager.urls={https://aps-workspaces.us-east-1.amazonaws.com/workspaces/ws-1/alertmanager}'
# Proxy mode must know which addresses may send identity headers.
refuses guardrail-proxy-cidrs --set auth.mode=proxy
# ...and not every address, unless the operator says the network ensures it.
refuses guardrail-proxy-any-cidr --set auth.mode=proxy --set 'auth.trustedProxyCIDRs={10.0.0.0/8,0.0.0.0/0}'
# Identity headers must be ones oauth2-proxy sets and strips, unless explicitly allowed.
refuses schema-custom-user-header --set auth.userHeader=X-Remote-User
# The CloudWatch reader needs a log group, from the cluster name or explicitly.
refuses guardrail-cloudwatch-group --set audit.sources.cloudwatch.enabled=true
# Incidents follow the informer cache's views.
refuses guardrail-incidents-cache --set incidents.enabled=true --set server.cache=false
# Two replicas would each run the engine: the incidents lock needs Postgres.
refuses guardrail-incidents-replicas --set replicas=2 --set incidents.enabled=true
# CloudTrail only attaches to incidents; the server refuses it alone.
refuses guardrail-cloudtrail-needs-incidents --set incidents.cloudtrail.mode=lookup
# A trail in CloudWatch Logs needs its log group...
refuses guardrail-cloudtrail-log-group --set incidents.enabled=true --set incidents.cloudtrail.mode=logs
# ...and CloudWatch container logs a group, or the cluster name for Container Insights'.
refuses guardrail-incident-logs-group --set incidents.enabled=true --set incidents.logs.mode=cloudwatch
# The schema rejects values the server would not understand.
refuses schema-auth-mode --set auth.mode=sso
refuses schema-production-label --set 'alerts.production.labelKey=bad key'
refuses schema-allowed-origins --set 'server.allowedOrigins={portal.example.com}'
refuses schema-digest-at --set 'alerts.digests.at=9am'
# An incident covers at most 24 hours.
refuses schema-incidents-max-range --set incidents.enabled=true --set incidents.maxRange=48h
# The investigator sends incident data to the provider only when acknowledged...
refuses guardrail-investigator-ack --set incidents.enabled=true --set incidents.investigator.enabled=true \
  --set incidents.investigator.existingSecret=anthropic
# ...investigates incidents...
refuses guardrail-investigator-incidents --set incidents.investigator.enabled=true \
  --set incidents.investigator.acknowledgeDataEgress=true --set incidents.investigator.existingSecret=anthropic
# ...and on the Anthropic API needs the key's Secret.
refuses guardrail-investigator-secret --set incidents.enabled=true --set incidents.investigator.enabled=true \
  --set incidents.investigator.acknowledgeDataEgress=true
refuses schema-investigator-provider --set incidents.investigator.provider=openai

if [ "$failed" -ne 0 ]; then
  echo "helm tests FAILED"
  exit 1
fi
$update || echo "helm tests passed"
