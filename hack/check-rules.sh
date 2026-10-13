#!/usr/bin/env bash
# Checks the alerting configuration with Prometheus's and Alertmanager's own tools.
#
#   hack/check-rules.sh                 the checks below
#   hack/check-rules.sh --kps <chart>   also render kube-prometheus-stack (a chart
#                                       directory or .tgz) with the example profile
#                                       and check every rule and the Alertmanager
#                                       configuration it produces
#
# 1. kubesentry's PrometheusRule, rendered from the chart with every optional
#    rule on (charts/kubesentry/examples/values-eks.yaml):
#      - promtool check rules, failing on any warning
#      - promtool test rules charts/kubesentry/testdata/prometheusrule.test.yaml
#      - every kubesentry_* and go_* metric it reads exists in internal/metrics
# 2. The extra rules in examples/monitoring-eks.yaml (additionalPrometheusRulesMap):
#      - promtool check rules, and promtool test rules examples/testdata/monitoring-eks.test.yaml
# 3. Every kube_* metric used by those rules and the Grafana dashboards is in the
#    profile's kube-state-metrics metricAllowlist.
# 4. The profile's Alertmanager configuration (alertmanager.config):
#      - amtool check-config
#      - amtool config routes test: where sample alerts are routed
#
# promtool and amtool run from PATH when installed, otherwise from the official
# images with docker (override with PROMETHEUS_IMAGE and ALERTMANAGER_IMAGE).
set -euo pipefail
cd "$(dirname "$0")/.."
# Low priority: these are checks, not a service.
renice -n 19 $$ >/dev/null 2>&1 || true

PROMETHEUS_IMAGE=${PROMETHEUS_IMAGE:-prom/prometheus:v3.15.0}
ALERTMANAGER_IMAGE=${ALERTMANAGER_IMAGE:-prom/alertmanager:v0.34.1}
CHART=charts/kubesentry
PROFILE=examples/monitoring-eks.yaml

kps=""
case "${1:-}" in
  --kps) kps=${2:?usage: $0 [--kps <kube-prometheus-stack chart>]} ;;
  "") ;;
  *) echo "usage: $0 [--kps <kube-prometheus-stack chart>]" >&2; exit 2 ;;
esac

command -v helm >/dev/null || { echo "missing tool: helm" >&2; exit 1; }
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
failed=0

# Runs a tool inside $tmp, from PATH or from its image (the directory mounted at /w).
tool() { # name image args...
  local name=$1 image=$2 bin; shift 2
  # type -P looks only at PATH: the wrapper functions below share the tools' names.
  if bin=$(type -P "$name"); then
    (cd "$tmp" && "$bin" "$@")
  else
    command -v docker >/dev/null || { echo "missing tool: $name (or docker to run $image)" >&2; exit 1; }
    docker run --rm --cpus=1 --user "$(id -u):$(id -g)" -v "$tmp:/w" -w /w --entrypoint "$name" "$image" "$@"
  fi
}
promtool() { tool promtool "$PROMETHEUS_IMAGE" "$@"; }
amtool() { tool amtool "$ALERTMANAGER_IMAGE" "$@"; }

check() { # name command...: runs it, prints its output on failure
  local name=$1; shift
  if "$@" >"$tmp/out" 2>&1; then
    echo "ok   $name"
  else
    echo "FAIL $name"
    sed 's/^/     /' "$tmp/out"
    failed=1
  fi
}

# promtool check rules prints warnings but exits 0 for some; fail on those too.
check_rules() { # files...
  promtool check rules ${LINT:---lint=all --lint-fatal} "$@" >"$tmp/check" 2>&1 || { cat "$tmp/check"; return 1; }
  cat "$tmp/check"
  ! grep -qi 'warn' "$tmp/check"
}

# The spec of each PrometheusRule in a rendered manifest, as a rule file.
prometheusrule_specs() {
  awk '
    /^---/                       { keep = 0; spec = 0; next }
    /^kind: PrometheusRule$/     { keep = 1 }
    keep && /^spec:$/            { spec = 1; next }
    keep && spec && /^[^ ]/      { spec = 0 }
    keep && spec                 { print substr($0, 3) }
  '
}

# Block-style YAML only: the block under top-level key $1, child $2, dedented,
# or with $2 = "*", each child of $1 written to $3/<child>.yaml.
yaml_block() { # top child [dir]
  awk -v top="$1" -v child="$2" -v dir="${3:-}" '
    function indent(s) { match(s, /^ */); return RLENGTH }
    /^[ ]*$/ { if (out != "") print "" > out; next }
    {
      ind = indent($0); rest = substr($0, ind + 1)
      if (rest ~ /^#/ && ind < 4) next
      if (ind == 0) { intop = (rest ~ ("^" top ":")); out = ""; next }
      if (!intop) next
      if (ind == 2) {
        name = rest; sub(/:.*/, "", name)
        out = (child == "*") ? dir "/" name ".yaml" : (name == child ? "/dev/stdout" : "")
        next
      }
      if (out != "" && ind >= 4) print substr($0, 5) > out
    }
  ' "$PROFILE"
}

# The kube-state-metrics metricAllowlist entries of the profile.
ksm_allowlist() {
  yaml_block kube-state-metrics metricAllowlist | sed -n 's/^- *//p'
}

# Metric names read by the expressions of a rule file.
rule_metrics() { # file prefix-regex
  awk '
    function indent(s) { match(s, /^ */); return RLENGTH }
    inexpr && (indent($0) > exprind || $0 ~ /^[ ]*$/) { print; next }
    { inexpr = 0 }
    /^[ ]*(- )?expr:/ {
      line = $0; sub(/^[ ]*(- )?expr:[ ]*/, "", line)
      if (line ~ /^[|>]/) { inexpr = 1; exprind = indent($0) } else print line
    }
  ' "$1" | grep -oE "\\b$2[a-z0-9_]*" | sort -u
}

echo "== kubesentry's PrometheusRule (chart, every optional rule on)"
helm template kubesentry "$CHART" --namespace kubesentry --kube-version 1.33.0 \
  --api-versions monitoring.coreos.com/v1/PrometheusRule \
  -f "$CHART/examples/values-eks.yaml" -s templates/prometheusrule.yaml \
  | prometheusrule_specs >"$tmp/kubesentry-rules.yaml"
cp "$CHART/testdata/prometheusrule.test.yaml" "$tmp/"
check "promtool check rules (kubesentry)" check_rules kubesentry-rules.yaml
check "promtool test rules (kubesentry)" promtool test rules prometheusrule.test.yaml

known=$({ grep -ohE '"kubesentry_[a-z0-9_]+"' internal/metrics/names.go
          grep -ohE '"(go|process)_[a-z0-9_]+"' internal/metrics/runtime.go; } | tr -d '"' | sort -u)
unknown=""
for m in $(rule_metrics "$tmp/kubesentry-rules.yaml" '(kubesentry|go|process)_'); do
  base=${m%_bucket}; base=${base%_count}; base=${base%_sum}
  grep -qxF "$base" <<<"$known" || unknown="$unknown $m"
done
if [ -z "$unknown" ]; then
  echo "ok   kubesentry rules use only metrics from internal/metrics"
else
  echo "FAIL kubesentry rules use unknown metrics:$unknown"
  failed=1
fi
unknown=""
for m in $(grep -ohE '\b(kubesentry|go)_[a-z0-9_]+' "$CHART"/dashboards/*.json | sort -u); do
  base=${m%_bucket}; base=${base%_count}; base=${base%_sum}
  grep -qxF "$base" <<<"$known" || unknown="$unknown $m"
done
if [ -z "$unknown" ]; then
  echo "ok   kubesentry dashboards use only metrics from internal/metrics"
else
  echo "FAIL kubesentry dashboards use unknown metrics:$unknown"
  failed=1
fi

echo "== extra rules in $PROFILE"
mkdir -p "$tmp/examples"
yaml_block additionalPrometheusRulesMap '*' "$tmp/examples"
for f in "$tmp"/examples/*.yaml; do
  check "promtool check rules ($(basename "$f" .yaml))" check_rules "examples/$(basename "$f")"
done
cp examples/testdata/monitoring-eks.test.yaml "$tmp/examples/"
check "promtool test rules (examples)" promtool test rules examples/monitoring-eks.test.yaml

echo "== kube-state-metrics allowlist in $PROFILE"
allow=$(ksm_allowlist | paste -sd'|' -)
missing=""
for m in $( { rule_metrics "$tmp/kubesentry-rules.yaml" kube_
              for f in "$tmp"/examples/*.yaml; do rule_metrics "$f" kube_; done
              grep -ohE '\bkube_[a-z0-9_]+' "$CHART"/dashboards/*.json examples/grafana/*.json; } | sort -u); do
  [[ $m =~ ^($allow)$ ]] || missing="$missing $m"
done
if [ -z "$missing" ]; then
  echo "ok   every kube_* metric the rules and dashboards read is allowed"
else
  echo "FAIL kube_* metrics missing from kube-state-metrics.metricAllowlist:$missing"
  failed=1
fi

echo "== Alertmanager configuration in $PROFILE"
yaml_block alertmanager config >"$tmp/alertmanager.yaml"
check "amtool check-config" amtool check-config alertmanager.yaml
routes() { # expected-receiver labels...
  local want=$1; shift
  check "route {$*} -> $want" amtool config routes test --config.file=alertmanager.yaml --verify.receivers="$want" "$@"
}
routes deadmans-switch alertname=Watchdog severity=none
routes null alertname=InfoInhibitor severity=none
routes platform alertname=KubePodCrashLooping severity=warning namespace=payments
routes platform-pager alertname=CertManagerCertificateExpiring severity=critical namespace=payments
routes team-payments alertname=KubesentryMemoryLeak severity=warning owner=payments
routes team-payments-pager alertname=KubesentryCrashLooping severity=critical owner=payments
routes platform-pager alertname=KubesentryCrashLooping severity=critical owner=unmapped-team
routes digest alertname=KubesentryUnusedVolume severity=critical owner=payments kubesentry_digest=true
# kubesentry's finding alerts (docs/alerts.md), as the server labels them.
routes team-payments-pager alertname=KubesentryWorkloadUnhealthy severity=critical owner=payments namespace=payments \
  workload=Deployment/api check=workload-unhealthy production=true
routes team-payments alertname=KubesentryCertificateExpiring severity=warning owner=payments namespace=payments \
  object=Certificate/api-tls check=cert-expiring production=false
routes platform-pager alertname=KubesentryRBACDrift severity=critical owner=platform object=ClusterRoleBinding/erin-admin check=cluster-admin
routes digest alertname=KubesentryFindingsDigest severity=warning owner=payments check=digest kubesentry_digest=true

if [ -n "$kps" ]; then
  echo "== kube-prometheus-stack ($kps) rendered with $PROFILE"
  helm template kps "$kps" --namespace monitoring --kube-version 1.33.0 -f "$PROFILE" >"$tmp/kps.yaml"
  # One rule file per PrometheusRule: their list indentation differs.
  mkdir -p "$tmp/kps"
  awk -v dir="$tmp/kps" '
    /^---/                       { keep = 0; spec = 0; next }
    /^kind: PrometheusRule$/     { keep = 1; n++ }
    keep && /^spec:$/            { spec = 1; next }
    keep && spec && /^[^ ]/      { spec = 0 }
    keep && spec                 { print substr($0, 3) > (dir "/rules-" n ".yaml") }
  ' "$tmp/kps.yaml"
  echo "     $(ls "$tmp"/kps | wc -l) PrometheusRule objects rendered"
  # The stock rules are kubernetes-mixin's, which records some names once per
  # status-code class on purpose (code_verb:apiserver_request_total:increase1h),
  # so promtool's duplicate-rule lint is off for them; ours are linted above.
  LINT=--lint=none check "promtool check rules (every rendered rule)" check_rules $(cd "$tmp" && ls kps/*.yaml)
  awk '/^kind: Secret$/ { s = 1 } /^---/ { s = 0 } s && /^  alertmanager.yaml: / { print $2 }' "$tmp/kps.yaml" \
    | tr -d '"' | base64 -d >"$tmp/kps-alertmanager.yaml"
  check "amtool check-config (rendered)" amtool check-config kps-alertmanager.yaml
fi

if [ "$failed" -ne 0 ]; then
  echo "rule checks FAILED"
  exit 1
fi
echo "rule checks passed"
