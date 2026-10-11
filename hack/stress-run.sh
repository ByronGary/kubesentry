#!/usr/bin/env bash
# Runs the stress test at one level (or all levels up to TOP_LEVEL, default L3):
# gen → settle → verify assoc → connectivity → users ramp → audit firehose →
# agents → report. Results go to test/stress/results/<variant>-<level>/.
#
#   hack/stress-run.sh L1 baseline
#   hack/stress-run.sh all after              # L1, L2, L3
#   STEPS="users report" hack/stress-run.sh L2 baseline
#
# Env:
#   STEPS          steps to run (default: gen verify conn users audit agents report)
#   TOP_LEVEL      highest level for "all" (default L3; L4 is defined but was not run)
#   USERS_STAGES   ramp (default 10:3m,50:3m,200:5m,500:5m,1000:5m,2000:5m)
#   USERS_1GI      1: at L2 and above, repeat the users ramp with a 1Gi memory limit (default 1)
#   AUDIT_EVENTS   (1000000), AUDIT_RATE (3000), AGENTS (500)
#   AUDIT_1GI      1: also run the firehose with a 1Gi limit, so queries over a full store can be timed (default 1)
#   SERIES_L1..L4  metrics-sim series per level (5000, 8000, 12000, 20000)
#   MAP_NAMESPACES generated namespaces the verifier maps besides stress-* (40; -1 all)
set -uo pipefail
cd "$(dirname "$0")/.."
source hack/stress-lib.sh

LEVEL=${1:-all}
VARIANT=${2:-baseline}
TOP_LEVEL=${TOP_LEVEL:-L3}
STEPS=${STEPS:-gen verify conn users audit agents report}
USERS_STAGES=${USERS_STAGES:-10:3m,50:3m,200:5m,500:5m,1000:5m,2000:5m}
USERS_1GI=${USERS_1GI:-1}
AUDIT_1GI=${AUDIT_1GI:-1}
AUDIT_EVENTS=${AUDIT_EVENTS:-1000000}
AUDIT_RATE=${AUDIT_RATE:-3000}
AGENTS=${AGENTS:-500}
MAP_NAMESPACES=${MAP_NAMESPACES:-40}
SHIPPED_LIMIT=${SHIPPED_LIMIT:-256Mi}

if [ "$LEVEL" = all ]; then
  for l in L1 L2 L3 L4; do
    "$0" "$l" "$VARIANT" || exit
    [ "$l" = "$TOP_LEVEL" ] && break
  done
  exit 0
fi

RUN=$VARIANT-$LEVEL
DIR=$STRESS_RESULTS/$RUN
mkdir -p "$DIR" .kind/stress-pids
build_stress_bin || exit 1

# The guard runs for the whole level.
if ! { [ -e .kind/stress-guard.pid ] && kill -0 "$(cat .kind/stress-guard.pid)" 2>/dev/null; }; then
  rm -f "$STRESS_RESULTS/.guard-stop"
  RESULTS=$STRESS_RESULTS hack/stress-guard.sh >/dev/null 2>&1 &
  GUARD_PID=$!
  trap 'kill $GUARD_PID 2>/dev/null' EXIT
fi
hack/stress-guard.sh --once >&2 || { log "below the memory threshold; not starting"; exit 1; }

has() { [[ " $STEPS " == *" $1 "* ]]; }
series_for() { local v="SERIES_$1"; echo "${!v:-$(case $1 in L1) echo 5000 ;; L2) echo 8000 ;; L3) echo 12000 ;; *) echo 20000 ;; esac)}"; }

do_gen() {
  k -n stress-load set env deployment/metrics-sim SERIES="$(series_for "$LEVEL")" >/dev/null
  "$STRESS_BIN" gen --level "$LEVEL" --out "$DIR" &
  local pid=$!
  echo "$pid" >.kind/stress-pids/gen.pid
  wait "$pid"
  local rc=$?
  rm -f .kind/stress-pids/gen.pid
  return $rc
}

set_limit() {
  local cur
  cur=$(kubesentry_memory_limit)
  [ "$cur" = "$1" ] && return 0
  log "kubesentry memory limit $cur → $1"
  k -n kubesentry set resources deployment/kubesentry --limits=memory="$1" >/dev/null
  k -n kubesentry rollout status deployment/kubesentry --timeout 5m
}

do_users() {
  local limit=$1
  set_limit "$limit" || return 1
  sleep 30 # let the new pod catch up with agents and the audit log
  run_job "users-$(echo "$limit" | tr 'A-Z' 'a-z')" "$RUN" 7200 1536Mi users --stages "$USERS_STAGES" --name "users-$limit"
}

has gen && step gen "$RUN" do_gen
has verify && step verify "$RUN" run_job verify "$RUN" 3600 1024Mi verify --out /results --map-namespaces "$MAP_NAMESPACES" --timeout 600s
has conn && step connectivity "$RUN" run_job connectivity "$RUN" 900 256Mi connectivity --out /results
if has users; then
  step "users-$SHIPPED_LIMIT" "$RUN" do_users "$SHIPPED_LIMIT"
  if [ "$USERS_1GI" = 1 ] && [ "$LEVEL" != L1 ]; then
    step users-1Gi "$RUN" do_users 1Gi
    set_limit "$SHIPPED_LIMIT"
  fi
fi
do_audit_1gi() {
  set_limit 1Gi || return 1
  sleep 30
  run_job audit-1gi "$RUN" 3600 512Mi audit --events "$AUDIT_EVENTS" --rate "$AUDIT_RATE" --level "$LEVEL" --name audit-1Gi
}

has audit && step audit "$RUN" run_job audit "$RUN" 3600 512Mi audit --events "$AUDIT_EVENTS" --rate "$AUDIT_RATE" --level "$LEVEL"
if has audit && [ "$AUDIT_1GI" = 1 ]; then
  step audit-1Gi "$RUN" do_audit_1gi
  set_limit "$SHIPPED_LIMIT"
fi
if has agents; then
  step agents "$RUN" run_job agents "$RUN" 1200 1024Mi agents --agents "$AGENTS" --duration 3m --name agents
  step agents-surge "$RUN" run_job agents-surge "$RUN" 1200 1024Mi agents --agents "$AGENTS" --surge --duration 2m --name agents-surge
fi
if has report; then
  docker cp "$LOADGEN_NODE:$HOST_RESULTS/metrics-sim-truth.json" "$DIR/" >/dev/null 2>&1 || true
  "$STRESS_BIN" report --dir "$DIR" --level "$LEVEL" --variant "$VARIANT" --memory-limit "$SHIPPED_LIMIT" && log "report: $DIR/report.md"
fi
