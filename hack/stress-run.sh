#!/usr/bin/env bash
# Runs the stress test at one level (or all levels up to TOP_LEVEL, default L3):
# gen → settle → verify assoc → connectivity → users ramp → audit firehose →
# agents → report. Results go to test/stress/results/<variant>-<level>/.
#
#   hack/stress-run.sh L1 baseline
#   hack/stress-run.sh L3 after               # after VARIANT=after hack/stress-up.sh
#   STEPS="users report" hack/stress-run.sh L2 baseline
#
# The after variant talks to the chart's Services (web through oauth2-proxy on
# 4180 with JWT personas, ingest on 8081, ops on 9090) and adds the steps
# authz (verify authz), cloudwatch (every cwfake event in Postgres once) and
# chaos (the smoke set, host side). It also runs hack/cluster-cautions.py for
# the whole level into results/cautions-<variant>/ (CAUTIONS=0 to skip).
#
# Phase 4 (after) adds the steps soak (users, firehose and agents together for
# SOAK_FOR, with a Postgres sampler and soak-report), storm (the RBAC storm with
# verify authz running during and after) and coldrestart (both replicas deleted
# under 500 users). After users, audit, agents and chaos steps it records
# server-side metrics (stress server-metrics) while Prometheus still has them.
#
# Env:
#   STEPS          steps to run, in this order (default: gen verify conn users audit agents report;
#                  after: gen verify authz conn users audit cloudwatch agents chaos report;
#                  also: soak storm coldrestart)
#   CHAOS_SCENARIOS (after) spoof,oversize,prometheus,postgres,apiserver,killreplica,standby;
#                  Phase 4 adds workerstop,drain,churn,rollout,nsdelete (rbacstorm and
#                  coldrestart run as their own steps)
#   CHAOS_NAME     result name for the chaos step (chaos-<name>.json; default chaos.json)
#   VERIFY_NAME    result names for verify and authz (assoc-<name>.json, authz-<name>.json)
#   SOAK_FOR       soak duration (2h), SOAK_USERS (500), SOAK_AUDIT_RATE (300/s)
#   USERS_PERSONAS (after) distinct JWT identities the virtual users cycle through (2000)
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
if [ "$VARIANT" = after ]; then
  STEPS=${STEPS:-gen verify authz conn users audit cloudwatch agents chaos report}
  USERS_1GI=${USERS_1GI:-0}
  AUDIT_1GI=${AUDIT_1GI:-0}
  SHIPPED_LIMIT=${SHIPPED_LIMIT:-1Gi}
  KS=(--base http://kubesentry.kubesentry.svc:4180 --auth jwt --ingest http://kubesentry-ingest.kubesentry.svc:8081)
  CONN_EXTRA=(--kubesentry-svc kubesentry.kubesentry.svc.cluster.local:4180 --ops http://kubesentry-ops.kubesentry.svc:9090)
  # Every virtual user is a distinct identity (persona i; the 5/15/80 mix),
  # so authorization reviews and their cache scale as with real users.
  USERS_EXTRA=(--ui after --level "${1:-L3}" --personas "${USERS_PERSONAS:-2000}")
  AGENTS_EXTRA=(--fanout kubesentry-ingest-headless.kubesentry.svc --gzip)
else
  STEPS=${STEPS:-gen verify conn users audit agents report}
  KS=()
  CONN_EXTRA=()
  USERS_EXTRA=()
  AGENTS_EXTRA=()
fi
CHAOS_SCENARIOS=${CHAOS_SCENARIOS:-spoof,oversize,prometheus,postgres,apiserver,killreplica,standby}
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

# The guard (and the cautions collector) run for the whole level.
GUARD_PID="" CAUTIONS_PID=""
cleanup() {
  [ -z "$GUARD_PID" ] || kill "$GUARD_PID" 2>/dev/null
  if [ -n "$CAUTIONS_PID" ]; then
    kill "$CAUTIONS_PID" 2>/dev/null
    python3 hack/cluster-cautions.py --summarize "$STRESS_RESULTS/cautions-$VARIANT" >"$STRESS_RESULTS/cautions-$VARIANT/cautions.md" 2>/dev/null
  fi
}
trap cleanup EXIT
if ! { [ -e .kind/stress-guard.pid ] && kill -0 "$(cat .kind/stress-guard.pid)" 2>/dev/null; }; then
  rm -f "$STRESS_RESULTS/.guard-stop"
  RESULTS=$STRESS_RESULTS hack/stress-guard.sh >/dev/null 2>&1 &
  GUARD_PID=$!
fi
if [ "${CAUTIONS:-1}" = 1 ] && ! { [ -e .kind/cautions.pid ] && kill -0 "$(cat .kind/cautions.pid)" 2>/dev/null; }; then
  mkdir -p "$STRESS_RESULTS/cautions-$VARIANT"
  nice -n 19 python3 hack/cluster-cautions.py --context "$CTX" --out "$STRESS_RESULTS/cautions-$VARIANT" --label "$LEVEL" --every 300 \
    >>"$STRESS_RESULTS/cautions-$VARIANT/collector.log" 2>&1 &
  CAUTIONS_PID=$!
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
  local limit=$1 rc
  set_limit "$limit" || return 1
  sleep 30 # let the new pod catch up with agents and the audit log
  run_job "users-$(echo "$limit" | tr 'A-Z' 'a-z')" "$RUN" 7200 1536Mi users --stages "$USERS_STAGES" --name "users-$limit" "${KS[@]}" "${USERS_EXTRA[@]}"
  rc=$?
  server_metrics --users "users-$limit.json"
  return $rc
}

# server_metrics records kubesentry's, Postgres' and oauth2-proxy's numbers
# for windows of this run (stress server-metrics) while Prometheus has them.
server_metrics() {
  [ "$VARIANT" = after ] || return 0
  "$STRESS_BIN" server-metrics --context "$CTX" --dir "$DIR" "$@" >>"$DIR/server-metrics.log" 2>&1 ||
    log "server-metrics $*: failed (see server-metrics.log)"
}

# pg_sample prints one CSV line: time, database size, audit partitions, estimated audit rows.
pg_sample() {
  k -n stress-pg exec postgres-0 -- psql -U kubesentry -d kubesentry -At -F, -c \
    "select to_char(now() at time zone 'utc', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), pg_database_size('kubesentry'),
       (select count(*) from pg_inherits where inhparent = 'kubesentry.audit_events'::regclass),
       (select coalesce(sum(c.reltuples), 0)::bigint from pg_inherits i join pg_class c on c.oid = i.inhrelid
          where i.inhparent = 'kubesentry.audit_events'::regclass)" 2>/dev/null
}

secs_of() { # 2h, 90m, 300s → seconds
  case $1 in *h) echo $(( ${1%h} * 3600 )) ;; *m) echo $(( ${1%m} * 60 )) ;; *s) echo "${1%s}" ;; *) echo "$1" ;; esac
}

# do_soak: SOAK_USERS users, a background audit firehose at SOAK_AUDIT_RATE and
# 500 staggered agents together for SOAK_FOR, with Postgres sampled every 5 minutes.
do_soak() {
  local dur=${SOAK_FOR:-2h} users=${SOAK_USERS:-500} rate=${SOAK_AUDIT_RATE:-300} secs r0 sampler upid apid gpid rc=0
  secs=$(secs_of "$dur")
  r0=$(kubesentry_restarts)
  ( while true; do pg_sample >>"$DIR/pg-soak.csv"; sleep 300; done ) &
  sampler=$!
  echo "$sampler" >.kind/stress-pids/pg-sampler.pid
  run_job audit-soak "$RUN" $((secs + 1800)) 512Mi audit --events $((rate * secs)) --rate "$rate" --level "$LEVEL" --name audit-soak \
    --max-run "$((secs + 300))s" --query-reps 10 "${KS[@]}" &
  apid=$!
  run_job agents-soak "$RUN" $((secs + 1200)) 1024Mi agents --agents "$AGENTS" --duration "${secs}s" --name agents-soak "${KS[@]}" "${AGENTS_EXTRA[@]}" &
  gpid=$!
  sleep 20
  run_job users-soak "$RUN" $((secs + 1800)) 1536Mi users --stages "$users:${secs}s" --name users-soak "${KS[@]}" "${USERS_EXTRA[@]}" || rc=1
  wait "$apid" || rc=1
  wait "$gpid" || rc=1
  pg_sample >>"$DIR/pg-soak.csv"
  kill "$sampler" 2>/dev/null
  rm -f .kind/stress-pids/pg-sampler.pid
  "$STRESS_BIN" soak-report --context "$CTX" --dir "$DIR" --restarts "$(( $(kubesentry_restarts) - r0 )) ($(kubesentry_last_reason))" ||
    log "soak-report failed"
  server_metrics --users users-soak.json
  return $rc
}

# do_storm: the RBAC storm (stress chaos rbacstorm) with verify authz running
# back to back during it, then once more afterwards.
do_storm() {
  local vpid rc
  (for i in 1 2 3; do
    run_job "authz-storm-$i" "$RUN" 1800 512Mi verify authz --out /results --level "$LEVEL" --timeout 300s --name "authz-during-storm-$i" "${KS[@]}"
  done) &
  vpid=$!
  sleep 10
  # shellcheck disable=SC2046
  "$STRESS_BIN" chaos --context "$CTX" --out "$DIR" --scenarios rbacstorm --name chaos-storm --level "$LEVEL" $(cw_args | sed 's/--start/--cw-start/')
  rc=$?
  wait "$vpid"
  run_job authz-after-storm "$RUN" 1800 512Mi verify authz --out /results --level "$LEVEL" --timeout 300s --name authz-after-storm "${KS[@]}" || rc=1
  server_metrics --chaos chaos-storm.json
  return $rc
}

# do_cold: both replicas deleted while 500 users run (stress chaos coldrestart).
do_cold() {
  local upid rc
  run_job users-cold "$RUN" 2400 1536Mi users --stages 500:15m --name users-cold "${KS[@]}" "${USERS_EXTRA[@]}" &
  upid=$!
  sleep 300
  # shellcheck disable=SC2046
  "$STRESS_BIN" chaos --context "$CTX" --out "$DIR" --scenarios coldrestart --name chaos-cold --users-file "$DIR/users-cold.json" \
    $(cw_args | sed 's/--start/--cw-start/')
  rc=$?
  wait "$upid"
  server_metrics --chaos chaos-cold.json
  server_metrics --users users-cold.json
  return $rc
}

# cwfake's options, read from its Deployment, for the CloudWatch checks.
cw_args() {
  local e
  e=$(k -n stress-cw get deploy cwfake -o jsonpath='{range .spec.template.spec.containers[0].env[*]}{.name}={.value}{" "}{end}')
  local start events rate seed
  for kv in $e; do
    case $kv in START=*) start=${kv#START=} ;; EVENTS=*) events=${kv#EVENTS=} ;; RATE=*) rate=${kv#RATE=} ;; SEED=*) seed=${kv#SEED=} ;; esac
  done
  echo "--start $start --events ${events:-1000000} --rate ${rate:-500} --seed ${seed:-2026}"
}

VN=${VERIFY_NAME:+-$VERIFY_NAME}
has gen && step gen "$RUN" do_gen
has verify && step "verify$VN" "$RUN" run_job "verify$VN" "$RUN" 3600 1024Mi verify --out /results --map-namespaces "$MAP_NAMESPACES" --timeout 600s --name "assoc$VN" "${KS[@]}"
has authz && step "authz$VN" "$RUN" run_job "verify-authz$VN" "$RUN" 3600 512Mi verify authz --out /results --level "$LEVEL" --timeout 300s --name "authz$VN" "${KS[@]}"
has conn && step connectivity "$RUN" run_job connectivity "$RUN" 900 256Mi connectivity --out /results "${KS[@]}" "${CONN_EXTRA[@]}"
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

if has audit; then
  step audit "$RUN" run_job audit "$RUN" 3600 512Mi audit --events "$AUDIT_EVENTS" --rate "$AUDIT_RATE" --level "$LEVEL" "${KS[@]}"
  server_metrics --steps audit --name audit
fi
if has audit && [ "$AUDIT_1GI" = 1 ]; then
  step audit-1Gi "$RUN" do_audit_1gi
  set_limit "$SHIPPED_LIMIT"
fi
# The CloudWatch check (every cwfake event stored once, live-tail lag) runs
# after the webhook firehose, so the lag is measured with the store loaded.
# shellcheck disable=SC2046
has cloudwatch && step cloudwatch "$RUN" "$STRESS_BIN" verify-cloudwatch --context "$CTX" --out "$DIR" $(cw_args)
if has agents; then
  step agents "$RUN" run_job agents "$RUN" 1200 1024Mi agents --agents "$AGENTS" --duration 3m --name agents "${KS[@]}" "${AGENTS_EXTRA[@]}"
  step agents-surge "$RUN" run_job agents-surge "$RUN" 1200 1024Mi agents --agents "$AGENTS" --surge --duration 2m --name agents-surge "${KS[@]}" "${AGENTS_EXTRA[@]}"
  server_metrics --steps agents,agents-surge --name agents
fi
has soak && step soak "$RUN" do_soak
has storm && step storm "$RUN" do_storm
has coldrestart && step coldrestart "$RUN" do_cold
if has chaos; then
  CN=${CHAOS_NAME:+-$CHAOS_NAME}
  # shellcheck disable=SC2046
  step "chaos$CN" "$RUN" "$STRESS_BIN" chaos --context "$CTX" --out "$DIR" --scenarios "$CHAOS_SCENARIOS" --name "chaos$CN" --level "$LEVEL" $(cw_args | sed 's/--start/--cw-start/')
  server_metrics --chaos "chaos$CN.json"
fi
if has report; then
  docker cp "$LOADGEN_NODE:$HOST_RESULTS/metrics-sim-truth.json" "$DIR/" >/dev/null 2>&1 || true
  "$STRESS_BIN" report --dir "$DIR" --level "$LEVEL" --variant "$VARIANT" --memory-limit "$SHIPPED_LIMIT" && log "report: $DIR/report.md"
fi
