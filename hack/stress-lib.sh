#!/usr/bin/env bash
# Shared helpers for hack/stress-up.sh and hack/stress-run.sh. Source it.
STRESS_CLUSTER=${STRESS_CLUSTER:-kubesentry}
CTX=${CTX:-kind-$STRESS_CLUSTER}
LOADGEN_NODE=${LOADGEN_NODE:-$STRESS_CLUSTER-worker5}
CONTROL_PLANE=${CONTROL_PLANE:-$STRESS_CLUSTER-control-plane}
STRESS_RESULTS=${STRESS_RESULTS:-test/stress/results}
STRESS_BIN=${STRESS_BIN:-.kind/stress}
HOST_RESULTS=/var/lib/kubesentry-stress

k() { kubectl --context "$CTX" "$@"; }
log() { echo "$(date -u +%H:%M:%S) ==> $*" >&2; }

# build_stress_bin compiles the harness for the host.
build_stress_bin() {
  (cd test/stress && CGO_ENABLED=0 go build -o "../../$STRESS_BIN" ./cmd/stress)
}

# json_args prints its arguments as a JSON array (for a YAML flow sequence).
json_args() {
  local first=1 a
  printf '['
  for a in "$@"; do
    a=${a//\\/\\\\}
    a=${a//\"/\\\"}
    [ $first = 1 ] || printf ','
    printf '"%s"' "$a"
    first=0
  done
  printf ']'
}

guard_stopped() { [ -e "$STRESS_RESULTS/.guard-stop" ]; }

# run_job NAME RUN DEADLINE_SECONDS MEMORY_LIMIT ARGS...: runs the stress image
# as a Job on the load-generator node, streams its log to results/RUN/NAME.log
# and copies what it wrote under /results to results/RUN/. Returns the Job's result.
run_job() {
  local name=$1 run=$2 deadline=$3 mem=$4
  shift 4
  local dir=$STRESS_RESULTS/$run
  mkdir -p "$dir"
  k -n stress-load delete job "$name" --ignore-not-found --wait=true >/dev/null 2>&1
  k apply -f - >/dev/null <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: $name
  namespace: stress-load
  labels: {kubesentry.io/stress: "true", kubesentry.io/stress-load: "true"}
spec:
  backoffLimit: 0
  activeDeadlineSeconds: $deadline
  ttlSecondsAfterFinished: 86400
  template:
    metadata:
      labels: {kubesentry.io/stress: "true", kubesentry.io/stress-load: "true", stress-job: $name}
    spec:
      serviceAccountName: stress-runner
      restartPolicy: Never
      nodeSelector: {kubesentry.io/role: loadgen}
      tolerations:
        - {key: kubesentry.io/loadgen, operator: Exists, effect: NoSchedule}
      securityContext: {runAsUser: 0}
      containers:
        - name: stress
          image: kubesentry-stress:dev
          imagePullPolicy: Never
          args: $(json_args "$@")
          env:
            - {name: GOMEMLIMIT, value: "$(( ${mem%Mi} * 85 / 100 ))MiB"}
          resources:
            requests: {cpu: 200m, memory: 64Mi}
            limits: {memory: $mem}
          volumeMounts:
            - {name: results, mountPath: /results}
      volumes:
        - name: results
          hostPath: {path: $HOST_RESULTS/$run, type: DirectoryOrCreate}
EOF
  log "job $name: $*"
  k -n stress-load wait --for=condition=Ready pod -l stress-job="$name" --timeout=180s >/dev/null 2>&1 || true
  k -n stress-load logs -f "job/$name" >"$dir/$name.log" 2>&1 || true
  # The log stream can end early (container restart, API hiccup); wait for the Job itself.
  local i status=""
  for i in $(seq 1 "$deadline"); do
    status=$(k -n stress-load get job "$name" -o jsonpath='{.status.succeeded}/{.status.failed}' 2>/dev/null) || status="gone"
    case "$status" in
      1/*) break ;;
      */1) break ;;
      gone) break ;;
    esac
    guard_stopped && break
    sleep 1
  done
  k -n stress-load logs "job/$name" >"$dir/$name.log" 2>&1 || true
  docker exec "$LOADGEN_NODE" sh -c "test -d $HOST_RESULTS/$run" 2>/dev/null &&
    docker cp "$LOADGEN_NODE:$HOST_RESULTS/$run/." "$dir/" >/dev/null 2>&1
  tail -n 3 "$dir/$name.log" >&2
  [ "${status%%/*}" = 1 ]
}

kubesentry_restarts() {
  k -n kubesentry get pods -l app=kubesentry -o jsonpath='{range .items[*]}{.status.containerStatuses[0].restartCount}{"\n"}{end}' 2>/dev/null |
    awk '{s += $1} END {print s + 0}'
}

kubesentry_last_reason() {
  k -n kubesentry get pods -l app=kubesentry -o jsonpath='{.items[0].status.containerStatuses[0].lastState.terminated.reason}' 2>/dev/null
}

kubesentry_memory_limit() {
  k -n kubesentry get deploy kubesentry -o jsonpath='{.spec.template.spec.containers[0].resources.limits.memory}'
}

# step NAME RUN CMD...: runs CMD and appends a line to results/RUN/steps.tsv.
step() {
  local name=$1 run=$2
  shift 2
  local dir=$STRESS_RESULTS/$run
  mkdir -p "$dir"
  if guard_stopped; then
    log "guard stop file present ($STRESS_RESULTS/.guard-stop): skipping $name"
    return 1
  fi
  local start r0 rc
  [ "$name" = gen ] || wait_kubesentry
  start=$(date +%s)
  r0=$(kubesentry_restarts)
  log "step $name ($run)"
  "$@"
  rc=$?
  local status=ok
  [ $rc = 0 ] || status=failed
  guard_stopped && status=guard-stopped
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$start" "$(date +%s)" "$status" "$r0" "$(kubesentry_restarts)" "$(kubesentry_last_reason)" "limit=$(kubesentry_memory_limit)" >>"$dir/steps.tsv"
  log "step $name: $status ($(( $(date +%s) - start ))s)"
  return $rc
}

# reload_stress_image rebuilds the harness image and binary after harness changes.
reload_stress_image() {
  docker build -q -t kubesentry-stress:dev test/stress >/dev/null &&
    kind load docker-image --name "$STRESS_CLUSTER" --nodes "$LOADGEN_NODE" kubesentry-stress:dev >/dev/null &&
    build_stress_bin
}

# wait_kubesentry waits (up to 6 minutes) until the kubesentry pod is Ready, e.g.
# after OOM kills left it in CrashLoopBackOff.
wait_kubesentry() {
  local i
  for i in $(seq 1 72); do
    [ "$(k -n kubesentry get pods -l app=kubesentry -o jsonpath='{.items[0].status.containerStatuses[0].ready}' 2>/dev/null)" = true ] && return 0
    [ "$i" = 1 ] && log "waiting for kubesentry to become ready"
    sleep 5
  done
  log "kubesentry still not ready"
  return 1
}
