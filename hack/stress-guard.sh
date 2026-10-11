#!/usr/bin/env bash
# Host memory guard for the stress test. Docker Desktop's VM (15.6 GiB here)
# also runs the WSL distros and Docker Desktop's own Kubernetes, so a runaway
# load level could take the whole machine down.
#
# Every INTERVAL seconds it samples available memory (free -m, which on WSL2
# sees the whole VM) and the memory of the kind containers (docker stats) into
# a CSV. When available memory drops below MIN_MB it stops the load: deletes
# the load-generator Jobs and Deployments (label kubesentry.io/stress-load=true,
# all on the loadgen worker), kills host-side generator processes listed in
# .kind/stress-pids/, writes a STOP file that hack/stress-run.sh checks between
# steps, and records why in guard-events.log.
#
#   hack/stress-guard.sh            # run in the foreground (stress-run.sh starts it)
#   hack/stress-guard.sh --once     # one sample; exit 1 if below the threshold
#
# Env: INTERVAL (10), MIN_MB (1536), RESULTS (test/stress/results), CTX (kind-kubesentry)
set -uo pipefail
cd "$(dirname "$0")/.."

INTERVAL=${INTERVAL:-10}
MIN_MB=${MIN_MB:-1536}
RESULTS=${RESULTS:-test/stress/results}
CTX=${CTX:-kind-kubesentry}
ONCE=0
[ "${1:-}" = "--once" ] && ONCE=1

mkdir -p "$RESULTS" .kind/stress-pids
CSV=$RESULTS/guard.csv
EVENTS=$RESULTS/guard-events.log
STOP=$RESULTS/.guard-stop
[ -s "$CSV" ] || echo "epoch,time,mem_total_mb,mem_available_mb,swap_used_mb,kind_containers_mb,all_containers_mb,docker_total_mb" >"$CSV"

docker_total_mb=$(( $(docker info --format '{{.MemTotal}}' 2>/dev/null || echo 0) / 1048576 ))

# docker stats prints e.g. "1.267GiB / 15.58GiB"; sum the kind node containers and all containers in MiB.
container_mem() {
  docker stats --no-stream --format '{{.Name}} {{.MemUsage}}' 2>/dev/null | awk '
    function mib(v) {
      if (v ~ /GiB$/) { sub(/GiB$/, "", v); return v * 1024 }
      if (v ~ /MiB$/) { sub(/MiB$/, "", v); return v }
      if (v ~ /KiB$/) { sub(/KiB$/, "", v); return v / 1024 }
      if (v ~ /kB$/)  { sub(/kB$/, "", v);  return v / 1024 }
      if (v ~ /GB$/)  { sub(/GB$/, "", v);  return v * 1000 }
      if (v ~ /MB$/)  { sub(/MB$/, "", v);  return v }
      sub(/B$/, "", v); return v / 1048576
    }
    { m = mib($2); all += m; if ($1 ~ /^kubesentry-/) kind += m }
    END { printf "%d %d\n", kind, all }'
}

sample() {
  read -r total avail swap < <(free -m | awk '/^Mem:/ {t=$2; a=$7} /^Swap:/ {s=$3} END {print t, a, s}')
  read -r kind all < <(container_mem)
  echo "$(date +%s),$(date -u +%FT%TZ),$total,$avail,$swap,${kind:-0},${all:-0},$docker_total_mb" >>"$CSV"
  AVAIL=$avail
  LINE="available ${avail} MiB of ${total} MiB, swap used ${swap} MiB, kind containers ${kind:-?} MiB, all containers ${all:-?} MiB"
}

stop_load() {
  local why="$1"
  echo "$(date -u +%FT%TZ) STOP: $why" | tee -a "$EVENTS" >&2
  touch "$STOP"
  kubectl --context "$CTX" delete jobs,deployments -A -l kubesentry.io/stress-load=true --wait=false 2>&1 | sed 's/^/  /' | tee -a "$EVENTS" >&2
  for f in .kind/stress-pids/*.pid; do
    [ -e "$f" ] || continue
    pid=$(cat "$f")
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" && echo "  killed host process $pid ($(basename "$f" .pid))" | tee -a "$EVENTS" >&2
    fi
    rm -f "$f"
  done
}

if [ "$ONCE" = 1 ]; then
  sample
  echo "$LINE (threshold ${MIN_MB} MiB)"
  [ "$AVAIL" -ge "$MIN_MB" ]
  exit
fi

echo "$(date -u +%FT%TZ) guard started (pid $$, threshold ${MIN_MB} MiB, every ${INTERVAL}s)" >>"$EVENTS"
echo $$ >.kind/stress-guard.pid
last_stop=0
while true; do
  sample
  if [ "$AVAIL" -lt "$MIN_MB" ] && [ $(( $(date +%s) - last_stop )) -ge 60 ]; then
    stop_load "$LINE"
    last_stop=$(date +%s)
  fi
  sleep "$INTERVAL"
done
