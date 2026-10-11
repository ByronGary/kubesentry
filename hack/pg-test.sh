#!/usr/bin/env bash
# Starts a throwaway Postgres 17 for the internal/pgstore tests and prints the
# DSN to export. Data lives on tmpfs, so nothing survives `hack/pg-test.sh stop`.
#
#   eval "$(hack/pg-test.sh)"      # start (or reuse) and export KUBESENTRY_TEST_PG_DSN
#   go test ./internal/pgstore/...
#   hack/pg-test.sh stop           # remove the container
#
# PG_TEST_NAME (kubesentry-pg-test, the container), PG_TEST_PORT (55432), PG_TEST_IMAGE (postgres:17), PG_TEST_TMPFS (2g, the data
# volume) and PG_TEST_MEMORY (3g: tmpfs pages count against the container's
# memory limit, so it must exceed the tmpfs size; it is a cap, not a reservation)
# override the defaults.
#
# For data sets larger than memory (TestPGConcurrentLoad's millions of events),
# PG_TEST_VOLUME=<docker volume> keeps the data on disk in that volume instead
# of tmpfs; it survives `stop` (remove it with `docker volume rm`). PG_TEST_CPUS
# caps the CPUs (docker --cpus) and PG_TEST_SHARED_BUFFERS (64MB) sizes the
# buffer cache.
set -euo pipefail

NAME=${PG_TEST_NAME:-kubesentry-pg-test}
PORT=${PG_TEST_PORT:-55432}
IMAGE=${PG_TEST_IMAGE:-postgres:17}
TMPFS=${PG_TEST_TMPFS:-2g}
MEMORY=${PG_TEST_MEMORY:-3g}
VOLUME=${PG_TEST_VOLUME:-}
CPUS=${PG_TEST_CPUS:-}
SHARED_BUFFERS=${PG_TEST_SHARED_BUFFERS:-64MB}
PASSWORD=kubesentry
DSN="postgres://postgres:${PASSWORD}@127.0.0.1:${PORT}/postgres?sslmode=disable"

command -v docker >/dev/null || { echo "missing tool: docker" >&2; exit 1; }

case "${1:-start}" in
stop)
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  echo "removed $NAME" >&2
  exit 0
  ;;
start) ;;
*)
  echo "usage: $0 [start|stop]" >&2
  exit 2
  ;;
esac

if [ "$(docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null || true)" != "true" ]; then
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  echo "starting $IMAGE as $NAME on 127.0.0.1:$PORT" >&2
  # Small and disposable: tmpfs data, no fsync, modest buffers, low CPU weight
  # so it shares the machine politely with other work.
  data=(--tmpfs "/var/lib/postgresql/data:rw,size=${TMPFS}")
  if [ -n "$VOLUME" ]; then
    data=(-v "${VOLUME}:/var/lib/postgresql/data")
  fi
  cpus=()
  if [ -n "$CPUS" ]; then
    cpus=(--cpus "$CPUS")
  fi
  docker run -d --name "$NAME" \
    -p "127.0.0.1:${PORT}:5432" \
    -e POSTGRES_PASSWORD="$PASSWORD" \
    "${data[@]}" \
    --memory "$MEMORY" --cpu-shares 256 "${cpus[@]}" \
    --shm-size 128m \
    "$IMAGE" \
    -c shared_buffers="$SHARED_BUFFERS" -c work_mem=8MB -c maintenance_work_mem=64MB \
    -c fsync=off -c synchronous_commit=off -c full_page_writes=off \
    -c max_connections=100 -c max_wal_size=256MB -c min_wal_size=64MB >/dev/null
fi

for _ in $(seq 1 60); do
  if docker exec "$NAME" pg_isready -U postgres -h 127.0.0.1 >/dev/null 2>&1 &&
     docker exec "$NAME" psql -U postgres -h 127.0.0.1 -tAc 'select 1' >/dev/null 2>&1; then
    echo "export KUBESENTRY_TEST_PG_DSN='${DSN}'"
    exit 0
  fi
  sleep 1
done
echo "postgres did not become ready; see: docker logs $NAME" >&2
exit 1
