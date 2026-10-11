# Checkpoint D: the new build at L3

Run 2026-10-11, 18:44–21:18 UTC, on the L3 cluster (500 KWOK nodes, ~10,000 pods, 160 namespaces) after the baseline. kubesentry is master at 61e3d75, installed with the Helm chart (`deploy/kind/values-kind.yaml` + `test/stress/deploy/values-after.yaml`).

**Configuration under test:**
- two replicas, 1Gi each (GOMEMLIMIT 90%)
- Postgres 17 audit store (`stress-pg`, on worker2)
- `auth.mode: proxy` with the oauth2-proxy sidecar reaching kubesentry over the Unix socket
- virtual users sign in with RS256 JWTs from the harness's test issuer (`stress oidc`)
- agents fanning out to both replicas through the headless ingest Service
- Prometheus found by discovery
- the CloudWatch reader pointed at cwfake
- file tail of the API server audit log (`fromStart: false`)

## Results

| Item | Result | Numbers |
|---|---|---|
| Deploy with the chart (kustomize → Helm switch) | pass | Both replicas Ready. Informer cache synced in 1.3s with `unavailable=map[]`: the chart's ClusterRole covers everything the cache watches (endpointslices, replicasets, RBAC objects, cert-manager, create subjectaccessreviews). No chart change was needed |
| verify assoc | **pass, 42/42** | Map, all 173 namespaces: pod→owner, service→pods, pod→node, pod→PVC, CronJob→Job and Ingress→Service all at 100% precision and recall. Security grouping 100%/100%. Workload pod counts 2,496/2,496 exact. Node view pod→owner precision 99.9% (bug 2). The whole verifier took 14s, with map calls at 43 ms average; at baseline L3 it took 304s, with each map call at 5.8s |
| verify authz | **pass, 0 leaks** | 15 personas: 2 admins, 3 cluster viewers, 8 team members (1 namespace each, some with process and audit grants), 1 user in 300 groups, 1 with no grants. Every list route paged through as each (pods, workloads, storage, security and its summary, map default/visible/hidden, certificates, pvcs/unused, two audit-events variants, audit summary, nodes and its summary, oom, agents, `/info` capabilities): ~200k items checked, 0 outside scope, 0 other problems. The no-grants user got empty lists and an empty audit summary. Users without the nodes, PVs or storage-classes capabilities saw only nodes, volumes and classes behind their own pods and claims. The hidden-namespace map answered 404 |
| Connectivity | **pass, 120/120** | pod→pod (6×12), pod→ClusterIP, Service DNS, the web Service (oauth2-proxy `/ping`) and the ingest Service from every real node, on both pod and host network. Admin JWT → `/api/v1/info` gives identity `proxy`, `admin0@corp.example`, all capabilities. No credentials → 401. Forged `X-Forwarded-Email` without a token → 401. Ops `/readyz` 200 with 336 `kubesentry_*` metric lines. Snapshot age 1.5s, audit store postgres, Prometheus discovered. Prometheus targets: kubesentry-ops 2/2 up. The fake-node kube-proxy targets are gone after the kps-values relabel. Agents fresh on 6/6 real nodes |
| CloudWatch (cwfake) | **pass** | 1,000,000 events (0.5% logged twice, 1% delivered 3 min late) stored exactly once: 0 missing, 0 duplicated. Live tail at 300 events/s lags 31–47s (target < 60s). The chaos lock moves found 2,105,643 and then 2,196,812 events, again complete with no duplicates |
| Chaos: spoof | pass | Port-forward straight to a server pod: 8080 has no listener. 4180 (oauth2-proxy) with forged headers and no token → 401. With forged headers plus a real token for `nobody` → identity `nobody`, every capability false. 8081 and 9090 → 404 for `/api/v1/pods` |
| Chaos: oversized agent reports | pass | 9 MiB body → 413; 25,000 processes → 413; gzip bomb (65 KB inflating to 64 MiB) → 413; `Content-Encoding: br` → 415. Both replicas stayed ready |
| Chaos: Prometheus down, then up | pass | While down: `/oom` 200 with "leak detection unavailable", `/pods` 200, both `/readyz` 200. Metrics back 21s after Prometheus returned |
| Chaos: Postgres down 2 min under a 1,000 events/s webhook firehose | pass | Queue grew to its 50,000 cap, then 72 answers of 503 + Retry-After; the firehose retried 7 batches and gave none up. 229,905 distinct accepted events, all stored exactly once (0 missing, 0 duplicated). `/readyz` stayed 200 with `degraded.postgres` throughout |
| Chaos: API server restart | pass (with a caution) | API server down 4–7s. kubesentry answered every probe (200), snapshot age at most 6s, fresh again at once. **Caution:** right after the restart both replicas logged "forbidden" watch errors for about 1s (24 lines, e.g. `jobs.batch is forbidden: User "system:serviceaccount:kubesentry:kubesentry" cannot watch`) while the API server's RBAC caches warmed up. It recovered by itself |
| Chaos: kill the CloudWatch leader | pass | Leader found from `pg_locks`. The Deployment's replacement pod took the lock 2.6s after the delete (the old leader releases on SIGTERM). Agents on the survivor stayed 6→6, 6 fresh after. 0 web errors. CloudWatch complete |
| Chaos: standby takeover (no replacement) | pass | Leader marked `pod-deletion-cost=-1000`, Deployment scaled to 1. The standby took the lock in 5.1s (limit 45s). Agents 6→6, CloudWatch complete. Scaled back to 2 |
| Users ramp 10 → 200 → 500 (JWT personas through oauth2-proxy) | pass (no abort), but see bug 1 | Error rate 0% / 0.18% / 0.49%. 0 restarts. kubesentry memory at most 1,050 MiB summed over both replicas (about 525 MiB each). 0 LISTs to the API server. SubjectAccessReviews ran at 1.4, 28.7 and 31.8 per second at 10, 200 and 500 users (102 distinct identities, 5 min cache). Postgres CPU up to 7.3 cores |

Earlier attempts are kept for the record: `chaos.md` (first run; killreplica failed on the expectation that has since been fixed), `chaos-lockmove.md` (both lock-move variants) and `chaos-rerun.md` (spoof, oversize and apiserver, with the corrected spoof labels).

### Users ramp at 500 users, by route (all requests; ms)

| Route | n | p50 | p95 | p99 | errors |
|---|---:|---:|---:|---:|---|
| pods (first page, limit 1000) | 666 | 4 | 23 | 57 | 0 |
| pods (next pages) | 1,035 | 4 | 11 | 25 | 0 |
| workloads (first page) | 708 | 3 | 11 | 19 | 0 |
| security?view=summary | 2,592 | 5 | 17 | 35 | 0 |
| oom?window=24h | 2,225 | 4 | 13 | 30 | 0 |
| pvcs/unused | 2,225 | 4 | 13 | 26 | 0 |
| certificates | 2,383 | 4 | 14 | 31 | 0 |
| map | 503 | 4 | 11 | 23 | 0 |
| nodes?summary=true | 223 | 7 | 17 | 35 | 0 |
| storage (first page) | 198 | 3 | 19 | 33 | 0 |
| processes | 1,688 | 2 | 8 | 18 | 0 (2 × 404: pod gone) |
| **diagnostics** | 1,691 | 288 | **15,411** | 20,741 | 0 (9 × 404: pod gone) |
| **info** (every user every 30s) | 4,939 | 3 | **9,968** | 18,786 | 0 |
| **audit/summary** | 347 | **6,979** | 19,935 | 26,830 | 0.6% (502) |
| **audit/events** | 1,464 | **8,508** | **30,014** | 30,014 | **7.7%** (95 × 502 at oauth2-proxy's 30s upstream timeout, 17 × 503) |

At 10 users every route but `audit/summary` (p50 3.4s) and `/info` (p95 1.5s) answered in under 20 ms. The inventory routes clear the Phase 4 targets at 500 users (p95 < 300 ms, p99 < 1s). The audit-backed routes do not: the target is audit query p95 < 500 ms.

## kubesentry bugs found

1. **Postgres audit queries collapse under concurrent users (performance, significant).**
   - **Where:** `internal/pgstore/query.go:296` (Coverage) and `internal/pgstore/query.go:150` (Summarize).
   - **Coverage:** runs `SELECT min(time), max(time), count(*) FROM audit_events` (834 ms on 3.4M rows here). It is needed for every `/info`, which the UI polls every 30s per user, and sits behind a 30s TTL without singleflight, so concurrent misses stampede.
   - **Summarize:** takes 1.5s cluster-wide for 24h and is cached per scope key, so each team user's scope runs its own.
   - **Effect at 500 users:** Postgres reaches 7.3 CPU cores. `/info` p95 is 10s, `audit/summary` p50 7s, `audit/events` p50 8.5s with p95 at the 30s oauth2-proxy timeout (7.7% errors), and pod diagnostics p95 15s (pod activity reads the same store).
   - **Repro:** `kubectl -n stress-pg exec postgres-0 -- psql -U kubesentry -d kubesentry -c '\timing' -c 'SELECT min(time), max(time), count(*) FROM kubesentry.audit_events'`. Or the ramp: `STEPS=users USERS_STAGES=10:3m,200:5m,500:5m hack/stress-run.sh L3 after`.
   - **Suggestions:** singleflight on both. For coverage, an estimate (`pg_class.reltuples`, or per-partition counts kept by the maintenance job) instead of `count(*)`. For the summary, a longer TTL or a pre-aggregated table.
2. **Mirror (static) pods show the Node as their workload (minor).**
   - **Where:** `internal/detectors/assoc.go:672`, `WorkloadOf` does not skip `KindNode`. The map (`topology.go:93`) and security grouping (`rootOf`) do.
   - **Repro:** `GET /api/v1/nodes` lists `stress-tricky/static-web-kubesentry-worker` (and `kube-system/etcd-…`, `kube-apiserver-…` and the other static pods) with `"workload": "Node/<node>"`. The pods route's `workload` field follows the same function.
3. **Chart: oauth2-proxy settings (minor).**
   - **Upstream timeout:** oauth2-proxy's default `--upstream-timeout` (30s) turns any slower `/api` request into 502. That is where bug 1's 502s come from. The chart could set it to match kubesentry's route timeouts.
   - **Trusted proxy IPs:** the sidecar runs `--reverse-proxy=true` without `--trusted-proxy-ip`, and oauth2-proxy warns that it trusts X-Forwarded-* from any client. Identity headers are not affected (they are stripped and set by the proxy, and the spoof test confirms it). X-Forwarded-For/Host/Proto are, so the chart should expose `trustedProxyIPs` for the ALB subnets.
4. **Possible, not reproduced: a stale CloudWatch lag gauge.**
   - **Where:** `cmd/server/audit.go:115`. `kubesentry_cloudwatch_lag_seconds` is computed from `cw.cur`, which `lead()` clears only after `r.Run` returns.
   - **Risk:** if `Run` blocks after the lock is lost (e.g. writing while Postgres is down), the old leader keeps reporting lag > 0.
   - **Evidence:** in the first chaos run (right after the Postgres outage), the lag-based leader pick was ambiguous. In the two lock-move runs, with pg_locks as the source of truth, no replica without the lock showed lag > 0.
5. **Observation, not a bug:** a Prometheus outage shows only in `/oom` warnings. `/readyz` and `/info` (`unavailable`) say nothing about it. It is worth a UI banner.

## Cluster cautions during the run
From `cautions-after/cautions.md`: 24 snapshots, 19:06–21:17. The collector is still running.

**Real cautions:**
- **PrometheusMissingRuleEvaluations:** pending in 22 of 24 snapshots (36 rule groups).
- **KubesentryPostgresErrors:** pending during the Postgres outage. The chart's PrometheusRule works.
- **KubeAPIErrorBudgetBurn:** pending 19:23–19:46, around the API server restart.
- **KubeClientErrors and PrometheusKubernetesListWatchFailures:** once each, at the API server restart.
- **NodeDiskIOSaturation:** once, during the 500-user stage.
- **NodeClockNotSynchronising:** once.
- **cert-manager:** still failing its liveness probe (8,151 Unhealthy events, 5 restarts).
- **Certificates:** 117 expiring within 14 days; 9 not ready (missing issuers, planted).
- **Planted workload faults:** crashloop (66 restarts), ImagePullBackOff and Unschedulable, as designed.
- **leaky:** at 97% of its memory limit.

**Control plane:**
- API read p99 up to 697 ms (at the restart), write p99 99 ms, etcd p99 86 ms.
- API server 429s 0.01/s at peak, 5xx 0.14/s (the restart).
- Real nodes went down to 24% memory available. The host guard's lowest reading was 3,050 MiB available (during the 500-user stage), and it never had to stop anything.

The kind artifacts are the same as at baseline: etcd, scheduler and controller-manager metrics bound to localhost, and kube-proxy on the 6 real nodes (127.0.0.1).

## What changed for checkpoint D (no product code, no commits)
- **Chart:** nothing. RBAC was complete.
- **`test/stress/deploy/`:**
  - `values-after.yaml`: the stress overlay.
  - `postgres.yaml`: Postgres 17.
  - `oidc.yaml`: the test issuer, HTTPS with a self-signed certificate, because the chart's schema requires an https issuer; oauth2-proxy gets `--ssl-insecure-skip-verify`.
  - `cwfake.yaml`: cwfake.
- **`test/stress/kind/kps-values.yaml`:** a kube-proxy relabel drops the 172.19.100.0/22 targets; re-applied with kube-prometheus-stack 92.3.0.
- **`hack/stress-up.sh`:** `VARIANT=after` path:
  - re-applies kube-prometheus-stack with kps-values at the pinned version
  - deploys Postgres, the issuer, cwfake and the secrets
  - builds the images from this tree (`BUILD_IMAGES`)
  - switches kustomize → Helm and installs with both values files
  - applies the persona RBAC

  The harness image now builds from the repository root (it hosts cwfake).
- **`hack/stress-run.sh`:** `after` variant:
  - the chart's Services: web on 4180 with JWT, ingest on 8081, ops on 9090
  - new steps `authz`, `cloudwatch` and `chaos`
  - the cautions collector for the whole level, summarized at exit
- **`hack/stress-lib.sh`:** helpers find the server by the chart's labels and the `server` container.
- **Harness, new packages:**
  - `oidc`: issuer and JWT minting
  - `personas`: personas and their RBAC
  - `cwserve`: hosting cwfake and the exactly-once check
  - `chaos`
  - `verify authz`
- **Harness, extended:**
  - `verify assoc`: pages through results, reads Controller owner kinds, retries 429, and follows the EndpointSlice for the succeeded-pod case
  - `users`: JWT personas, the new UI's request mix (paged lists, summaries, `/info` every 30s, capability gating)
  - `firehose`: ingest URL, Retry-After retries, a log of accepted IDs
  - `agents`: fan-out to every replica, gzip
  - `connectivity`: web path, ops and ingest
  - `report`: Postgres and oauth2-proxy columns

## Re-run
```bash
VARIANT=after hack/stress-up.sh                      # BUILD_IMAGES=0 to keep the loaded images
STEPS="verify authz conn cloudwatch" MAP_NAMESPACES=-1 hack/stress-run.sh L3 after
STEPS="users" USERS_STAGES=10:3m,200:5m,500:5m hack/stress-run.sh L3 after
STEPS="chaos" hack/stress-run.sh L3 after            # CHAOS_SCENARIOS=spoof,oversize,prometheus,postgres,apiserver,killreplica,standby
STEPS="report" hack/stress-run.sh L3 after
```
