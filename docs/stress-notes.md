# Stress run notes

These are running notes from the enterprise stress test of kubesentry. Each run gets its own section. Alongside the performance numbers, the notes keep track of every caution and critical alert the cluster itself raised while the run was going.

**Where things are:**
- **Generated reports:** `test/stress/results/<variant>-<level>/report.md`. The baseline write-up is in `test/stress/results/baseline-summary.md`.
- **Cluster cautions:** `hack/cluster-cautions.py` takes a snapshot every 5 minutes. Each snapshot covers:
  - Prometheus alerts, firing or pending
  - API server, etcd and Prometheus health
  - node conditions
  - pods in trouble
  - warning events
  - cert-manager status
  - PVCs

  Each run's summary is in `test/stress/results/cautions-<run>/cautions.md`, produced by `hack/cluster-cautions.py --summarize <dir>`. Alerts are split into real ones and artifacts of the kind/KWOK environment. Pass `--no-artifacts` on a real cluster.
- **Next build:** the last section collects what these runs teach us for the alerting, automation and monitoring build that comes next.

**Environment:**
- kind on Kubernetes 1.36.4, with 1 control plane and 5 workers (worker 5 runs only the load generators).
- KWOK fake nodes with EKS labels.
- kube-prometheus-stack with Grafana and Alertmanager off, 6h retention, Prometheus capped at 1.5 GiB.
- cert-manager.
- Host: WSL2 with 15.6 GiB and 12 CPUs.
- Stress scale is capped at L3: 500 nodes and about 10k pods.

## Run log

### Baseline: L1, L2 and L3 (2026-10-11, 15:33–18:30 UTC)
This run tested the code tagged `baseline` as shipped: one replica, a 256 MiB memory limit, client-go defaults, and an in-memory audit store holding 50k events.

| | L1 | L2 | L3 |
|---|---:|---:|---:|
| Fake nodes / pods | 100 / 2,036 | 250 / 5,023 | 500 / 10,002 |
| Namespaces / Services / Deployments | 29 / 185 / 285 | 78 / 554 / 844 | 160 / 1,148 / 1,727 |
| Single user, map of one namespace / nodes / security | 1.6s / 1.2s / 1.4s | 3.0s / 2.5s / 2.7s | 5.8s / 4.9s / 4.8s |
| Highest passing user stage (≤20% errors, p99 ≤ 60s) at 256 MiB | 10 | **0** (31% errors at 10 users) | **0** (56% errors at 10 users) |
| Same at 1 GiB | not run | 10 | **0**: pages never finish within their poll |
| kubesentry OOM kills | 8 | 13 | 10 |
| kubesentry → API server while serving users | 4.5/s | 7.6/s | 5.0/s |
| Association, pod → owner precision / recall | 99.9% / 99.6% | 99.9% / 99.6% | 99.9% / 99.8% |
| Tricky cases right | 29/42 | 29/42 | 29/42 |
| Connectivity probes | 108/108 | 108/108 | 108/108 |
| Audit webhook, 1M events | 3,003/s, p99 32ms | 3,003/s, p99 26ms | 3,003/s, p99 25ms |
| 500 agents, staggered / all at once | 100% / 49% (OOM) | 100% / 70% (OOM) | 100% / 57% (OOM) |
| `/oom` 24h answer, projected (cap 64 MiB) | 21 MB | 41 MB | **81 MB** |
| kube-apiserver / etcd / Prometheus memory max | 1.27 GB / 115 MB / 452 MB | 1.72 GB / 179 MB / 560 MB | 2.31 GB / 312 MB / 695 MB |

**Why the baseline fails:**
- **Client-side throttling.** Every request does full LISTs through client-go's default limit of 5 QPS per API group. kubesentry tops out at 5–8 API requests/s however many users there are, and page latency grows by about 0.55 ms per pod. The API server is not the bottleneck: it answers in 3–14 ms p50 and never returned a 429.
- **Memory.** 256 MiB is too small, and every OOM costs minutes. Each one means CrashLoopBackOff, losing the audit and process stores, and replaying the audit log from the start. With 1 GiB there are no OOMs, but throttling remains.
- **Synchronized agents kill the server.** 500 agents posting at the same moment (as after a DaemonSet rollout) OOM-kill it every time. The baseline agent has no jitter.
- **Association.** Selector-based association is wrong where selectors and ownership diverge: overlapping selectors, manual Job selectors, orphaned ReplicaSets, custom-resource and Rollout owners, terminating pods counted, unready pods shown as ok.
- **`/oom` outgrows its read cap at L3.**
- **The audit store fills fast.** The 50k cap holds about 17 seconds of a 3k/s firehose.

### After: the new build at L3, checkpoint D (2026-10-11, 18:55–21:17 UTC): passed
Full write-up: `test/stress/results/after-L3/checkpoint-d.md`.

**Setup:**
- installed with the Helm chart: 2 replicas, 1 GiB memory limit
- SSO: oauth2-proxy over a Unix socket, with a test OIDC issuer that mints JWTs per persona
- Postgres 17 audit store, with CloudWatch read from an in-cluster fake
- Prometheus found by autodiscovery
- agents on the 6 real nodes only

| Check | Result |
|---|---|
| Authorization leaks (15 personas, every list route paged through) | **0 leaks**, 0 problems; about 200k items checked |
| Association | **42/42 tricky cases** (baseline 29/42). Every relation at 100% precision and recall. Verifier time 14s (baseline 304s) |
| Connectivity | **120/120**, including oauth2-proxy and ingest from every node |
| CloudWatch | 1M events stored exactly once, with 0.5% duplicates and 1% late deliveries in the input. Live-tail lag 31–47s |
| Chaos | **all pass**: spoofed headers, oversized reports, Prometheus down, Postgres down for 2 min (0 lost), API server restart, leader killed (the replacement took the lock in 2.6s), standby-only takeover (5.1s) |
| Users through SSO, 10 → 200 → 500 | Errors 0% / 0.18% / 0.49%. 0 restarts. About 525 MiB per replica. **0 LISTs to the API server.** Inventory routes at 500 users: **p95 11–23 ms, p99 19–57 ms** |
| **Audit-backed routes at 500 users** | **fail the target.** `/info` p95 10s; `audit/events` p50 8.5s, p95 30s, 7.7% errors; `audit/summary` p50 7s; diagnostics p95 15s. Cause: the Postgres coverage `count(*)` (834 ms over 3.4M rows) runs uncoordinated on every `/info`, and the 24h summary (1.5s) runs per team scope. Postgres hit 7.3 cores. A fix is in progress |
| **Re-run after the audit fix** (22:21–22:34 UTC, same ramp) | **pass.** At 500 users, every route has p95 ≤ 23 ms and p99 ≤ 57 ms with 0% errors: `/info` 2/5/12 ms, `audit/events` 8/19/44 ms, `audit/summary` 3/11/22 ms, diagnostics 3/7/19 ms (p50/p95/p99). The only slow call left is the first cluster-wide summary after a restart (3.9 s, once; later callers share it) |

**Smaller findings, being fixed:**
- static pods are shown with their node as the workload
- the oauth2-proxy upstream timeout (30s) is shorter than kubesentry's route timeouts
- `--reverse-proxy` runs without trusted proxy IPs
- a possibly stale CloudWatch lag gauge after the lock is lost
- a Prometheus outage doesn't show in `/readyz` or `/info`

### After: full L3 run (Phase 4)
*Next.* It covers the 2,000-user ramp, a 2h soak at 500 users, every chaos scenario, and the baseline-vs-after report.

## Cautions and critical alerts across the cluster (baseline, 20 snapshots, 16:49–18:30 UTC)
Full table: `test/stress/results/cautions-baseline/cautions.md`.

### Real cautions

| What | Severity | Detail | Why it matters on EKS |
|---|---|---|---|
| **No alert routing** | critical (gap) | Alertmanager is off, so every alert below fired into nothing (`PrometheusNotConnectedToAlertmanagers`) | An alert that reaches no one is the same as no alert. Route through Alertmanager or AMP's alert manager to Slack, PagerDuty or email |
| **Prometheus falling behind** | warning | `PrometheusMissingRuleEvaluations` pending in 19 of 20 snapshots, for 35 rule groups, at 0.13 missed/s. 102k head series, RSS up to 695 MiB, and that is with kube-state-metrics cut to one metric and only real nodes scraped | A full kube-state-metrics on a 500-node EKS cluster is several times this. Size Prometheus (or use AMP) before adding rules |
| **kubesentry crash-looping (baseline build)** | critical | 31 OOM kills over the run, 4,137 readiness probe failures, 181 BackOff events | The monitoring tool needs its own alert, and its memory must scale with the cluster. The new build is being tested for exactly this |
| **cert-manager restarting under load** | warning | Liveness probe returned HTTP 500 at L3; 3 restarts. cert-manager runs with no resource requests or limits | With hundreds of certificates, give cert-manager requests and limits and watch its restarts. A restart pauses issuance and renewal |
| **Certificates expiring** | warning | 117 Certificates expire within 14 days, some within 1 day. The generator makes short-lived certs on purpose | Exactly what a cert-expiry alert with an owner should catch. kube-prometheus-stack has no cert-manager rules by default |
| **Certificates not ready** | warning | 9 Certificates reference issuers that don't exist (`DoesNotExist`) | Broken issuance is silent until the old certificate expires |
| **Certificate with an empty Issuer DN** | caution | 12 `BadConfig` events: a self-signed issuer without a subject produces RFC 5280-violating certificates | Strict TLS clients (Java, some meshes) reject them. Give issuers a subject |
| **ClusterIP repair** | caution | 3 `ClusterIPNotAllocated` events ("not allocated; repairing") while creating 1,148 Services | The API server's IP allocator repaired leaked or raced allocations. Worth an alert if it repeats, because it means Service IP state drifted |
| **Control-plane latency under load** | caution | API read p99 up to 250ms and write p99 up to 361ms (16–23ms when idle); etcd p99 44ms; kube-apiserver 2.31 GB at L3 | Fine here. On EKS, watch API latency and APF rejections per flow, because kubesentry and every controller share them |
| **Node clock** | caution | `NodeClockNotSynchronising` was pending once (WSL clock drift) | On EKS, clock skew breaks token validation and SigV4. Keep the node-exporter rule |
| **Real node pressure** | caution | Real nodes went down to 24% memory available; load per CPU reached 1.04 | Fine for the load generators. On EKS, node pressure leads to evictions |
| **Event volume** | caution | Events were the largest object type at L2 (7k). At L3, pods 10k and RoleBindings 3.1k led | Event churn costs etcd and API capacity. kind runs `--event-ttl=30m`; EKS uses 1h |
| **API server restart: RBAC briefly denies** | caution | Right after the API server restart (after-run chaos), kubesentry's ServiceAccount got about 1s of `forbidden` watch errors while the API server's RBAC caches warmed up. It recovered by itself | Every controller sees this after a control-plane restart. Alert only if `forbidden` persists, and expect a burst during EKS control-plane upgrades |
| **cert-manager keeps failing liveness** | warning | After run: 8,151 `Unhealthy` events and 5 restarts. Worse than the baseline's 3 restarts, under more load | Give cert-manager resource requests and raise its probe tolerance, and alert on restarts. A restart pauses issuance and renewal |
| **API error budget burn after a control-plane restart** | warning | `KubeAPIErrorBudgetBurn` pending in 5 snapshots, plus `KubeClientErrors` and `PrometheusKubernetesListWatchFailures` around the API server restart. API 5xx up to 0.14/s, 429 up to 0.01/s, read p99 up to 697 ms | Expect the same during EKS control-plane upgrades. Route these to the platform team, not to application owners |
| **Node disk I/O saturation** | caution | `NodeDiskIOSaturation` pending once (6 devices) during the after run's Postgres and CloudWatch load | On EKS, gp3 volumes for Postgres (or RDS) need provisioned IOPS sized to the audit ingest |
| **kubesentry's own Postgres alert works** | info | `KubesentryPostgresErrors` (from the chart's PrometheusRule) went pending during the Postgres chaos test | Proof that the self-monitoring rules fire. They still need routing |
| **Planted workload faults** | expected | crashloop (38 restarts), `leaky` (OOMKilled ×6, 88% of its limit), ImagePullBackOff (704 `Failed` events), Unschedulable (107 `FailedScheduling`) | kubesentry must flag all of these. The after run checks it |

**Control plane, overall:**
- no 429s or 5xx from the API server, and nothing queued by APF
- real nodes kept at least 77% disk free
- the host never went below 3.9 GiB available, and the memory guard never fired

### Artifacts of the stress environment, not real problems

| Alert | Peak | Cause |
|---|---:|---|
| KubeProxyInstanceUnreachable | 501 | kube-proxy binds its metrics to 127.0.0.1, and on KWOK nodes nothing runs |
| etcdInsufficientMembers (critical), etcdMembersDown | 1 each | kind binds etcd metrics to localhost |
| KubeControllerManagerInstanceUnreachable, KubeSchedulerInstanceUnreachable | 1 each | kind binds both to localhost |
| TargetDown | 4 | the same targets |
| Watchdog | 1 | the always-firing heartbeat |

**The same noise appears on EKS unless the monitoring stack is set up for it.** EKS manages etcd, the scheduler and the controller manager, so none of them can be scraped. To avoid alerts that fire forever on day one:
- turn those components off in kube-prometheus-stack (`kubeEtcd`, `kubeScheduler` and `kubeControllerManager` with `enabled: false`)
- patch kube-proxy's `metricsBindAddress` to `0.0.0.0:10249`, or turn its scraping off

## Inputs for the alerting, automation and monitoring build
These are candidates from the runs so far. The proposal is in `docs/proposals/alerting-automation.md`.
- **Routing first:** Alertmanager, or AMP alert manager on EKS, with receivers per team, routed by namespace owner. That is the same RBAC ownership kubesentry already uses for scoping.
- **Watch the monitor:**
  - kubesentry crash loops and OOMs
  - snapshot age
  - authorization review errors
  - audit queue depth and store errors
  - CloudWatch lag
  - agents not reporting
  - cert-manager restarts
- **Alerts kubesentry can raise from its own detectors:**
  - certificates expiring or not ready, with owner and issuer
  - unused PVCs, with cost
  - memory leaks before the OOM
  - crash loops attributed to their owning workload
  - RBAC drift
  - exposure changes
  - sensitive audit events
- **Automation candidates:**
  - a ticket or Slack thread per finding, with a dedupe key
  - opt-in node cordon and drain
  - restarting stuck certificate requests
  - approval-gated PVC cleanup
  - a runbook link on every alert
- **Monitoring gaps:**
  - no alert routing
  - Prometheus capacity at 500+ nodes
  - EKS-specific scrape configuration
  - no cert-manager rules
  - no resource requests on cert-manager
  - event volume
  - API server latency and APF per flow
