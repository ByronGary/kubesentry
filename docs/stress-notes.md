# Stress run notes

These are running notes from the enterprise stress test of kubesentry. Each run gets its own section. Alongside the performance numbers, the notes keep track of every caution and critical alert the cluster itself raised while the run was going.

- **Full reports.** The generated per-level reports live in `test/stress/results/<run>/report.md`.
- **Cluster cautions.** `hack/cluster-cautions.py` takes a snapshot every 5 minutes. Each run's summary goes in `test/stress/results/cautions-<run>/cautions.md`, produced with `hack/cluster-cautions.py --summarize <dir>`. A snapshot covers:
  - Prometheus alerts that are firing or pending
  - warning events
  - node conditions
  - pods in trouble
  - cert-manager status
  - API server, etcd and Prometheus health

  Alerts are split into *real* ones and *artifacts* of the kind/KWOK environment. Pass `--no-artifacts` on a real cluster.
- **Feeding the next build.** The last section collects what these runs teach us about the alerting, automation and monitoring build that comes next.

**Environment:**
- kind on Kubernetes 1.36.4: 1 control plane and 5 workers, with worker 5 reserved for load generators.
- KWOK fake nodes with EKS labels.
- kube-prometheus-stack with Grafana and Alertmanager off. Prometheus keeps 6h of data and is capped at 1.5 GiB.
- cert-manager.
- The host is WSL2 with 15.6 GiB and 12 CPUs. Stress levels are capped at L3: 500 nodes and about 10k pods.

## Run log

### Baseline L1: 100 fake nodes, 2,036 pods (2026-10-11, 15:33–16:15 UTC)
This run used the code tagged `baseline` with today's manifest (kubesentry memory limit 256 MiB).

| Step | Result |
|---|---|
| Generate | 2,076 objects created, 0 failed, in 96s |
| Association | pod→node 100%. pod→owner 99.9% precision and 99.6% recall. service→pods 100% / 99.9%. workload→pods 99.1%. Only **29 of 42** tricky cases are right |
| Connectivity | 108/108 probes pass: pod→pod, pod→ClusterIP, DNS and →kubesentry across all real nodes. Agents are fresh on 6 of 6 real nodes |
| Users | **Aborted at 200 users.** At 10 users list pages already take 2–8s at p95. At 50 users the error rate is 51%, with p95 30–46s. At 200 users errors reach 98.5%, mostly timeouts |
| Audit firehose | 1,000,000 events at **3,003/s**, 0 failed batches, webhook p99 32ms. Queries after a restart got "connection refused", and the store was empty after the OOM restart |
| Agents, staggered | 500 agents at 33 posts/s: 100% success, p99 2ms |
| Agents, surge | **49% success**: 1,211 timeouts and 937 errors. After the restarts no process data was available (94 of 100 pods) |
| kubesentry itself | **OOMKilled repeatedly** at 256 MiB, with 12 restarts by L2. Its readiness probe failed 1,689 times |

Where the baseline breaks, and what the new build is meant to fix:
- **Every request does full-cluster LISTs.** During the user test that was 2,765 API calls, including 1,043 pod lists. Latency grows with users until the 256 MiB pod is OOM-killed.
- **All state lives in the process.** Every OOM restart wipes the audit store and the process data, so the run loses both.
- **`/oom` will outgrow its read cap.** The 24h `/oom` query would be about 20 MB at L1 (2,389 series) against a 64 MiB read cap. At L3 it would exceed the cap.
- **Selector-based association gets the tricky cases wrong:**
  - custom-resource owners and Rollouts are not reported
  - orphaned ReplicaSets are not reported
  - Jobs with manual selectors get the wrong owner
  - overlapping Deployment selectors attribute a canary's pods to the main Deployment

### Baseline L2: 250 fake nodes, about 5k pods
*In progress.*

### Baseline L3: 500 fake nodes, about 10k pods
*Pending.*

### After: new build at L3
*Pending.* This needs the baseline to finish, kind switched to the Helm chart, and checkpoint D at L1.

## Cautions and critical alerts across the cluster

Snapshot at 2026-10-11 16:49 UTC, during baseline L2 (256 nodes, about 5k pods). It is refreshed every 5 minutes into `test/stress/results/cautions-baseline/`.

### Real cautions

| What | Severity | Detail | Why it matters on EKS |
|---|---|---|---|
| **No alert routing** | critical (gap) | Alertmanager is off, so every alert below fires into nothing. `PrometheusNotConnectedToAlertmanagers` is firing | In production, an alert that reaches no one is the same as no alert. Route through Alertmanager, or AMP's alert manager, to Slack, PagerDuty or email |
| **Prometheus is falling behind** | warning | 35 rule groups have pending `PrometheusMissingRuleEvaluations`, at 0.13 missed evaluations per second. 81k head series, 477 MiB RSS, and that is with kube-state-metrics cut to one metric and kubelet scraping limited to real nodes | A full kube-state-metrics on a 500-node EKS cluster is several times this. Size Prometheus (or use AMP) before adding rules |
| **kubesentry crash-looping** | critical | OOMKilled at 256 MiB, 12 restarts, 1,689 readiness probe failures, 92 BackOff events | The monitoring tool itself needs an alert, such as `KubePodCrashLooping` on its own namespace. Its memory must scale with the cluster |
| **Certificates expiring** | warning | 56 Certificates expire within 14 days, with some at 1 day. The generator makes short-lived certs on purpose | This is exactly what a cert-expiry alert with an owner must catch. kube-prometheus-stack has no cert-manager rules by default |
| **Certificates not ready** | warning | 5 Certificates reference issuers that do not exist (`DoesNotExist`) | Broken TLS issuance is silent until the old certificate expires |
| **Certificate issued with an empty Issuer DN** | caution | 6 `BadConfig` events: a self-signed issuer without a subject produces certificates that break RFC 5280 | Strict TLS clients (Java, some service meshes) reject them. Give issuers a subject |
| **Duplicate CertificateRequest** | caution | 1 `RequestFailed`: "certificaterequests ... already exists" | cert-manager races under churn. Watch it if it repeats |
| **Crash-looping workload** | warning | `stress-tricky/crashloop` has 19 restarts. `demo-apps/leaky` was OOMKilled | Planted on purpose. kubesentry should flag both |
| **Image pull failure** | warning | `stress-tricky/imagepull`: ImagePullBackOff for more than 5 minutes, 283 `Failed` events | Planted. On EKS this is usually ECR auth or rate limits |
| **Unschedulable pod** | warning | `stress-tricky/unschedulable`: 105 `FailedScheduling` events ("102 nodes had untolerated taints, 4 didn't match affinity") | Planted. On EKS this means Karpenter or the nodegroup cannot satisfy the pod |
| **Event volume** | caution | 7,033 Event objects in etcd, the largest object type, ahead of pods (5,047) | Event churn costs etcd and API server capacity. kind runs with `--event-ttl=30m`; EKS uses 1h by default |

**Control-plane health, which is fine so far at L2:**
- no 429s or 5xx from the API server, and nothing queued by APF
- API read p99 54ms and write p99 24ms
- etcd request p99 19ms
- real nodes have at least 39% memory and 77% disk free, with load per CPU at 0.17
- the host has at least 6.1 GiB available

### Artifacts of the stress environment, not real problems
These alerts are expected here and are filtered out in the summaries.

| Alert | Count | Cause |
|---|---:|---|
| KubeProxyInstanceUnreachable | 256 | kube-proxy binds its metrics to 127.0.0.1, and on KWOK nodes nothing runs |
| etcdInsufficientMembers (critical), etcdMembersDown | 1 each | kind binds etcd metrics to localhost |
| KubeControllerManagerInstanceUnreachable, KubeSchedulerInstanceUnreachable | 1 each | kind binds both to localhost |
| TargetDown | 4 | the same targets |
| Watchdog | 1 | the always-firing heartbeat (good: it proves rule evaluation works) |

**The same noise appears on EKS unless the monitoring stack is configured for it.** EKS manages etcd, the scheduler and the controller manager, so none of them can be scraped. To avoid alerts that fire forever on day one:
- turn those components off in kube-prometheus-stack (`kubeEtcd`, `kubeScheduler` and `kubeControllerManager` with `enabled: false`)
- patch kube-proxy's `metricsBindAddress` to `0.0.0.0:10249`, or turn its scraping off

## Inputs for the alerting, automation and monitoring build
These are candidates collected while the runs go on. The proposal comes after the baseline L3 data is in.
- **Routing comes first.** Choose Alertmanager, or AMP alert manager on EKS, with receivers per team. Route by namespace owner, the same RBAC ownership kubesentry already uses for scoping.
- **Watch the monitor:**
  - kubesentry crash loops and OOMs
  - snapshot age (`kubesentry_snapshot_age_seconds`)
  - authorization review errors and latency
  - audit queue depth and store errors
  - CloudWatch lag
  - agents not reporting

  The chart's `PrometheusRule` is the start of this.
- **Alerts kubesentry can raise from its own detectors,** which plain Prometheus rules cannot express as well:
  - certificates expiring or not ready, with owner and issuer
  - unused PVCs, with cost
  - memory leaks before the OOM, from the leak scanner
  - crash loops attributed to their owning workload
  - RBAC drift, such as new cluster-admin bindings or wildcard roles
  - exposure changes (a new internet-facing load balancer, or an Ingress without TLS)
  - sensitive audit events (secret reads, exec, denied bursts)
- **Automation candidates:**
  - open or update a ticket or Slack thread per finding, with a dedupe key
  - annotate a workload with its leak finding
  - cordon and drain on node pressure (opt-in)
  - restart stuck certificate requests
  - clean up unused PVCs after an approval
  - attach a runbook link to every alert
- **Monitoring gaps found so far:**
  - no alert routing
  - Prometheus capacity at 500+ nodes
  - EKS-specific scrape configuration
  - no cert-manager rules
  - event volume
