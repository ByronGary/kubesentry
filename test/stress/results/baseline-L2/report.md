# Stress report: baseline-L2 (baseline, level L2)

Generated 2026-10-11T18:07:06Z. kubesentry memory limit: 256Mi.

## Cluster

- Plan: 250 fake nodes (map[batch:36 default:70 fargate:13 ng-arm:46 ng-general:75 ng-system:10]), 74 team + 4 add-on namespaces, 844 Deployments, 110 StatefulSets, 6 DaemonSets, 112 Jobs, 74 CronJobs, 25 bare pods
- Services map[ClusterIP:351 ExternalName:15 Headless:110 LoadBalancer:25 MultiWorkload:19 NodePort:19 SelectorLess:15], Ingresses map[alb-internal:29 alb-tls:28 nginx-tls:29 none:28], 483 PVCs / 520 PVs, 740 Roles, 1480 RoleBindings, 37 ClusterRoles, 71 ClusterRoleBindings, 99 Certificates
- After settling: 256 nodes (250 fake, 250 ready), 5023 pods map[Pending:2 Running:4781 Succeeded:240]; generator: 3747 created, 2075 existed, 0 failed; phases map[certificates:0 cleanup-l0:0 cluster:1 config:14 namespaces:0 network:3 nodes:5 settle:60 tricky:0 workloads:5]

## Steps and resource use

| Step | Status | Duration | kubesentry mem avg/max MiB | kubesentry CPU avg/max | restarts | last termination | kubesentry API req/s avg (peak min) | apiserver mem max MiB | apiserver CPU max | etcd mem max | Prometheus mem max | host avail min MiB |
|---|---|---:|---|---|---:|---|---|---:|---:|---:|---:|---:|
| gen | ok | 100s | 86 / 95 | 0.01 / 0.02 | 0 | OOMKilled | 0.00 (0.00) | 1406 | 1.72 | 116 | 433 | 6310 |
| verify-first | ok | 156s | 118 / 127 | 0.09 / 0.11 | 0 | OOMKilled | 7.04 (6.98) | 1631 | 0.50 | 118 | 455 | 5984 |
| connectivity | ok | 6s | 0 / 0 | 0.00 / 0.00 | 0 | OOMKilled | 2.83 (0.28) | 0 | 0.00 | 0 | 0 | 5953 |
| users-256Mi-first | ok | 1589s | 165 / 238 | 0.14 / 0.37 | 7 | OOMKilled | 7.57 (13.75) | 1686 | 0.27 | 168 | 503 | 5765 |
| users-1Gi | ok | 422s | 143 / 305 | 0.10 / 0.14 | 0 |  | 5.74 (7.10) | 1659 | 0.23 | 149 | 515 | 5890 |
| audit | ok | 366s | 100 / 114 | 0.07 / 0.08 | 1 | OOMKilled | 0.00 (0.00) | 1610 | 0.20 | 147 | 523 | 5964 |
| agents | ok | 222s | 141 / 161 | 0.04 / 0.08 | 0 | OOMKilled | 0.45 (1.47) | 1575 | 0.17 | 179 | 530 | 6066 |
| agents-surge | ok | 157s | 159 / 236 | 0.04 / 0.06 | 2 | OOMKilled | 0.64 (1.67) | 1562 | 0.15 | 134 | 502 | 6013 |
| verify | ok | 159s | 203 / 210 | 0.08 / 0.09 | 0 | OOMKilled | 6.91 (7.05) | 1708 | 0.25 | 122 | 509 | 5742 |
| users-256Mi | ok | 605s | 157 / 245 | 0.10 / 0.17 | 3 | OOMKilled | 3.31 (8.02) | 1723 | 0.28 | 148 | 560 | 5899 |

- kubesentry → API server during **verify-first**: 1098 requests (7.04/s, peak minute 6.98/s), codes map[200:1098], server time p50 10ms p99 22ms; top: list pods 528, list deployments 96, list services 92, list cronjobs 48, list statefulsets 48, list daemonsets 48, list jobs 48, list ingresses 46
- kubesentry → API server during **connectivity**: 17 requests (2.83/s, peak minute 0.28/s), codes map[200:17], server time p50 12ms p99 16ms; top: list pods 11, get pods 6
- kubesentry → API server during **users-256Mi-first**: 12034 requests (7.57/s, peak minute 13.75/s), codes map[200:12034], server time p50 4ms p99 21ms; top: get /apis/cert-manager.io/v1 3621, list deployments 2009, list pods 1407, list certificates 1195, list issuers 567, list statefulsets 492, list cronjobs 449, list daemonsets 449
- kubesentry → API server during **users-1Gi**: 2424 requests (5.74/s, peak minute 7.10/s), codes map[200:2424], server time p50 10ms p99 21ms; top: list pods 1165, get pods 109, list deployments 108, get /apis/cert-manager.io/v1 99, list issuers 99, list clusterissuers 99, list certificates 99, list certificaterequests 99
- kubesentry → API server during **agents**: 100 requests (0.45/s, peak minute 1.47/s), codes map[200:100], server time p50 1ms p99 2ms; top: get pods 100
- kubesentry → API server during **agents-surge**: 100 requests (0.64/s, peak minute 1.67/s), codes map[200:100], server time p50 1ms p99 2ms; top: get pods 100
- kubesentry → API server during **verify**: 1098 requests (6.91/s, peak minute 7.05/s), codes map[200:1098], server time p50 10ms p99 21ms; top: list pods 528, list deployments 96, list services 92, list daemonsets 48, list jobs 48, list cronjobs 48, list statefulsets 48, list nodes 46
- kubesentry → API server during **users-256Mi**: 2003 requests (3.31/s, peak minute 8.02/s), codes map[200:2000 404:3], server time p50 9ms p99 24ms; top: list pods 858, list deployments 138, get pods 117, get /apis/cert-manager.io/v1 101, list certificates 92, list issuers 83, list clusterissuers 72, list statefulsets 63

## Association (verify assoc)

| Relation@source | Precision | Recall | Truth | Reported |
|---|---:|---:|---:|---:|
| cronjob-job@map | 100.0% | 100.0% | 17 | 18 |
| ingress-service@map | 100.0% | 100.0% | 52 | 52 |
| pod-node@map | 100.0% | 100.0% | 2253 | 2254 |
| pod-node@nodes | 100.0% | 100.0% | 5046 | 5047 |
| pod-owner@map | 99.9% | 99.6% | 2239 | 2234 |
| pod-owner@nodes | 100.0% | 99.8% | 5013 | 5008 |
| pod-pvc@map | 100.0% | 100.0% | 113 | 113 |
| security-group@security | 99.1% | 99.3% | 677 | 678 |
| service-pods@map | 100.0% | 99.9% | 1550 | 1549 |
| workload-pods@workloads | 99.8% | 99.8% | 1230 | 1227 |

Tricky-case expectations kubesentry meets: 29/42. Top mismatch categories:

- custom-owner: pod-owner: owner not reported (Widget) ×4 (e.g. Pod/stress-tricky/widget-a-0 owned by Widget/stress-tricky/widget-a)
- rollout-like: pod-owner: owner not reported (Rollout) ×4 (e.g. Pod/stress-tricky/checkout-rs-pvprt owned by Rollout/stress-tricky/checkout)
- orphan-replicaset: pod-owner: owner not reported (ReplicaSet) ×4 (e.g. Pod/stress-tricky/orphan-src-7c448bf6cf-6cz5s owned by ReplicaSet/stress-tricky/orphan-src-7c448bf6cf)
- jobs-manual-selector: workload-pods: count differs (Job) ×2 (e.g. Job/stress-tricky/manual-a: 1 live pods, reported 2)
- jobs-manual-selector: pod-owner: wrong owner (Job instead of Job) ×2 (e.g. Pod/stress-tricky/manual-b-vrx55 owned by Job/stress-tricky/manual-b, reported Job/stress-tricky/manual-a)
- orphan-replicaset: security: unexpected group (Pod) ×2 (e.g. Pod/stress-tricky/orphan-src-7c448bf6cf-6cz5s)
- overlap-selectors: pod-owner: wrong owner (Deployment instead of Deployment) ×2 (e.g. Pod/stress-tricky/web-canary-7785cc787d-vk49m owned by Deployment/stress-tricky/web-canary, reported Deployment/stress-tricky/web)
- custom-owner: security: unexpected group (Pod) ×2 (e.g. Pod/stress-tricky/widget-a-0)
- rollout-like: security: unexpected group (Pod) ×2 (e.g. Pod/stress-tricky/checkout-rs-pvprt)
- jobs-manual-selector: security: group not reported (Job) ×1 (e.g. Job/stress-tricky/manual-b)
- custom-owner: security: group not reported (Widget) ×1 (e.g. Widget/stress-tricky/widget-a)
- orphan-replicaset: security: group not reported (ReplicaSet) ×1 (e.g. ReplicaSet/stress-tricky/orphan-src-7c448bf6cf)
- overlap-selectors: security: group not reported (Deployment) ×1 (e.g. Deployment/stress-tricky/web-canary)
- overlap-selectors: workload-pods: count differs (Deployment) ×1 (e.g. Deployment/stress-tricky/web: 2 live pods, reported 3)
- rollout-like: security: group not reported (Rollout) ×1 (e.g. Rollout/stress-tricky/checkout)

See assoc.md for the full case table.

## /oom and Prometheus

The range query behind /api/v1/oom?window=24h, run for the end of this run, returned 2.6 MB (5697 series, 83024 points, 32 bytes/point; Prometheus keeps 6h here). With 24h of history (240 points per series) it would be about **41 MB** against kubesentry's 64 MiB read cap.

## Connectivity

108 passed, 0 failed: map[DNS→Service:[12 12] pod→ClusterIP:[12 12] pod→pod:[72 72] →kubesentry:[12 12]]. Prometheus: info.metrics=true, /oom metricsAvailable=true (555ms). Agents fresh on real nodes: 6/6. See conn.md.

## Users: users-1Gi

Stages 10:3m0s,50:3m0s,200:5m0s,500:5m0s,1000:5m0s,2000:5m0s, think 5s-30s, request timeout 2m0s. **Aborted:** stage 50 users: abort criteria held for 2m0s (last 30s: err 46%, p99 60s, 3 requests stuck > 1m0s).

Latency p50 / p95 / p99 over all requests; timeouts, superseded and abandoned requests count at their elapsed time (a lower bound). Error rate = 5xx, 429, timeouts, transport errors and superseded polls (still running when the page's next poll replaced it, as the browser does) over requests not abandoned by navigation.

| Users | req/s | info | pods | diagnostics | processes | oom | pvcs-unused | workloads | nodes | map | security | storage | certificates | audit-events | audit-summary | errors | timeouts | superseded | abandoned |
|---:|---:|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---:|---:|---:|---:|
| 10 | 1.0 | 0ms / 3ms / 3ms | 10s / 13s / 13s | 1.4s / 3.1s / 3.1s | 1.2s / 2.6s / 2.8s | 17s / 30s / 30s | 18s / 31s / 31s | 13s / 28s / 28s | 13s / 30s / 30s | 16s / 30s / 30s | 20s / 35s / 37s | - | 46ms / 61ms / 61ms | 11ms / 18ms / 19ms | 35ms / 37ms / 37ms | 1.9% | 0 | 3 | 13 |
| 50 | 3.8 | 0ms / 2ms / 2ms | 30s / 30s / 30s | 20s / 28s / 29s | 15s / 15s / 15s | 60s / 60s / 60s | 60s / 60s / 60s | 30s / 30s / 30s | 30s / 30s / 30s | 30s / 30s / 30s | 60s / 60s / 60s | 60s / 60s / 60s | 47ms / 64ms / 100ms | 11ms / 19ms / 27ms | 33ms / 47ms / 47ms | 49.0% | 0 | 271 | 92 |

10 users, page loads: activity p50 35ms p95 37ms (5, 0 not loaded within the page timeout); findings p50 20s p95 37s (14, 0 not loaded within the page timeout); map p50 16s p95 83s (4, 0 not loaded within the page timeout); pod p50 1.5s p95 3.1s (17, 0 not loaded within the page timeout); pods p50 13s p95 13s (5, 0 not loaded within the page timeout); security p50 14s p95 28s (6, 0 not loaded within the page timeout); workloads p50 26s p95 28s (4, 0 not loaded within the page timeout);
10 users, status codes: audit-events map[200:20] (268 KB avg); audit-summary map[200:5] (5 KB avg); certificates map[200:15] (45 KB avg); diagnostics map[200:18 aborted:1] (4 KB avg); info map[200:10] (0 KB avg); map map[200:2 aborted:2 superseded:2] (16 KB avg); nodes map[200:2 aborted:1 superseded:1] (709 KB avg); oom map[200:14 aborted:1] (23 KB avg); pods map[200:5 aborted:1] (600 KB avg); processes map[200:30 aborted:1] (0 KB avg); pvcs-unused map[200:14 aborted:1] (53 KB avg); security map[200:20 aborted:1] (934 KB avg); workloads map[200:4 aborted:4] (385 KB avg);

50 users, page loads: activity p50 33ms p95 47ms (8, 0 not loaded within the page timeout); certificates p50 43ms p95 57ms (4, 0 not loaded within the page timeout); findings p50 120s p95 120s (20, 20 not loaded within the page timeout); map p50 120s p95 120s (8, 7 not loaded within the page timeout); pod p50 14s p95 120s (21, 8 not loaded within the page timeout); pods p50 120s p95 120s (4, 4 not loaded within the page timeout); security p50 120s p95 120s (2, 2 not loaded within the page timeout); storage p50 120s p95 120s (3, 3 not loaded within the page timeout); workloads p50 120s p95 120s (2, 2 not loaded within the page timeout);
50 users, status codes: audit-events map[200:88] (289 KB avg); audit-summary map[200:8] (5 KB avg); certificates map[200:84] (45 KB avg); diagnostics map[200:48 aborted:6] (3 KB avg); info map[200:40] (0 KB avg); map map[200:1 aborted:2 superseded:12] (30 KB avg); nodes map[aborted:4 superseded:16] (0 KB avg); oom map[aborted:18 superseded:43] (0 KB avg); pods map[aborted:5 superseded:17] (0 KB avg); processes map[200:13 aborted:15 superseded:79] (0 KB avg); pvcs-unused map[aborted:18 superseded:43] (0 KB avg); security map[aborted:20 superseded:47] (0 KB avg); storage map[aborted:2 superseded:6] (0 KB avg); workloads map[aborted:2 superseded:8] (0 KB avg);

## Users: users-256Mi

Stages 10:3m0s,50:3m0s,200:5m0s,500:5m0s,1000:5m0s,2000:5m0s, think 5s-30s, request timeout 2m0s. **Aborted:** stage 200 users: abort criteria held for 2m0s (last 30s: err 60%, p99 20s, 0 requests stuck > 1m0s).

Latency p50 / p95 / p99 over all requests; timeouts, superseded and abandoned requests count at their elapsed time (a lower bound). Error rate = 5xx, 429, timeouts, transport errors and superseded polls (still running when the page's next poll replaced it, as the browser does) over requests not abandoned by navigation.

| Users | req/s | info | pods | diagnostics | processes | oom | pvcs-unused | workloads | nodes | map | security | storage | certificates | audit-events | audit-summary | errors | timeouts | superseded | abandoned |
|---:|---:|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---:|---:|---:|---:|
| 10 | 1.2 | 0ms / 3ms / 3ms | 2ms / 5.0s / 5.0s | 983ms / 3.6s / 5.1s | 760ms / 2.9s / 7.1s | 6.8s / 22s / 22s | 9.4s / 24s / 24s | 5.2s / 15s / 15s | 5.1s / 22s / 22s | 1ms / 14s / 14s | 6.2s / 17s / 18s | - | 60ms / 7.1s / 10.0s | 20ms / 10.0s / 10.0s | 49ms / 72ms / 72ms | 30.5% | 8 | 0 | 1 |
| 50 | 4.9 | 0ms / 2ms / 6ms | 10.0s / 30s / 30s | 6.1s / 13s / 20s | 6.8s / 15s / 15s | 10.0s / 47s / 52s | 10.0s / 47s / 52s | 10.0s / 30s / 30s | 10.0s / 30s / 30s | 10.0s / 30s / 30s | 10.0s / 45s / 52s | 10.0s / 24s / 24s | 10.0s / 10.0s / 10.0s | 7.1s / 10.0s / 10.0s | 4.1s / 10.0s / 10.0s | 79.9% | 335 | 25 | 74 |
| 200 | 19.0 | 10.0s / 10.0s / 10.0s | 10.0s / 10.0s / 10.0s | 10.0s / 11s / 22s | 10.0s / 15s / 15s | 10.0s / 10.0s / 10.0s | 10.0s / 10.0s / 10.0s | 10.0s / 10.0s / 10.0s | 10.0s / 10.0s / 10.0s | 10.0s / 10.0s / 10.0s | 10.0s / 10.0s / 10.0s | 10.0s / 10.0s / 10.0s | 10.0s / 10.0s / 16s | 10.0s / 10.0s / 10.0s | 10.0s / 10.0s / 10.0s | 95.7% | 2599 | 28 | 334 |

10 users, page loads: activity p50 49ms p95 72ms (8, 0 not loaded within the page timeout); certificates p50 41ms p95 60ms (2, 0 not loaded within the page timeout); findings p50 9.4s p95 18s (16, 0 not loaded within the page timeout); map p50 5.1s p95 22s (7, 0 not loaded within the page timeout); pod p50 1.0s p95 3.6s (25, 0 not loaded within the page timeout); pods p50 2ms p95 5.0s (5, 0 not loaded within the page timeout); security p50 1.4s p95 17s (6, 0 not loaded within the page timeout); workloads p50 5.2s p95 15s (5, 0 not loaded within the page timeout);
10 users, status codes: audit-events map[200:22 error:4 timeout:2] (229 KB avg); audit-summary map[200:8] (5 KB avg); certificates map[200:17 error:4 timeout:1] (45 KB avg); diagnostics map[200:21 error:6] (5 KB avg); info map[200:8 error:2] (0 KB avg); map map[200:1 error:2] (30 KB avg); nodes map[200:3 error:1] (709 KB avg); oom map[200:10 error:7 timeout:1] (30 KB avg); pods map[200:1 error:4] (600 KB avg); processes map[200:31 aborted:1 error:12] (0 KB avg); pvcs-unused map[200:11 error:5 timeout:2] (53 KB avg); security map[200:12 error:8 timeout:2] (934 KB avg); workloads map[200:3 error:2] (385 KB avg);

50 users, page loads: activity p50 7.0s p95 10.0s (22, 0 not loaded within the page timeout); certificates p50 78ms p95 10.0s (6, 0 not loaded within the page timeout); findings p50 10.0s p95 47s (86, 0 not loaded within the page timeout); map p50 10.0s p95 49s (32, 0 not loaded within the page timeout); pod p50 10.0s p95 18s (51, 0 not loaded within the page timeout); pods p50 10.0s p95 46s (23, 0 not loaded within the page timeout); security p50 13s p95 48s (12, 0 not loaded within the page timeout); storage p50 10.0s p95 24s (8, 0 not loaded within the page timeout); workloads p50 10.0s p95 47s (34, 0 not loaded within the page timeout);
50 users, status codes: audit-events map[200:40 aborted:1 error:14 timeout:55] (256 KB avg); audit-summary map[200:8 error:5 timeout:10] (5 KB avg); certificates map[200:35 aborted:2 error:9 timeout:48] (45 KB avg); diagnostics map[200:17 aborted:11 error:25 timeout:15] (3 KB avg); info map[200:40] (0 KB avg); map map[aborted:3 error:13 superseded:3 timeout:9] (0 KB avg); nodes map[aborted:6 error:10 superseded:4 timeout:4] (0 KB avg); oom map[200:1 aborted:2 error:44 timeout:43] (31 KB avg); pods map[aborted:7 error:18 superseded:6 timeout:7] (0 KB avg); processes map[200:17 aborted:27 error:32 superseded:6 timeout:26] (0 KB avg); pvcs-unused map[aborted:2 error:41 timeout:47] (0 KB avg); security map[200:2 aborted:2 error:53 timeout:49] (934 KB avg); storage map[error:4 timeout:4] (0 KB avg); workloads map[200:2 aborted:11 error:15 superseded:6 timeout:18] (385 KB avg);

200 users, page loads: activity p50 10.0s p95 10.0s (131, 0 not loaded within the page timeout); certificates p50 10s p95 10s (22, 0 not loaded within the page timeout); findings p50 10s p95 10s (294, 0 not loaded within the page timeout); map p50 10.0s p95 10.0s (119, 0 not loaded within the page timeout); pod p50 10.0s p95 10.0s (183, 0 not loaded within the page timeout); pods p50 10.0s p95 10.0s (103, 0 not loaded within the page timeout); security p50 10.0s p95 10.0s (60, 0 not loaded within the page timeout); storage p50 10.0s p95 10.0s (22, 0 not loaded within the page timeout); workloads p50 10.0s p95 10.0s (101, 0 not loaded within the page timeout);
200 users, status codes: audit-events map[200:66 error:14 timeout:393] (250 KB avg); audit-summary map[200:21 error:6 timeout:103] (5 KB avg); certificates map[200:8 error:6 timeout:312] (45 KB avg); diagnostics map[200:15 404:2 aborted:73 error:19 timeout:163] (2 KB avg); info map[error:17 timeout:133] (0 KB avg); map map[aborted:32 error:6 timeout:81] (0 KB avg); nodes map[aborted:12 error:4 timeout:32] (0 KB avg); oom map[error:7 timeout:288] (0 KB avg); pods map[aborted:32 error:8 timeout:98] (0 KB avg); processes map[200:11 404:1 aborted:143 error:26 superseded:28 timeout:257] (0 KB avg); pvcs-unused map[error:11 timeout:285] (0 KB avg); security map[aborted:1 error:15 timeout:340] (0 KB avg); storage map[error:2 timeout:20] (0 KB avg); workloads map[aborted:41 error:7 timeout:94] (0 KB avg);

## Audit firehose: audit

1000000 of 1000000 events accepted in 333s: **3003 events/s** (target 3000/s, batches of 1000), 0 failed batches, 858 MB sent. Webhook latency p50 8ms p95 21ms p99 26ms max 347ms, status map[200:1000]. Findings audit query during ingest: p50 40ms p99 60ms (166).

| Query (store full) | n | status | p50 | p95 | p99 | max | KB | returned |
|---|---:|---|---:|---:|---:|---:|---:|---:|
| events 1h | 30 | map[error:30] map[connection refused:30] | 1ms | 2ms | 2ms | 2ms | 0 | 0 |
| events Activity | 30 | map[200:5 error:25] map[connection refused:25] | 2ms | 78ms | 79ms | 80ms | 114 | 200 |
| events all reads | 30 | map[error:30] map[connection refused:30] | 1ms | 2ms | 2ms | 2ms | 0 | 0 |
| events default (Findings) | 30 | map[200:30] map[] | 72ms | 86ms | 105ms | 105ms | 283 | 500 |
| events namespace | 30 | map[error:30] map[connection refused:30] | 1ms | 2ms | 2ms | 2ms | 0 | 0 |
| events tag=denied | 30 | map[error:30] map[connection refused:30] | 1ms | 2ms | 2ms | 2ms | 0 | 0 |
| events tag=exec | 30 | map[error:30] map[connection refused:30] | 2ms | 2ms | 2ms | 2ms | 0 | 0 |
| events user | 30 | map[error:30] map[connection refused:30] | 2ms | 3ms | 3ms | 3ms | 0 | 0 |
| summary 1h | 30 | map[error:30] map[connection refused:30] | 1ms | 2ms | 2ms | 2ms | 0 | 0 |
| summary 24h | 30 | map[error:30] map[connection refused:30] | 1ms | 2ms | 2ms | 2ms | 0 | 0 |

## Agents: agents (staggered)

500 agents (237 real fake-node names, 263 synthetic), 4642 pods covered, 125131 processes per round, report size p50 101 KB max 150 KB, every 15s for 180s: 33.3 posts/s, 3.3 MB/s.
POST /agent/report: 6000 posts, success 100.0%, 429 0, 5xx 0, timeouts 0; latency p50 1ms p95 1ms p99 2ms max 21ms; status map[204:6000].
Freshness check of 100 fake pods: 100 fresh, 0 stale, 0 unavailable, 0 errors; GET processes p50 202ms p99 202ms.

## Agents: agents-surge (surge)

500 agents (237 real fake-node names, 263 synthetic), 4642 pods covered, 125131 processes per round, report size p50 101 KB max 150 KB, every 15s for 120s: 37.3 posts/s, 3.7 MB/s.
POST /agent/report: 4481 posts, success 70.4%, 429 0, 5xx 0, timeouts 457; latency p50 72ms p95 7.2s p99 7.2s max 7.2s; status map[204:3153 error:871 timeout:457].
Freshness check of 100 fake pods: 100 fresh, 0 stale, 0 unavailable, 0 errors; GET processes p50 202ms p99 202ms.

