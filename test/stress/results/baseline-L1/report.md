# Stress report: baseline-L1 (baseline, level L1)

Generated 2026-10-11T18:07:06Z. kubesentry memory limit: 256Mi.

## Cluster

- Plan: 100 fake nodes (map[batch:15 default:34 fargate:4 ng-arm:13 ng-general:29 ng-system:5]), 25 team + 4 add-on namespaces, 285 Deployments, 39 StatefulSets, 4 DaemonSets, 37 Jobs, 25 CronJobs, 9 bare pods
- Services map[ClusterIP:114 ExternalName:5 Headless:39 LoadBalancer:9 MultiWorkload:6 NodePort:7 SelectorLess:5], Ingresses map[alb-internal:11 alb-tls:9 nginx-tls:10 none:9], 168 PVCs / 181 PVs, 250 Roles, 500 RoleBindings, 27 ClusterRoles, 51 ClusterRoleBindings, 34 Certificates
- After settling: 106 nodes (100 fake, 100 ready), 2036 pods map[Pending:2 Running:1959 Succeeded:75]; generator: 2076 created, 0 existed, 0 failed; phases map[certificates:0 cleanup-l0:0 cluster:0 config:4 namespaces:0 network:1 nodes:5 settle:50 tricky:25 workloads:2]

## Steps and resource use

| Step | Status | Duration | kubesentry mem avg/max MiB | kubesentry CPU avg/max | restarts | last termination | kubesentry API req/s avg (peak min) | apiserver mem max MiB | apiserver CPU max | etcd mem max | Prometheus mem max | host avail min MiB |
|---|---|---:|---|---|---:|---|---|---:|---:|---:|---:|---:|
| gen | ok | 96s | 43 / 54 | 0.01 / 0.01 | 0 |  | 0.00 (0.00) | 1081 | 1.32 | 110 | 295 | 5588 |
| verify | ok | 74s | 79 / 84 | 0.04 / 0.07 | 0 |  | 8.43 (5.68) | 1272 | 0.15 | 101 | 332 | 6166 |
| connectivity | ok | 18s | 56 / 56 | 0.00 / 0.00 | 0 |  | 0.72 (0.22) | 1071 | 0.11 | 97 | 389 | 6285 |
| users-256Mi | ok | 613s | 108 / 249 | 0.09 / 0.14 | 5 | OOMKilled | 4.51 (8.38) | 1252 | 0.17 | 115 | 420 | 5922 |
| audit | ok | 367s | 104 / 114 | 0.08 / 0.11 | 0 | OOMKilled | 0.00 (0.00) | 1102 | 0.10 | 103 | 452 | 7077 |
| agents | ok | 222s | 181 / 200 | 0.04 / 0.06 | 0 | OOMKilled | 0.45 (1.67) | 1128 | 0.08 | 97 | 436 | 6679 |
| agents-surge | ok | 175s | 57 / 200 | 0.02 / 0.02 | 3 | OOMKilled | 0.54 (1.57) | 1131 | 0.08 | 92 | 435 | 6819 |

- kubesentry → API server during **verify**: 624 requests (8.43/s, peak minute 5.68/s), codes map[200:624], server time p50 3ms p99 23ms; top: list pods 210, list cronjobs 42, list daemonsets 42, list statefulsets 42, list deployments 42, list jobs 42, list services 40, list nodes 40
- kubesentry → API server during **connectivity**: 13 requests (0.72/s, peak minute 0.22/s), codes map[200:13], server time p50 1ms p99 17ms; top: get pods 8, list pods 5
- kubesentry → API server during **users-256Mi**: 2765 requests (4.51/s, peak minute 8.38/s), codes map[200:2765], server time p50 3ms p99 21ms; top: list pods 1043, get pods 152, get /apis/cert-manager.io/v1 138, list certificates 130, list issuers 128, list clusterissuers 125, list certificaterequests 122, list persistentvolumeclaims 108
- kubesentry → API server during **agents**: 100 requests (0.45/s, peak minute 1.67/s), codes map[200:100], server time p50 1ms p99 2ms; top: get pods 100
- kubesentry → API server during **agents-surge**: 94 requests (0.54/s, peak minute 1.57/s), codes map[200:94], server time p50 1ms p99 9ms; top: get pods 94

## Association (verify assoc)

| Relation@source | Precision | Recall | Truth | Reported |
|---|---:|---:|---:|---:|
| cronjob-job@map | 100.0% | 100.0% | 2 | 2 |
| ingress-service@map | 100.0% | 100.0% | 40 | 40 |
| pod-node@map | 100.0% | 100.0% | 2007 | 2007 |
| pod-node@nodes | 100.0% | 100.0% | 2007 | 2007 |
| pod-owner@map | 99.9% | 99.6% | 1991 | 1985 |
| pod-owner@nodes | 99.9% | 99.6% | 1990 | 1984 |
| pod-pvc@map | 100.0% | 100.0% | 85 | 85 |
| security-group@security | 97.5% | 97.9% | 237 | 238 |
| service-pods@map | 100.0% | 99.9% | 1304 | 1303 |
| workload-pods@workloads | 99.1% | 99.1% | 430 | 426 |

Tricky-case expectations kubesentry meets: 29/42. Top mismatch categories:

- custom-owner: pod-owner: owner not reported (Widget) ×4 (e.g. Pod/stress-tricky/widget-a-0 owned by Widget/stress-tricky/widget-a)
- rollout-like: pod-owner: owner not reported (Rollout) ×4 (e.g. Pod/stress-tricky/checkout-rs-pvprt owned by Rollout/stress-tricky/checkout)
- orphan-replicaset: pod-owner: owner not reported (ReplicaSet) ×4 (e.g. Pod/stress-tricky/orphan-src-7c448bf6cf-6cz5s owned by ReplicaSet/stress-tricky/orphan-src-7c448bf6cf)
- jobs-manual-selector: workload-pods: count differs (Job) ×2 (e.g. Job/stress-tricky/manual-a: 1 live pods, reported 2)
- rollout-like: security: unexpected group (Pod) ×2 (e.g. Pod/stress-tricky/checkout-rs-pvprt)
- jobs-manual-selector: pod-owner: wrong owner (Job instead of Job) ×2 (e.g. Pod/stress-tricky/manual-b-vrx55 owned by Job/stress-tricky/manual-b, reported Job/stress-tricky/manual-a)
- custom-owner: security: unexpected group (Pod) ×2 (e.g. Pod/stress-tricky/widget-a-0)
- orphan-replicaset: security: unexpected group (Pod) ×2 (e.g. Pod/stress-tricky/orphan-src-7c448bf6cf-6cz5s)
- overlap-selectors: pod-owner: wrong owner (Deployment instead of Deployment) ×2 (e.g. Pod/stress-tricky/web-canary-7785cc787d-vk49m owned by Deployment/stress-tricky/web-canary, reported Deployment/stress-tricky/web)
- orphan-replicaset: security: group not reported (ReplicaSet) ×1 (e.g. ReplicaSet/stress-tricky/orphan-src-7c448bf6cf)
- overlap-selectors: security: group not reported (Deployment) ×1 (e.g. Deployment/stress-tricky/web-canary)
- overlap-selectors: workload-pods: count differs (Deployment) ×1 (e.g. Deployment/stress-tricky/web: 2 live pods, reported 3)
- custom-owner: security: group not reported (Widget) ×1 (e.g. Widget/stress-tricky/widget-a)
- jobs-manual-selector: security: group not reported (Job) ×1 (e.g. Job/stress-tricky/manual-b)
- rollout-like: security: group not reported (Rollout) ×1 (e.g. Rollout/stress-tricky/checkout)

See assoc.md for the full case table.

## /oom and Prometheus

The range query behind /api/v1/oom?window=24h, run for the end of this run, returned 0.6 MB (2328 series, 16339 points, 39 bytes/point; Prometheus keeps 6h here). With 24h of history (240 points per series) it would be about **21 MB** against kubesentry's 64 MiB read cap.

## Connectivity

108 passed, 0 failed: map[DNS→Service:[12 12] pod→ClusterIP:[12 12] pod→pod:[72 72] →kubesentry:[12 12]]. Prometheus: info.metrics=true, /oom metricsAvailable=true (207ms). Agents fresh on real nodes: 6/6. See conn.md.

## Users: users-256Mi

Stages 10:3m0s,50:3m0s,200:5m0s,500:5m0s,1000:5m0s,2000:5m0s, think 5s-30s, request timeout 2m0s. **Aborted:** stage 200 users: abort criteria held for 2m0s (last 30s: err 100%, p99 10s, 0 requests stuck > 1m0s).

Latency p50 / p95 / p99 over all requests; timeouts, superseded and abandoned requests count at their elapsed time (a lower bound). Error rate = 5xx, 429, timeouts, transport errors and superseded polls (still running when the page's next poll replaced it, as the browser does) over requests not abandoned by navigation.

| Users | req/s | info | pods | diagnostics | processes | oom | pvcs-unused | workloads | nodes | map | security | storage | certificates | audit-events | audit-summary | errors | timeouts | superseded | abandoned |
|---:|---:|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---:|---:|---:|---:|
| 10 | 1.4 | 0ms / 3ms / 3ms | 1.8s / 3.0s / 3.0s | 10ms / 1.7s / 2.0s | 3ms / 1.1s / 2.2s | 1.8s / 5.4s / 8.8s | 2.0s / 5.2s / 6.1s | 1.8s / 7.6s / 7.6s | 305ms / 4.3s / 4.3s | 2.1s / 5.6s / 5.6s | 2.3s / 6.6s / 7.1s | - | 35ms / 49ms / 65ms | 45ms / 60ms / 81ms | 49ms / 83ms / 83ms | 0.0% | 0 | 0 | 1 |
| 50 | 4.3 | 0ms / 2ms / 2ms | 13s / 30s / 30s | 7.1s / 16s / 18s | 5.4s / 15s / 15s | 21s / 38s / 45s | 23s / 45s / 46s | 10.0s / 30s / 30s | 10.0s / 30s / 30s | 6.0s / 30s / 30s | 22s / 45s / 46s | 19s / 46s / 46s | 66ms / 10.0s / 15s | 31ms / 9.8s / 10.0s | 41ms / 10.0s / 10.0s | 50.7% | 22 | 0 | 92 |
| 200 | 20.6 | 10.0s / 10.0s / 10.0s | 10.0s / 10.0s / 25s | 10.0s / 10.0s / 10.0s | 10.0s / 10.0s / 10.0s | 10.0s / 10.0s / 30s | 10.0s / 10.0s / 31s | 10.0s / 10.0s / 28s | 10.0s / 10.0s / 28s | 10.0s / 10.0s / 15s | 10.0s / 10.0s / 31s | 10.0s / 10.0s / 22s | 10.0s / 10.0s / 10.0s | 10.0s / 10.0s / 10.0s | 10.0s / 10.0s / 10.0s | 98.5% | 2585 | 0 | 297 |

10 users, page loads: activity p50 49ms p95 83ms (10, 0 not loaded within the page timeout); certificates p50 20ms p95 22ms (2, 0 not loaded within the page timeout); findings p50 3.6s p95 6.6s (21, 0 not loaded within the page timeout); map p50 2.1s p95 5.6s (8, 0 not loaded within the page timeout); pod p50 10ms p95 1.7s (27, 0 not loaded within the page timeout); pods p50 1.8s p95 3.0s (6, 0 not loaded within the page timeout); security p50 202ms p95 5.5s (7, 0 not loaded within the page timeout); workloads p50 1.8s p95 7.6s (9, 0 not loaded within the page timeout);
10 users, status codes: audit-events map[200:34] (263 KB avg); audit-summary map[200:10] (8 KB avg); certificates map[200:26] (17 KB avg); diagnostics map[200:28] (2 KB avg); info map[200:10] (0 KB avg); map map[200:4] (24 KB avg); nodes map[200:4] (287 KB avg); oom map[200:22] (1 KB avg); pods map[200:6] (242 KB avg); processes map[200:44 aborted:1] (0 KB avg); pvcs-unused map[200:21] (19 KB avg); security map[200:28] (364 KB avg); workloads map[200:9] (139 KB avg);

50 users, page loads: activity p50 41ms p95 10.0s (19, 0 not loaded within the page timeout); certificates p50 30ms p95 5.3s (7, 0 not loaded within the page timeout); findings p50 25s p95 45s (70, 0 not loaded within the page timeout); map p50 20s p95 39s (23, 0 not loaded within the page timeout); pod p50 10.0s p95 18s (42, 0 not loaded within the page timeout); pods p50 25s p95 44s (16, 0 not loaded within the page timeout); security p50 22s p95 45s (8, 0 not loaded within the page timeout); storage p50 31s p95 46s (7, 0 not loaded within the page timeout); workloads p50 24s p95 39s (21, 0 not loaded within the page timeout);
50 users, status codes: audit-events map[200:98 error:6 timeout:5] (296 KB avg); audit-summary map[200:13 error:4 timeout:2] (8 KB avg); certificates map[200:88 aborted:5 error:2 timeout:2] (17 KB avg); diagnostics map[200:30 aborted:5 error:18] (2 KB avg); info map[200:40] (0 KB avg); map map[200:1 aborted:7 error:12] (6 KB avg); nodes map[200:2 aborted:5 error:12 timeout:1] (287 KB avg); oom map[200:10 aborted:7 error:57 timeout:3] (2 KB avg); pods map[200:1 aborted:9 error:19] (242 KB avg); processes map[200:38 aborted:22 error:29] (0 KB avg); pvcs-unused map[200:5 aborted:7 error:62 timeout:3] (19 KB avg); security map[200:5 aborted:8 error:69 timeout:4] (364 KB avg); storage map[aborted:3 error:7] (0 KB avg); workloads map[200:1 aborted:14 error:24 timeout:2] (139 KB avg);

200 users, page loads: activity p50 10.0s p95 10.0s (126, 0 not loaded within the page timeout); certificates p50 10.0s p95 10.0s (25, 0 not loaded within the page timeout); findings p50 10.0s p95 10.0s (342, 0 not loaded within the page timeout); map p50 10.0s p95 10.0s (140, 0 not loaded within the page timeout); pod p50 10.0s p95 10.0s (219, 0 not loaded within the page timeout); pods p50 10.0s p95 10.0s (122, 0 not loaded within the page timeout); security p50 10.0s p95 10s (71, 0 not loaded within the page timeout); storage p50 10.0s p95 10.0s (30, 0 not loaded within the page timeout); workloads p50 10.0s p95 19s (124, 0 not loaded within the page timeout);
200 users, status codes: audit-events map[200:13 error:58 timeout:382] (293 KB avg); audit-summary map[200:2 error:16 timeout:108] (8 KB avg); certificates map[200:7 error:50 timeout:294] (17 KB avg); diagnostics map[200:3 aborted:65 error:45 timeout:187] (2 KB avg); info map[200:15 error:15 timeout:120] (0 KB avg); map map[aborted:28 error:20 timeout:84] (0 KB avg); nodes map[aborted:9 error:10 timeout:33] (0 KB avg); oom map[error:70 timeout:273] (0 KB avg); pods map[aborted:22 error:35 timeout:94] (0 KB avg); processes map[200:9 aborted:135 error:71 timeout:281] (0 KB avg); pvcs-unused map[error:64 timeout:278] (0 KB avg); security map[aborted:1 error:85 timeout:329] (0 KB avg); storage map[error:4 timeout:26] (0 KB avg); workloads map[aborted:37 error:33 timeout:96] (0 KB avg);

## Audit firehose: audit

1000000 of 1000000 events accepted in 333s: **3003 events/s** (target 3000/s, batches of 1000), 0 failed batches, 860 MB sent. Webhook latency p50 10ms p95 23ms p99 32ms max 39ms, status map[200:1000]. Findings audit query during ingest: p50 42ms p99 72ms (166).

| Query (store full) | n | status | p50 | p95 | p99 | max | KB | returned |
|---|---:|---|---:|---:|---:|---:|---:|---:|
| events 1h | 30 | map[error:30] map[connection refused:30] | 1ms | 2ms | 2ms | 2ms | 0 | 0 |
| events Activity | 30 | map[200:30] map[] | 58ms | 84ms | 86ms | 86ms | 115 | 200 |
| events all reads | 30 | map[error:30] map[connection refused:30] | 1ms | 127ms | 127ms | 127ms | 0 | 0 |
| events default (Findings) | 30 | map[200:30] map[] | 57ms | 78ms | 84ms | 84ms | 283 | 500 |
| events namespace | 30 | map[200:30] map[] | 4ms | 9ms | 12ms | 12ms | 113 | 200 |
| events tag=denied | 30 | map[200:30] map[] | 6ms | 12ms | 12ms | 12ms | 106 | 200 |
| events tag=exec | 30 | map[200:30] map[] | 6ms | 12ms | 13ms | 13ms | 137 | 200 |
| events user | 30 | map[200:30] map[] | 3ms | 3ms | 3ms | 3ms | 0 | 0 |
| summary 1h | 30 | map[error:30] map[connection refused:30] | 1ms | 2ms | 2ms | 2ms | 0 | 0 |
| summary 24h | 30 | map[error:30] map[connection refused:30] | 1ms | 2ms | 2ms | 2ms | 0 | 0 |

## Agents: agents (staggered)

500 agents (96 real fake-node names, 404 synthetic), 1839 pods covered, 155623 processes per round, report size p50 125 KB max 200 KB, every 15s for 180s: 33.3 posts/s, 4.2 MB/s.
POST /agent/report: 6000 posts, success 100.0%, 429 0, 5xx 0, timeouts 0; latency p50 1ms p95 1ms p99 2ms max 17ms; status map[204:6000].
Freshness check of 100 fake pods: 100 fresh, 0 stale, 0 unavailable, 0 errors; GET processes p50 202ms p99 202ms.

## Agents: agents-surge (surge)

500 agents (96 real fake-node names, 404 synthetic), 1839 pods covered, 155623 processes per round, report size p50 125 KB max 200 KB, every 15s for 120s: 35.3 posts/s, 4.4 MB/s.
POST /agent/report: 4237 posts, success 49.3%, 429 0, 5xx 0, timeouts 1211; latency p50 118ms p95 10.0s p99 10.0s max 10s; status map[204:2089 error:937 timeout:1211].
Freshness check of 100 fake pods: 0 fresh, 0 stale, 94 unavailable, 6 errors; GET processes p50 202ms p99 10.0s.

