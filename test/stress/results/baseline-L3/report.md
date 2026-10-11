# Stress report: baseline-L3 (baseline, level L3)

Generated 2026-10-11T18:26:24Z. kubesentry memory limit: 256Mi.

## Cluster

- Plan: 500 fake nodes (map[batch:72 default:152 fargate:24 ng-arm:89 ng-general:136 ng-system:22 ng-windows:5]), 156 team + 4 add-on namespaces, 1727 Deployments, 237 StatefulSets, 10 DaemonSets, 240 Jobs, 156 CronJobs, 52 bare pods
- Services map[ClusterIP:718 ExternalName:32 Headless:237 LoadBalancer:52 MultiWorkload:39 NodePort:39 SelectorLess:31], Ingresses map[alb-internal:60 alb-tls:60 nginx-tls:61 none:59], 1005 PVCs / 1083 PVs, 1560 Roles, 3120 RoleBindings, 47 ClusterRoles, 91 ClusterRoleBindings, 208 Certificates
- After settling: 506 nodes (500 fake, 500 ready), 10002 pods map[Pending:2 Running:9481 Succeeded:519]; generator: 6176 created, 5822 existed, 0 failed; phases map[certificates:0 cleanup-l0:0 cluster:5 config:31 namespaces:0 network:8 nodes:5 settle:110 tricky:0 workloads:11]

## Steps and resource use

| Step | Status | Duration | kubesentry mem avg/max MiB | kubesentry CPU avg/max | restarts | last termination | kubesentry API req/s avg (peak min) | apiserver mem max MiB | apiserver CPU max | etcd mem max | Prometheus mem max | host avail min MiB |
|---|---|---:|---|---|---:|---|---|---:|---:|---:|---:|---:|
| gen | ok | 191s | 128 / 205 | 0.01 / 0.02 | 0 | OOMKilled | 0.00 (0.00) | 2085 | 2.43 | 156 | 556 | 4224 |
| verify | ok | 304s | 139 / 150 | 0.10 / 0.12 | 0 | OOMKilled | 6.12 (6.43) | 2311 | 0.34 | 238 | 603 | 3472 |
| connectivity | ok | 8s | 143 / 143 | 0.11 / 0.11 | 0 | OOMKilled | 3.38 (0.45) | 2192 | 0.26 | 142 | 603 | 4704 |
| users-256Mi | ok | 606s | 126 / 252 | 0.10 / 0.16 | 6 | OOMKilled | 2.39 (4.32) | 2193 | 0.44 | 312 | 695 | 4408 |
| users-1Gi | ok | 420s | 214 / 326 | 0.11 / 0.21 | 0 |  | 4.96 (6.15) | 2098 | 0.42 | 234 | 619 | 3613 |
| audit | ok | 371s | 104 / 122 | 0.08 / 0.17 | 1 | OOMKilled | 0.00 (0.00) | 2024 | 0.30 | 278 | 559 | 4033 |
| audit-1Gi | ok | 406s | 98 / 115 | 0.07 / 0.08 | 0 |  | 0.00 (0.00) | 1970 | 0.29 | 210 | 561 | 4845 |
| agents | ok | 223s | 189 / 206 | 0.04 / 0.07 | 0 |  | 0.45 (1.15) | 2018 | 0.19 | 158 | 547 | 4780 |
| agents-surge | ok | 157s | 69 / 254 | 0.04 / 0.05 | 3 | OOMKilled | 0.64 (1.67) | 1940 | 0.19 | 183 | 558 | 4619 |

- kubesentry → API server during **verify**: 1862 requests (6.12/s, peak minute 6.43/s), codes map[200:1862], server time p50 14ms p99 29ms; top: list pods 1008, list deployments 192, list services 138, list persistentvolumeclaims 135, list nodes 92, list jobs 48, list daemonsets 48, list statefulsets 48
- kubesentry → API server during **connectivity**: 27 requests (3.38/s, peak minute 0.45/s), codes map[200:27], server time p50 14ms p99 19ms; top: list pods 21, get pods 6
- kubesentry → API server during **users-256Mi**: 1451 requests (2.39/s, peak minute 4.32/s), codes map[200:1451], server time p50 14ms p99 27ms; top: list pods 721, list persistentvolumeclaims 103, list deployments 101, get pods 76, get /apis/cert-manager.io/v1 68, list certificates 62, list issuers 60, list clusterissuers 58
- kubesentry → API server during **users-1Gi**: 2083 requests (4.96/s, peak minute 6.15/s), codes map[200:2083], server time p50 14ms p99 28ms; top: list pods 1093, list persistentvolumeclaims 172, list clusterissuers 101, list certificates 101, list certificaterequests 101, get /apis/cert-manager.io/v1 101, list issuers 101, list deployments 88
- kubesentry → API server during **agents**: 100 requests (0.45/s, peak minute 1.15/s), codes map[200:100], server time p50 1ms p99 42ms; top: get pods 100
- kubesentry → API server during **agents-surge**: 100 requests (0.64/s, peak minute 1.67/s), codes map[200:100], server time p50 1ms p99 2ms; top: get pods 100

## Association (verify assoc)

| Relation@source | Precision | Recall | Truth | Reported |
|---|---:|---:|---:|---:|
| cronjob-job@map | 100.0% | 100.0% | 7 | 9 |
| ingress-service@map | 100.0% | 100.0% | 48 | 48 |
| pod-node@map | 100.0% | 100.0% | 3287 | 3289 |
| pod-node@nodes | 100.0% | 100.0% | 9999 | 10001 |
| pod-owner@map | 99.9% | 99.8% | 3273 | 3269 |
| pod-owner@nodes | 100.0% | 99.9% | 9939 | 9935 |
| pod-pvc@map | 100.0% | 100.0% | 144 | 144 |
| security-group@security | 99.6% | 99.6% | 1350 | 1351 |
| service-pods@map | 100.0% | 100.0% | 2021 | 2020 |
| workload-pods@workloads | 99.8% | 99.8% | 2453 | 2449 |

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

The range query behind /api/v1/oom?window=24h, run for the end of this run, returned 5.6 MB (11368 series, 179221 points, 31 bytes/point; Prometheus keeps 6h here). With 24h of history (240 points per series) it would be about **81 MB** against kubesentry's 64 MiB read cap.

## Connectivity

108 passed, 0 failed: map[DNS→Service:[12 12] pod→ClusterIP:[12 12] pod→pod:[72 72] →kubesentry:[12 12]]. Prometheus: info.metrics=true, /oom metricsAvailable=true (3.3s). Agents fresh on real nodes: 6/6. See conn.md.

## Users: users-1Gi

Stages 10:3m0s,50:3m0s,200:5m0s,500:5m0s,1000:5m0s,2000:5m0s, think 5s-30s, request timeout 2m0s. **Aborted:** stage 50 users: abort criteria held for 2m0s (last 30s: err 47%, p99 60s, 0 requests stuck > 1m0s).

Latency p50 / p95 / p99 over all requests; timeouts, superseded and abandoned requests count at their elapsed time (a lower bound). Error rate = 5xx, 429, timeouts, transport errors and superseded polls (still running when the page's next poll replaced it, as the browser does) over requests not abandoned by navigation.

| Users | req/s | info | pods | diagnostics | processes | oom | pvcs-unused | workloads | nodes | map | security | storage | certificates | audit-events | audit-summary | errors | timeouts | superseded | abandoned |
|---:|---:|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---:|---:|---:|---:|
| 10 | 0.8 | 0ms / 3ms / 3ms | 30s / 30s / 30s | 2.1s / 4.8s / 4.8s | 2.4s / 4.6s / 4.6s | 60s / 60s / 60s | 60s / 60s / 60s | - | 30s / 30s / 30s | 30s / 30s / 30s | 60s / 60s / 60s | - | 95ms / 159ms / 159ms | 38ms / 65ms / 65ms | - | 38.7% | 0 | 48 | 19 |
| 50 | 3.8 | 0ms / 2ms / 3ms | 30s / 30s / 30s | 22s / 30s / 30s | 15s / 15s / 15s | 60s / 60s / 60s | 60s / 60s / 60s | 30s / 30s / 30s | 30s / 30s / 30s | 30s / 30s / 30s | 60s / 60s / 60s | 60s / 60s / 60s | 95ms / 210ms / 635ms | 38ms / 75ms / 153ms | 57ms / 67ms / 67ms | 51.4% | 0 | 283 | 101 |

10 users, page loads: findings p50 120s p95 120s (6, 5 not loaded within the page timeout); map p50 120s p95 120s (2, 2 not loaded within the page timeout); pod p50 2.6s p95 4.8s (9, 0 not loaded within the page timeout); pods p50 120s p95 120s (2, 2 not loaded within the page timeout);
10 users, status codes: audit-events map[200:19] (314 KB avg); certificates map[200:19] (92 KB avg); diagnostics map[200:9 aborted:1] (2 KB avg); info map[200:10] (0 KB avg); map map[aborted:1 superseded:4] (0 KB avg); nodes map[superseded:4] (0 KB avg); oom map[200:2 aborted:5 superseded:9] (31 KB avg); pods map[aborted:1 superseded:11] (0 KB avg); processes map[200:15 aborted:1] (0 KB avg); pvcs-unused map[200:1 aborted:5 superseded:10] (113 KB avg); security map[200:1 aborted:5 superseded:10] (1849 KB avg);

50 users, page loads: activity p50 57ms p95 67ms (8, 0 not loaded within the page timeout); certificates p50 88ms p95 105ms (2, 0 not loaded within the page timeout); findings p50 120s p95 120s (22, 22 not loaded within the page timeout); map p50 120s p95 120s (6, 6 not loaded within the page timeout); pod p50 15s p95 120s (16, 8 not loaded within the page timeout); pods p50 120s p95 120s (5, 5 not loaded within the page timeout); security p50 120s p95 120s (4, 4 not loaded within the page timeout); storage p50 120s p95 120s (3, 3 not loaded within the page timeout); workloads p50 120s p95 120s (2, 2 not loaded within the page timeout);
50 users, status codes: audit-events map[200:88] (289 KB avg); audit-summary map[200:8] (5 KB avg); certificates map[200:82] (92 KB avg); diagnostics map[200:39 aborted:9 superseded:4] (3 KB avg); info map[200:40] (0 KB avg); map map[aborted:3 superseded:12] (0 KB avg); nodes map[aborted:4 superseded:12] (0 KB avg); oom map[aborted:20 superseded:45] (0 KB avg); pods map[aborted:6 superseded:18] (0 KB avg); processes map[200:11 aborted:11 superseded:78] (0 KB avg); pvcs-unused map[aborted:20 superseded:45] (0 KB avg); security map[aborted:24 superseded:53] (0 KB avg); storage map[aborted:2 superseded:6] (0 KB avg); workloads map[aborted:2 superseded:10] (0 KB avg);

## Users: users-256Mi

Stages 10:3m0s,50:3m0s,200:5m0s,500:5m0s,1000:5m0s,2000:5m0s, think 5s-30s, request timeout 2m0s. **Aborted:** stage 200 users: abort criteria held for 2m0s (last 30s: err 97%, p99 10s, 0 requests stuck > 1m0s).

Latency p50 / p95 / p99 over all requests; timeouts, superseded and abandoned requests count at their elapsed time (a lower bound). Error rate = 5xx, 429, timeouts, transport errors and superseded polls (still running when the page's next poll replaced it, as the browser does) over requests not abandoned by navigation.

| Users | req/s | info | pods | diagnostics | processes | oom | pvcs-unused | workloads | nodes | map | security | storage | certificates | audit-events | audit-summary | errors | timeouts | superseded | abandoned |
|---:|---:|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---:|---:|---:|---:|
| 10 | 1.1 | 0ms / 4ms / 4ms | 1.9s / 29s / 29s | 1.4s / 4.5s / 5.4s | 1.3s / 4.1s / 4.5s | 22s / 43s / 43s | 22s / 43s / 43s | 8.0s / 30s / 30s | 16s / 17s / 17s | 3.9s / 16s / 16s | 22s / 39s / 43s | - | 88ms / 136ms / 141ms | 36ms / 84ms / 539ms | 30ms / 70ms / 70ms | 55.9% | 0 | 1 | 13 |
| 50 | 4.9 | 9.6s / 10.0s / 10.0s | 10.0s / 30s / 30s | 10.0s / 16s / 18s | 9.2s / 14s / 15s | 10.0s / 46s / 48s | 10.0s / 46s / 48s | 6.0s / 22s / 30s | 10.0s / 30s / 30s | 10.0s / 30s / 30s | 10.0s / 46s / 48s | 10.0s / 40s / 40s | 10.0s / 10.0s / 13s | 10.0s / 10.0s / 10.0s | 10.0s / 10.0s / 10.0s | 84.5% | 437 | 13 | 86 |
| 200 | 21.4 | 10.0s / 10.0s / 10.0s | 10.0s / 10.0s / 15s | 10.0s / 10.0s / 10.0s | 10.0s / 10.0s / 10.0s | 10.0s / 10.0s / 13s | 10.0s / 10.0s / 13s | 10.0s / 10.0s / 21s | 10.0s / 10.0s / 22s | 10.0s / 10.0s / 10.0s | 10.0s / 10.0s / 13s | 10.0s / 18s / 26s | 10.0s / 10.0s / 10.0s | 10.0s / 10.0s / 10.0s | 10.0s / 10.0s / 10.0s | 97.9% | 2580 | 0 | 324 |

10 users, page loads: activity p50 30ms p95 70ms (6, 0 not loaded within the page timeout); certificates p50 1ms p95 81ms (2, 0 not loaded within the page timeout); findings p50 29s p95 43s (16, 0 not loaded within the page timeout); map p50 2.3s p95 17s (4, 0 not loaded within the page timeout); pod p50 1.0s p95 5.4s (18, 0 not loaded within the page timeout); pods p50 17s p95 29s (5, 0 not loaded within the page timeout); security p50 2ms p95 32s (6, 0 not loaded within the page timeout); workloads p50 25s p95 38s (4, 0 not loaded within the page timeout);
10 users, status codes: audit-events map[200:18 aborted:1 error:6] (268 KB avg); audit-summary map[200:4 error:2] (5 KB avg); certificates map[200:15 error:5] (92 KB avg); diagnostics map[200:11 aborted:2 error:7] (2 KB avg); info map[200:10] (0 KB avg); map map[aborted:1 error:2] (0 KB avg); nodes map[aborted:1 error:2] (0 KB avg); oom map[200:1 aborted:1 error:16] (31 KB avg); pods map[aborted:1 error:7] (0 KB avg); processes map[200:17 aborted:4 error:9] (0 KB avg); pvcs-unused map[200:1 aborted:1 error:16] (112 KB avg); security map[200:2 aborted:1 error:21] (1835 KB avg); workloads map[error:6 superseded:1] (0 KB avg);

50 users, page loads: activity p50 10.0s p95 10.0s (24, 0 not loaded within the page timeout); certificates p50 10.0s p95 11s (6, 0 not loaded within the page timeout); findings p50 10.0s p95 46s (80, 0 not loaded within the page timeout); map p50 10.0s p95 43s (31, 0 not loaded within the page timeout); pod p50 10.0s p95 23s (56, 0 not loaded within the page timeout); pods p50 10.0s p95 49s (18, 0 not loaded within the page timeout); security p50 10.0s p95 39s (11, 0 not loaded within the page timeout); storage p50 10.0s p95 40s (7, 0 not loaded within the page timeout); workloads p50 10.0s p95 25s (31, 0 not loaded within the page timeout);
50 users, status codes: audit-events map[200:37 aborted:2 error:16 timeout:65] (280 KB avg); audit-summary map[200:5 error:6 timeout:13] (5 KB avg); certificates map[200:34 aborted:3 error:7 timeout:59] (92 KB avg); diagnostics map[200:17 aborted:15 error:14 timeout:30] (2 KB avg); info map[200:9 error:11 timeout:20] (0 KB avg); map map[aborted:3 error:7 superseded:3 timeout:13] (0 KB avg); nodes map[aborted:4 error:7 superseded:1 timeout:6] (0 KB avg); oom map[aborted:2 error:29 timeout:55] (0 KB avg); pods map[aborted:3 error:11 superseded:4 timeout:8] (0 KB avg); processes map[200:22 aborted:37 error:26 superseded:4 timeout:42] (0 KB avg); pvcs-unused map[aborted:3 error:31 timeout:52] (0 KB avg); security map[aborted:3 error:37 timeout:57] (0 KB avg); storage map[aborted:2 error:4 timeout:3] (0 KB avg); workloads map[aborted:9 error:18 superseded:1 timeout:14] (0 KB avg);

200 users, page loads: activity p50 10.0s p95 10.0s (125, 0 not loaded within the page timeout); certificates p50 10.0s p95 10.0s (26, 0 not loaded within the page timeout); findings p50 10.0s p95 10.0s (333, 0 not loaded within the page timeout); map p50 10.0s p95 10.0s (130, 0 not loaded within the page timeout); pod p50 10.0s p95 10.0s (211, 0 not loaded within the page timeout); pods p50 10.0s p95 10.0s (118, 0 not loaded within the page timeout); security p50 10.0s p95 10.0s (68, 0 not loaded within the page timeout); storage p50 10.0s p95 18s (29, 0 not loaded within the page timeout); workloads p50 10.0s p95 10.0s (117, 0 not loaded within the page timeout);
200 users, status codes: audit-events map[200:21 error:37 timeout:389] (264 KB avg); audit-summary map[200:5 error:20 timeout:100] (5 KB avg); certificates map[200:7 error:33 timeout:308] (92 KB avg); diagnostics map[200:3 aborted:68 error:41 timeout:176] (2 KB avg); info map[200:22 error:18 timeout:110] (0 KB avg); map map[aborted:28 error:19 timeout:75] (0 KB avg); nodes map[aborted:13 error:9 timeout:31] (0 KB avg); oom map[error:47 timeout:286] (0 KB avg); pods map[aborted:31 error:25 timeout:94] (0 KB avg); processes map[200:6 aborted:149 error:58 timeout:267] (0 KB avg); pvcs-unused map[error:49 timeout:284] (0 KB avg); security map[error:54 timeout:347] (0 KB avg); storage map[error:11 timeout:18] (0 KB avg); workloads map[aborted:35 error:29 timeout:95] (0 KB avg);

## Audit firehose: audit

1000000 of 1000000 events accepted in 333s: **3003 events/s** (target 3000/s, batches of 1000), 0 failed batches, 858 MB sent. Webhook latency p50 9ms p95 20ms p99 25ms max 53ms, status map[200:1000]. Findings audit query during ingest: p50 40ms p99 64ms (166).

| Query (store full) | n | status | p50 | p95 | p99 | max | KB | returned |
|---|---:|---|---:|---:|---:|---:|---:|---:|
| events 1h | 30 | map[error:30] map[connection refused:30] | 1ms | 2ms | 2ms | 2ms | 0 | 0 |
| events Activity | 30 | map[200:30] map[] | 55ms | 89ms | 93ms | 93ms | 114 | 200 |
| events all reads | 30 | map[error:30] map[connection refused:30] | 1ms | 122ms | 122ms | 122ms | 0 | 0 |
| events default (Findings) | 30 | map[200:30] map[] | 58ms | 86ms | 91ms | 91ms | 283 | 500 |
| events namespace | 30 | map[200:30] map[] | 4ms | 4ms | 4ms | 4ms | 59 | 105 |
| events tag=denied | 30 | map[200:30] map[] | 7ms | 19ms | 21ms | 21ms | 106 | 200 |
| events tag=exec | 30 | map[200:30] map[] | 7ms | 14ms | 14ms | 14ms | 137 | 200 |
| events user | 30 | map[200:30] map[] | 4ms | 5ms | 5ms | 5ms | 17 | 31 |
| summary 1h | 30 | map[error:30] map[connection refused:30] | 1ms | 1ms | 1ms | 1ms | 0 | 0 |
| summary 24h | 30 | map[error:30] map[connection refused:30] | 1ms | 2ms | 2ms | 2ms | 0 | 0 |

## Audit firehose: audit-1Gi

1000000 of 1000000 events accepted in 333s: **3003 events/s** (target 3000/s, batches of 1000), 0 failed batches, 858 MB sent. Webhook latency p50 9ms p95 20ms p99 28ms max 66ms, status map[200:1000]. Findings audit query during ingest: p50 41ms p99 75ms (166).

| Query (store full) | n | status | p50 | p95 | p99 | max | KB | returned |
|---|---:|---|---:|---:|---:|---:|---:|---:|
| events 1h | 30 | map[200:30] map[] | 30ms | 41ms | 42ms | 43ms | 114 | 200 |
| events Activity | 30 | map[200:30] map[] | 55ms | 73ms | 75ms | 75ms | 114 | 200 |
| events all reads | 30 | map[200:30] map[] | 210ms | 288ms | 299ms | 299ms | 537 | 1000 |
| events default (Findings) | 30 | map[200:30] map[] | 66ms | 84ms | 86ms | 86ms | 282 | 500 |
| events namespace | 30 | map[200:30] map[] | 4ms | 7ms | 8ms | 8ms | 59 | 105 |
| events tag=denied | 30 | map[200:30] map[] | 5ms | 12ms | 13ms | 13ms | 106 | 200 |
| events tag=exec | 30 | map[200:30] map[] | 5ms | 13ms | 14ms | 14ms | 137 | 200 |
| events user | 30 | map[200:30] map[] | 3ms | 3ms | 3ms | 3ms | 17 | 31 |
| summary 1h | 30 | map[200:30] map[] | 66ms | 88ms | 88ms | 88ms | 125 | 735 |
| summary 24h | 30 | map[200:30] map[] | 138ms | 153ms | 174ms | 174ms | 125 | 735 |

## Agents: agents (staggered)

500 agents (471 real fake-node names, 29 synthetic), 9288 pods covered, 123007 processes per round, report size p50 99 KB max 150 KB, every 15s for 180s: 33.3 posts/s, 3.2 MB/s.
POST /agent/report: 6000 posts, success 100.0%, 429 0, 5xx 0, timeouts 0; latency p50 1ms p95 1ms p99 2ms max 37ms; status map[204:6000].
Freshness check of 100 fake pods: 100 fresh, 0 stale, 0 unavailable, 0 errors; GET processes p50 202ms p99 202ms.

## Agents: agents-surge (surge)

500 agents (471 real fake-node names, 29 synthetic), 9288 pods covered, 123007 processes per round, report size p50 99 KB max 150 KB, every 15s for 120s: 35.1 posts/s, 3.4 MB/s.
POST /agent/report: 4215 posts, success 57.0%, 429 0, 5xx 0, timeouts 702; latency p50 78ms p95 10.0s p99 10.0s max 10s; status map[204:2401 error:1112 timeout:702].
Freshness check of 100 fake pods: 0 fresh, 0 stale, 100 unavailable, 0 errors; GET processes p50 201ms p99 201ms.

