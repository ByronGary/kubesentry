# Stress report: after-L3 (after, level L3)

Generated 2026-10-11T21:17:10Z. kubesentry memory limit: 1Gi.

## Steps and resource use

| Step | Status | Duration | kubesentry mem avg/max MiB | kubesentry CPU avg/max | restarts | last termination | kubesentry API req/s avg (peak min) | apiserver mem max MiB | apiserver CPU max | etcd mem max | Prometheus mem max | Postgres mem / CPU max | oauth2-proxy CPU max | host avail min MiB |
|---|---|---:|---|---|---:|---|---|---:|---:|---:|---:|---|---:|---:|
| users-1Gi | ok | 893s | 780 / 1050 | 0.21 / 0.37 | 0 |  | 23.80 (43.63) | 1412 | 0.36 | 227 | 451 | 1176 / 7.30 | 0.12 | 3050 |
| verify | ok | 14s | 805 / 805 | 0.08 / 0.08 | 0 |  | 0.29 (0.07) | 1277 | 0.18 | 118 | 465 | 546 / 0.03 | 0.00 | 4235 |
| authz | ok | 97s | 789 / 829 | 0.14 / 0.18 | 0 |  | 1.86 (1.50) | 1302 | 0.40 | 246 | 464 | 1190 / 0.53 | 0.01 | 4348 |

- kubesentry → API server during **users-1Gi**: 21256 requests (23.80/s, peak minute 43.63/s), codes map[200:85 201:21171], server time p50 1ms p99 7ms; top: create subjectaccessreviews 21171, get /apis/cert-manager.io/v1 6, watch services 4, watch clusterroles 4, watch rolebindings 4, watch ingresses 4, watch replicasets 4, watch roles 4
- kubesentry → API server during **verify**: 4 requests (0.29/s, peak minute 0.07/s), codes map[201:4], server time p50 1ms p99 1ms; top: create subjectaccessreviews 4
- kubesentry → API server during **authz**: 180 requests (1.86/s, peak minute 1.50/s), codes map[201:180], server time p50 1ms p99 1ms; top: create subjectaccessreviews 180

## Association (verify assoc)

| Relation@source | Precision | Recall | Truth | Reported |
|---|---:|---:|---:|---:|
| cronjob-job@map | 100.0% | 100.0% | 80 | 80 |
| ingress-service@map | 100.0% | 100.0% | 233 | 233 |
| pod-node@map | 100.0% | 100.0% | 9543 | 9543 |
| pod-node@nodes | 100.0% | 100.0% | 9543 | 9543 |
| pod-owner@map | 100.0% | 100.0% | 9484 | 9484 |
| pod-owner@nodes | 99.9% | 100.0% | 9483 | 9488 |
| pod-pvc@map | 100.0% | 100.0% | 497 | 497 |
| security-group@security | 100.0% | 100.0% | 1380 | 1380 |
| service-pods@map | 100.0% | 100.0% | 6029 | 6029 |
| workload-pods@workloads | 100.0% | 100.0% | 2496 | 2496 |

Tricky-case expectations kubesentry meets: 42/42. Top mismatch categories:

- system: pod-owner: spurious owner ×4 (e.g. Pod/kube-system/etcd-kubesentry-control-plane reported under Node/kube-system/kubesentry-control-plane; pod has no workload owner)
- static-pod: pod-owner: spurious owner ×1 (e.g. Pod/stress-tricky/static-web-kubesentry-worker reported under Node/stress-tricky/kubesentry-worker; pod has no workload owner)

See assoc.md for the full case table.

## /oom and Prometheus

The range query behind /api/v1/oom?window=24h, run for the end of this run, returned 6.7 MB (10857 series, 227573 points, 30 bytes/point; Prometheus keeps 6h here). With 24h of history (240 points per series) it would be about **74 MB** against kubesentry's 64 MiB read cap.

## Connectivity

120 passed, 0 failed: map[DNS→Service:[12 12] pod→ClusterIP:[12 12] pod→pod:[72 72] →ingest:[12 12] →kubesentry:[12 12]]. Prometheus: info.metrics=true, /oom metricsAvailable=true (1.1s). Agents fresh on real nodes: 6/6. See conn.md.

## Users: users-1Gi

Stages 10:3m0s,200:5m0s,500:5m0s, think 5s-30s, request timeout 2m0s.

Latency p50 / p95 / p99 over all requests; timeouts, superseded and abandoned requests count at their elapsed time (a lower bound). Error rate = 5xx, 429, timeouts, transport errors and superseded polls (still running when the page's next poll replaced it, as the browser does) over requests not abandoned by navigation.

| Users | req/s | info | pods | diagnostics | processes | oom | pvcs-unused | workloads | nodes | map | security | storage | certificates | audit-events | audit-summary | errors | timeouts | superseded | abandoned |
|---:|---:|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---:|---:|---:|---:|
| 10 | 2.2 | 3ms / 1.5s / 2.5s | 10ms / 14ms / 14ms | 6ms / 10ms / 19ms | 3ms / 5ms / 6ms | 3ms / 5ms / 12ms | 3ms / 8ms / 11ms | 6ms / 9ms / 9ms | 7ms / 8ms / 8ms | 2ms / 2ms / 2ms | 6ms / 11ms / 13ms | 9ms / 9ms / 9ms | 3ms / 8ms / 11ms | 8ms / 15ms / 21ms | 3.4s / 3.6s / 3.6s | 0.0% | 0 | 0 | 0 |
| 200 | 32.6 | 3ms / 14ms / 2.9s | 4ms / 18ms / 32ms | 5ms / 5.0s / 13s | 2ms / 5ms / 8ms | 2ms / 8ms / 16ms | 2ms / 8ms / 17ms | 3ms / 9ms / 15ms | 7ms / 15ms / 33ms | 3ms / 7ms / 8ms | 4ms / 12ms / 24ms | 4ms / 17ms / 22ms | 3ms / 8ms / 16ms | 147ms / 27s / 30s | 125ms / 11s / 18s | 0.2% | 0 | 0 | 1 |
| 500 | 77.2 | 3ms / 10.0s / 19s | 4ms / 23ms / 57ms | 288ms / 15s / 21s | 2ms / 8ms / 18ms | 4ms / 13ms / 30ms | 4ms / 13ms / 26ms | 3ms / 11ms / 19ms | 7ms / 17ms / 35ms | 4ms / 11ms / 23ms | 5ms / 17ms / 35ms | 3ms / 19ms / 33ms | 4ms / 14ms / 31ms | 8.5s / 30s / 30s | 7.0s / 20s / 27s | 0.5% | 0 | 0 | 132 |

10 users, page loads: activity p50 3.4s p95 3.6s (10, 0 not loaded within the page timeout); certificates p50 2ms p95 3ms (2, 0 not loaded within the page timeout); findings p50 9ms p95 15ms (26, 0 not loaded within the page timeout); map p50 2ms p95 8ms (10, 0 not loaded within the page timeout); pod p50 6ms p95 10ms (28, 0 not loaded within the page timeout); pods p50 45ms p95 58ms (6, 0 not loaded within the page timeout); security p50 6ms p95 7ms (7, 0 not loaded within the page timeout); storage p50 16ms p95 16ms (1, 0 not loaded within the page timeout); workloads p50 15ms p95 19ms (10, 0 not loaded within the page timeout);
10 users, status codes: audit-events map[200:36] (235 KB avg); audit-summary map[200:10] (133 KB avg); certificates map[200:28] (92 KB avg); diagnostics map[200:28] (2 KB avg); info map[200:60] (1 KB avg); map map[200:5] (41 KB avg); nodes map[200:5] (206 KB avg); oom map[200:26] (26 KB avg); pods map[200:6] (201 KB avg); pods(next page) map[200:54] (190 KB avg); processes map[200:45] (0 KB avg); pvcs-unused map[200:26] (134 KB avg); security map[200:33] (75 KB avg); storage map[200:1] (808 KB avg); storage(next page) map[200:1] (497 KB avg); workloads map[200:10] (329 KB avg); workloads(next page) map[200:20] (242 KB avg);

200 users, page loads: activity p50 6ms p95 14s (321, 0 not loaded within the page timeout); certificates p50 2ms p95 6ms (73, 0 not loaded within the page timeout); findings p50 12ms p95 24s (920, 0 not loaded within the page timeout); map p50 4ms p95 11ms (322, 0 not loaded within the page timeout); pod p50 5ms p95 5.2s (613, 0 not loaded within the page timeout); pods p50 6ms p95 59ms (335, 0 not loaded within the page timeout); security p50 4ms p95 11ms (155, 0 not loaded within the page timeout); storage p50 5ms p95 30ms (82, 0 not loaded within the page timeout); workloads p50 3ms p95 20ms (311, 0 not loaded within the page timeout);
200 users, status codes: audit-events map[200:658 502:15 503:3] (227 KB avg); audit-summary map[200:176] (120 KB avg); certificates map[200:998] (19 KB avg); diagnostics map[200:628 aborted:1] (2 KB avg); info map[200:2001] (1 KB avg); map map[200:224] (41 KB avg); nodes map[200:98] (73 KB avg); oom map[200:925] (5 KB avg); pods map[200:335] (60 KB avg); pods(next page) map[200:594] (190 KB avg); processes map[200:584] (0 KB avg); pvcs-unused map[200:925] (27 KB avg); security map[200:1080] (36 KB avg); storage map[200:82] (181 KB avg); storage(next page) map[200:20] (395 KB avg); workloads map[200:311] (77 KB avg); workloads(next page) map[200:128] (242 KB avg);

500 users, page loads: activity p50 153ms p95 20s (665, 0 not loaded within the page timeout); certificates p50 2ms p95 9ms (158, 0 not loaded within the page timeout); findings p50 40ms p95 30s (2157, 0 not loaded within the page timeout); map p50 5ms p95 14ms (724, 0 not loaded within the page timeout); pod p50 11ms p95 16s (1478, 0 not loaded within the page timeout); pods p50 6ms p95 71ms (666, 0 not loaded within the page timeout); security p50 4ms p95 11ms (367, 0 not loaded within the page timeout); storage p50 3ms p95 35ms (198, 0 not loaded within the page timeout); workloads p50 4ms p95 26ms (708, 0 not loaded within the page timeout);
500 users, status codes: audit-events map[200:1352 502:95 503:17] (217 KB avg); audit-summary map[200:345 502:2] (118 KB avg); certificates map[200:2383] (19 KB avg); diagnostics map[200:1551 404:9 aborted:131] (2 KB avg); info map[200:4939] (1 KB avg); map map[200:502 aborted:1] (36 KB avg); nodes map[200:223] (63 KB avg); oom map[200:2225] (5 KB avg); pods map[200:666] (55 KB avg); pods(next page) map[200:1035] (190 KB avg); processes map[200:1686 404:2] (0 KB avg); pvcs-unused map[200:2225] (27 KB avg); security map[200:2592] (36 KB avg); storage map[200:198] (118 KB avg); storage(next page) map[200:31] (384 KB avg); workloads map[200:708] (71 KB avg); workloads(next page) map[200:262] (242 KB avg);

