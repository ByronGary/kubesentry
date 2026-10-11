# Connectivity

120 probes passed, 0 failed.

| Check | Passed |
|---|---|
| DNS→Service | 12/12 |
| pod→ClusterIP | 12/12 |
| pod→pod | 72/72 |
| →ingest | 12/12 |
| →kubesentry | 12/12 |

## pod→pod matrix (rows: source node and network, columns: target node; ms or FAIL)

| from \ to | control-plane | worker | worker2 | worker3 | worker4 | worker5 | ClusterIP | DNS | kubesentry | ingest |
|---|---|---|---|---|---|---|---|---|---|---|
| control-plane (host) | 51 | 35 | 32 | 51 | 2 | 24 | 2 | 25 | 51 | 47 |
| control-plane (pod) | 53 | 51 | 49 | 17 | 51 | 23 | 51 | 51 | 31 | 63 |
| worker2 (host) | 55 | 55 | 57 | 54 | 26 | 29 | 55 | 63 | 38 | 65 |
| worker2 (pod) | 56 | 52 | 51 | 53 | 29 | 30 | 53 | 35 | 38 | 34 |
| worker3 (host) | 50 | 25 | 19 | 24 | 22 | 57 | 48 | 30 | 26 | 55 |
| worker3 (pod) | 24 | 25 | 47 | 55 | 53 | 18 | 23 | 53 | 57 | 31 |
| worker4 (host) | 52 | 53 | 51 | 25 | 21 | 20 | 24 | 33 | 63 | 47 |
| worker4 (pod) | 22 | 17 | 22 | 20 | 20 | 49 | 6 | 31 | 66 | 25 |
| worker5 (host) | 26 | 20 | 48 | 49 | 49 | 48 | 21 | 34 | 31 | 36 |
| worker5 (pod) | 54 | 48 | 50 | 52 | 54 | 50 | 51 | 34 | 62 | 61 |
| worker (host) | 49 | 22 | 17 | 17 | 23 | 49 | 48 | 59 | 34 | 28 |
| worker (pod) | 53 | 2 | 28 | 28 | 44 | 24 | 25 | 28 | 20 | 49 |

## kubesentry → Prometheus

- /api/v1/info metrics: true
- /api/v1/oom?window=1h: metricsAvailable=true, warnings [], 1119 ms, 56718 bytes 
- Prometheus targets up map[apiserver:1 coredns:2 kps-kube-prometheus-stack-operator:1 kps-kube-prometheus-stack-prometheus:2 kube-state-metrics:1 kubelet:12 kubesentry-ops:2 metrics-sim:1 node-exporter:6], down map[kube-controller-manager:1 kube-etcd:1 kube-proxy:6 kube-scheduler:1]
- simulated series (metrics-sim): 10745
  - down: kube-controller-manager https://172.19.0.11:10257/metrics: Get "https://172.19.0.11:10257/metrics": dial tcp 172.19.0.11:10257: connect: connection refused
  - down: kube-etcd http://172.19.0.11:2381/metrics: Get "http://172.19.0.11:2381/metrics": dial tcp 172.19.0.11:2381: connect: connection refused
  - down: kube-proxy http://172.19.0.6:10249/metrics: Get "http://172.19.0.6:10249/metrics": dial tcp 172.19.0.6:10249: connect: connection refused
  - down: kube-proxy http://172.19.0.9:10249/metrics: Get "http://172.19.0.9:10249/metrics": dial tcp 172.19.0.9:10249: connect: connection refused
  - down: kube-proxy http://172.19.0.7:10249/metrics: Get "http://172.19.0.7:10249/metrics": dial tcp 172.19.0.7:10249: connect: connection refused
  - down: kube-proxy http://172.19.0.8:10249/metrics: Get "http://172.19.0.8:10249/metrics": dial tcp 172.19.0.8:10249: connect: connection refused
  - down: kube-proxy http://172.19.0.11:10249/metrics: Get "http://172.19.0.11:10249/metrics": dial tcp 172.19.0.11:10249: connect: connection refused
  - down: kube-proxy http://172.19.0.10:10249/metrics: Get "http://172.19.0.10:10249/metrics": dial tcp 172.19.0.10:10249: connect: connection refused
  - down: kube-scheduler https://172.19.0.11:10259/metrics: Get "https://172.19.0.11:10259/metrics": dial tcp 172.19.0.11:10259: connect: connection refused

## Web path and ops listener

- /api/v1/info as the harness identity: HTTP 200, identity admin0@corp.example (proxy, groups [stress:admins system:authenticated]), capabilities map[agents:true audit:true clusterAudit:true clusterIssuers:true clusterRBAC:true nodes:true processes:true pvs:true storageClasses:true]
- no credentials: HTTP 401 (want 401); forged X-Forwarded-Email without a token: HTTP 401 (want 401)
- ops /readyz: HTTP 200 {"status":"ready"}
- kubesentry_* metric lines: 336; snapshot age 1.5s; audit store postgres; Prometheus discovered
- verdict: true []

## Agent freshness (real nodes)

| Node | Pod | available | stale | reported by | processes | ok |
|---|---|---|---|---|---:|---|
| kubesentry-control-plane | mesh-m2xn2 | true | false | kubesentry-control-plane | 2 | true  |
| kubesentry-worker | mesh-9tkm8 | true | false | kubesentry-worker | 2 | true  |
| kubesentry-worker2 | mesh-p5mcv | true | false | kubesentry-worker2 | 2 | true  |
| kubesentry-worker3 | mesh-27p2k | true | false | kubesentry-worker3 | 2 | true  |
| kubesentry-worker4 | mesh-7njzz | true | false | kubesentry-worker4 | 2 | true  |
| kubesentry-worker5 | mesh-vmv4b | true | false | kubesentry-worker5 | 2 | true  |
