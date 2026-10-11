# Connectivity

108 probes passed, 0 failed.

| Check | Passed |
|---|---|
| DNS→Service | 12/12 |
| pod→ClusterIP | 12/12 |
| pod→pod | 72/72 |
| →kubesentry | 12/12 |

## pod→pod matrix (rows: source node and network, columns: target node; ms or FAIL)

| from \ to | control-plane | worker | worker2 | worker3 | worker4 | worker5 | ClusterIP | DNS | kubesentry |
|---|---|---|---|---|---|---|---|---|---|
| control-plane (host) | 28 | 29 | 27 | 9 | 5 | 5 | 32 | 39 | 20 |
| control-plane (pod) | 8 | 26 | 7 | 29 | 28 | 30 | 27 | 28 | 36 |
| worker2 (host) | 27 | 9 | 25 | 37 | 25 | 26 | 24 | 12 | 31 |
| worker2 (pod) | 27 | 5 | 7 | 5 | 6 | 10 | 32 | 28 | 8 |
| worker3 (host) | 31 | 28 | 25 | 10 | 23 | 23 | 25 | 22 | 25 |
| worker3 (pod) | 23 | 4 | 2 | 1 | 27 | 4 | 9 | 20 | 22 |
| worker4 (host) | 5 | 10 | 4 | 6 | 6 | 15 | 19 | 13 | 14 |
| worker4 (pod) | 25 | 3 | 9 | 19 | 17 | 24 | 20 | 10 | 33 |
| worker5 (host) | 14 | 6 | 6 | 10 | 6 | 20 | 10 | 33 | 16 |
| worker5 (pod) | 10 | 18 | 6 | 28 | 11 | 3 | 9 | 36 | 20 |
| worker (host) | 30 | 23 | 17 | 15 | 23 | 19 | 5 | 27 | 26 |
| worker (pod) | 10 | 3 | 17 | 29 | 10 | 8 | 5 | 14 | 36 |

## kubesentry → Prometheus

- /api/v1/info metrics: true
- /api/v1/oom?window=1h: metricsAvailable=true, warnings [], 207 ms, 10409 bytes 
- Prometheus targets up map[apiserver:1 coredns:2 kps-kube-prometheus-stack-operator:1 kps-kube-prometheus-stack-prometheus:2 kube-state-metrics:1 kubelet:12 metrics-sim:1 node-exporter:6], down map[kube-controller-manager:1 kube-etcd:1 kube-proxy:106 kube-scheduler:1]
- simulated series (metrics-sim): 2195
  - down: kube-controller-manager https://172.19.0.11:10257/metrics: Get "https://172.19.0.11:10257/metrics": dial tcp 172.19.0.11:10257: connect: connection refused
  - down: kube-etcd http://172.19.0.11:2381/metrics: Get "http://172.19.0.11:2381/metrics": dial tcp 172.19.0.11:2381: connect: connection refused
  - down: kube-proxy http://172.19.100.66:10249/metrics: Get "http://172.19.100.66:10249/metrics": dial tcp 172.19.100.66:10249: connect: no route to host
  - down: kube-proxy http://172.19.100.70:10249/metrics: Get "http://172.19.100.70:10249/metrics": dial tcp 172.19.100.70:10249: connect: no route to host
  - down: kube-proxy http://172.19.100.17:10249/metrics: Get "http://172.19.100.17:10249/metrics": dial tcp 172.19.100.17:10249: connect: no route to host
  - down: kube-proxy http://172.19.100.40:10249/metrics: Get "http://172.19.100.40:10249/metrics": dial tcp 172.19.100.40:10249: connect: no route to host
  - down: kube-proxy http://172.19.100.61:10249/metrics: Get "http://172.19.100.61:10249/metrics": dial tcp 172.19.100.61:10249: connect: no route to host
  - down: kube-proxy http://172.19.100.63:10249/metrics: Get "http://172.19.100.63:10249/metrics": dial tcp 172.19.100.63:10249: connect: no route to host
  - down: kube-proxy http://172.19.100.75:10249/metrics: Get "http://172.19.100.75:10249/metrics": dial tcp 172.19.100.75:10249: connect: no route to host
  - down: kube-proxy http://172.19.100.87:10249/metrics: Get "http://172.19.100.87:10249/metrics": dial tcp 172.19.100.87:10249: connect: no route to host

## Agent freshness (real nodes)

| Node | Pod | available | stale | reported by | processes | ok |
|---|---|---|---|---|---:|---|
| kubesentry-control-plane | mesh-m2xn2 | true | false | kubesentry-control-plane | 2 | true  |
| kubesentry-worker | mesh-9tkm8 | true | false | kubesentry-worker | 2 | true  |
| kubesentry-worker2 | mesh-p5mcv | true | false | kubesentry-worker2 | 2 | true  |
| kubesentry-worker3 | mesh-27p2k | true | false | kubesentry-worker3 | 2 | true  |
| kubesentry-worker4 | mesh-7njzz | true | false | kubesentry-worker4 | 2 | true  |
| kubesentry-worker5 | mesh-vmv4b | true | false | kubesentry-worker5 | 2 | true  |
