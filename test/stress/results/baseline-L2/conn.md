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
| control-plane (host) | 25 | 26 | 25 | 26 | 27 | 28 | 27 | 49 | 49 |
| control-plane (pod) | 25 | 24 | 51 | 29 | 33 | 23 | 24 | 46 | 45 |
| worker2 (host) | 28 | 5 | 33 | 17 | 33 | 32 | 32 | 47 | 44 |
| worker2 (pod) | 6 | 6 | 16 | 3 | 10 | 10 | 19 | 27 | 49 |
| worker3 (host) | 19 | 20 | 20 | 31 | 32 | 33 | 15 | 46 | 28 |
| worker3 (pod) | 28 | 18 | 31 | 20 | 30 | 13 | 31 | 36 | 36 |
| worker4 (host) | 23 | 29 | 31 | 19 | 29 | 17 | 15 | 30 | 41 |
| worker4 (pod) | 33 | 19 | 32 | 5 | 5 | 29 | 39 | 30 | 49 |
| worker5 (host) | 48 | 28 | 45 | 29 | 31 | 45 | 46 | 38 | 29 |
| worker5 (pod) | 31 | 33 | 30 | 45 | 40 | 17 | 29 | 29 | 28 |
| worker (host) | 40 | 28 | 29 | 33 | 30 | 28 | 32 | 35 | 36 |
| worker (pod) | 29 | 28 | 31 | 40 | 28 | 28 | 32 | 30 | 49 |

## kubesentry → Prometheus

- /api/v1/info metrics: true
- /api/v1/oom?window=1h: metricsAvailable=true, warnings [], 555 ms, 19598 bytes 
- Prometheus targets up map[apiserver:1 coredns:2 kps-kube-prometheus-stack-operator:1 kps-kube-prometheus-stack-prometheus:2 kube-state-metrics:1 kubelet:12 metrics-sim:1 node-exporter:6], down map[kube-controller-manager:1 kube-etcd:1 kube-proxy:256 kube-scheduler:1]
- simulated series (metrics-sim): 5556
  - down: kube-controller-manager https://172.19.0.11:10257/metrics: Get "https://172.19.0.11:10257/metrics": dial tcp 172.19.0.11:10257: connect: connection refused
  - down: kube-etcd http://172.19.0.11:2381/metrics: Get "http://172.19.0.11:2381/metrics": dial tcp 172.19.0.11:2381: connect: connection refused
  - down: kube-proxy http://172.19.100.200:10249/metrics: Get "http://172.19.100.200:10249/metrics": dial tcp 172.19.100.200:10249: connect: no route to host
  - down: kube-proxy http://172.19.100.238:10249/metrics: Get "http://172.19.100.238:10249/metrics": dial tcp 172.19.100.238:10249: connect: no route to host
  - down: kube-proxy http://172.19.100.133:10249/metrics: Get "http://172.19.100.133:10249/metrics": dial tcp 172.19.100.133:10249: connect: no route to host
  - down: kube-proxy http://172.19.100.214:10249/metrics: Get "http://172.19.100.214:10249/metrics": dial tcp 172.19.100.214:10249: connect: no route to host
  - down: kube-proxy http://172.19.100.74:10249/metrics: Get "http://172.19.100.74:10249/metrics": dial tcp 172.19.100.74:10249: connect: no route to host
  - down: kube-proxy http://172.19.0.6:10249/metrics: Get "http://172.19.0.6:10249/metrics": dial tcp 172.19.0.6:10249: connect: connection refused
  - down: kube-proxy http://172.19.100.100:10249/metrics: Get "http://172.19.100.100:10249/metrics": dial tcp 172.19.100.100:10249: connect: no route to host
  - down: kube-proxy http://172.19.100.82:10249/metrics: Get "http://172.19.100.82:10249/metrics": dial tcp 172.19.100.82:10249: connect: no route to host

## Agent freshness (real nodes)

| Node | Pod | available | stale | reported by | processes | ok |
|---|---|---|---|---|---:|---|
| kubesentry-control-plane | mesh-m2xn2 | true | false | kubesentry-control-plane | 2 | true  |
| kubesentry-worker | mesh-9tkm8 | true | false | kubesentry-worker | 2 | true  |
| kubesentry-worker2 | mesh-p5mcv | true | false | kubesentry-worker2 | 2 | true  |
| kubesentry-worker3 | mesh-27p2k | true | false | kubesentry-worker3 | 2 | true  |
| kubesentry-worker4 | mesh-7njzz | true | false | kubesentry-worker4 | 2 | true  |
| kubesentry-worker5 | mesh-vmv4b | true | false | kubesentry-worker5 | 2 | true  |
