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
| control-plane (host) | 43 | 30 | 34 | 33 | 34 | 37 | 41 | 56 | 48 |
| control-plane (pod) | 45 | 34 | 37 | 50 | 33 | 34 | 32 | 15 | 17 |
| worker2 (host) | 33 | 30 | 29 | 2 | 29 | 37 | 36 | 58 | 55 |
| worker2 (pod) | 6 | 48 | 5 | 34 | 9 | 31 | 53 | 49 | 46 |
| worker3 (host) | 46 | 6 | 39 | 1 | 29 | 29 | 5 | 11 | 52 |
| worker3 (pod) | 33 | 50 | 49 | 33 | 46 | 31 | 45 | 44 | 41 |
| worker4 (host) | 16 | 8 | 46 | 37 | 33 | 49 | 12 | 47 | 49 |
| worker4 (pod) | 29 | 7 | 33 | 41 | 41 | 39 | 40 | 49 | 55 |
| worker5 (host) | 11 | 50 | 12 | 51 | 19 | 54 | 39 | 59 | 20 |
| worker5 (pod) | 15 | 11 | 11 | 51 | 55 | 12 | 38 | 52 | 57 |
| worker (host) | 37 | 34 | 4 | 32 | 43 | 56 | 41 | 54 | 41 |
| worker (pod) | 35 | 39 | 4 | 9 | 4 | 29 | 8 | 54 | 58 |

## kubesentry → Prometheus

- /api/v1/info metrics: true
- /api/v1/oom?window=1h: metricsAvailable=true, warnings [], 3268 ms, 256827 bytes 
- Prometheus targets up map[apiserver:1 coredns:2 kps-kube-prometheus-stack-operator:1 kps-kube-prometheus-stack-prometheus:2 kube-state-metrics:1 kubelet:12 metrics-sim:1 node-exporter:6], down map[kube-controller-manager:1 kube-etcd:1 kube-proxy:501 kube-scheduler:1]
- simulated series (metrics-sim): 11245
  - down: kube-controller-manager https://172.19.0.11:10257/metrics: Get "https://172.19.0.11:10257/metrics": dial tcp 172.19.0.11:10257: connect: connection refused
  - down: kube-etcd http://172.19.0.11:2381/metrics: Get "http://172.19.0.11:2381/metrics": dial tcp 172.19.0.11:2381: connect: connection refused
  - down: kube-proxy http://172.19.100.50:10249/metrics: Get "http://172.19.100.50:10249/metrics": dial tcp 172.19.100.50:10249: connect: no route to host
  - down: kube-proxy http://172.19.100.95:10249/metrics: Get "http://172.19.100.95:10249/metrics": dial tcp 172.19.100.95:10249: connect: no route to host
  - down: kube-proxy http://172.19.100.218:10249/metrics: Get "http://172.19.100.218:10249/metrics": dial tcp 172.19.100.218:10249: connect: no route to host
  - down: kube-proxy http://172.19.101.20:10249/metrics: Get "http://172.19.101.20:10249/metrics": dial tcp 172.19.101.20:10249: connect: no route to host
  - down: kube-proxy http://172.19.101.212:10249/metrics: Get "http://172.19.101.212:10249/metrics": dial tcp 172.19.101.212:10249: connect: no route to host
  - down: kube-proxy http://172.19.100.202:10249/metrics: Get "http://172.19.100.202:10249/metrics": dial tcp 172.19.100.202:10249: connect: no route to host
  - down: kube-proxy http://172.19.101.128:10249/metrics: Get "http://172.19.101.128:10249/metrics": dial tcp 172.19.101.128:10249: connect: no route to host
  - down: kube-proxy http://172.19.100.58:10249/metrics: Get "http://172.19.100.58:10249/metrics": dial tcp 172.19.100.58:10249: connect: no route to host

## Agent freshness (real nodes)

| Node | Pod | available | stale | reported by | processes | ok |
|---|---|---|---|---|---:|---|
| kubesentry-control-plane | mesh-m2xn2 | true | false | kubesentry-control-plane | 2 | true  |
| kubesentry-worker | mesh-9tkm8 | true | false | kubesentry-worker | 2 | true  |
| kubesentry-worker2 | mesh-p5mcv | true | false | kubesentry-worker2 | 2 | true  |
| kubesentry-worker3 | mesh-27p2k | true | false | kubesentry-worker3 | 2 | true  |
| kubesentry-worker4 | mesh-7njzz | true | false | kubesentry-worker4 | 2 | true  |
| kubesentry-worker5 | mesh-vmv4b | true | false | kubesentry-worker5 | 2 | true  |
