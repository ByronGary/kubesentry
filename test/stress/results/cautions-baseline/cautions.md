# Cluster cautions: cautions-baseline

20 snapshots from 2026-10-11T16:49:04+00:00 to 2026-10-11T18:30:34+00:00.

## Alerts that point at real problems

| Alert | Severity | State | Peak count | Seen in | First / last | Example |
|---|---|---|---:|---:|---|---|
| PrometheusMissingRuleEvaluations | warning | pending | 35 | 19/20 | 16:49:04 / 18:30:34 | namespace=monitoring, pod=prometheus-kps-kube-prometheus-stack-prometheus-0, container=prometheus, job=kps-kube-prometheus-stack-prometheus, instance=10.240.2.2:9090, service=kps-kube-prometheus-stack-prometheus |
| NodeClockNotSynchronising | warning | pending | 1 | 1/20 | 17:28:18 / 17:28:18 | namespace=monitoring, pod=kps-prometheus-node-exporter-9bmf9, container=node-exporter, job=node-exporter, instance=172.19.0.10:9100, service=kps-prometheus-node-exporter |

## Alerts caused by the stress environment

| Alert | Severity | State | Peak count | Why it is an artifact |
|---|---|---|---:|---|
| etcdInsufficientMembers | critical | firing | 1 | kind binds etcd metrics to localhost, so Prometheus cannot scrape them |
| KubeProxyInstanceUnreachable | warning | firing | 501 | kube-proxy binds its metrics to 127.0.0.1 (kind's default, and EKS's unless the kube-proxy config is patched); on KWOK fake nodes nothing runs at all |
| TargetDown | warning | firing | 4 | targets that kind binds to localhost or that run on KWOK nodes |
| PrometheusNotConnectedToAlertmanagers | warning | firing | 1 | Alertmanager is disabled in the stress profile (no alert routing) |
| KubeControllerManagerInstanceUnreachable | warning | firing | 1 | kind binds kube-controller-manager metrics to localhost |
| KubeSchedulerInstanceUnreachable | warning | firing | 1 | kind binds kube-scheduler metrics to localhost |
| etcdMembersDown | warning | firing | 1 | kind binds etcd metrics to localhost |
| Watchdog | none | firing | 1 | always-firing heartbeat that proves the alert pipeline works |
| KubeProxyInstanceUnreachable | warning | pending | 245 | kube-proxy binds its metrics to 127.0.0.1 (kind's default, and EKS's unless the kube-proxy config is patched); on KWOK fake nodes nothing runs at all |

## Control plane and monitoring health (worst value seen)

| Signal | Worst | Last |
|---|---:|---:|
| API server 429s /s | 0 | 0 |
| API server 5xx /s | 0 | 0 |
| APF queued requests | 0 | 0 |
| API server inflight | 5 | 2 |
| API read p99 | 250 ms | 16 ms |
| API write p99 | 361 ms | 23 ms |
| etcd request p99 | 44 ms | 21 ms |
| Prometheus missed rule evals /s | 0.134 | 0.13 |
| Prometheus rule eval failures /s | 0 | 0 |
| Prometheus head series | 1.02e+05 | 1.01e+05 |
| Prometheus RSS | 655 MiB | 560 MiB |
| Slowest rule group | 64 ms | 55 ms |
| Real node min mem available | 24% | 30% |
| Real node min disk available | 77% | 77% |
| Real node max load/CPU | 1.04 | 1.04 |

Largest object counts in etcd (last snapshot): pods 10036, rolebindings.rbac.authorization.k8s.io 3136, replicasets.apps 1761, deployments.apps 1753, roles.rbac.authorization.k8s.io 1576

Containers above 85% of their memory limit: demo-apps/leaky-d6f4f9b88-j5q2l/app (88%)

## Pods, nodes and objects in trouble (peak across snapshots)

| Signal | Peak | Example |
|---|---:|---|
| Pods: OOMKilled(last) | 2 | demo-apps/leaky-d6f4f9b88-j5q2l, kubesentry/kubesentry-5cfb87696b-4jtl7 |
| Pods: CrashLoopBackOff | 2 | kubesentry/kubesentry-5cfb87696b-4jtl7, stress-tricky/crashloop-6f96d49bc9-z89ts |
| Pods: PendingOver5m | 1 | stress-tricky/imagepull-686cfbcbfd-w7rx2 |
| Pods: ImagePullBackOff | 1 | stress-tricky/imagepull-686cfbcbfd-w7rx2 |
| Pods: Unschedulable | 1 | stress-tricky/unschedulable-b7b9bbcdf-826nw |
| Certificates not ready | 9 | demo-apps/broken-tls: DoesNotExist; fraud-01/web-tls-0: DoesNotExist; fraud-03/api-tls-0: DoesNotExist |
| Certificates expiring < 14d | 117 | billing-01/api-tls-0: 9d left; billing-01/consumer-tls-1: 1d left; billing-02/cache-tls-1: 1d left |

Most restarted pods (last snapshot): stress-tricky/crashloop-6f96d49bc9-z89ts ×38, demo-apps/leaky-d6f4f9b88-j5q2l ×6, cert-manager/cert-manager-76ffbfcbfc-2hmq5 ×3, kubesentry/kubesentry-5cfb87696b-528pf ×3

## Warning events (peak count per reason)

| Reason (object) | Peak | Example |
|---|---:|---|
| Unhealthy (Pod) | 4137 | kubesentry/kubesentry-5cfb87696b-4jtl7: Readiness probe failed: Get "http://10.240.0.7:8080/healthz": dial tcp 10.240.0.7:8080: connect: connection refused |
| Failed (Pod) | 704 | stress-tricky/imagepull-686cfbcbfd-w7rx2: Error: ImagePullBackOff |
| BackOff (Pod) | 181 | kubesentry/kubesentry-5cfb87696b-4jtl7: Back-off restarting failed container server in pod kubesentry-5cfb87696b-4jtl7_kubesentry(ced09e38-7a12-44b5-aeda-5d5f37d007de) |
| FailedScheduling (Pod) | 107 | stress-tricky/unschedulable-b7b9bbcdf-826nw: 0/106 nodes are available: 102 node(s) had untolerated taint(s), 4 node(s) didn't match Pod's node affinity/selector. no new claims to deallocate, preemption: 0 |
| BadConfig (CertificateRequest) | 12 | catalog-02/api-tls-0-1: Certificate will be issued with an empty Issuer DN, which contravenes RFC 5280 and could break some strict clients |
| ClusterIPNotAllocated (Service) | 3 | tax-05/cache: Cluster IP [IPv4]: 10.96.192.142 is not allocated; repairing |
| RequestFailed (Certificate) | 1 | reporting-02/cache-tls-1: Failed to create CertificateRequest: certificaterequests.cert-manager.io "cache-tls-1-1" already exists |

Host memory available: min 3910 MiB, last 5263 MiB.
