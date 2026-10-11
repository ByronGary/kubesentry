# Cluster cautions: cautions-after

24 snapshots from 2026-10-11T19:06:50+00:00 to 2026-10-11T21:17:29+00:00.

## Alerts that point at real problems

| Alert | Severity | State | Peak count | Seen in | First / last | Example |
|---|---|---|---:|---:|---|---|
| PrometheusMissingRuleEvaluations | warning | pending | 36 | 22/24 | 19:06:50 / 21:17:29 | namespace=monitoring, pod=prometheus-kps-kube-prometheus-stack-prometheus-0, container=prometheus, job=kps-kube-prometheus-stack-prometheus, instance=10.240.2.2:9090, service=kps-kube-prometheus-stack-prometheus |
| NodeDiskIOSaturation | warning | pending | 6 | 1/24 | 21:00:18 / 21:00:18 | namespace=monitoring, pod=kps-prometheus-node-exporter-wwz9k, container=node-exporter, job=node-exporter, instance=172.19.0.9:9100, service=kps-prometheus-node-exporter |
| KubesentryPostgresErrors | warning | pending | 2 | 1/24 | 19:18:11 / 19:18:11 | namespace=kubesentry, pod=kubesentry-5897598d7f-ds9x7 |
| KubeAPIErrorBudgetBurn | warning | pending | 2 | 5/24 | 19:23:53 / 19:46:32 |  |
| NodeClockNotSynchronising | warning | pending | 1 | 1/24 | 19:12:29 / 19:12:29 | namespace=monitoring, pod=kps-prometheus-node-exporter-9bmf9, container=node-exporter, job=node-exporter, instance=172.19.0.10:9100, service=kps-prometheus-node-exporter |
| PrometheusKubernetesListWatchFailures | warning | pending | 1 | 1/24 | 19:23:53 / 19:23:53 | namespace=monitoring, pod=prometheus-kps-kube-prometheus-stack-prometheus-0, container=prometheus, job=kps-kube-prometheus-stack-prometheus, instance=10.240.2.8:9090, service=kps-kube-prometheus-stack-prometheus |
| KubeClientErrors | warning | pending | 1 | 1/24 | 19:23:53 / 19:23:53 | namespace=default, job=apiserver, instance=172.19.0.11:6443 |

## Alerts caused by the stress environment

| Alert | Severity | State | Peak count | Why it is an artifact |
|---|---|---|---:|---|
| etcdInsufficientMembers | critical | firing | 1 | kind binds etcd metrics to localhost, so Prometheus cannot scrape them |
| KubeProxyInstanceUnreachable | warning | firing | 6 | kube-proxy binds its metrics to 127.0.0.1 (kind's default, and EKS's unless the kube-proxy config is patched); on KWOK fake nodes nothing runs at all |
| TargetDown | warning | firing | 4 | targets that kind binds to localhost or that run on KWOK nodes |
| PrometheusNotConnectedToAlertmanagers | warning | firing | 1 | Alertmanager is disabled in the stress profile (no alert routing) |
| KubeControllerManagerInstanceUnreachable | warning | firing | 1 | kind binds kube-controller-manager metrics to localhost |
| KubeSchedulerInstanceUnreachable | warning | firing | 1 | kind binds kube-scheduler metrics to localhost |
| etcdMembersDown | warning | firing | 1 | kind binds etcd metrics to localhost |
| Watchdog | none | firing | 1 | always-firing heartbeat that proves the alert pipeline works |
| KubeProxyInstanceUnreachable | warning | pending | 6 | kube-proxy binds its metrics to 127.0.0.1 (kind's default, and EKS's unless the kube-proxy config is patched); on KWOK fake nodes nothing runs at all |
| TargetDown | warning | pending | 4 | targets that kind binds to localhost or that run on KWOK nodes |
| PrometheusNotConnectedToAlertmanagers | warning | pending | 1 | Alertmanager is disabled in the stress profile (no alert routing) |
| KubeControllerManagerInstanceUnreachable | warning | pending | 1 | kind binds kube-controller-manager metrics to localhost |
| KubeSchedulerInstanceUnreachable | warning | pending | 1 | kind binds kube-scheduler metrics to localhost |
| etcdMembersDown | warning | pending | 1 | kind binds etcd metrics to localhost |

## Control plane and monitoring health (worst value seen)

| Signal | Worst | Last |
|---|---:|---:|
| API server 429s /s | 0.0103 | 0 |
| API server 5xx /s | 0.141 | 0 |
| APF queued requests | 0 | 0 |
| API server inflight | 9 | 2 |
| API read p99 | 697 ms | 97 ms |
| API write p99 | 99 ms | 23 ms |
| etcd request p99 | 86 ms | 22 ms |
| Prometheus missed rule evals /s | 0.137 | 0.134 |
| Prometheus rule eval failures /s | 0 | 0 |
| Prometheus head series | 9.15e+04 | 8.72e+04 |
| Prometheus RSS | 573 MiB | 504 MiB |
| Slowest rule group | 70 ms | 56 ms |
| Real node min mem available | 24% | 28% |
| Real node min disk available | 76% | 76% |
| Real node max load/CPU | 1.78 | 0.356 |

Largest object counts in etcd (last snapshot): pods 9544, rolebindings.rbac.authorization.k8s.io 3448, replicasets.apps 1769, deployments.apps 1755, events 1720

Containers above 85% of their memory limit: demo-apps/leaky-d6f4f9b88-j5q2l/app (97%)

## Pods, nodes and objects in trouble (peak across snapshots)

| Signal | Peak | Example |
|---|---:|---|
| Pods: OOMKilled(last) | 1 | demo-apps/leaky-d6f4f9b88-j5q2l |
| Pods: CrashLoopBackOff | 1 | stress-tricky/crashloop-6f96d49bc9-z89ts |
| Pods: PendingOver5m | 1 | stress-tricky/imagepull-686cfbcbfd-w7rx2 |
| Pods: ErrImagePull | 1 | stress-tricky/imagepull-686cfbcbfd-w7rx2 |
| Pods: Unschedulable | 1 | stress-tricky/unschedulable-b7b9bbcdf-826nw |
| Pods: ImagePullBackOff | 1 | stress-tricky/imagepull-686cfbcbfd-w7rx2 |
| Certificates not ready | 9 | demo-apps/broken-tls: DoesNotExist; fraud-01/web-tls-0: DoesNotExist; fraud-03/api-tls-0: DoesNotExist |
| Certificates expiring < 14d | 117 | billing-01/api-tls-0: 9d left; billing-01/consumer-tls-1: 1d left; billing-02/cache-tls-1: 1d left |

Most restarted pods (last snapshot): stress-tricky/crashloop-6f96d49bc9-z89ts ×70, demo-apps/leaky-d6f4f9b88-j5q2l ×11, cert-manager/cert-manager-76ffbfcbfc-2hmq5 ×6

## Warning events (peak count per reason)

| Reason (object) | Peak | Example |
|---|---:|---|
| Unhealthy (Pod) | 8151 | cert-manager/cert-manager-76ffbfcbfc-2hmq5: Liveness probe failed: HTTP probe failed with statuscode: 500 |
| Failed (Pod) | 1389 | stress-tricky/imagepull-686cfbcbfd-w7rx2: Failed to pull image "registry.invalid/stress/does-not-exist:1": failed to pull and unpack image "registry.invalid/stress/does-not-exist:1": failed to resolve r |
| BackOff (Pod) | 265 | kubesentry/kubesentry-5897598d7f-jxhdq: Back-off restarting failed container oauth2-proxy in pod kubesentry-5897598d7f-jxhdq_kubesentry(f7218e2c-f26d-4fea-8450-efcea2e0b19e) |
| FailedScheduling (Pod) | 40 | stress-tricky/unschedulable-b7b9bbcdf-826nw: 0/506 nodes are available: 4 node(s) didn't match Pod's node affinity/selector, 502 node(s) had untolerated taint(s). no new claims to deallocate, preemption: 0 |
| FailedMount (Pod) | 1 | stress-oidc/oidc-869bddf968-qp94m: MountVolume.SetUp failed for volume "key" : secret "oidc-signing-key" not found |

Host memory available: min 3899 MiB, last 4200 MiB.
