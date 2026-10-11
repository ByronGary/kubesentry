# kubesentry architecture

kubesentry is a self-hosted Kubernetes observability and debugging dashboard. You run one instance per cluster. It covers four things cluster browsers such as Headlamp do not:

- audit-log user activity
- OOMKilled and memory-leak detection
- per-pod process monitoring
- unused PVC cost

The UI is a per-pod "doctor" page backed by a findings worklist.

## Components

```
 kube-apiserver ── LIST/GET pods, PVCs ─────────────┐
   │ audit events: webhook (POST) or log file tail  │
   ▼                                                ▼
 node agent ── POST /agent/report ──▶  kubesentry server  ◀── query_range ── Prometheus
 (DaemonSet, hostPID, /proc only)      ├ internal/kube      client-go adapter (only client-go importer)
                                       ├ internal/prom      HTTP client, PromQL with quoted names
                                       ├ internal/audit     parse, tag, merge, store, tail, journal
                                       ├ internal/procmon   /proc scanner, cgroup mapping, per-node store
                                       ├ internal/detectors pure: PVC, OOM, leak, pod checks
                                       ├ internal/api       JSON routes + token auth
                                       └ internal/web       go:embed of the built React UI
```

- **Stdlib only.** Everything except `internal/kube` and `cmd/server` uses only the standard library, so tests never need a cluster.
- **State.** Everything is held in memory. The audit journal is the only persistence.
- **Optional sources.** Each optional data source can be absent: `Metrics` (Prometheus), `Audit` and `Processes`. An absent source turns its checks to `unknown`, and `/api/v1/info` reports which sources are enabled.
- **Demo mode.** `internal/demo` provides synthetic sources. `demo_test.go` drives the real API over that data, so it doubles as the end-to-end acceptance test.

## Kubernetes 1.36 notes

- **cgroup v2.** Since 1.35 the kubelet refuses cgroup v1 by default, so v2 is the path that matters. procmon parses both. On kind, paths look like `/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-burstable.slice/kubelet-kubepods-burstable-pod<uid_>.slice/cri-containerd-<id>.scope`, usually relative to the agent's private cgroup namespace.
- **Container IDs.** The API returns `containerd://<64hex>`. `internal/kube` strips the runtime prefix so the ID matches what procmon reads from cgroups.
- **Native sidecars.** These are init containers with `restartPolicy: Always`. `internal/kube` does not read init container statuses yet, so a sidecar OOM is missed. This is the next fix in `convertPod`.
- **In-place resize.** Pods can be resized in place, so limits can change while a pod runs. The leak detector uses the current kube-state-metrics limit.
- **Client version.** client-go is pinned to v0.36.x to match the local cluster.

## Local cluster

`deploy/kind/` and `hack/` bring up kind v0.33.0 on `kindest/node:v1.36.4` (pinned by digest). The cluster has 1 control-plane and 2 workers, with:

- kube-prometheus-stack in `monitoring`, with grafana and alertmanager off
- API server audit logging to `/var/log/kubernetes/audit/audit.log` on the control-plane, using the policy in `deploy/audit-policy.yaml`
- the kubesentry server on the control-plane node, tailing that log
- the agent DaemonSet on every node
- demo workloads in `demo-apps`

See the README section "Local cluster (kind)" for usage.

## Roadmap

See CLAUDE.md "Next". It covers process history, alerting on tagged audit events, CloudWatch polling for EKS, a persistent store, shared informers, packaging and CI.
