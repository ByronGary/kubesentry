# kubesentry architecture

kubesentry is a self-hosted Kubernetes observability and debugging dashboard. You run one instance per cluster (several replicas with the Postgres audit store). It covers four things cluster browsers such as Headlamp do not:

- audit-log user activity
- OOMKilled and memory-leak detection
- per-pod process monitoring
- unused PVC cost

The UI is a per-pod "doctor" page backed by a findings worklist.

## Components

```
 kube-apiserver ── LIST+WATCH (informers), SubjectAccessReviews ──┐
   │ audit events: webhook, log file tail, CloudWatch Logs (EKS)  │
   ▼                                                              ▼
 node agent ── POST /agent/report ──▶  kubesentry server  ◀── queries ── Prometheus / AMP
 (DaemonSet, hostPID, /proc only)      ├ internal/kube       informer cache, conversions, reviews (only client-go importer)
                                       ├ internal/snapshot   precomputed view, rebuilt (debounced) as the cluster changes
                                       ├ internal/detectors  pure: association, PVC, OOM, leak, pod, security, RBAC index
                                       ├ internal/auth       proxy/token identity, SubjectAccessReview authorizer
                                       ├ internal/api        JSON routes filtered by the caller's scope, middleware
                                       ├ internal/prom       client, cache, discovery, background leak scanner
                                       ├ internal/audit      parse, tag, merge, memory store, tail, journal
                                       ├ internal/pgstore    Postgres audit store, advisory-lock leadership
                                       ├ internal/cloudwatch EKS audit reader
                                       ├ internal/procmon    /proc scanner, cgroup mapping, indexed per-node store
                                       └ internal/web        go:embed of the built React UI
```

- **Requests never touch the cluster.** Informers keep the cluster in memory; `snapshot.Manager` runs every detector over it at most every couple of seconds and swaps the new view in. Handlers only filter that view by the caller's scope and page it (`internal/api/views.go`), with per-view derived data memoised by `View.Memo`. The last good view keeps serving through API-server outages, marked stale. `-cache=false` lists per request instead, for debugging.
- **Per-user scope.** In proxy mode an SSO proxy passes the user; every namespace they see is confirmed by a SubjectAccessReview (candidates from the view's RBAC index), cached for minutes. Cluster-scoped data needs its cluster-wide permission and otherwise degrades to names only.
- **Dependencies.** client-go only in `internal/kube`, pgx only in `internal/pgstore`, the AWS SDK only in `internal/cloudwatch` and `internal/awsauth`; everything else is stdlib, so tests never need a cluster.
- **State.** Views, authorization decisions and process reports are in memory per replica. Audit history is in memory (with an optional journal) or in Postgres, which several replicas share; the CloudWatch reader and partition maintenance run on the replica holding an advisory lock.
- **Optional sources.** Each optional data source can be absent: `Metrics` (Prometheus), `Audit` and `Processes`. An absent source turns its checks to `unknown`, and `/api/v1/info` reports which sources are enabled and which resources could not be read.
- **Listeners.** Web (UI and API), ingest (agent reports, audit webhook) and ops (probes, metrics, pprof) can be separate; see `docs/contracts.md`.
- **Demo mode.** `internal/demo` provides a synthetic EKS-shaped cluster served through the same snapshot views and handlers. `demo_test.go` drives the real API over that data, so it doubles as the end-to-end acceptance test.

## Kubernetes 1.36 notes

- **cgroup v2.** Since 1.35 the kubelet refuses cgroup v1 by default, so v2 is the path that matters. procmon parses both. On kind, paths look like `/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-burstable.slice/kubelet-kubepods-burstable-pod<uid_>.slice/cri-containerd-<id>.scope`, usually relative to the agent's private cgroup namespace.
- **Container IDs.** The API returns `containerd://<64hex>`. `internal/kube` strips the runtime prefix so the ID matches what procmon reads from cgroups.
- **Native sidecars.** These are init containers with `restartPolicy: Always`. `internal/kube` reports init container statuses (marked `Init`), so sidecar OOM kills and `Init:CrashLoopBackOff` are seen.
- **In-place resize.** Pods can be resized in place, so limits can change while a pod runs. Memory limits come from the container status the kubelet applied, then the spec; kube-state-metrics only with `-prometheus-ksm-limits`.
- **Client version.** client-go is pinned to v0.36.x to match the local cluster.

## Local cluster

`deploy/kind/` and `hack/` bring up kind v0.33.0 on `kindest/node:v1.36.4` (pinned by digest). The cluster has 1 control-plane and 2 workers, with:

- kube-prometheus-stack in `monitoring`, with grafana and alertmanager off
- API server audit logging to `/var/log/kubernetes/audit/audit.log` on the control-plane, using the policy in `deploy/audit-policy.yaml`
- the kubesentry server on the control-plane node, tailing that log
- the agent DaemonSet on every node
- demo workloads in `demo-apps`

See the README section "Local cluster (kind)" for usage, and `deploy/kind/values-kind.yaml` for installing with the Helm chart instead.

## Roadmap

See CLAUDE.md "Next".
