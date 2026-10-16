# kubesentry reference

Details that used to live in the README: running from source, process monitoring, the UI, flags, the API, how the detectors and audit ingestion work, security notes, required RBAC and the source layout. The complete flag and route contract is in [contracts.md](contracts.md).

## Running from source

```bash
go mod tidy            # downloads client-go and friends
go test ./...
go run ./cmd/server -prometheus-url http://prometheus:9090
```

Open `http://127.0.0.1:8080`. The UI is embedded in the binary and uses no external fonts or CDNs, so it works in air-gapped clusters.

### Try it without a cluster

```bash
go run ./cmd/demo      # synthetic cluster, metrics and audit log at http://127.0.0.1:8080
```

The demo has three leaking or growing containers, four unused volumes and every kind of audit activity. The UI shows a "Demo data" badge.

### Rebuilding the UI

The built UI is committed under `internal/web/dist`. To change it:

```bash
cd web && npm install && npm test && npm run build   # writes ../internal/web/dist
npm run dev                                          # hot reload, proxies /api to :8080
```

### Local cluster (kind)

A local cluster on Kubernetes 1.36.4 with every data source live. It runs Prometheus (kube-prometheus-stack), cert-manager, the API server audit log, the node agent and some demo workloads:

- a leaking pod, a steady one and an orphaned volume
- a Service and Ingress routed to the steady pod
- a NodePort service, and an Ingress without TLS
- a privileged pod
- risky RBAC bindings
- self-signed and CA issuers, with a healthy certificate, one expiring soon and one broken one

Needs Docker, [kind](https://kind.sigs.k8s.io/) v0.33+, kubectl, helm and openssl.

```bash
hack/kind-up.sh            # create cluster "kubesentry", install everything (re-run to redeploy)
hack/audit-scenarios.sh    # generate exec, secret, RBAC, impersonation, token, debug and anonymous events
hack/dashboard.sh          # port-forward the UI to http://localhost:8080 and print the API token
kind delete cluster --name kubesentry
```

The UI asks for the printed API token once per browser tab. The leaking pod shows a trend on its pod page within minutes (pick the 1-hour window) and is OOMKilled about every 30 minutes. The orphaned volume appears after `-pvc-min-age` (5 minutes here).

The manifests in `deploy/kind/` are for a local cluster only. The server runs as uid 0 on the control-plane node so it can read the root-owned audit log, and agents report over plain http inside the cluster.


## Process monitoring

The Kubernetes API cannot see inside containers, so a small agent runs on each node and reports the processes that belong to pods.

```bash
# Server: setting a token turns the feature on
go run ./cmd/server -agent-token "$TOKEN" ...

# Agent, one per node (see deploy/agent-daemonset.yaml)
go run ./cmd/agent -server https://kubesentry:8080 -node "$NODE_NAME" -token "$TOKEN"

# Try the scanner on any Linux host and see what it would send
go run ./cmd/agent -once
```

Each pod page then shows a Processes table: name, container, CPU, memory, threads and command line.

**What it reads.** `/proc/<pid>/{cgroup,stat,statm,cmdline}` only. The cgroup path maps a process to a pod UID and container ID (cgroup v1 and v2, systemd and cgroupfs drivers, containerd, CRI-O and Docker).

**What it never touches.** Environment variables, open files, memory, and any process outside a pod. Command lines are truncated to 512 characters, and values that look like secrets are masked: `--password=x`, `--password x`, `API_KEY=x`, `token:x`, and `user:pass@` in URLs. Masking is best effort, so treat the command line as sensitive and keep `-api-token` set.

**Privileges.** The agent needs `hostPID: true` to see other pods' processes. It does not need to be privileged or run as root, and mounts nothing from the host. Namespaces enforcing the Pod Security `baseline` or `restricted` levels reject `hostPID`, so label the agent's namespace `pod-security.kubernetes.io/enforce=privileged`. A node whose `/proc` is mounted with `hidepid=2` hides other users' processes from a non-root agent.

**Security.** `POST /agent/report` fails closed: it answers 503 until `-agent-token` is set, and requires that bearer token. Use https between agent and server outside a trusted network; the agent warns when it is given an `http` URL. Reports are limited to 8 MiB and 20,000 processes. The server keeps only each node's latest report in memory, and flags data older than two minutes as stale.

**Limits.** CPU is computed from deltas between reports, so the first report after an agent starts shows 0. There is no process history yet, only the latest snapshot.

## The UI

- **Findings** is a ranked worklist across OOM kills, memory leaks, unused volumes and notable activity.
- **Pods** lists pods; a pod page is a one-stop diagnosis: checks (phase, OOM, restarts, memory growth, volumes, activity), a memory chart per container with the limit and a projection to it, volumes, and recent audit activity.
- **Map** draws a namespace as Ingress → Service → workload → Pod → Node, with each pod's volumes. A toggle switches to the node view: nodes with requested vs allocatable CPU and memory, pressure, taints and their pods.
- **Workloads**, **Storage** (claims, unused claims with cost, volumes, classes), **Security** (findings grouped by check, Pod Security labels per namespace) and **Certificates** (cert-manager) each give a status per object.
- **Memory** and **Activity** are the full tables, with URL-driven filters.

Access has three modes (`-auth-mode`):

- **proxy**: an SSO proxy (oauth2-proxy, as the Helm chart deploys it) signs users in and passes their identity in headers. With the sidecar, kubesentry listens only on a Unix socket the two containers share (`-addr unix:///var/run/kubesentry/web.sock`) and trusts the headers on it alone; a proxy elsewhere is trusted from `-auth-trusted-proxy-cidrs` (never `0.0.0.0/0` without `-auth-allow-any-proxy`, and with a startup warning for loopback, which `kubectl port-forward` also comes from). Each user sees exactly what their Kubernetes RBAC lets them list: kubesentry asks the API server with SubjectAccessReviews and caches the answers (`-authz-cache-ttl`). A user can force a recheck after an RBAC change. Cluster-scoped data (nodes, volumes, storage classes, cluster RBAC, ClusterIssuers) needs its cluster-wide permission; without it the pages show only names related to the user's own objects. See `docs/deploy-eks.md`.
- **token** (default): the shared `-api-token`, a break-glass identity that sees everything. The UI asks for it and keeps it for the browser tab only. Without a token the server only listens on loopback.
- **none**: everyone sees everything; loopback only. This is the local mode for running on your own workstation (`docs/run-remote.md`). Here, and in token mode without a token, only the Host names `localhost`, `127.0.0.1` and `[::1]` are answered (`-allowed-hosts`), so a web page cannot reach the server through DNS rebinding.

Credentials are resolved from `-kubeconfig` (with `-kube-context`, or its current context), then the in-cluster service account, then `KUBECONFIG` / `~/.kube/config`. With `-eks-cluster`, kubesentry signs every request with an EKS token it mints from AWS credentials, and without a kubeconfig takes the endpoint and CA from `eks:DescribeCluster`.

### Flags

The most used; `docs/contracts.md` lists every flag, and `kubesentry -h` describes them. Durations take days too (`30d`).

| Flag | Default | Purpose |
|---|---|---|
| `-addr` | `127.0.0.1:8080` | UI and API listen address. Use `:8080` to listen on all interfaces, together with `-api-token` or `-auth-mode=proxy`; `unix:///path` listens on a Unix socket (mode 0660) for an SSO proxy sidecar |
| `-allowed-hosts` | loopback names without auth, else any | Host header patterns (`host[:port]`, `*.domain`, `*`) the web listener answers; others get 403 |
| `-ingest-addr`, `-ops-addr` | | Separate listeners for agent reports and the audit webhook, and for `/healthz`, `/readyz`, `/metrics` (and `/debug/pprof/` with `-pprof`). Empty: ingest and probes on `-addr` |
| `-auth-mode` | `token` | `token`, `proxy` or `none` (above); `-auth-user-header`, `-auth-groups-header`, `-auth-trusted-proxy-cidrs` configure proxy mode |
| `-api-token` | | Break-glass bearer token for `/api/` routes (env `KUBESENTRY_API_TOKEN`) |
| `-max-inflight-per-identity` | `4` | Requests one user may have in flight on the expensive routes (`/oom`, pod diagnostics, audit summary); more get 429 |
| `-tls-cert`, `-tls-key` | | Serve HTTPS on the web and ingest listeners |
| `-kubeconfig` | | Path to kubeconfig |
| `-kube-context` | current context | kubeconfig context to use |
| `-eks-cluster` | | Sign in to this EKS cluster with a token kubesentry mints from AWS credentials (no AWS CLI needed); without `-kubeconfig`/`-kube-context` the endpoint and CA come from `eks:DescribeCluster`. Region from `-aws-region` |
| `-prometheus-via-apiserver` | `auto` | Reach discovered Prometheus Services and `-prometheus-service` through the API server's service proxy: `auto` (outside the cluster), `true` or `false` |
| `-cache` | `true` | Serve from shared informers and a precomputed view; `false` lists the cluster on every request (debugging) |
| `-cluster-name` | | Shown in the UI; names the EKS CloudWatch log group |
| `-prometheus-url` | | Prometheus (or an AMP workspace, signed with SigV4) for leak detection; `PROMETHEUS_TOKEN` for bearer auth (preferred over `user:password@` in the URL, which is sent as basic auth but kept out of logs and `/info`). Empty: discover an in-cluster Prometheus (`-prometheus-autodiscover`) |
| `-pvc-min-age` | `24h` | Ignore unused PVCs younger than this |
| `-pvc-default-price` | unset | USD per GiB-month for classes nothing else prices; unset means no estimate. EBS classes are priced from a table (`-ebs-prices`), and a StorageClass annotation `kubesentry.io/price-per-gib-month` wins |
| `-pvc-class-prices` | | Per storage class, e.g. `gp3=0.08,io2=0.125` |
| `-audit-token` | | Bearer token the audit webhook requires; the webhook is disabled without it (env `KUBESENTRY_AUDIT_TOKEN`) |
| `-audit-log-file` | | Follow a kube-apiserver audit log file |
| `-audit-from-start` | `false` | With `-audit-log-file`, read existing content instead of starting at the end |
| `-audit-store` | `memory` | `memory` or `postgres` (`-pg-dsn` or `KUBESENTRY_PG_DSN`, `-audit-retention`, default `30d`; `-pg-max-conns` 10 per replica and `-pg-query-timeout` 10s, past which an audit read answers 503 + Retry-After) |
| `-audit-journal` | | Memory store: JSONL file that keeps audit history across restarts (not rotated) |
| `-audit-max-events` | `50000` | Memory store: audit events kept |
| `-cloudwatch` | `false` | Read EKS audit logs from CloudWatch Logs |
| `-agent-token` | | Bearer token node agents send; setting it enables process monitoring (env `KUBESENTRY_AGENT_TOKEN`) |
| `-alerts` | `false` | Turn findings into alerts for Alertmanager or the AMP alert manager (`-alertmanager-url`, token from `ALERTMANAGER_TOKEN`; `-external-url` links each alert to its page). Notify only, never writes to the cluster; with Postgres one replica notifies. See `docs/alerts.md` |

## API

Every list shows only what the caller may see (proxy mode). Lists page with `?limit=` (default 200, at most 1000) and the `continue` token of the previous page.

- `GET /healthz`, `GET /readyz` (503 until the cluster has been read; then 200, naming degraded dependencies).
- `GET /api/v1/pvcs/unused[?minAge=48h]` returns PVCs no live pod mounts, most expensive first, plus a total estimated monthly cost.
- `GET /api/v1/info` reports the enabled features, who is calling and what they may see, the cluster, the age of the view being served and how far back audit history goes.
- `GET /api/v1/alerts[?namespace=&owner=&state=]` (with `-alerts`) lists the alert findings the caller may see: open, acknowledged, silenced, and resolved in the last day (`docs/alerts.md`).
- `POST /api/v1/auth/recheck` re-reads the caller's access (at most once a minute).
- `GET /api/v1/pods[?namespace=]` lists pods, OOMKilled first, with readiness, the worst waiting reason, node and owner.
- `GET /api/v1/pods/{namespace}/{name}/diagnostics[?window=6h]` returns checks, per-container memory series with any leak finding, volumes and recent audit activity for one pod.
- `GET /api/v1/pods/{namespace}/{name}/processes` returns the pod's processes as last reported by its node's agent (`available: false` if none has).
- `POST /agent/report` receives a node report from the agent. Authenticated with `-agent-token`.
- `GET /api/v1/agents` lists the node agents and when each last reported.
- `GET /api/v1/oom[?window=24h]` returns `events` (containers whose last termination was OOMKilled) and `leaks` (containers with steadily rising memory), sorted by how soon they hit their limit. Window is 10m to 168h; for the background scan's window (`-leak-scan-window`) leaks come from that scan, which looks only at containers whose memory grows. If Prometheus is unreachable you still get `events`, plus a `warnings` entry.
- `GET /api/v1/map[?namespace=]` returns one namespace's topology: Ingress → Service → workload (via ReplicaSets) → Pod → Node, and Pod → PVC. Services link to pods through their EndpointSlices, with ready, not ready and terminating counts. Without a namespace, the server picks the busiest non-system namespace.
- `GET /api/v1/nodes[?summary=true]` returns nodes with placement (zone, instance type, node group or Karpenter pool, spot or on-demand, Fargate), requested vs allocatable CPU and memory, pressure conditions, taints and their pods; `/api/v1/nodes/{name}` one node.
- `GET /api/v1/workloads[?namespace=]` returns Deployments, StatefulSets, DaemonSets, Jobs and CronJobs with a status per workload.
- `GET /api/v1/storage` returns claims (paged), persistent volumes, storage classes and the unused claims with their cost.
- `GET /api/v1/security[?view=summary]` returns risks: privileged or root containers, host access, added capabilities, cluster-admin and wildcard RBAC, secret readers, bindings to anonymous users, namespaces without Pod Security labels, NodePort and LoadBalancer services, and Ingresses without TLS. Findings in system namespaces and about built-in `system:` RBAC are marked `system`.
- `GET /api/v1/certificates` returns cert-manager Certificates (expiry, readiness), Issuers and ClusterIssuers (type, server, readiness message), and failing CertificateRequests. It returns `installed: false` without cert-manager.
- `POST /audit/webhook` receives audit events (see below). Authenticated with `-audit-token`, not `-api-token`.
- `GET /api/v1/audit/events` lists events, newest first. Parameters: `since` (default `24h`), `user`, `namespace`, `resource`, `verb`, `tag`, `actors` (comma list of `user`, `serviceaccount`, `system`), `includeReads` (`true`/`false`), `limit` (default 200, max 1000), `continue`.
- `GET /api/v1/audit/summary[?since=24h]` aggregates per user and per tag: totals, writes, execs, secret reads, denied requests.

Audit routes exist only when audit ingestion is enabled.

## How the detectors work

**Unused PVCs.** A PVC is unused when no pod outside phase `Succeeded`/`Failed` references it (including generic ephemeral volumes). `Pending` PVCs are skipped because with `WaitForFirstConsumer` they are unused by design. Caveat: a StatefulSet scaled to zero leaves PVCs unmounted on purpose; `-pvc-min-age` only reduces that noise.

**OOMKilled.** Read from container status. The Kubernetes API keeps only the *last* termination per container, so this is "most recent OOM", not a count.

**Leak detection.** Working-set memory is pulled from Prometheus and split into process lifetimes wherever it drops more than 30% (a restart). A least-squares line is fitted to each lifetime; a container is flagged when a lifetime grows at least 1 MiB/h with R² of at least 0.8, meaning steady climb rather than spiky load. Two or more leaky lifetimes give `high` confidence. If a memory limit is known, `timeToLimitHours` extrapolates when the next OOM will hit. Thresholds are in `detectors.DefaultLeakOptions()`.

Prometheus must scrape cAdvisor (`container_memory_working_set_bytes`) and kube-state-metrics (`kube_pod_container_resource_limits`).

## Audit log ingestion

kubesentry turns the API server audit log into a "who did what" view. There are three ways to feed it.

**1. Webhook (self-managed clusters).** Give the API server the files in `deploy/` and start kubesentry with `-audit-token`, `-tls-cert` and `-tls-key`:

```
--audit-policy-file=/etc/kubernetes/audit-policy.yaml
--audit-webhook-config-file=/etc/kubernetes/audit-webhook-kubeconfig.yaml
--audit-webhook-mode=batch
```

**2. Log file.** `-audit-log-file /var/log/kubernetes/audit.log` follows the file written by `--audit-log-path` and handles rotation and truncation. It starts at the end unless you add `-audit-from-start`.

**3. CloudWatch Logs (EKS).** With `-cloudwatch` and `-cluster-name`, kubesentry reads `/aws/eks/<cluster>/cluster` itself (IAM: `logs:FilterLogEvents`), resuming from a checkpoint; with several replicas and Postgres only one reads at a time.

**4. Bulk import (EKS and anything else).** EKS does not let you set API server flags. After enabling audit logging in the cluster's logging settings, the events land in CloudWatch Logs (log group `/aws/eks/<cluster>/cluster`, streams starting with `kube-apiserver-audit-`; check the names in your account). Export and post them in chunks:

```bash
aws logs filter-log-events --log-group-name /aws/eks/CLUSTER/cluster \
  --log-stream-name-prefix kube-apiserver-audit \
  --start-time "$(date -d '-1 day' +%s)000" --output json \
  | jq -c '.events[].message | fromjson' > audit.jsonl
split -l 5000 audit.jsonl chunk_
for f in chunk_*; do
  curl -sS -X POST -H "Authorization: Bearer $AUDIT_TOKEN" --data-binary @"$f" https://kubesentry:8443/audit/webhook
done
```

The webhook accepts an `EventList`, a single `Event`, or newline-delimited events, and rejects a payload atomically if any part is malformed. Payloads are capped at 32 MiB.

### What you see

Raw audit logs are mostly noise, so the default view of `/api/v1/audit/events` hides system components and plain reads. It always keeps events that carry a tag:

| Tag | Meaning |
|---|---|
| `exec` | `pods/exec` or `pods/attach` (the command is in `requestURI`) |
| `portforward` | `pods/portforward` |
| `debug-container` | `kubectl debug` (ephemeral containers) |
| `secret-access` | Read of a Secret |
| `secret-change` | Write to a Secret |
| `rbac-change` | Write to roles, rolebindings, clusterroles or clusterrolebindings |
| `delete` | `delete` or `deletecollection` |
| `impersonate` | Impersonation used |
| `token-request` | A ServiceAccount token was minted |
| `denied` | HTTP 401/403 or an authorizer `forbid` |
| `anonymous` | `system:anonymous` or the `system:unauthenticated` group |

A request's `ResponseStarted` and `ResponseComplete` events (exec sessions, watches) are merged into one record by `auditID`. For AWS IAM authentication, `user.extra` carries `arn` and `sessionName`, which are surfaced so you can see the person behind a shared role. Those key names vary by authenticator, so treat them as best effort.

### Security and limits

- Only metadata is kept. Request and response bodies are never decoded, and the example policy logs at `Metadata` level so they are never written in the first place. `requestURI` is kept, and for `exec` it contains the command line, which can include secrets typed as arguments.
- Audit data shows who is doing what in your cluster. Listen on loopback or set `-api-token`; the server warns if neither applies. The webhook refuses all requests until `-audit-token` is set, because otherwise anyone could inject fake records.
- History is held in memory by default (`-audit-max-events`, oldest dropped first); `-audit-journal` replays it after a restart, but the file is not rotated. `-audit-store=postgres` keeps it in daily partitions for `-audit-retention` and is required for more than one replica.
- Audit ingestion needs no Kubernetes RBAC.

## Required RBAC

The Helm chart creates these (`charts/kubesentry/templates/rbac.yaml` is authoritative). A resource kubesentry may not list is reported as unavailable in `/info` and its checks are skipped; the server still starts.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kubesentry
rules:
  - apiGroups: [""]
    resources: ["pods", "persistentvolumeclaims", "persistentvolumes", "services", "nodes", "namespaces"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["apps"]
    resources: ["deployments", "replicasets", "statefulsets", "daemonsets"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["batch"]
    resources: ["jobs", "cronjobs"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["networking.k8s.io"]
    resources: ["ingresses"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["discovery.k8s.io"]
    resources: ["endpointslices"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["storage.k8s.io"]
    resources: ["storageclasses"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["cert-manager.io"]   # optional; without it the Certificates page says so
    resources: ["certificates", "certificaterequests", "issuers", "clusterissuers"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["authorization.k8s.io"]   # per-user scope (proxy mode) and the startup permission probe
    resources: ["subjectaccessreviews", "selfsubjectaccessreviews"]
    verbs: ["create"]
```

kubesentry never reads Secrets. The cert-manager page shows expiry from the Certificate status, not from the issued Secret.

## Layout

```
cmd/server            entrypoint and flags
cmd/agent             node agent for process monitoring
cmd/demo              demo server with synthetic data
web                   React + TypeScript UI source (builds into internal/web/dist)
internal/web          embeds the built UI
internal/demo         synthetic cluster, metrics and audit data
internal/kube         the only package that imports client-go: informer cache, conversions, SubjectAccessReviews
internal/model        plain data types shared across packages
internal/detectors    pure analysis logic (association, PVC, OOM, leak, security, RBAC index), no cluster needed
internal/snapshot     the precomputed view requests are served from, rebuilt as the cluster changes
internal/auth         authentication (proxy headers, token) and the SubjectAccessReview authorizer
internal/metrics      Prometheus text exposition of kubesentry's own metrics
internal/prom         Prometheus client, result cache, discovery probe, background leak scanner
internal/awsauth      SigV4 signing for Amazon Managed Prometheus, EKS tokens and DescribeCluster
internal/procmon      /proc scanner, cgroup-to-pod mapping, redaction, per-node store
internal/audit        audit event parsing, tagging, memory store, file tailer
internal/pgstore      Postgres audit store (the only package that imports pgx)
internal/cloudwatch   EKS audit log reader for CloudWatch Logs
internal/api          JSON HTTP API, scoped per caller
charts/kubesentry     Helm chart
deploy                example audit policy, API server webhook config, kind profile
```

Only `internal/kube` imports client-go, only `internal/pgstore` pgx, and only `internal/cloudwatch` and `internal/awsauth` the AWS SDK; everything else depends on the standard library, so the detectors and the API are unit tested with synthetic data.

## Roadmap

**User activity, next steps.** Alerts on tagged events such as `exec` into production or a new `cluster-admin` binding.

**Process monitoring, next steps.** Process history and a per-process memory trend, so a leaking child process is named in the leak finding; a process tree view; an optional eBPF mode for short-lived processes.

**Also planned.** Persisted history of findings.
