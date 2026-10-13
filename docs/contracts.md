# Contracts for the enterprise hardening work

This file fixes the shared interfaces before the parallel workstreams start. The Go types it names already exist in the tree and compile. Change a contract only through the integrator, and update this file, the Go types and `web/src/types.ts` together.

## Workstreams and ownership

| Stream | Owns (exclusively) | Implements |
|---|---|---|
| K kube | `internal/kube/**` | informer `Cache` implementing `snapshot.Source` + `snapshot.Notifier` (and the old `ClusterSource`/`InventorySource`/`CertSource` from listers), transforms, conversions for every new model field, cluster info, Prometheus Service discovery, `Reviewer` (SubjectAccessReview), aws-auth parsing |
| D detectors | `internal/detectors/**`, `internal/snapshot/**` | association (`assoc.go`), `RBACIndex` (implements `auth.Candidates`), `Policy` use everywhere, pricing, placement, container checks, cert thresholds, exposure annotations, snapshot `Manager` / `OnDemand` / `FromLists` / `Static` |
| U auth+ops | `internal/auth/**`, `internal/metrics/**`, new files `internal/api/middleware.go`, `internal/api/authz.go` | header and token authenticators, cached SAR authorizer, metrics registry, gzip/ETag/LRU/rate-limit/inflight/timeouts/access-log middleware |
| A audit | `internal/audit/**`, `internal/pgstore/**`, `internal/cloudwatch/**`, `hack/pg-test.sh` | `audit.Store` on MemoryStore (indexed), Postgres store, CloudWatch reader, `cwfake` |
| P prom+procs | `internal/prom/**`, `internal/awsauth/**`, `internal/procmon/**`, `cmd/agent/**` | result cache + singleflight, matchers, leak scanner (`detectors.LeakReport`), SigV4 transport, indexed process store, agent jitter/gzip/backoff/fanout |
| H packaging | `charts/**`, `Dockerfile`, `deploy/**`, `hack/kind-up.sh`, `hack/build-images.sh`, `docs/deploy-eks.md` | Helm chart, multi-arch image, kind values profile, EKS guide |
| W web | `web/src/**`, `internal/web/dist/**` | UI for everything below |
| S stress | `test/stress/**`, `hack/stress-*.sh` | harness |
| Integrator | `internal/api/*.go` (existing files), `cmd/server/**`, `internal/demo/**`, `internal/model/**`, README, ARCHITECTURE, CLAUDE.md | wiring, handlers on views + scope + pagination |

Shared contract files (read-only for streams): `internal/model/*.go`, `internal/detectors/inventory.go`, `internal/detectors/policy.go`, `internal/snapshot/snapshot.go`, `internal/auth/auth.go`, the `Store`/`Query`/`Cursor`/`Coverage` part of `internal/audit/store.go`, `web/src/types.ts`.

Dependency rule: client-go only in `internal/kube` (and `test/stress`); pgx only in `internal/pgstore`; AWS SDK v2 only in `internal/cloudwatch`, `internal/awsauth`, `internal/aws/**`. Everything else is stdlib, `internal/alerts` included (its Postgres store is `pgstore.AlertStore`, its SigV4 transport comes from `internal/awsauth` through `cmd/server`).

## HTTP

### Listeners
- `-addr` (default `127.0.0.1:8080`): UI and `/api/`. `unix:///path` listens on a Unix socket instead (chmod 0660; a stale socket file is replaced, a live one or any other file refuses to start; plain HTTP even with `-tls-cert`; needs `-ingest-addr`). The chart's oauth2-proxy sidecar reaches kubesentry through `unix:///var/run/kubesentry/web.sock` in a shared in-memory `emptyDir`, so with the sidecar there is no TCP web port.
- `-ingest-addr` (e.g. `:8081`): `POST /agent/report`, `POST /audit/webhook`, token-authenticated. Empty: served on `-addr`.
- `-ops-addr` (e.g. `:9090`): `/healthz`, `/readyz`, `/metrics`, and `/debug/pprof/` when `-pprof`. Empty: `/healthz` and `/readyz` on `-addr`, no metrics. Set: the probes are only there.
- `/readyz` is 503 until caches have synced and the first view exists; afterwards it stays ready. On the ops listener it reports degraded sources in its body: `{status: "ready"|"starting", degraded?: {name: reason}, unavailable?: {source: reason}}`. `degraded` names failing dependencies (`postgres` ping, `cloudwatch` reader errors, a `snapshot` serving its last good view after failed rebuilds, `prometheus` when it cannot be queried). A degraded dependency never fails readiness. `prometheus` is judged from every request kubesentry sends it (pages, the leak scanner, and a probe every 15s): down after 2 failed requests in a row (a transport error, a timeout, 5xx, 401, 403 or 429; not a request its caller cancelled), up again at the next answer; the reason (`queries fail: HTTP 503 Service Unavailable`, `queries fail: unreachable: dial tcp ...`, `queries fail: no answer in time`) names the status or the network error, never the query, and does not change while the failure stays the same. On the web listener (no `-ops-addr`) it answers `{status}` only, without dependency errors. On SIGTERM it turns 503 for `-shutdown-drain` before the listeners stop.
- The UI's static files and `/healthz` are unauthenticated. The web listener answers only Host headers matching `-allowed-hosts` (403 otherwise; the probes are exempt). It defaults to `localhost,127.0.0.1,[::1]` (any port) when every local caller is trusted (`-auth-mode=none`, or token mode without a token), against DNS rebinding, and to any Host otherwise. Ingest routes keep their token guards and body limits and are not rate limited per user; `/api/` gets authentication, the per-identity rate limit and the in-flight cap.

### Routes (new and changed)
| Route | Change |
|---|---|
| `GET /api/v1/info` | adds `version` (the build's `main.version`), `identity`, `capabilities`, `cluster`, `snapshot`, `auditStore`, `prometheus`, `unavailable` (see `web/src/types.ts` `Info`). `unavailable` leaves out sources this server was not given ("not configured"), and lists `prometheus` with the reason while a configured or discovered Prometheus cannot be queried (as the ops `/readyz` does under `degraded`). `auditStore` (cluster-wide event counts and span) only with the `audit` or `clusterAudit` capability, and only when the store answers within 50ms: the Postgres store serves it from a cache it refreshes in the background, so `/info` never queues behind the database; `auditStore` is left out of an answer that would have to wait. With Postgres, `events` is exact below 100,000 and above that an estimate from the planner's statistics (within a few percent); `oldest` and `newest` are exact. `prometheus.url` never carries user info |
| `GET /api/v1/pods` | `?namespace=&limit=&continue=`; items gain `ready`, `reason`, `node`, `workload`; response gains `continue` |
| `GET /api/v1/workloads` | `?limit=&continue=`; items gain `notReady`, `waiting` |
| `GET /api/v1/nodes` | `?summary=true` omits `pods` (keeps `podCount`); items gain `placement`. `pods`, `podCount`, `cpuRequestedMilli` and `memoryRequestedBytes` cover the caller's namespaces unless they see all |
| `GET /api/v1/nodes/{name}` | one node with its pods; 404 when the caller may not see it or the view has no such node (no authorization review per unknown name) |
| `GET /api/v1/storage` | claims, classes gain cost/price fields; `?limit=&continue=` pages claims; `volumes`, `classes` and `unused` are complete on every page |
| `GET /api/v1/security` | `?view=summary` returns counts + the 200 most severe non-system findings (no `continue`); `?limit=&continue=` pages findings. Counts cover only what the caller can see: namespaced RBAC findings need `ViewRBAC` in their namespace |
| `GET /api/v1/map` | edges gain `how`, endpoint counts; kinds gain `ReplicaSet`, `Controller`; response gains `namespaceStats` (live pods per visible namespace, with `system`). Without `?namespace=` the server picks the caller's busiest non-system namespace; a namespace they cannot see, or without pods in the view, is 404 (the latter before any authorization review) |
| `GET /api/v1/pods/{ns}/{name}/diagnostics` | gains `activityWindow` (Go duration). 404 when the view has no such pod (before any authorization review, same body) or the caller cannot see the namespace; activity is left out, with a warning, without `ViewAudit` there. Memory limits come from the pod unless kube-state-metrics reports them |
| `GET /api/v1/pods/{ns}/{name}/processes` | 404 when the view has no such pod or the caller cannot see the namespace, 403 without `ViewProcesses` there |
| `GET /api/v1/oom` | leaks come from the background `LeakReport` when the window matches its window (scan warnings are passed on in `warnings`); any other window queries Prometheus now: every container for a caller who sees all namespaces, otherwise only their namespaces (`namespace=~` matchers, split to keep each query under ~8 KiB), and nothing at all when they see none. Pod diagnostics, `/oom` and the audit summary share a per-identity cap (`-max-inflight-per-identity`, 429 with `Retry-After`) |
| `GET /api/v1/audit/events` | `?continue=` (opaque cursor); scope-filtered; `limit` defaults to 200. A caller who may read no audit event gets an empty list without the store being asked (`/audit/summary` likewise). Both answer 503 with `Retry-After: 5` when the audit store is overloaded (`audit.ErrOverloaded`: every Postgres read slot stayed busy for 2s, or the query ran past `-pg-query-timeout` and was cancelled), instead of holding the request until the route or the SSO proxy times out |
| `GET /api/v1/agents` | new: `[{node, lastReport, processes, bytes, stale, dropped?}]` (a bare array); 403 without `ViewAgents`; absent (404) when process monitoring is off |
| `POST /agent/report` | plain or gzip JSON (`Content-Encoding: gzip`): 413 when the body or the decompressed report exceeds 8 MiB or it lists more processes than the store's per-node cap (20,000; decoding stops there), 415 for another encoding, 400 when invalid. The process store evicts the longest-silent nodes beyond 5000 nodes or 256 MiB of process data |
| `POST /audit/webhook` | 503 with `Retry-After` when the audit store's write queue is full |
| `GET /api/v1/overview` | new: the landing dashboard (`OverviewResponse` in `types.ts`), `?namespace=&owner=`. Scoped like every route, then narrowed by the filters (a filter that selects nothing visible answers zeros, 400 only for a malformed value); `namespaces` lists the namespaces the caller can see before the filter, sorted, for the picker; counts and owners only from visible namespaces. `nodes` null without `nodes`; pool `cpuRequestedPct`/`memRequestedPct` cover the selected namespaces' pods unless the caller sees every namespace and gives no filter (the `/nodes` rule), and are left out for Fargate. `certificates` null without cert-manager. `security` counts follow `/security` (`rbac` for namespaced RBAC findings, `clusterRBAC` for cluster-scoped ones, which a filter leaves out). Pods: `failing` is what the map shows critical (stuck containers, the node failed it, phase Failed while still shown), `pending` is Pending past `-pending-grace`, `running` the rest in phase Running; `byReason` covers failing and pending pods. `attention`: the 10 worst, folded per workload root (a Job under its CronJob), from unhealthy workloads, nodes not ready (`nodes` only; under a filter only nodes running the selected pods), crit security findings, certificates warn or crit, and the background leak scan; `href` uses the pages' own parameters (`#/workloads?namespace=&q=`, `#/security?check=&q=`, `#/certificates?q=ns/name`, `#/nodes?node=`, `#/pods/ns/name`). `activity`: null without audit configured, or for a caller who may read no audit event; otherwise counts over 24h by users and service accounts (as the Activity summary counts them) from the store's tag counts, never the 24h summary; `execProduction` counts exec in production namespaces; `latest` holds the 5 newest exec, rbac-change, denied or impersonate events (secret reads are counted, not listed); `productionNamespaces` are the caller's visible namespaces with the production label; under a filter only the selected namespaces; null, and the answer `Cache-Control: no-store`, when the store does not answer within 3s. `health.cloudwatchLagSeconds` only for callers who may read audit events, `health.agents` with `agents`. `badges` leave out zero counts (`pods` is failing as crit, else pending as warn). `history`: per-replica, in-memory, 24h in 5-minute buckets, summed over what the caller may see; `security.newSince24h` (crit+warn now minus a day ago) only once the history covers a day. The view-derived part is memoised per (scope, selected namespaces, view version); the response cache keys on `nodes`, `rbac`, `clusterRBAC`, `audit`, `clusterAudit`, `agents` and namespace scope, plus a 10s window, so `ageSeconds`, health and activity are at most 10s old. Owner comes from the namespace annotation `-owner-annotation`; production from the namespace label `-production-label` |
| `POST /api/v1/auth/recheck` | new: forgets the caller's cached authorization decisions and returns `{capabilities}`; at most once a minute per identity (429 otherwise) |
| `GET /api/v1/alerts` | new with `-alerts` (404 without): `AlertsResponse` in `types.ts`, `?namespace=&owner=&state=&limit=&continue=`. The findings kubesentry alerts on that are open, acknowledged or silenced, and those resolved in the last 24h, most troubled first (state, then critical first, then newest), keyset-paged. Served from the alerting runner's board (the leader's own state, or what another replica last read from `alert_findings`, every 15s), never evaluated per request. Scoped: a namespaced finding needs `ViewNamespace` there, a namespaced RBAC drift finding also `ViewRBAC` there, a cluster-scoped one (RBAC drift) `ViewClusterRBAC`. `counts` covers everything the caller can see by state, before the filters. Cached on `ViewNamespace`, `ViewRBAC`, `ViewClusterRBAC`, the view version and the board's version |
| `GET /api/v1/info` (alerts) | gains `alerts: {enabled, sink: "alertmanager"\|"none", leader?, lastSentAt?, lastError?}`; the delivery fields are this replica's (only the leader sends). `lastError` names the Alertmanager by position (`alertmanager 2 of 2: HTTP 503 Service Unavailable`, `...: unreachable: dial tcp ...`), never the response body |
| `GET /api/v1/overview` (alerts) | gains `alerts?: {open, acknowledged, silenced, byOwner}` (absent without `-alerts`): unresolved findings in the caller's scope and filter, with the `/alerts` gates; a filter leaves cluster-scoped findings out |

### Authentication rules
- Proxy mode with `-addr unix://...` reads identity headers only on connections to that socket; TCP CIDRs are then ignored. Over TCP it reads them only from `-auth-trusted-proxy-cidrs` (a CIDR admitting every address is refused without `-auth-allow-any-proxy`; loopback CIDRs log a startup warning, since `kubectl port-forward` arrives from loopback). From anywhere else they are ignored.
- The user header must appear exactly once (a repeated one is 401). `X-Forwarded-Groups` is comma-separated (oauth2-proxy joins a user's groups with commas; repeated headers add up), so group names containing commas are not supported. The chart's schema allows only the headers oauth2-proxy sets and strips (`X-Forwarded-Email`, `X-Forwarded-User`, `X-Forwarded-Preferred-Username`; `X-Forwarded-Groups`) unless `auth.allowCustomHeaders` is true.
- A proxy user starting with a platform principal prefix (`system:` always, plus `-system-principal-prefixes`, default `system:,eks:`) is refused, and IdP groups with such a prefix (after `-auth-groups-prefix`) are dropped, so no IdP group can become `system:masters` or an `eks:` identity; groups produced by the admin's group map are kept as written.
- The ingest token guards compare SHA-256 digests in constant time, so neither the token nor its length shows in the response time.
- Every identity, including the token and `none` identities, carries `system:authenticated`.
- The UI learns the mode from `/info` `identity.source`. In proxy mode oauth2-proxy guards every path, so a 401 mid-session means the SSO session expired: the UI reloads the page to sign in again. In token mode a 401 shows the token prompt.

Pod readiness: `ready` on pods and node pods is omitted when the pod has not reported a Ready condition (Go `*bool` with `omitempty`), so "unknown" is never shown as "not ready". `/info` `namespaces` is the number of namespaces the caller can see.

Pagination: `limit` (default 200, max 1000) and an opaque `continue` token; the response carries `continue` when there is more. A larger `limit` is clamped to 1000; a limit below 1 or not a number, and a `continue` token that is malformed or from another route, is 400. Tokens are keyset positions in the route's sort order (most troubled first), so a rebuilt view between pages neither repeats nor skips items whose sort key did not change; they are not signed, and editing one only moves the start. Responses of the view-backed list routes may come from a cache keyed by path, query, the caller's scope over every capability the route depends on, and the view version (`X-Kubesentry-Cache: hit|miss`). Each request resolves its scopes once (a per-request memo), so the key and the handler's filter always agree. Nothing is cached before the first view exists, nor any response built while an authorization lookup failed (such a response fails closed: it shows less).

### Scope per route
Every namespaced item is shown only if the caller holds `auth.ViewNamespace` in its namespace. Further gates: processes `ViewProcesses`; audit `ViewAudit` per namespace and `ViewClusterAudit` for events without a namespace; namespaced RBAC findings (RoleBindings, Roles) need `ViewRBAC` (list rolebindings) in their namespace, so listing pods there is not enough; nodes, PVs, storage classes, ClusterRole/ClusterRoleBinding findings, ClusterIssuers need their cluster-wide capability; `/agents` needs `ViewAgents`. Without one, the page degrades (names only, status `unknown`) instead of failing: nodes that run the caller's pods, volumes and classes their claims use, ClusterIssuers their certificates use; cluster-scoped security findings are left out. Class claim counts and issuer certificate counts then cover only the caller's namespaces. A caller with no grants gets empty lists, not errors. `/info` returns the caller's capabilities so the UI hides what it cannot use. The break-glass token and `-auth-mode=none` are unrestricted, and so is every caller of an `api.Server` with neither an authenticator nor an API token (tests, the demo).

## Server flags (new)

| Flag | Default | Purpose |
|---|---|---|
| `-auth-mode` | `token` | `proxy`, `token` or `none` (`none` only on loopback). Token mode without `-api-token` refuses a non-loopback `-addr` (on loopback it acts as `none`). Proxy mode still accepts the API token as the break-glass identity |
| `-auth-user-header` / `-auth-groups-header` | `X-Forwarded-Email` / `X-Forwarded-Groups` | identity headers from the proxy |
| `-auth-username-prefix` / `-auth-groups-prefix` | `""` | match the API server's (or EKS OIDC provider's) prefixes |
| `-auth-group-map-file` | | JSON `{ "idp-group": ["k8s-group", ...] }` |
| `-auth-trusted-proxy-cidrs` | `127.0.0.1/32,::1/128` | over TCP, only these may send identity headers (ignored with a Unix socket `-addr`) |
| `-auth-allow-any-proxy` | `false` | permit `0.0.0.0/0` or `::/0` in `-auth-trusted-proxy-cidrs` |
| `-allowed-hosts` | loopback names when every local caller is trusted, else any | Host header patterns the web listener answers (`host[:port]`, `*.domain`, `[v6]:port`, `*`); others get 403 |
| `-auth-sign-out-url` | `""` | returned in `/info` as `signOutURL`; the chart sets `/oauth2/sign_out` when oauth2-proxy is enabled |
| `-authz-qps` / `-authz-cache-ttl` / `-authz-deny-ttl` | `200` / `5m` / `5m` | SubjectAccessReview budget and cache. Grants and revocations take up to the TTL to show; a user can force a recheck (below) |
| `-authz-share-by-groups` | `false` | cache by group set instead of per user; a user the RBAC index finds named as a subject in any binding is still cached per user |
| `-ingest-addr` / `-ops-addr` / `-pprof` | | listeners (above) |
| `-cache` | `true` | informer cache; `false` lists per request (debugging) |
| `-kube-qps` / `-kube-burst` | `50` / `100` | client-go limits |
| `-kube-context` | current context | kubeconfig context (`ConfigOverrides.CurrentContext`); setting it skips the in-cluster configuration |
| `-eks-cluster` | | sign in to EKS with a token kubesentry mints (no AWS CLI); without `-kubeconfig`/`-kube-context` the endpoint and CA come from `eks:DescribeCluster`; also the default `-cluster-name` |
| `-prometheus-via-apiserver` | `auto` | `auto` (when not in cluster), `true`, `false`: discovered Prometheus Services and `-prometheus-service` are queried at `https://<apiserver>/api/v1/namespaces/<ns>/services/<name>:<port>/proxy` with the kube client's transport; `PROMETHEUS_TOKEN` and SigV4 are not applied there |
| `-snapshot-min-interval` / `-snapshot-max-delay` | `2s` / `10s` | view rebuild debounce |
| `-cluster-name` | | shown in the UI; CloudWatch log group default `/aws/eks/<name>/cluster` |
| `-system-namespaces` / `-system-namespaces-add` | Policy default / | replace or extend system namespaces |
| `-system-principal-prefixes` / `-builtin-rbac-prefixes` | `system:,eks:` / `system:,eks:,kubeadm:` | |
| `-node-label-keys-add` | | extra node labels to keep |
| `-restart-warn`, `-restart-crit`, `-oom-recent`, `-pending-grace`, `-not-ready-grace`, `-terminating-grace`, `-recent-pod`, `-activity-window`, `-leak-crit-hours`, `-leak-min-slope`, `-leak-min-r2`, `-leak-drop-ratio`, `-leak-min-points`, `-cert-crit-cap`, `-cert-warn-cap` | Policy defaults | thresholds |
| `-pvc-default-price` | unset | now optional: unset means "no estimate" |
| `-ebs-prices` | Policy defaults | `gp3=0.08,io2=0.125,...` per region |
| `-owner-annotation` | `kubesentry.io/owner` | namespace annotation naming the owning team (Overview owner filter and attention, alert routing); one outside `kubesentry.io/` is added to the informers' namespace annotation allowlist |
| `-production-label` | `environment=production` | namespace label `key=value` marking production (exec into production) |
| `-prometheus-autodiscover` | `true` | find an in-cluster Prometheus when `-prometheus-url` is empty |
| `-prometheus-service` | | `namespace/name:port` to pin discovery |
| `-prometheus-selector` | | extra matchers, e.g. `cluster="prod"` |
| `-prometheus-sigv4` / `-aws-region` | auto for `aps-workspaces.*.amazonaws.com` | Amazon Managed Prometheus |
| `-prometheus-ksm-limits` | `false` | read limits from kube-state-metrics instead of pod specs |
| `-leak-scan-interval` / `-leak-scan-window` | `5m` / `24h` | background leak scanner |
| `-audit-store` | `memory` | `memory` or `postgres` |
| `-pg-dsn` (env `KUBESENTRY_PG_DSN`) / `-pg-schema` | / `kubesentry` | Postgres |
| `-audit-retention` | `30d` (Postgres) | |
| `-pg-max-conns` / `-pg-query-timeout` | `10` / `10s` | Postgres connections per replica (audit reads share all but two, kept for writes and maintenance; at least 3) and the limit on one audit read |
| `-audit-redact-exec-args` | `false` | drop exec command arguments from stored request URIs |
| `-cloudwatch` / `-cloudwatch-log-group` / `-cloudwatch-stream-prefix` / `-cloudwatch-start` / `-cloudwatch-endpoint` | `false` / `/aws/eks/<cluster>/cluster` / `kube-apiserver-audit` / `24h` / | EKS audit reader |
| `-aws-auth` | `false` | read kube-system/aws-auth (needs the chart's scoped Role) |
| `-rate-limit` / `-rate-burst` / `-max-inflight` | `20` / `40` / `512` | per identity / total |
| `-max-inflight-per-identity` | `4` | requests one identity may have in flight on the expensive routes (`/oom`, pod diagnostics, audit summary); more get 429 with `Retry-After`; 0 disables |
| `-tls-cert` / `-tls-key` | | TLS for the web and ingest listeners; the ops listener stays plain HTTP (probes, scraping) |
| `-shutdown-drain` / `-shutdown-timeout` | `5s` / `20s` | on SIGTERM: how long `/readyz` fails before the listeners stop, then how long requests in flight may take |
| `-agent-interval` | `15s` | the agents' `-interval`; process data is stale after 8 and forgotten after 40 of these |
| `-version` | | print the version and exit |
| `-alerts` | `false` | evaluate findings and send them to Alertmanager (`docs/alerts.md`); with `-audit-store=postgres` only the holder of the `alerts` advisory lock does, with the memory store the one replica. Needs `-cache=true` |
| `-alertmanager-url` | | Alertmanager base URLs, comma-separated (`/api/v2/alerts` appended unless present); every alert to each. No user info (refused). Needs `-alerts`. Empty with `-alerts`: findings tracked, nobody notified |
| `-alertmanager-ca-file` / `-alertmanager-sigv4` / `-alertmanager-basic-auth-user` | / auto for `aps-workspaces.*` URLs / | CA bundle added to the system roots; SigV4 (service `aps`, region from the URL or `-aws-region`); basic auth user. Secrets from the environment only: `ALERTMANAGER_TOKEN` (bearer) or `ALERTMANAGER_PASSWORD`; one kind of credential at a time. Mixing AMP and other URLs needs `-alertmanager-sigv4` |
| `-alerts-interval` / `-alerts-resend` / `-alerts-resolve-grace` | `30s` / `1m` / `5m` | evaluate after view builds at most (and in a quiet cluster at least) every interval; re-post open alerts every resend with `endsAt` = now + 4 × resend (resend ≥ interval); resolve a finding gone this long (`endsAt` = now) |
| `-alerts-max-new` | `50` | more new alerts in one evaluation go out as one `KubesentryFindingsDigest` per owner |
| `-alerts-default-owner` | `platform` | owner of findings in namespaces without the owner annotation, and of cluster-scoped findings |
| `-alerts-leak-crit-hours` | `0` (= `-leak-crit-hours`) | a memory leak alert is critical when the limit is closer |
| `-alerts-runbook-url` | `https://github.com/ByronGary/kubesentry/blob/main/docs/alerts.md` | `runbook_url` = this + `#<alertname lower case>` |
| `-external-url` | | kubesentry's URL as users reach it; alerts link to their finding there (`kubesentry_url`, `generatorURL`) |

Every duration flag also takes days (`30d`, `1d12h`). `-leak-min-slope` is a growth per hour in bytes, with an optional unit (`1MiB`, `512KiB`). `GOMEMLIMIT`, when unset, defaults to 90% of the cgroup memory limit. Kept from before: `-addr`, `-kubeconfig`, `-api-token`, `-agent-token`, `-audit-token`, `-prometheus-url` (with `PROMETHEUS_TOKEN`), `-pvc-min-age`, `-pvc-class-prices`, `-audit-log-file`, `-audit-from-start`, `-audit-journal` (memory store only) and `-audit-max-events` (memory store).

Remote mode (`docs/run-remote.md`): `internal/awsauth` mints the EKS token (`EKSTokenSource.Token`: `k8s-aws-v1.` + base64url of a presigned STS `GetCallerIdentity` URL with `x-k8s-aws-id` signed, valid 14 minutes or until the credentials expire) and calls `DescribeCluster` with its SigV4 signer. `internal/kube` takes the token as a plain `ClientOptions.TokenSource func(ctx) (token, expiry, error)`, caches it until a minute before expiry or a 401, and drops the kubeconfig's credentials; `ClientOptions.ExecFallback` is asked for one when the kubeconfig's `aws eks get-token` or `aws-iam-authenticator` plugin is not installed. `Clients.InCluster` says which configuration was used, and `Clients.ServiceProxy(ns, name, port)` returns a Service's proxy URL and the authenticated transport (`rest.TransportFor`). The cgroup memory limit is read on Linux only; the server builds for darwin, windows and linux.

Agent flags (new): `-jitter` (0.2), `-gzip` (true), `-server-fanout` (a bare host, e.g. the headless ingest Service: the agent resolves it and posts to every address with the scheme and port of `-server`, verifying TLS against the `-server` host; if resolution fails it posts to `-server` alone), `-ca-file`, `-version`. Both binaries take `-X main.version=...` at build time; the server's Kubernetes user agent is `kubesentry/<version>`, the agent's `kubesentry-agent/<version>`.

## Cluster-sourced configuration
- Namespace label `kubesentry.io/system: "true" | "false"`.
- Namespace annotation `kubesentry.io/owner: <team>` (or `-owner-annotation`); every `kubesentry.io/*` namespace annotation is kept for alert routing hints, other namespace annotations are dropped.
- Namespace label `environment=production` (or `-production-label`).
- StorageClass annotation `kubesentry.io/price-per-gib-month: "0.08"`.
- Service annotation `kubesentry.io/prometheus: "true"` marks the Prometheus to discover.
- Node labels (kept): `topology.kubernetes.io/{zone,region}`, `node.kubernetes.io/instance-type`, `kubernetes.io/{arch,os}`, `eks.amazonaws.com/{nodegroup,capacityType,compute-type}`, `karpenter.sh/{nodepool,capacity-type}`, `karpenter.k8s.aws/instance-family`, `node-role.kubernetes.io/*`.
- Service annotations (kept): `service.beta.kubernetes.io/aws-load-balancer-{scheme,internal,type,nlb-target-type}`.
- Ingress annotations (kept): `alb.ingress.kubernetes.io/{scheme,certificate-arn,listen-ports,ssl-redirect}`, `kubernetes.io/ingress.class`.

## Helm values (top level)
`clusterName`, `image`, `imagePullSecrets`, `agent`, `replicas`, `updateStrategy`, `server{cache,kubeQPS,kubeBurst,snapshot...,rateLimit,rateBurst,maxInflight,maxInflightPerIdentity,allowedHosts,systemPrincipalPrefixes,builtinRBACPrefixes,nodeLabelKeysAdd,pprof}`, `tls{enabled,existingSecret}`, `tokens{api,agent,audit}{existingSecret,key}`, `rbac{viewerRoles.*.aggregateTo}`, `resources`, `serviceAccount{create,name,annotations}`, `auth{mode,userHeader,groupsHeader,allowCustomHeaders,usernamePrefix,groupsPrefix,groupMap,trustedProxyCIDRs,allowAnyProxy,authzQPS,authzCacheTTL,authzDenyTTL,shareByGroups}`, `oauth2Proxy{enabled,image,provider,issuerURL,clientID,existingSecret,upstreamTimeout,trustedProxyIPs,extraArgs,sessionStore}`, `prometheus{url,autodiscover,service,selector,ksmLimits,bearerTokenSecret,leakScan,amp{enabled,workspaceURL,region}}`, `audit{store,retention,maxEvents,redactExecArgs,postgres{existingSecret,dsnKey,schema,maxConns,queryTimeout,sslmode,sslRootCert},sources{webhook{enabled},cloudwatch{enabled,logGroup,streamPrefix,start,endpoint},file{path,fromStart,hostPathDir}}}`, `eks{clusterName,region,awsAuth{read}}`, `systemNamespaces{replace,add}`, `thresholds{...}`, `pricing{defaultPrice,ebsPrices,classPrices}`, `alerts{enabled,ownerAnnotation,production{labelKey,labelValue},defaultOwner,interval,resend,resolveGrace,maxNew,leakCritHours,runbookBaseURL,alertmanager{urls,existingSecret,tokenKey,basicAuth{username,passwordKey},sigv4,ca{configMap,secret,key}}}`, `externalURL`, `pdb`, `networkPolicy{...,egress.podIdentityAgent,egress.alertmanager{toCIDRs,toNamespaces,ports}}`, `topologySpread`, `ingress`, `metrics{serviceMonitor,prometheusRule,grafanaDashboards}`, `apf{enabled}`, `extraArgs`, plus the usual pod knobs (resources, probes, affinity, tolerations, extra env/volumes/containers). The chart is authoritative: `charts/kubesentry/values.yaml` and `values.schema.json`. With `alerts.enabled` the chart refuses `replicas > 1` without `audit.store=postgres` (the lock), and a token Secret together with AMP's SigV4. Postgres TLS comes from `PGSSLMODE`/`PGSSLROOTCERT` env, so pgstore must build its config with `pgxpool.ParseConfig`.

## Metrics (`/metrics` on the ops listener)
`kubesentry_http_requests_total{route,code}`, `kubesentry_http_request_duration_seconds{route}`, `kubesentry_http_inflight`, `kubesentry_http_cache_total{result}`, `kubesentry_snapshot_build_seconds`, `kubesentry_snapshot_age_seconds`, `kubesentry_snapshot_version`, `kubesentry_informer_objects{resource}`, `kubesentry_kube_requests_total{verb,resource,code}`, `kubesentry_authz_reviews_total{result}`, `kubesentry_authz_cache_total{result}`, `kubesentry_prometheus_query_seconds{kind}`, `kubesentry_prometheus_cache_total{result}`, `kubesentry_audit_ingested_total{source}`, `kubesentry_audit_queue_depth`, `kubesentry_audit_store_errors_total`, `kubesentry_cloudwatch_lag_seconds`, `kubesentry_agent_reports_total{code}`, `kubesentry_agent_nodes_reporting`, plus Go runtime metrics.

Added with alerting phase B:
- `kubesentry_findings{check,severity}`: open (unresolved) alert findings on the replica that evaluates; the others report 0. `check` is one of the alert checks below, `severity` `warning` or `critical`; no object, namespace or owner labels.
- `kubesentry_alerts_sent_total{result}`: alerts posted to Alertmanager, per URL; `sent`, `failed` (every attempt failed, or a 4xx other than 429), `dropped` (queue full, or leadership lost).
- `kubesentry_alerts_queue_depth`, `kubesentry_alerts_evaluation_seconds` (histogram), `kubesentry_alerts_leader` (1 on the evaluating replica).
- `kubesentry_http_rejected_total{reason}`: `/api/` requests turned away before routing: `rate_limit` (429), `max_inflight` (503), `unauthenticated` (401).
- `kubesentry_dependency_up{dependency}`: 1 while a configured dependency works, from the state behind `/readyz`: `snapshot` (0 before the first view and while serving a stale one), `prometheus` (1 while none is known), `postgres`, `cloudwatch`, `alertmanager` (0 while the latest delivery to some URL failed).
- `kubesentry_leak_scan_runs_total{result}`: `ok`, `partial` (some queries failed), `failed` (no fresh findings).
- `kubesentry_snapshot_last_change_timestamp_seconds`: when the informers last announced a change (every poll without them); newer than the view's build time means a change waits for a rebuild.

Label values: `route` is one of `info`, `auth_recheck`, `overview`, `alerts`, `pods`, `pod_diagnostics`, `pod_processes`, `pvcs_unused`, `oom`, `workloads`, `nodes`, `node`, `storage`, `security`, `map`, `certificates`, `audit_events`, `audit_summary`, `agents`, `ingest_agent_report`, `ingest_audit_webhook`. `kubesentry_kube_requests_total` uses the Kubernetes verb (`list`, `watch`, `get`, `create`, ...), the resource (with `/subresource`; `discovery` for non-resource paths) and the status code or `error`. `kubesentry_audit_ingested_total{source}` is `webhook`, `file` (lines read) or `cloudwatch`.

## Postgres schema (`internal/pgstore/migrations/0001_audit.sql`, `0002_read_indexes.sql`, `0003_alerts.sql`)
```sql
CREATE TABLE IF NOT EXISTS audit_events (
  audit_id text COLLATE "C" NOT NULL, time timestamptz NOT NULL, stage_rank smallint NOT NULL, stage text NOT NULL,
  verb text NOT NULL, username text NOT NULL, actor_kind text NOT NULL, groups text[], arn text,
  session_name text, impersonated_user text, source_ips text[], user_agent text, api_group text,
  resource text, subresource text, namespace text NOT NULL DEFAULT '', name text, request_uri text,
  status_code int, decision text, tags text[] NOT NULL DEFAULT '{}', is_read boolean NOT NULL,
  ingested_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (audit_id, time)
) PARTITION BY RANGE (time);
CREATE INDEX IF NOT EXISTS audit_events_time ON audit_events (time DESC, audit_id DESC);
CREATE INDEX IF NOT EXISTS audit_events_user ON audit_events (username, time DESC);
CREATE INDEX IF NOT EXISTS audit_events_obj ON audit_events (namespace, resource, name, time DESC);
CREATE INDEX IF NOT EXISTS audit_events_tags ON audit_events USING gin (tags);
CREATE INDEX IF NOT EXISTS audit_events_default_view ON audit_events (time DESC, audit_id DESC)
  WHERE (actor_kind <> 'system' OR tags <> '{}') AND (NOT is_read OR tags <> '{}');
CREATE TABLE IF NOT EXISTS audit_events_default PARTITION OF audit_events DEFAULT;
CREATE TABLE IF NOT EXISTS ingest_checkpoints (
  source text PRIMARY KEY, position jsonb NOT NULL, owner text, updated_at timestamptz NOT NULL DEFAULT now()
);
```
`audit_id` uses `COLLATE "C"` so ordering and the keyset cursor compare bytes exactly as the memory store does, whatever the database locale. The default-view index carries the default view's exact predicate (system actors hidden unless tagged, reads hidden unless tagged) so the planner can use it. Daily partitions `audit_events_YYYYMMDD` are created ahead and dropped after `-audit-retention` by the advisory-lock holder.

Migration `0002_read_indexes.sql` (forward-only, never edit `0001`) adds two indexes for reads scoped to a few namespaces:
```sql
CREATE INDEX IF NOT EXISTS audit_events_summary ON audit_events (namespace, time DESC)
  INCLUDE (username, actor_kind, verb, tags, is_read) WHERE actor_kind <> 'system';
CREATE INDEX IF NOT EXISTS audit_events_scoped_view ON audit_events (namespace, time DESC, audit_id DESC)
  WHERE (actor_kind <> 'system' OR tags <> '{}') AND (NOT is_read OR tags <> '{}');
```
Migration `0003_alerts.sql` adds the alert store (written only by the holder of the `alerts` lock, on the lock's connection after checking it is held; read by every replica):
```sql
CREATE TABLE IF NOT EXISTS alert_findings (
  key text COLLATE "C" PRIMARY KEY, alert text NOT NULL, check_name text NOT NULL, kind text NOT NULL,
  namespace text NOT NULL DEFAULT '', name text NOT NULL, severity text NOT NULL, title text NOT NULL, owner text NOT NULL,
  production boolean NOT NULL DEFAULT false, labels jsonb NOT NULL DEFAULT '{}', annotations jsonb NOT NULL DEFAULT '{}',
  state text NOT NULL, silenced_until timestamptz, digest boolean NOT NULL DEFAULT false,
  first_seen timestamptz NOT NULL, last_seen timestamptz NOT NULL, last_notified timestamptz, resolved_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS alert_findings_unresolved ON alert_findings (key) WHERE state <> 'resolved';
CREATE INDEX IF NOT EXISTS alert_findings_resolved ON alert_findings (resolved_at) WHERE state = 'resolved';
CREATE TABLE IF NOT EXISTS alert_baseline (
  check_name text PRIMARY KEY, keys text[] NOT NULL DEFAULT '{}', updated_at timestamptz NOT NULL DEFAULT now()
);
```
`labels` is the label set last sent. `state` is `open`, `acknowledged`, `silenced` or `resolved`. The maintenance loop deletes findings resolved more than 30 days ago (`alerts.Retention`). A missing `alert_baseline` row means the change-based check has no baseline yet. `TestPGAlertsMatchMemory` keeps the store equal to `alerts.MemoryStore`.

Summaries without system actors are index-only scans of `audit_events_summary` (known actor kinds are written into the SQL as literals so the planner can prove its predicate). A page of the default view in at most 32 namespaces reads one `audit_events_scoped_view` range per namespace (plus one for events without a namespace with `ViewClusterAudit`), merged with `UNION ALL`. Summaries and coverage are cached stale-while-revalidate (30s fresh; a summary is served up to 5 minutes old while one background refresh per scope and window runs; coverage is served however old), with one computation per key at a time.

## Alerting (phase B)

`internal/alerts` (stdlib): the finding model and `Store`, the checks, the evaluator, the leadership runner and the Alertmanager sink. `docs/alerts.md` is the user guide and has a runbook per alert.

| Alert (`alertname`) | `check` | Severity | Pending |
|---|---|---|---|
| `KubesentryCertificateExpiring` | `cert-expiring` | the cert detector's (lifetime-relative); never while renewal is scheduled and not overdue by `CertRenewalGrace` | |
| `KubesentryCertificateNotReady` | `cert-not-ready` (annotation `reason`: `issuer-missing` or `not-ready`) | the cert detector's | 10m |
| `KubesentryMemoryLeak` | `memory-leak` | warning; critical below `-alerts-leak-crit-hours` to the limit | |
| `KubesentryWorkloadUnhealthy` | `workload-unhealthy` | critical with CrashLoopBackOff or a workload status crit, else warning | 5m |
| `KubesentryPodEvicted` | `pod-evicted` | warning | |
| `KubesentryPodStuckTerminating` | `pod-stuck-terminating` | warning | |
| `KubesentryRBACDrift` | `cluster-admin`, `anonymous-binding`, `wildcard-rbac`, `aws-auth-masters` | critical; change-based (baseline in `alert_baseline`; the first evaluation records it; open 24h while the object exists) | |
| `KubesentryFindingsDigest` | `digest` | warning; `kubesentry_digest="true"`, one per owner, when more than `-alerts-max-new` new alerts would fire at once | |

Findings are folded per workload root (`Assoc.RootOf`). Dedupe key: `check/kind/namespace/name`.

**Labels:**
- `alertname`, `severity`, `check`, `owner`, `production` (`"true"`/`"false"`)
- `namespace` (namespaced findings)
- `workload` or `object` (`Kind/name`)
- `node` (pod alerts on a single node)
- `cluster` (`-cluster-name`)
- `kubesentry_<x>` for every other `kubesentry.io/<x>` namespace annotation (sanitized, at most 10, values ≤ 256 bytes, `kubesentry_digest` reserved)

**Annotations:**
- `summary`, `description`, `runbook_url`, `dedupe_key`
- `kubesentry_url` (with `-external-url`; also `generatorURL`)
- per alert: `pods`, `reasons`, `latest_eviction`, `oldest_deletion`, `predicted_oom`, `container`, `pod`, `growth_bytes_per_hour`, `expires_at`, `issuer`, `reason`, `findings`

**Lifecycle:**
- New findings fire (`startsAt` = first seen).
- Open ones are re-posted every `-alerts-resend` with `endsAt` = now + 4 × resend.
- A label change retires the old set (`endsAt` = now).
- Gone ones resolve after `-alerts-resolve-grace`, with `endsAt` = now, once.
- Checks whose source is unreadable (`Inventory.Unavailable`, no leak scan) are skipped: their findings neither refresh nor resolve.

Writes are committed before anything is sent. Losing the lease cancels the evaluation and drops the sink's queues. Duplicates during a leader change are harmless: Alertmanager dedupes by label set.
