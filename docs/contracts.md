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

Dependency rule: client-go only in `internal/kube` (and `test/stress`); pgx only in `internal/pgstore`; AWS SDK v2 only in `internal/cloudwatch`, `internal/awsauth`, `internal/aws/**` and `internal/llm` (Bedrock credentials); the Anthropic SDK only in `internal/llm`. Everything else is stdlib, `internal/alerts` included (its Postgres store is `pgstore.AlertStore`, its SigV4 transport comes from `internal/awsauth` through `cmd/server`).

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
| `-owner-annotation` | `kubesentry.io/owner` | namespace annotation naming the owning team (Overview owner filter and attention, alert routing); one outside `kubesentry.io/` is added to the informers' namespace annotation allowlist. Since M2 also kept on the objects that may name their own owner (alerting phase C, "Object-level owners") |
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
| `-external-url` | | kubesentry's URL as users reach it; alerts link to their finding there (`kubesentry_url`, `generatorURL`). Its origin is trusted for write requests (M2), so it is validated with or without `-alerts` |

Every duration flag also takes days (`30d`, `1d12h`). `-leak-min-slope` is a growth per hour in bytes, with an optional unit (`1MiB`, `512KiB`). `GOMEMLIMIT`, when unset, defaults to 90% of the cgroup memory limit. Kept from before: `-addr`, `-kubeconfig`, `-api-token`, `-agent-token`, `-audit-token`, `-prometheus-url` (with `PROMETHEUS_TOKEN`), `-pvc-min-age`, `-pvc-class-prices`, `-audit-log-file`, `-audit-from-start`, `-audit-journal` (memory store only) and `-audit-max-events` (memory store).

Remote mode (`docs/run-remote.md`): `internal/awsauth` mints the EKS token (`EKSTokenSource.Token`: `k8s-aws-v1.` + base64url of a presigned STS `GetCallerIdentity` URL with `x-k8s-aws-id` signed, valid 14 minutes or until the credentials expire) and calls `DescribeCluster` with its SigV4 signer. `internal/kube` takes the token as a plain `ClientOptions.TokenSource func(ctx) (token, expiry, error)`, caches it until a minute before expiry or a 401, and drops the kubeconfig's credentials; `ClientOptions.ExecFallback` is asked for one when the kubeconfig's `aws eks get-token` or `aws-iam-authenticator` plugin is not installed. `Clients.InCluster` says which configuration was used, and `Clients.ServiceProxy(ns, name, port)` returns a Service's proxy URL and the authenticated transport (`rest.TransportFor`). The cgroup memory limit is read on Linux only; the server builds for darwin, windows and linux.

Agent flags (new): `-jitter` (0.2), `-gzip` (true), `-server-fanout` (a bare host, e.g. the headless ingest Service: the agent resolves it and posts to every address with the scheme and port of `-server`, verifying TLS against the `-server` host; if resolution fails it posts to `-server` alone), `-ca-file`, `-version`. Both binaries take `-X main.version=...` at build time; the server's Kubernetes user agent is `kubesentry/<version>`, the agent's `kubesentry-agent/<version>`.

## Cluster-sourced configuration
- Namespace label `kubesentry.io/system: "true" | "false"`.
- Namespace annotation `kubesentry.io/owner: <team>` (or `-owner-annotation`); every `kubesentry.io/*` namespace annotation is kept for alert routing hints, other namespace annotations are dropped. The same owner annotation (and no other) on Deployments, StatefulSets, DaemonSets, Jobs, CronJobs, Services, Ingresses, Certificates, Roles, RoleBindings, ClusterRoles and ClusterRoleBindings overrides the namespace's for their alerts (M2).
- Namespace label `environment=production` (or `-production-label`).
- StorageClass annotation `kubesentry.io/price-per-gib-month: "0.08"`.
- Service annotation `kubesentry.io/prometheus: "true"` marks the Prometheus to discover.
- Node labels (kept): `topology.kubernetes.io/{zone,region}`, `node.kubernetes.io/instance-type`, `kubernetes.io/{arch,os}`, `eks.amazonaws.com/{nodegroup,capacityType,compute-type}`, `karpenter.sh/{nodepool,capacity-type}`, `karpenter.k8s.aws/instance-family`, `node-role.kubernetes.io/*`.
- Service annotations (kept): `service.beta.kubernetes.io/aws-load-balancer-{scheme,internal,type,nlb-target-type}`.
- Ingress annotations (kept): `alb.ingress.kubernetes.io/{scheme,certificate-arn,listen-ports,ssl-redirect}`, `kubernetes.io/ingress.class`.

## Helm values (top level)
`clusterName`, `image`, `imagePullSecrets`, `agent`, `replicas`, `updateStrategy`, `server{cache,kubeQPS,kubeBurst,snapshot...,rateLimit,rateBurst,maxInflight,maxInflightPerIdentity,allowedHosts,allowedOrigins,systemPrincipalPrefixes,builtinRBACPrefixes,nodeLabelKeysAdd,pprof}`, `tls{enabled,existingSecret}`, `tokens{api,agent,audit}{existingSecret,key}`, `rbac{viewerRoles.{auditViewer,processViewer,agentsViewer,cloudtrailViewer,logsViewer,alertsResponder}.aggregateTo}`, `resources`, `serviceAccount{create,name,annotations}`, `auth{mode,userHeader,groupsHeader,allowCustomHeaders,usernamePrefix,groupsPrefix,groupMap,trustedProxyCIDRs,allowAnyProxy,authzQPS,authzCacheTTL,authzDenyTTL,shareByGroups}`, `oauth2Proxy{enabled,image,provider,issuerURL,clientID,existingSecret,upstreamTimeout,trustedProxyIPs,extraArgs,sessionStore}`, `prometheus{url,autodiscover,service,selector,ksmLimits,bearerTokenSecret,leakScan,amp{enabled,workspaceURL,region}}`, `audit{store,retention,maxEvents,redactExecArgs,postgres{existingSecret,dsnKey,schema,maxConns,queryTimeout,sslmode,sslRootCert},sources{webhook{enabled},cloudwatch{enabled,logGroup,streamPrefix,start,endpoint},file{path,fromStart,hostPathDir}}}`, `eks{clusterName,region,awsAuth{read}}`, `systemNamespaces{replace,add}`, `thresholds{...}`, `pricing{defaultPrice,ebsPrices,classPrices}`, `alerts{enabled,ownerAnnotation,production{labelKey,labelValue},defaultOwner,interval,resend,resolveGrace,maxNew,ownerMaxNew,ownerWindow,maxSilence,leakCritHours,runbookBaseURL,alertmanager{urls,existingSecret,tokenKey,basicAuth{username,passwordKey},sigv4,ca{configMap,secret,key}}}`, `externalURL` (passed as `-external-url` whatever `alerts.enabled` says: it is also a trusted origin), `incidents{enabled,interval,maxRange,retention,eventsRetention,quiet,lookbehind,logLead,logLag,namespaces,includeSystem,appLabel,appLabels,thresholds{requestRatio,requestCritRatio,requestMinRPS,errorRatio,errorCritRatio,memoryLimitPct,memoryCritPct,memoryJumpRatio,memoryJumpMin,spikeRecent,spikeBaseline,eventMinCount},requestSources,requestProfiles,alb,eventNormalReasons,logs{mode,group,streamPrefix,maxLines,maxBytes},redactPatterns,cloudtrail{mode,logGroup,region,qps,start}}`, `pdb`, `networkPolicy{...,egress.podIdentityAgent,egress.alertmanager{toCIDRs,toNamespaces,ports}}`, `topologySpread`, `ingress`, `metrics{serviceMonitor,prometheusRule,grafanaDashboards}`, `apf{enabled}`, `extraArgs`, plus the usual pod knobs (resources, probes, affinity, tolerations, extra env/volumes/containers). The chart is authoritative: `charts/kubesentry/values.yaml` and `values.schema.json`. With `alerts.enabled` the chart refuses `replicas > 1` without `audit.store=postgres` (the lock), and a token Secret together with AMP's SigV4. With `incidents.enabled` it refuses `server.cache: false`, `replicas > 1` without `audit.store=postgres`, `cloudtrail.mode: logs` without `cloudtrail.logGroup`, and `logs.mode: cloudwatch` with neither `logs.group` nor a cluster name; it refuses a `cloudtrail.mode` other than off without incidents, and the schema a `maxRange` above 24h. Postgres TLS comes from `PGSSLMODE`/`PGSSLROOTCERT` env, so pgstore must build its config with `pgxpool.ParseConfig`.

## Metrics (`/metrics` on the ops listener)
`kubesentry_http_requests_total{route,code}`, `kubesentry_http_request_duration_seconds{route}`, `kubesentry_http_inflight`, `kubesentry_http_cache_total{result}`, `kubesentry_snapshot_build_seconds`, `kubesentry_snapshot_age_seconds`, `kubesentry_snapshot_version`, `kubesentry_informer_objects{resource}`, `kubesentry_kube_requests_total{verb,resource,code}`, `kubesentry_authz_reviews_total{result}`, `kubesentry_authz_cache_total{result}`, `kubesentry_prometheus_query_seconds{kind}`, `kubesentry_prometheus_cache_total{result}`, `kubesentry_audit_ingested_total{source}`, `kubesentry_audit_queue_depth`, `kubesentry_audit_store_errors_total`, `kubesentry_cloudwatch_lag_seconds`, `kubesentry_agent_reports_total{code}`, `kubesentry_agent_nodes_reporting`, plus Go runtime metrics.

Added with alerting phase B:
- `kubesentry_findings{check,severity}`: open (unresolved) alert findings on the replica that evaluates; the others report 0. `check` is one of the alert checks below, `severity` `warning` or `critical`; no object, namespace or owner labels.
- `kubesentry_alerts_sent_total{result}`: alerts posted to Alertmanager, per URL; `sent`, `failed` (every attempt failed, or a 4xx other than 429), `dropped` (queue full, or leadership lost).
- `kubesentry_alerts_queue_depth`, `kubesentry_alerts_evaluation_seconds` (histogram), `kubesentry_alerts_leader` (1 on the evaluating replica).
- `kubesentry_http_rejected_total{reason}`: `/api/` requests turned away before routing: `rate_limit` (429), `max_inflight` (503), `unauthenticated` (401), `cross_origin` (403; M2).
- `kubesentry_dependency_up{dependency}`: 1 while a configured dependency works, from the state behind `/readyz`: `snapshot` (0 before the first view and while serving a stale one), `prometheus` (1 while none is known), `postgres`, `cloudwatch`, `alertmanager` (0 while the latest delivery to some URL failed).
- `kubesentry_leak_scan_runs_total{result}`: `ok`, `partial` (some queries failed), `failed` (no fresh findings).
- `kubesentry_snapshot_last_change_timestamp_seconds`: when the informers last announced a change (every poll without them); newer than the view's build time means a change waits for a rebuild.

Label values: `route` is one of `info`, `auth_recheck`, `overview`, `alerts`, `alert_actions`, `alert_actions_list`, `pods`, `pod_diagnostics`, `pod_processes`, `pvcs_unused`, `oom`, `workloads`, `nodes`, `node`, `storage`, `security`, `map`, `certificates`, `audit_events`, `audit_summary`, `agents`, `ingest_agent_report`, `ingest_audit_webhook`. `kubesentry_kube_requests_total` uses the Kubernetes verb (`list`, `watch`, `get`, `create`, ...), the resource (with `/subresource`; `discovery` for non-resource paths) and the status code or `error`. `kubesentry_audit_ingested_total{source}` is `webhook`, `file` (lines read) or `cloudwatch`.

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

## Incidents (`-incidents`)

One incident per **workload root** (`Assoc.RootOf`). **Trigger** signals open an incident and set its severity (`critical`/`warning`; "caution" in the UI is `warning`). **Context** signals only attach. An incident resolves once no trigger has been active for `-incident-quiet`. It is capped at **24h**: it then closes with `capped` and continues in a new incident linked through `previous`. Logs and events are read in the padded window `[start − log-lead, end + log-lag]`.

**Dashboard only:** incidents never notify. Phase B alerts keep notifying per finding; a finding's episode joins its workload's incident as an `alert` signal. The user guide is `docs/incidents.md`.

Go types: `internal/incidents/types.go`. Model additions: `internal/model/incidents.go`, plus `Workload.Labels`/`Revision`, `ReplicaSet.Revision`/`Images`, and `Inventory.ServiceAccounts`/`TargetGroupBindings`. TypeScript: `Incident*` in `web/src/types.ts`.

### Signals
| Type | Role | Default rule |
|---|---|---|
| `request-spike` | trigger | rate over the last 5m against a 1h baseline (offset 5m): ×2 warning, ×4 critical, at least 1 req/s |
| `error-rate` | trigger | 5xx share: 5% warning, 20% critical |
| `memory-spike` | trigger | 85% / 95% of the limit; with no limit, a jump of ×1.5 and at least 128 MiB |
| `oom-kill`, `crashloop` | trigger | critical |
| `restart` | trigger | `-restart-warn` / `-restart-crit` within the quiet window |
| `eviction` | trigger | warning |
| `k8s-event` | trigger or context | trigger: BackOff, Unhealthy, FailedScheduling, FailedMount, Failed and FailedCreatePodSandBox at least `-incident-event-min-count` (3) times in 5m; OOMKilling and Evicted at once. Context otherwise |
| `alert` | trigger | phase B finding episodes (`key@firstSeen`), with the finding's own severity |
| `deploy`, `scale` | context | `Workload.Revision` change with the image diff; a `Desired` change |
| `audit-change` | context | writes by humans in the audit store |
| `cloudtrail-change` | context | non-read-only CloudTrail events matched to related resources: instance IDs, target groups (TargetGroupBinding), ALB names, IRSA role, security groups, EKS cluster/nodegroup/add-on |
| `log-errors` | context | error-line rate against the rate before the incident; open incidents only; no lines stored |

**App and service tags:**
- Keys: `app.kubernetes.io/{name,instance,part-of,component}`, `app`, `k8s-app`, plus `-incident-app-label`.
- Taken from the workload's labels, or the most common value across its pods.
- Also `service` (EndpointSlices) and `ingress`.
- Incidents sharing `part-of`/`instance`/the custom tag/a service with overlapping windows are "related" when read; they are never merged.

### Routes
| Route | Notes |
|---|---|
| `GET /api/v1/incidents` | `?window=1h..24h` or `from&to` (span at most 24h, inside retention), `severity`, `type` (repeatable), `state`, `namespace`, `owner`, `app`, `service`, `tag=k=v`, `limit`/`continue` (keyset on start and id). `counts` cover the range before the severity/type/state filters. Namespaced incidents need `ViewNamespace`; node and cluster subjects need `ViewNodes`. |
| `GET /api/v1/incidents/{id}` | `IncidentDetail`. 404 before any authorization review when the ID is unknown or out of scope. Signals are gated per source: audit needs `ViewAudit`, CloudTrail needs `ViewCloudTrail`. Series step = window/240, clamped to 15s–5m; at most 12 series per metric plus `others`. Counts against the per-identity cap on expensive routes. |
| `GET /api/v1/incidents/{id}/logs` | `?from&to&pod&container&level&q&source=auto\|kubernetes\|cloudwatch&limit`. Needs `ViewPodLogs` (`get pods/log`) in the incident's namespace (403 otherwise). Caps: 2,000 lines, 1 MiB, `truncated`. Redacted. `Cache-Control: no-store`. |
| `GET /api/v1/incidents/{id}/bundle` | Agent-ready. JSON, or `?format=ndjson`: an `IncidentBundleHeader` record, then `{"kind":"signal"\|"metric"\|"event"\|"log"\|"audit"\|"cloudtrail", …}` records. Schema `kubesentry.io/incident-bundle/v1`. Caps: logs 2k lines / 1 MiB, events 2k, audit 1k, CloudTrail 500, total 4 MiB, each with `truncated`. Redacted. Sections the caller can't see go in `omitted`, with `complete:false`; `?require=all` makes that a 403. |

**Elsewhere:**
- `/info`: `incidents{enabled, leader, sources, maxRangeHours, logLeadSeconds, logLagSeconds}` (left out when incidents are off; a CloudTrail source error reads just `error` without the `cloudtrail` capability), and `capabilities.podLogs` / `cloudtrail`.
- Overview: open incidents fold into "Needs attention" as `kind: "incident"` items in their workload's line, ranked before the other items of the same severity (`href` `#/incidents/<id>`), plus `badges.incidents` and `incidents.open{critical,warning}` (left out when incidents are off). Node incidents need `ViewNodes`, and with a filter a selected pod on the node.
- Pod diagnostics: `incidents[]` (`IncidentRef`): board incidents whose subject owns the pod or that name it, newest first, at most 20.

**Wire details (D):**
- Severity in `counts`, `IncidentRef.severity`, the Overview and the `severity` filter is the **peak** severity. `counts.byType` counts incidents holding each type.
- Gates also apply to the incident's own `types`/`counts` (list, detail and bundle): `audit-change` needs `ViewAudit` in the namespace (`ViewClusterAudit` for a node), `cloudtrail-change` needs `ViewCloudTrail`. The detail reports such sources, and the log sources without `ViewPodLogs`, as `"forbidden"`; events about a node need `ViewNodes`.
- Only the list is response-cached (`incidentsCaps`: namespace, nodes, audit, cluster audit, CloudTrail; plus the board version and a 10s window). The detail, logs and bundle are not cached, so an unknown ID costs no authorization review; they share the per-identity cap of the expensive routes.
- Logs: an unconfigured `source=` is 400; with no log source at all, or for a node incident, 200 with no lines and a warning. Windows (`window`, logs `from`/`to`, the bundle's) are UTC.
- The bundle answers with `Content-Disposition: attachment` and `Cache-Control: no-store`.

**Clarifications for clients (raised by E):**
- **`window` is the padded logs and events window,** `[start − log-lead, end + log-lag]` (end is now while open), clamped to 24h. It bounds the logs and Kubernetes events, not the signals: a context signal attached through the lookbehind (a deploy 30m before the start) starts **before** `window.from`. A client drawing one time axis extends it back to the earliest attached signal; the UI adds a minute of margin and reaches at most 24h before the window (`incidentDomain` in `web/src/incidents.ts`).
- **The logs `level` is a minimum:** `debug` < `info` < `warn` < `error`. `level=warn` returns warnings and errors; empty returns every line. Each line's own `level` is what detection found (JSON `level`/`lvl`/`severity`, logfmt, klog, then words), and may be empty.
- **`Incident.pods`** (and `services`) are bare names in the subject's namespace (`subject.namespace`), at most 50 each; `nodes` are node names. A node incident has no namespace and no pods. The logs route's `pod` filter takes the same bare names and keeps only the incident's own pods; without it the first 10 are read.
- **Signal `attrs`** (at most 16 keys of at most 512 bytes; a key is present only when it has a value), by type, from `internal/incidents/producers_*.go`:

  | Type | Keys |
  |---|---|
  | `request-spike` | `source` (profile name or `alb`), `ratio` (peak against the baseline, e.g. `"4.6"`), `window`, `baselineWindow` (Go durations, e.g. `"5m0s"`) |
  | `error-rate` | `source`, `rps` |
  | `memory-spike` | `pod`, `container`, `limit` (bytes, when the container has one) |
  | `oom-kill`, `restart` | `pod`, `container`, `reason`, `exitCode`, `restarts`, `node` |
  | `crashloop` | `pod`, `container`, `restarts`, `lastReason`, `exitCode`, `message` |
  | `eviction` | `pod`, `node`, `message` |
  | `k8s-event` | `reason`, `type`, `count`, `component`, `message`, `uid` |
  | `alert` | `alert`, `check`, `key`, `state`, `owner` |
  | `deploy` | `fromRevision`, `toRevision`, `images` (`repo: v1 → v2; +img; -img`), `rollback` (`"true"`) |
  | `scale` | `from`, `to` (desired replicas) |
  | `audit-change` | `user`, `verb`, `resource`, `subresource`, `apiGroup`, `auditID`, `statusCode`, `userAgent`, `sourceIP`, `arn` |
  | `cloudtrail-change` | `eventName`, `eventSource`, `eventID`, `actor`, `region`, `resources`, `matched` (comma-separated), `raw` (redacted, cut to 512 bytes) |
  | `log-errors` | `incident`, `source`, `truncated` |

  No producer sets `query`: request queries are built from the profiles, so a signal names its `source` profile instead of carrying PromQL. `region` appears on CloudTrail signals only; `reason` on events, OOM kills and restarts; `ratio` on request spikes.

**New capabilities:**
- `ViewPodLogs` = `get pods/log`, namespaced. `auth.Capability` gains `Subresource`, threaded through the Reviewer, the SAR, the cache keys and `RBACIndex`.
- `ViewCloudTrail` = `list kubesentry.io/cloudtrail`, cluster-wide. The chart ships viewer ClusterRoles.

### Storage (`0004_incidents.sql`)
- **Tables:**
  - `incidents`: subject columns, severity and peak severity, state, owner, production, `tags jsonb`, `services`/`pods`/`nodes`/`signal_types text[]`, `started_at`, `last_signal_at`, `resolved_at`, `capped`, `previous`.
  - `incident_signals`: PK `(incident_id, signal_id)`, cascading deletes.
  - `k8s_events`: partitioned by day on `first_seen`, PK `(uid, first_seen)`.
- **Writes:** only the lease holder (`TryLead("incidents")`) writes, on the lease's connection; followers refresh from the store every 15s.
- **Maintenance:** `Maintain` partitions both `audit_events` and `k8s_events`.
- **Retention:** incidents `-incident-retention` (7d); events `-incident-events-retention` (48h).
- **Parity:** the memory store behaves the same (parity tests).

### Flags (Helm `incidents{…}`)
- **Main:**
  - `-incidents` (needs `-cache`; more than one replica needs the Postgres store: `-audit-store=postgres` keeps the incidents, the events and the lease too, and without it the server warns to run one replica)
  - `-incident-interval` 1m
  - `-incident-max-range` 24h (refused above)
  - `-incident-retention` 7d, `-incident-events-retention` 48h
  - `-incident-quiet` 15m, `-incident-lookbehind` 30m
  - `-incident-log-lead` 5m, `-incident-log-lag` 10m
  - `-incident-namespaces`, `-incident-include-system`
  - `-incident-app-label` (custom tag key), `-incident-app-labels`
- **Thresholds:**
  - `-incident-request-ratio` 2 / `-incident-request-crit-ratio` 4, `-incident-request-min-rps` 1
  - `-incident-error-ratio` 0.05 / `-incident-error-crit-ratio` 0.2
  - `-incident-memory-limit-pct` 85 / `-incident-memory-crit-pct` 95, `-incident-memory-jump-ratio` 1.5, `-incident-memory-jump-min` 128MiB
  - `-incident-spike-recent` 5m, `-incident-spike-baseline` 1h, `-incident-event-min-count` 3
- **Sources:**
  - `-incident-request-sources` (`nginx,app`; built-in profiles), `-incident-request-profiles-file`, `-incident-alb`
  - `-incident-event-normal-reasons` (`SuccessfulRescale`)
  - `-incident-logs` (`auto|kubernetes|cloudwatch|off`; `auto` reads CloudWatch first when `-incident-logs-group` is set, then `pods/log`), `-incident-logs-group` (default with `cloudwatch`: `/aws/containerinsights/<cluster>/application`), `-incident-logs-stream-prefix`, `-incident-logs-max-lines` 2000, `-incident-logs-max-bytes` 1MiB, `-incident-redact-patterns` (repeat the flag for more patterns)
  - Incidents without an owner annotation belong to `-alerts-default-owner`.
- **CloudTrail:** `-cloudtrail` (`off|lookup|logs`; needs `-incidents`), `-cloudtrail-log-group` (`logs` only), `-cloudtrail-region` (default `-aws-region`), `-cloudtrail-qps` 1, `-cloudtrail-start` 1h. One CloudWatch Logs client per region and one throttling pacer are shared by the audit reader, container logs and the trail.

**Request profiles:** `{name, metric, namespaceLabel, serviceLabel|podLabel, statusLabel, errorRegex}`. Queries are always built through the prom package's selector, so `-prometheus-selector` applies. ALB uses CloudWatch `GetMetricData` with `SEARCH` over `AWS/ApplicationELB` (RequestCount, HTTPCode_Target_5XX_Count), keyed by the TargetGroupBinding's target group. CloudTrail `LookupEvents` and `GetMetricData` use SigV4-signed HTTP calls (`internal/aws/**`), so no new modules are needed.

### Chart RBAC and IAM
- **RBAC** (read-only additions to the server's ClusterRole): `serviceaccounts` list/watch and `elbv2.k8s.aws/targetgroupbindings` list/watch always (their informers always run); `events` list/watch with `incidents.enabled`; `pods/log` get with `incidents.enabled` and `logs.mode` `auto` or `kubernetes`.
- **Viewer ClusterRoles,** with `rbac.viewerRoles.<role>.aggregateTo` like the others: `<release>-cloudtrail-viewer` (`list cloudtrail.kubesentry.io`; bind cluster-wide) and `<release>-logs-viewer` (`get pods/log`; the built-in `view` already grants it).
- **IAM:** `logs:FilterLogEvents` on the application and trail log groups, `cloudtrail:LookupEvents`, `cloudwatch:GetMetricData` and `cloudwatch:ListMetrics` (`docs/deploy-eks.md`, section 3).
- **Self-monitoring rules** (chart PrometheusRule, with incidents on): `KubesentryCloudTrailFailing` (`dependency_up{dependency="cloudtrail"}` 0 for 15m; CloudTrail on), `KubesentryIncidentEventsFailing` (`k8s_events_total{result="error"}`, or `kube_requests_total{resource="events",code="403"}`, rising for 15m), `KubesentryIncidentLogsFailing` (only `error` log fetches from a source over 30m, for 10m; logs not off). An "Incidents" row on the health dashboard.

### Metrics
- `kubesentry_incidents{severity}`
- `kubesentry_incident_signals_total{type}`
- `kubesentry_k8s_events_total{result}`: `stored`, `error` (the store write failed). A watch refused by the permission probe is not counted here; it shows in `/info` (`incidents.sources.events`) and the server log
- `kubesentry_cloudtrail_events_total{result}`: `fetched`, `duplicate`, `unparsed`, `truncated`, `throttled` from the source; `kept` (matched a related resource) and `error` (a failed poll) from the engine
- `kubesentry_incident_log_fetches_total{source,result}`: source `kubernetes` or `cloudwatch`; result `ok`, `truncated`, `error`. Counts reads for the logs route and bundles, not the error-log counter
- `kubesentry_dependency_up{dependency="cloudtrail"}`
- Route labels: `incidents`, `incident`, `incident_logs`, `incident_bundle`.

## Close the gaps (2026-10): incident follow-ups, alerting phase C, AI investigator

Milestones land in order M1 → M7; each section names its milestone. TypeScript: `AlertFinding` additions, `AlertAction*`, `Info.alerts`/`Info.investigator` and `Investigation*` in `web/src/types.ts`.

### Write routes: cross-origin and body rules (M2)
- Every `/api/` request whose method is not GET, HEAD or OPTIONS passes `http.CrossOriginProtection` right after authentication. Trusted origins: the origin of `-external-url`, plus `-allowed-origins` (comma-separated `scheme://host[:port]`). A browser request from any other origin (`Sec-Fetch-Site: cross-site`/`same-site`, or an `Origin` that doesn't match the Host) is 403 `{"error":"cross-origin request refused"}` and counts `kubesentry_http_rejected_total{reason="cross_origin"}`. Requests without `Sec-Fetch-Site` and `Origin` (curl with the API token) pass.
- JSON bodies: `Content-Type: application/json` (415 otherwise), at most 16 KiB (413), unknown fields rejected (400).

### Incident follow-ups (M1)
- **Alert → incident:** the incidents board indexes signal ID → incident ID on every replica. A finding whose episode (`EpisodeID`, `alert:<key>@<firstSeen>`) has joined an incident gains the Alertmanager **annotation** `incident_url` (`-external-url` + `#/incidents/<id>`; never a label, so it never retires the alert). It goes out at the next resend. `firstSeen` is stored at microsecond precision on the leader too, so the episode ID is the same on every replica.
- `GET /api/v1/alerts` items gain `incidentId` (resolved at response time; same namespace as the finding).
- **Source health:** the runner probes every source, including `events` and each `logs:<name>`, every 10 minutes on every replica. `events` returns to `ok` on a successful probe (unless this replica's own watch is failing: a granted permission does not make a broken watch work), on a received batch, or once the watch has run 30s; a failed watch is retried after 10s, doubling after each quick failure up to 5m. `cloudtrail` returns to `ok` after a successful poll. Sources only the leader updates reset to their initial state when leadership ends.
- `/info.unavailable` gains `incidents:<source>` for sources in error (the CloudTrail reason reads `error` without the `cloudtrail` capability).
- Metrics: `kubesentry_incident_source_up{source}` (1 `ok`, 0 error; `absent` sources not exported), `kubesentry_incidents_leader`.
- Rules: `KubesentryIncidentSourceDown` (15m; `min by (namespace, source)` on the leader, CloudTrail excluded since `KubesentryCloudTrailFailing` covers it); `KubesentryIncidentEventsFailing` also fires on `kubesentry_incident_source_up{source="events"} == 0` on the leader (every replica probes the same permission, so followers would only repeat it).

### Alerting phase C (M2, M3)

**Ack and silence.** Human actions are an append-only log, written through the pool by any replica and applied by the leader's evaluator and by every follower's refresh (one pure function, `alerts.applyMarks`):
- **ack** applies to the current episode (`firstSeen`) and clears when the finding turns from warning to critical. An acknowledged finding keeps being re-posted with the annotations `acknowledged_by`, `acknowledged_at`. It does not stop Alertmanager's `repeat_interval`; use an Alertmanager silence for that.
- **silence** applies to the key until it expires or is lifted, across resolve and reopen. Silencing posts the alert once with `endsAt=now` and the annotations `silenced_by`, `silenced_until`, `silence_reason`, then stops; expiry or `unsilence` fires it again at once. Silenced findings are left out of digests. Duration 5m to `-alerts-max-silence` (default 7d, at most 30d); reason 3–500 characters.
- kubesentry never writes to Alertmanager's silence API.
- The acting replica republishes its board at once (the board version, and so the response cache, moves on) and wakes the leader, so notifications follow within one `-alerts-interval` (within about a second when the acting replica leads; another replica's action is read at the leader's next evaluation).

| Route | Notes |
|---|---|
| `POST /api/v1/alerts/actions` | Body `AlertActionRequest` (`keys` ≤ 100). 400 malformed, 403 without `alertsUpdate` anywhere, 413, 415. Otherwise 200 `AlertActionResponse` with a result per key: `not found` (unknown, or not visible to the caller), `forbidden` (visible, but no `UpdateAlerts` there), `resolved`, `invalid`. Cross-origin rule applies. Route label `alert_actions` |
| `GET /api/v1/alerts/actions` | `?key=&limit=` (default 50, a larger limit is clamped to 200, below 1 is 400), newest first, only actions on findings the caller can see (judged from the board's finding, else from the key's check, kind and namespace); items carry `namespace` (from the key; absent for cluster-scoped findings); `no-store`; in `TestNoAuthorizationLeaks`. Route label `alert_actions_list` |

**Capability:** `UpdateAlerts` = `update alerts.kubesentry.io`, namespaced (UI `alertsUpdate`); cluster-scoped findings need it cluster-wide. Chart role `<release>-alerts-responder`, `rbac.viewerRoles.alertsResponder.aggregateTo` (default `[]`).

**Visibility by finding kind** (`Finding.Gate()`; `/alerts`, `/alerts/actions` and the Overview counter share it):

| Gate | Namespaced finding | Cluster-scoped finding |
|---|---|---|
| `namespace` | `ViewNamespace` | — |
| `rbac` | `ViewNamespace` + `ViewRBAC` | `ViewClusterRBAC` |
| `audit` | `ViewNamespace` + `ViewAudit` | `ViewClusterAudit` |
| `node` | — | `ViewNodes` |
| `agents` | — | `ViewAgents` |

The "—" cells do not occur; should one, it fails closed: a cluster-scoped `namespace` finding needs `ViewNamespace` in every namespace, a namespaced `node` or `agents` finding `ViewNamespace` there plus the cluster-wide capability. `Finding.Gate()` maps the RBAC drift checks to `rbac`, `audit-*` checks to `audit`, `agent-missing` to `agents`, findings about a `Node` to `node`, the rest to `namespace` (`alerts.GateOf(check, kind)`, which also judges actions whose finding left the board).

The `/alerts` response cache adds `ViewAudit`, `ViewClusterAudit`, `ViewNodes`, `ViewAgents` and `UpdateAlerts` to its key (items carry `actionable`).

**Storm protection,** in order: the global `-alerts-max-new` breaker; a per-owner budget (`-alerts-owner-max-new` 20 per `-alerts-owner-window` 15m; the rest join that owner's digest); a digested finding that turns critical leaves the digest and fires (at most `-alerts-max-new` per evaluation); quiet findings never count. Metric `kubesentry_alerts_digested_total{reason}` (`max_new`, `owner_budget`).

**Standing-state digests:** on the leader at `-alerts-digest-at` (`"Mon 09:00"`, or `"09:00"` daily; empty turns them off) in `-alerts-digest-tz` (UTC), for `-alerts-digest-kinds` (`rbac-posture,unused-volumes,certificates`). One alert per owner and kind, sent once: `alertname="KubesentryStandingDigest"`, `severity="info"`, `digest=<kind>`, `kubesentry_digest="true"`, `owner`, `cluster`; `endsAt=startsAt+1h`; annotations `summary`, `count`, `findings` (the 10 worst), `monthly_cost_usd` (volumes), `kubesentry_url` (the page filtered by owner). The last run per kind is kept in `alert_digest_runs`; a new leader catches up only the latest missed slot. Certificates with more than `-alerts-cert-digest-days` (14) left are `quiet`: listed in the digest, never notified alone, until they cross the threshold. `/info.alerts` gains `lastDigestAt`, `nextDigestAt`. Metric `kubesentry_alerts_standing_digests_total{kind}`.

**New alerts:**

| Alert | `check` | Severity | Gate | Rule |
|---|---|---|---|---|
| `KubesentryExposureChange` | `loadbalancer` (internet-facing only), `nodeport`, `external-ip`, `ingress-no-tls` | warning | namespace | change-based (baseline like RBAC drift); system findings skipped |
| `KubesentryPrivilegedWorkload` | `privileged`; `host-namespaces` | critical; warning (critical in production) | namespace | change-based, per workload root |
| `KubesentryAuditActivity` | `audit-exec` (exec, attach, port-forward, debug containers), `audit-secret-read` (humans; both production-only by default); `audit-rbac-change` (humans); `audit-impersonation`; `audit-denied-burst` (≥ `-alerts-audit-denied-burst` 20 in `-alerts-audit-denied-window` 10m per actor); `audit-anonymous` (allowed requests) | warning; `audit-anonymous` critical | audit | open while the newest matching event is within `-alerts-audit-hold` (1h); key `check/User/<namespace>/<actor>`, label `object="User/<actor>"`; annotations `actor`, `actor_kind`, `count`, `first_at`, `last_at`, `verbs`, `examples` (≤ 3, redacted) |
| `KubesentryAgentMissing` | `agent-missing` | warning, 10m pending | agents | one per agent DaemonSet (`-agent-daemonset` ns/name): nodes running its pod that haven't reported for 3 intervals; Fargate, NotReady and nodes younger than 10m excluded; annotations `nodes` (first 20), `count`; `node` label when exactly one. `-alerts-agents=auto` (on with one replica or agent fanout), `on`, `off` |

Flags: `-alerts-disable-checks` (comma-separated checks), `-alerts-audit` (enabled audit checks; default all when an audit store exists), `-alerts-audit-production-only` (default `audit-exec,audit-secret-read`), `-alerts-audit-hold`, `-alerts-audit-denied-burst`, `-alerts-audit-denied-window`, `-alerts-owner-max-new`, `-alerts-owner-window`, `-alerts-max-silence`, `-alerts-digest-at`, `-alerts-digest-tz`, `-alerts-digest-kinds`, `-alerts-cert-digest-days`, `-alerts-agents`, `-agent-daemonset`, `-agent-fanout`, `-allowed-origins`. Helm: `alerts{ownerMaxNew,ownerWindow,maxSilence,disableChecks,audit{checks,productionOnly,hold,deniedBurst,deniedWindow},digests{at,tz,kinds,certDays},agents}`, `rbac.viewerRoles.alertsResponder`, `server.allowedOrigins` (`-allowed-origins`, next to `server.allowedHosts`; the schema takes `http(s)://host[:port]` only).

**As built (M3):**
- **Exposure and privileged** read the security detector's findings: exposure at `warn` only (internal load balancers and internal ALBs are `info` there), privileged and host namespaces as folded per workload root; system findings never. They join the change-based checks, so the first evaluation after the upgrade records their baselines silently.
- **Audit checks** count allowed requests only (status below 400, no `forbid`), except `audit-denied-burst`. `audit-anonymous` leaves out health checks, the version and OIDC discovery (`/healthz*`, `/livez*`, `/readyz*`, `/version`, `/.well-known/openid-configuration`, `/openid/v1/jwks`). Denied bursts are counted per actor across the cluster: the finding is cluster-scoped (`audit-denied-burst/User//<actor>`, `ViewClusterAudit`). Examples quote an exec's command only through the redactor (the incidents one, `-incident-redact-patterns`). Each tag reads at most 10 pages of 1,000 events per evaluation. `-alerts-audit-hold` is 10m to 24h; the denied window at most the hold.
- **Agent check:** key `agent-missing/DaemonSet//<namespace>/<name>`, label `object="DaemonSet/<namespace>/<name>"`, owner `-alerts-default-owner`. `auto` is on when the memory store is used (one replica) or with the new flag **`-agent-fanout`** ("every agent report reaches every replica"), which the chart sets when `replicas` is 1 or `agent.fanout` is on. The chart also passes `-agent-daemonset=<agent namespace>/<fullname>-agent` and `-agent-interval` (from `agent.interval`, which the server uses for staleness too) whenever `agent.enabled`, and refuses `alerts.agents=on` without `agent.enabled`.
- **Standing digests:** a kind never sent waits for the first scheduled time after the evaluator started (a fresh install or a restarted memory store sends nothing at once); a kind whose source is unreadable waits for the next evaluation. Certificates are quiet only while the certificates digest is scheduled. A quiet certificate that crosses the threshold counts as new for storm protection. The digest alerts also carry `description` and `runbook_url`; `kubesentry_url` is the Overview filtered to the owner (the only page with an owner filter today). `/info.alerts.lastDigestAt` is the latest run of any kind, read from the store on followers.
- `-alerts-audit` takes `all` (default) or `none` besides check names; the chart's `alerts.audit.checks: []` renders `none`.

**As built (M4, the Alerts UI):**
- **Alerts page** `#/alerts` (`web/src/pages/Alerts.tsx`, logic in `web/src/alerts.ts`), shown in the sidebar when `/info.alerts.enabled`. Address: `?state=open|acknowledged|silenced|resolved|all` (default `open`; `all` when `key` is given), `namespace`, `owner`, `severity`, `check`, `q`, `key` (that finding is opened, highlighted and scrolled to). The page asks `/alerts` for every state (narrowed by `namespace` and `owner` on the server) and filters state, severity, check and text itself; the tabs show the server's `counts` without filters and the loaded rows' counts with them. Actions per row by `actionable` and state; bulk ack, unack, silence and unsilence over the selected rows they apply to (at most 100 keys a request, split client-side); without `alertsUpdate` no action is offered. The silence dialog takes 1h, 4h, 24h, 7d or a custom length (`90m`, `6h`, `2d`, `1d12h`), checked against 5 minutes and the server's maximum, and a reason of 3 to 500 characters (code points, trimmed).
- **`/info.alerts.maxSilenceSeconds`**: the longest silence an action may ask for (`-alerts-max-silence`), so the dialog can check a length before sending; absent when alerting is off (the UI then assumes 7 days).
- **`badges.alerts`** on `/overview`: open findings that notify on their own (state `open`, not `quiet`) in the selection, `crit` when one is critical; left out at zero and when alerting is off. The sidebar links it to `#/alerts?state=open`. The Overview's alerts panel links each state and owner to the page with the Overview's namespace and owner.
- **Incident page:** alert signals (`type: "alert"`, `attrs.key`) link to `#/alerts?key=<key>`, in the Alerts lane and under "Alerts" in the facts.
- **Demo** (`internal/demo/alerts.go`): an alerts runner that is never run, with a memory store and no sink, seeded with ten findings (open across the catalog, including exposure, privileged, audit and agent findings; one acknowledged by dave and joined to the recommendations incident; one silenced by erin; one resolved; one quiet certificate). `/info.alerts` reports it enabled, leading, sink `none`; acknowledging and silencing go through `Runner.Act`.

**Object-level owners:** the owner annotation (`-owner-annotation`) is kept on Deployments, StatefulSets, DaemonSets, Jobs, CronJobs, Services, Ingresses, Certificates, Roles, RoleBindings, ClusterRoles and ClusterRoleBindings (no other annotation is added to the informer cache). Owner precedence: the object, then its namespace, then `-alerts-default-owner`. When the object's owner differs from its namespace's, the namespace's `kubesentry_*` routing labels are not copied. Pods carry no annotations; a bare pod uses its namespace's owner.

**`AlertFinding` additions:** `ackBy`, `ackAt`, `silencedBy`, `silencedAt`, `silenceReason`, `link` (UI route), `incidentId`, `quiet`, `actionable`.

**Storage (`0005_alerts_actions.sql`):**
```sql
ALTER TABLE alert_findings ADD COLUMN IF NOT EXISTS link  text    NOT NULL DEFAULT '';
ALTER TABLE alert_findings ADD COLUMN IF NOT EXISTS quiet boolean NOT NULL DEFAULT false;
CREATE TABLE IF NOT EXISTS alert_actions (
  id bigserial PRIMARY KEY, key text COLLATE "C" NOT NULL, first_seen timestamptz NOT NULL,
  action text NOT NULL CHECK (action IN ('ack','unack','silence','unsilence')),
  actor text NOT NULL, reason text NOT NULL DEFAULT '', until timestamptz,
  severity text NOT NULL, at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS alert_actions_key ON alert_actions (key, id);
CREATE INDEX IF NOT EXISTS alert_actions_at  ON alert_actions (at);
CREATE TABLE IF NOT EXISTS alert_digest_runs (name text PRIMARY KEY, last_sent timestamptz NOT NULL);
```
`alert_actions` is written through the pool by any replica (not the lock connection); `alert_findings` and `alert_digest_runs` stay leader-only. Maintenance deletes actions older than `alerts.Retention` + 1 day. Parity: `TestPGAlertsMatchMemory` covers actions and digest runs.

Metrics: `kubesentry_alert_actions_total{action,result}` (`ok`, `forbidden`, `not_found`, `invalid`, `resolved`).

### AI investigator (M5–M7)

**Off by default.** `-investigator=off|anthropic|bedrock`; any value but `off` also needs `-investigator-egress-ack=true` and `-incidents`. It sends a redacted digest of an incident, and the tool results the starting user may see, to the provider.

**Packages:** `internal/investigate` (stdlib: the `LLM` interface, digest, egress filter, tools, agent loop, prompt, report validation, `Service`, `Store` and memory store, `investigatetest.ScriptedLLM`); `internal/llm` (the only importer of `github.com/anthropics/anthropic-sdk-go`, and for Bedrock of the AWS SDK config); `internal/pgstore/investigations.go`. `investigate` never imports `llm`; `cmd/server` wires them.

**Capability:** `InvestigateIncidents` = `create investigations.kubesentry.io`, namespaced (UI `investigate`); node and cluster incidents need it cluster-wide. Chart role `<release>-investigator`, `rbac.viewerRoles.investigator.aggregateTo` (default `[]`).

| Route | Notes |
|---|---|
| `POST /api/v1/incidents/{id}/investigations` | Body `{fresh?: bool}` (or empty). 404 before any authorization review when the incident is unknown or out of scope; 403 without `investigate`; 409 `{runningId}` while one runs for the incident; 429 + `Retry-After` when the caller's or the global hourly quota is spent; 503 + `Retry-After: 30` when this replica runs `-investigator-concurrency` jobs. A completed run with the same input hash in the last 24h answers 200 `{investigation, cached: true}` without a model call (and without using quota) unless `fresh`. Otherwise 202 `{investigation}` (status `running`). Cross-origin and body rules apply. Route label `incident_investigate` |
| `GET /api/v1/incidents/{id}/investigations` | `InvestigationsResponse`: summaries the caller may read, newest first, plus `hidden`. Route label `incident_investigations`; in `TestNoAuthorizationLeaks` |
| `GET /api/v1/incidents/{id}/investigations/{iid}` | `Investigation`; 404 when the caller may not read it. Route label `incident_investigation` |
| `POST /api/v1/incidents/{id}/investigations/{iid}/cancel` | the starter only (403 otherwise); 409 when not running. Route label `incident_investigation_cancel` |

All answer `Cache-Control: no-store` and are never response-cached. Poll every 2s while `running`. Each start writes one access-log line (identity, incident, provider, model).

**Access is frozen at start:** `{logs: ViewPodLogs, audit: ViewAudit (ViewClusterAudit for node incidents), cloudtrail: ViewCloudTrail, nodes: ViewNodes}`, stored with the run. Tools the starter lacks are still offered to the model but answer an error without reading the source, and the section is listed in `omitted`. Reading a run needs the incident visible and every capability its `access` holds as true; otherwise 404, and lists count it in `hidden`. A permission revoked mid-run is not seen (a run lasts at most `-investigator-timeout`).

**Digest** (first user message, at most `-investigator-digest-bytes`, 64 KiB): header (incident, window, cluster, now, omitted, truncated), every trigger signal and the context signals (first and last per type plus counts when over a third of the budget), per-series metric statistics and a 30-point max-preserving downsample, Kubernetes events grouped by reason/type/object (top 50, warnings first), log templates (digits, hex, UUIDs, IPs, timestamps stripped; top 40, errors first, 2 samples nearest a trigger), audit writes and tagged events (≤ 100), CloudTrail summaries. Every record carries a `ref`.

**Tools** (inputs validated with unknown fields rejected; times clamped to the padded window; pods must be the incident's; 30s each; output through the egress filter, capped, JSON-encoded inside `<untrusted source="…">`):

| Tool | Input | Needs | Cap |
|---|---|---|---|
| `list_signals` | `type`, `role`, `from`, `to`, `limit` ≤ 200 | — | 32 KiB |
| `get_logs` | `pods` ≤ 5, `containers` ≤ 5, `from`, `to`, `level`, `contains` ≤ 200, `limit` ≤ 200 | logs | lines ≤ 2 KiB; 48 KiB |
| `get_metric_series` | `metric` (memory, requests, errors), `label`, `from`, `to`, `max_points` ≤ 120 | — | 24 KiB |
| `get_k8s_events` | `object_kind`, `object_name`, `reason`, `type`, `from`, `to`, `limit` ≤ 200 | nodes (Node events) | the incident's namespace only; messages ≤ 500; 32 KiB |
| `get_audit_events` | `verb`, `resource`, `user`, `tag`, `from`, `to`, `limit` ≤ 100 | audit | no source IPs or user agents; 32 KiB |
| `get_cloudtrail_events` | `event_name`, `from`, `to`, `limit` ≤ 50 | cloudtrail | from the incident's signals (no new AWS calls); raw ≤ 1 KiB without `sourceIPAddress`, `userAgent` |
| `get_workload_state` | — | nodes (node conditions) | the current snapshot, labelled as now; 16 KiB |
| `submit_report` | `InvestigationReport` (strict) | — | ends the run |

**Budgets** (flags): `-investigator-max-turns` 16, `-investigator-max-tool-calls` 24, `-investigator-max-tokens` 1,500,000 (input + output + cache reads + cache writes over the run), `-investigator-max-output-tokens` 16,000 per turn, `-investigator-timeout` 10m. Exhausted: pending calls answer "budget exhausted", one turn for `submit_report`, then a final turn with tools off and the report schema as structured output.

**Report validation:** refs not shown to the model during the run move to `unverified`; timeline entries more than 1h outside the window are dropped; lists and strings are capped. A `command` must start with an allowed read-only form (`kubectl get|describe|logs|top|events|explain|auth can-i|rollout history|rollout status|api-resources|version`, `cmctl status`, `helm status|history|get`, `aws <service> describe-*|get-*|list-*|lookup-*`) and contain none of ``;|&$`<>`` or a newline; otherwise it is removed and the description gains "(command removed: not read-only)". Output is shown as plain text; commands are never run.

**Model and provider:** `-investigator-model` (default `claude-opus-5-5`; with `bedrock`, `anthropic.claude-opus-5-5`, or an inference-profile ID or ARN), `-investigator-effort` (`high`; `low|medium|high|xhigh|max`), `-investigator-region` (default `-aws-region`), `-investigator-bedrock-api` (`mantle`, the SDK's Messages-API Bedrock endpoint, or `runtime`, InvokeModel), `-investigator-endpoint` (override for a VPC endpoint, proxy or tests). `ANTHROPIC_API_KEY` from the environment only. Adaptive thinking is implied (no `thinking` field is sent); effort goes in `output_config`.

**Limits:** `-investigator-per-hour` 10 per identity, `-investigator-per-hour-total` 60 (both counted from stored runs, so they hold across replicas; cache hits are free), `-investigator-concurrency` 2 per replica, one running run per incident. Cache key: SHA-256 of digest, model, effort, prompt version and access.

**`/info.investigator`:** `{enabled, provider, model, effort, perHour}` (absent when off).

**Redaction additions** (also in bundle downloads): signal `tags` and metric series labels are redacted; new built-in rules for GitHub (`ghp_`, `gho_`, `github_pat_`), Slack (`xox[abpr]-`), Anthropic (`sk-ant-`), Stripe (`sk_live_`) tokens and `aws_secret_access_key=`. Investigator egress also drops audit source IPs and user agents, the `sourceIP`/`userAgent` attributes, and CloudTrail `sourceIPAddress`/`userAgent`.

**Storage (`0006_investigations.sql`):**
```sql
CREATE TABLE IF NOT EXISTS incident_investigations (
  id text PRIMARY KEY,
  incident_id text COLLATE "C" NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
  namespace text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz, requested_by text NOT NULL,
  provider text NOT NULL, model text NOT NULL, effort text NOT NULL, prompt_version text NOT NULL,
  input_sha256 text NOT NULL, cached_from text,
  access jsonb NOT NULL, omitted jsonb NOT NULL DEFAULT '{}',
  status text NOT NULL CHECK (status IN ('running','completed','refused','failed','cancelled')),
  error text, refusal jsonb, progress jsonb NOT NULL DEFAULT '[]', report jsonb,
  input_tokens bigint NOT NULL DEFAULT 0, output_tokens bigint NOT NULL DEFAULT 0,
  cache_read_tokens bigint NOT NULL DEFAULT 0, cache_write_tokens bigint NOT NULL DEFAULT 0,
  turns int NOT NULL DEFAULT 0, tool_calls int NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS incident_investigations_incident ON incident_investigations (incident_id, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS incident_investigations_running ON incident_investigations (incident_id) WHERE status = 'running';
CREATE INDEX IF NOT EXISTS incident_investigations_quota ON incident_investigations (requested_by, created_at);
CREATE INDEX IF NOT EXISTS incident_investigations_hash ON incident_investigations (input_sha256, created_at DESC) WHERE status = 'completed';
```
Written through the pool by the replica running the job, after every turn (`updated_at` is the heartbeat; a `running` row older than 2 minutes reads as `failed`, `interrupted`). Shutdown marks the replica's running jobs failed. Rows go with their incident (cascade). Memory mode keeps the newest 1,000 runs.

**Helm:** `incidents.investigator{enabled,provider,acknowledgeDataEgress,model,effort,region,bedrockAPI,endpoint,timeout,limits{perHour,perHourTotal,concurrency,maxTurns,maxToolCalls,maxTokens},existingSecret,apiKeyKey}`. The chart refuses it without `acknowledgeDataEgress`, without `incidents.enabled`, or with provider `anthropic` and no secret. Bedrock IAM: the inference action of the chosen Bedrock API on the model and inference-profile ARNs (`docs/deploy-eks.md`).

**Metrics:** `kubesentry_investigations_total{provider,result}` (`completed`, `refused`, `failed`, `timeout`, `budget`, `cancelled`, `cached`, `quota`, `busy`), `kubesentry_investigations_running`, `kubesentry_investigation_duration_seconds`, `kubesentry_investigation_tokens_total{provider,model,kind}` (`input`, `output`, `cache_read`, `cache_write`), `kubesentry_investigation_tool_calls_total{tool,result}` (`ok`, `error`, `denied`, `invalid`), `kubesentry_llm_requests_total{provider,code}`.
