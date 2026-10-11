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

Dependency rule: client-go only in `internal/kube` (and `test/stress`); pgx only in `internal/pgstore`; AWS SDK v2 only in `internal/cloudwatch`, `internal/awsauth`, `internal/aws/**`. Everything else is stdlib.

## HTTP

### Listeners
- `-addr` (default `127.0.0.1:8080`): UI and `/api/`. Behind the oauth2-proxy sidecar in proxy mode.
- `-ingest-addr` (e.g. `:8081`): `POST /agent/report`, `POST /audit/webhook`, token-authenticated. Empty: served on `-addr`.
- `-ops-addr` (e.g. `:9090`): `/healthz`, `/readyz`, `/metrics`, and `/debug/pprof/` when `-pprof`. Empty: `/healthz` and `/readyz` on `-addr`, no metrics.
- `/readyz` is 503 until caches have synced and the first view exists; afterwards it stays ready and reports degraded sources in its body.

### Routes (new and changed)
| Route | Change |
|---|---|
| `GET /api/v1/info` | adds `identity`, `capabilities`, `cluster`, `snapshot`, `auditStore`, `prometheus`, `unavailable` (see `web/src/types.ts` `Info`) |
| `GET /api/v1/pods` | `?namespace=&limit=&continue=`; items gain `ready`, `reason`, `node`, `workload`; response gains `continue` |
| `GET /api/v1/workloads` | `?limit=&continue=`; items gain `notReady`, `waiting` |
| `GET /api/v1/nodes` | `?summary=true` omits `pods` (keeps `podCount`); items gain `placement` |
| `GET /api/v1/nodes/{name}` | one node with its pods |
| `GET /api/v1/storage` | claims, classes gain cost/price fields; `?limit=&continue=` pages claims |
| `GET /api/v1/security` | `?view=summary` returns counts + the 200 most severe; `?limit=&continue=` pages findings |
| `GET /api/v1/map` | edges gain `how`, endpoint counts; kinds gain `ReplicaSet`, `Controller` |
| `GET /api/v1/oom` | leaks come from the background `LeakReport` when the window matches its window |
| `GET /api/v1/audit/events` | `?continue=` (opaque cursor); scope-filtered |
| `GET /api/v1/agents` | new: `[{node, lastReport, processes, bytes, stale}]` |
| `POST /api/v1/auth/recheck` | new: forgets the caller's cached authorization decisions and returns `{capabilities}`; at most once a minute per identity (429 otherwise) |

### Authentication rules
- Proxy mode reads identity headers only from `-auth-trusted-proxy-cidrs`; from anywhere else they are ignored.
- A proxy user starting with `system:` is refused. IdP groups starting with `system:` are dropped (so no IdP group can become `system:masters`); groups produced by the admin's group map are kept as written.
- Every identity, including the token and `none` identities, carries `system:authenticated`.
- The UI learns the mode from `/info` `identity.source`. In proxy mode oauth2-proxy guards every path, so a 401 mid-session means the SSO session expired: the UI reloads the page to sign in again. In token mode a 401 shows the token prompt.

Pagination: `limit` (default 200, max 1000) and an opaque `continue` token; the response carries `continue` when there is more.

### Scope per route
Every namespaced item is shown only if the caller holds `auth.ViewNamespace` in its namespace. Further gates: processes `ViewProcesses`; audit `ViewAudit` per namespace and `ViewClusterAudit` for events without a namespace; nodes, PVs, storage classes, ClusterRole/ClusterRoleBinding findings, ClusterIssuers need their cluster-wide capability. Without one, the page degrades (names only, status `unknown`) instead of failing. `/info` returns the caller's capabilities so the UI hides what it cannot use. The break-glass token and `-auth-mode=none` are unrestricted.

## Server flags (new)

| Flag | Default | Purpose |
|---|---|---|
| `-auth-mode` | `token` | `proxy`, `token` or `none` (`none` only on loopback) |
| `-auth-user-header` / `-auth-groups-header` | `X-Forwarded-Email` / `X-Forwarded-Groups` | identity headers from the proxy |
| `-auth-username-prefix` / `-auth-groups-prefix` | `""` | match the API server's (or EKS OIDC provider's) prefixes |
| `-auth-group-map-file` | | JSON `{ "idp-group": ["k8s-group", ...] }` |
| `-auth-trusted-proxy-cidrs` | `127.0.0.1/32,::1/128` | only these may send identity headers |
| `-auth-sign-out-url` | `""` | returned in `/info` as `signOutURL`; the chart sets `/oauth2/sign_out` when oauth2-proxy is enabled |
| `-authz-qps` / `-authz-cache-ttl` / `-authz-deny-ttl` | `200` / `5m` / `5m` | SubjectAccessReview budget and cache. Grants and revocations take up to the TTL to show; a user can force a recheck (below) |
| `-authz-share-by-groups` | `false` | cache by RBAC-relevant group set instead of per user |
| `-ingest-addr` / `-ops-addr` / `-pprof` | | listeners (above) |
| `-cache` | `true` | informer cache; `false` lists per request (debugging) |
| `-kube-qps` / `-kube-burst` | `50` / `100` | client-go limits |
| `-snapshot-min-interval` / `-snapshot-max-delay` | `2s` / `10s` | view rebuild debounce |
| `-cluster-name` | | shown in the UI; CloudWatch log group default `/aws/eks/<name>/cluster` |
| `-system-namespaces` / `-system-namespaces-add` | Policy default / | replace or extend system namespaces |
| `-system-principal-prefixes` / `-builtin-rbac-prefixes` | `system:,eks:` / `system:,eks:,kubeadm:` | |
| `-node-label-keys-add` | | extra node labels to keep |
| `-restart-warn`, `-restart-crit`, `-oom-recent`, `-pending-grace`, `-not-ready-grace`, `-terminating-grace`, `-recent-pod`, `-activity-window`, `-leak-crit-hours`, `-leak-min-slope`, `-leak-min-r2`, `-leak-drop-ratio`, `-leak-min-points`, `-cert-crit-cap`, `-cert-warn-cap` | Policy defaults | thresholds |
| `-pvc-default-price` | unset | now optional: unset means "no estimate" |
| `-ebs-prices` | Policy defaults | `gp3=0.08,io2=0.125,...` per region |
| `-prometheus-autodiscover` | `true` | find an in-cluster Prometheus when `-prometheus-url` is empty |
| `-prometheus-service` | | `namespace/name:port` to pin discovery |
| `-prometheus-selector` | | extra matchers, e.g. `cluster="prod"` |
| `-prometheus-sigv4` / `-aws-region` | auto for `aps-workspaces.*.amazonaws.com` | Amazon Managed Prometheus |
| `-prometheus-ksm-limits` | `false` | read limits from kube-state-metrics instead of pod specs |
| `-leak-scan-interval` / `-leak-scan-window` | `5m` / `24h` | background leak scanner |
| `-audit-store` | `memory` | `memory` or `postgres` |
| `-pg-dsn` (env `KUBESENTRY_PG_DSN`) / `-pg-schema` | / `kubesentry` | Postgres |
| `-audit-retention` | `30d` (Postgres) | |
| `-audit-redact-exec-args` | `false` | drop exec command arguments from stored request URIs |
| `-cloudwatch` / `-cloudwatch-log-group` / `-cloudwatch-stream-prefix` / `-cloudwatch-start` / `-cloudwatch-endpoint` | `false` / `/aws/eks/<cluster>/cluster` / `kube-apiserver-audit` / `24h` / | EKS audit reader |
| `-aws-auth` | `false` | read kube-system/aws-auth (needs the chart's scoped Role) |
| `-rate-limit` / `-rate-burst` / `-max-inflight` | `20` / `40` / `512` | per identity / total |
| `-tls-cert` / `-tls-key` | | TLS for the web and ingest listeners; the ops listener stays plain HTTP (probes, scraping) |

Agent flags (new): `-jitter` (0.2), `-gzip` (true), `-server-fanout` (a bare host, e.g. the headless ingest Service: the agent resolves it and posts to every address with the scheme and port of `-server`, verifying TLS against the `-server` host; if resolution fails it posts to `-server` alone), `-ca-file`. Both binaries take `-X main.version=...` at build time.

## Cluster-sourced configuration
- Namespace label `kubesentry.io/system: "true" | "false"`.
- StorageClass annotation `kubesentry.io/price-per-gib-month: "0.08"`.
- Service annotation `kubesentry.io/prometheus: "true"` marks the Prometheus to discover.
- Node labels (kept): `topology.kubernetes.io/{zone,region}`, `node.kubernetes.io/instance-type`, `kubernetes.io/{arch,os}`, `eks.amazonaws.com/{nodegroup,capacityType,compute-type}`, `karpenter.sh/{nodepool,capacity-type}`, `karpenter.k8s.aws/instance-family`, `node-role.kubernetes.io/*`.
- Service annotations (kept): `service.beta.kubernetes.io/aws-load-balancer-{scheme,internal,type,nlb-target-type}`.
- Ingress annotations (kept): `alb.ingress.kubernetes.io/{scheme,certificate-arn,listen-ports,ssl-redirect}`, `kubernetes.io/ingress.class`.

## Helm values (top level)
`clusterName`, `image`, `imagePullSecrets`, `agent`, `replicas`, `updateStrategy`, `server{cache,kubeQPS,kubeBurst,snapshot...,rateLimit,rateBurst,maxInflight,systemPrincipalPrefixes,builtinRBACPrefixes,nodeLabelKeysAdd,pprof}`, `tls{enabled,existingSecret}`, `tokens{api,agent,audit}{existingSecret,key}`, `rbac{viewerRoles.*.aggregateTo}`, `resources`, `serviceAccount{create,name,annotations}`, `auth{mode,userHeader,groupsHeader,usernamePrefix,groupsPrefix,groupMap,trustedProxyCIDRs,authzQPS,authzCacheTTL,authzDenyTTL,shareByGroups}`, `oauth2Proxy{enabled,image,provider,issuerURL,clientID,existingSecret,extraArgs,sessionStore}`, `prometheus{url,autodiscover,service,selector,ksmLimits,bearerTokenSecret,leakScan,amp{enabled,workspaceURL,region}}`, `audit{store,retention,maxEvents,redactExecArgs,postgres{existingSecret,dsnKey,schema,sslmode,sslRootCert},sources{webhook{enabled},cloudwatch{enabled,logGroup,streamPrefix,start,endpoint},file{path,fromStart,hostPathDir}}}`, `eks{clusterName,region,awsAuth{read}}`, `systemNamespaces{replace,add}`, `thresholds{...}`, `pricing{defaultPrice,ebsPrices,classPrices}`, `pdb`, `networkPolicy{...,egress.podIdentityAgent}`, `topologySpread`, `ingress`, `metrics{serviceMonitor,prometheusRule}`, `apf{enabled}`, `extraArgs`, plus the usual pod knobs (resources, probes, affinity, tolerations, extra env/volumes/containers). The chart is authoritative: `charts/kubesentry/values.yaml` and `values.schema.json`. Postgres TLS comes from `PGSSLMODE`/`PGSSLROOTCERT` env, so pgstore must build its config with `pgxpool.ParseConfig`.

## Metrics (`/metrics` on the ops listener)
`kubesentry_http_requests_total{route,code}`, `kubesentry_http_request_duration_seconds{route}`, `kubesentry_http_inflight`, `kubesentry_http_cache_total{result}`, `kubesentry_snapshot_build_seconds`, `kubesentry_snapshot_age_seconds`, `kubesentry_snapshot_version`, `kubesentry_informer_objects{resource}`, `kubesentry_kube_requests_total{verb,resource,code}`, `kubesentry_authz_reviews_total{result}`, `kubesentry_authz_cache_total{result}`, `kubesentry_prometheus_query_seconds{kind}`, `kubesentry_prometheus_cache_total{result}`, `kubesentry_audit_ingested_total{source}`, `kubesentry_audit_queue_depth`, `kubesentry_audit_store_errors_total`, `kubesentry_cloudwatch_lag_seconds`, `kubesentry_agent_reports_total{code}`, `kubesentry_agent_nodes_reporting`, plus Go runtime metrics.

## Postgres schema (`internal/pgstore/migrations/0001_audit.sql`)
```sql
CREATE TABLE IF NOT EXISTS audit_events (
  audit_id text NOT NULL, time timestamptz NOT NULL, stage_rank smallint NOT NULL, stage text NOT NULL,
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
CREATE INDEX IF NOT EXISTS audit_events_default_view ON audit_events (time DESC)
  WHERE actor_kind <> 'system' AND (NOT is_read OR tags <> '{}');
CREATE TABLE IF NOT EXISTS audit_events_default PARTITION OF audit_events DEFAULT;
CREATE TABLE IF NOT EXISTS ingest_checkpoints (
  source text PRIMARY KEY, position jsonb NOT NULL, owner text, updated_at timestamptz NOT NULL DEFAULT now()
);
```
Daily partitions `audit_events_YYYYMMDD` are created ahead and dropped after `-audit-retention` by the advisory-lock holder.
