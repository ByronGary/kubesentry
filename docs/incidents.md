# Incidents

An incident is a workload in trouble, and everything around it on one time axis: its request rate, error ratio and memory, its restarts and OOM kills, its Kubernetes events, the deploys and edits made to it, the AWS changes that touch it, and its container logs. Only critical and warning problems open one.

Take an app that receives too many requests while its memory climbs. kubesentry opens one incident for its Deployment with a `request-spike` and a `memory-spike`. It attaches the deploy made 20 minutes earlier and a security group change from CloudTrail, then shows the error lines the pods wrote a few minutes after the spike.

Incidents are **dashboard only**: they never notify anyone. The alert findings (`docs/alerts.md`) keep notifying per finding, and each finding's episode shows up in its workload's incident as an `alert` signal. Once it has, the alert links to the incident: the Alertmanager annotation `incident_url` (with `-external-url`, from the next resend on) and `incidentId` in `GET /api/v1/alerts`. Each incident can be downloaded as an **agent-ready bundle**, a redacted, size-capped JSON or NDJSON file for an agent (or a person with `jq`). The optional AI investigator reads an incident and writes a report with cited evidence ([docs/investigator.md](investigator.md)).

Turn incidents on with `-incidents`, or `incidents.enabled` in the Helm chart. `go run ./cmd/demo` shows three seeded incidents without a cluster.

## Contents

1. [What an incident is](#1-what-an-incident-is)
2. [Signals](#2-signals)
3. [App and service tags, and related incidents](#3-app-and-service-tags-and-related-incidents)
4. [The incidents list](#4-the-incidents-list)
5. [Reading an incident](#5-reading-an-incident)
6. [The agent-ready bundle](#6-the-agent-ready-bundle)
7. [Permissions](#7-permissions)
8. [Configuration by scenario](#8-configuration-by-scenario)
9. [Settings](#9-settings)
10. [Known limits](#10-known-limits)

## 1. What an incident is

**One incident per workload.** Signals are grouped by the workload root a pod belongs to: a pod rolls up through its ReplicaSet to its Deployment, and a Job to its CronJob. Bare and static pods are their own root. A node has incidents of its own (kernel OOM kills, evictions reported on the node). Two workloads in trouble at the same time get two incidents, marked as related (section 3), never merged.

**Triggers and context.** Every signal is one or the other:

- **Triggers** open an incident and set its severity: spikes, OOM kills, crash loops, restarts, evictions, repeated warning events, alert episodes.
- **Context** only attaches to an incident: deploys, scaling, edits by people (audit log), AWS changes (CloudTrail) and bursts of error logs. A deploy on its own opens nothing.

**Lifecycle:**

| Rule | Behaviour | Setting (default) |
|---|---|---|
| Open | the first trigger for a workload that has no open incident | |
| Join | further triggers join while the incident is open. Context joins when it falls in `[start − lookbehind, end + log lag]`, so a deploy shortly before, or a CloudTrail event delivered late, still attaches | `lookbehind` (30m) |
| Severity | `critical` or `warning` (the UI's "caution"): the worst active trigger. The **peak severity** never goes down, and the list filters and counts by it | |
| Quiet close | resolved once no trigger is active and the last one ended at least the quiet period ago | `quiet` (15m) |
| 24-hour cap | an incident that reaches the cap closes with `capped` and continues in a new incident, which links back through `previous` | `maxRange` (24h, the most allowed) |
| Stale conditions | a spike, crash loop or alert episode whose producer stopped reporting for 30 minutes ends at its last report, so a source that went away cannot keep an incident open | |
| Bounds | at most 500 signals per incident. Point signals of one type on one object within a minute coalesce into one with a count. At most 50 pods, services and nodes are listed | |

**The padded window.** Logs are written after the fact, and events trail what caused them. Logs and events are therefore read in a window padded on both sides: `[start − log lead, end + log lag]`, where an open incident's end is now. The window is never longer than 24 hours. With the defaults (`logLead` 5m, `logLag` 10m), an incident from 14:00 to 14:20 reads logs and events from 13:55 to 14:30. Context is matched by when it happened, not when it arrived: a resolved incident stays ready for an hour after its window ends, so a CloudTrail event delivered up to about 15 minutes late still attaches when its time falls in the incident's range.

**Where incidents live.** The engine runs on one replica:

- **Memory store** (one replica, `audit.store=memory`): incidents are lost on restart. Running more replicas this way would give each its own incidents, so the chart refuses it.
- **Postgres** (`audit.store=postgres`): the replica holding the `incidents` advisory lock runs the engine and commits to Postgres; the others re-read the store every 15 seconds. When that replica stops, another takes the lock within 30 seconds and reloads the open incidents.

Resolved incidents are kept for `retention` (7 days) and raw Kubernetes events for `eventsRetention` (48 hours). The last 24 hours are served from memory. Older ranges, up to the retention, are read from the store.

## 2. Signals

| Type | Role | Default rule | Source |
|---|---|---|---|
| `request-spike` | trigger | request rate over the last 5 minutes against the hour before it: ×2 warning, ×4 critical, for subjects of at least 1 request per second. The baseline is frozen during a spike, which ends after 2 scans below 0.8× its threshold | Prometheus request profiles, ALB metrics |
| `error-rate` | trigger | share of 5xx responses: 5% warning, 20% critical | same |
| `memory-spike` | trigger | a container at 85% (warning) or 95% (critical) of its memory limit. Without a limit: a jump to ×1.5 the previous scan and at least 128 MiB more | Prometheus (`container_memory_working_set_bytes`) |
| `oom-kill` | trigger, critical | a container's last termination was OOMKilled and its restart count went up | the cluster view |
| `crashloop` | trigger, critical | a container in CrashLoopBackOff | the cluster view |
| `restart` | trigger | restarts of one pod within the quiet period, at `-restart-warn` (3) and `-restart-crit` (10) | the cluster view |
| `eviction` | trigger, warning | a pod evicted | the cluster view |
| `k8s-event` | trigger or context | trigger: `BackOff`, `Unhealthy`, `FailedScheduling`, `FailedMount`, `FailedAttachVolume`, `Failed`, `FailedCreatePodSandBox` and `FailedKillPod` at least 3 times in 5 minutes; `OOMKilling` (critical) and `Evicted` (warning) at once. Every other Warning event, and the Normal reasons kept, are context | Kubernetes events |
| `alert` | trigger | an alert finding's episode, with the finding's severity | the alerts (`-alerts`) |
| `deploy` | context | a workload's revision changed: the image diff (`repo: v1 → v2`), and a rollback flag when an older ReplicaSet came back | the cluster view |
| `scale` | context | a workload's desired replicas changed | the cluster view |
| `audit-change` | context | a write by a person (not a ServiceAccount or a system component) to the workload, its pods or Services, its HPA, or, for the whole namespace, to ConfigMaps, Secrets, RBAC, NetworkPolicies, quotas and similar | the audit store |
| `cloudtrail-change` | context | a non-read-only CloudTrail event that names an AWS resource tied to the workload (below) | CloudTrail |
| `log-errors` | context | error lines per minute at least 3× the rate before the incident and at least 5 a minute; counted every 2 minutes for at most 10 open incidents, no lines stored | the container logs |

**How often each source is read:** metrics every minute (`interval`), alert episodes every 15 seconds, the audit store every minute, CloudTrail every 2 minutes, error-log counts every 2 minutes, and events as they arrive. The cluster view is compared after each rebuild. The first view after a replica takes over only sets a baseline, so it does not report every existing restart again.

**CloudTrail matching.** An AWS change attaches when it names one of these identifiers, which kubesentry derives from the cluster:

- an EC2 instance ID, from a node's provider ID: the node and the workloads of the pods on it
- a target group ARN, from a TargetGroupBinding (AWS Load Balancer Controller): the workloads behind the bound Service
- a load balancer name, from the Ingress annotations `alb.ingress.kubernetes.io/group.name` and `load-balancer-name`, or the Service annotation `service.beta.kubernetes.io/aws-load-balancer-name`
- a security group, from the ALB and NLB security group annotations
- an IRSA role ARN, from a ServiceAccount's `eks.amazonaws.com/role-arn`: the workloads running as that account
- the EKS cluster name (`-cluster-name`), for cluster, node group and add-on changes, which attach to every incident as cluster context

Other events are dropped. Read-only calls are never fetched.

**Sources that are missing.** `GET /api/v1/info` reports each source under `incidents.sources` as `ok`, `absent` or `error: …`, and lists the ones in error under `unavailable` as `incidents:<source>`. Keys are `requests:<profile>` (for example `requests:nginx`, `requests:alb`), `memory`, `series`, `events`, `audit`, `alerts`, `cloudtrail` and `logs:<source>`. The scan skips what is missing, and the incident page hides a chart without data and says why. With no request metrics at all, memory spikes, restarts, events and alerts still open incidents.
- **Probes.** Every replica probes the request sources, the event permission (`list` and `watch` on `events`), each log source and CloudTrail at startup and every 10 minutes.
- **Recovery.** `events` returns to `ok` on a successful probe, when the watch delivers events, or once the watch has stayed up 30 seconds. On the replica running the engine, a successful probe does not hide a watch that keeps failing; a failed watch is retried after 10 seconds, waiting twice as long after each quick failure, up to 5 minutes. `cloudtrail` returns to `ok` after a successful poll.
- **Leadership.** Sources only the engine's replica updates (memory, audit, alerts, and the watch's and polls' errors) go back to their last probe, or their initial state, when that replica stops leading.
- **Metrics.** `kubesentry_incident_source_up{source}` is 1 for `ok` and 0 for an error; an `absent` source has no sample. `kubesentry_incidents_leader` is 1 on the replica running the engine.

## 3. App and service tags, and related incidents

Each incident carries tags that tie it to an app:

- **Label keys:** `app.kubernetes.io/name`, `app.kubernetes.io/instance`, `app.kubernetes.io/part-of`, `app.kubernetes.io/component`, `app` and `k8s-app`, plus a custom key of your own (`incidents.appLabel`, for example `example.com/system`). `incidents.appLabels` replaces the default keys; a trailing `*` keeps every key with that prefix on the workloads.
- **Values** come from the workload's own labels, or else the most common value across its live pods.
- **`service`** lists the Services that select the workload's pods (from EndpointSlices), and **`ingress`** the Ingresses routing to them.
- **`kubesentry.io/app`** is the display app: the custom key's value, else `app.kubernetes.io/name`, else `app`, else the workload's name. The list's `app` filter matches it.

**Related incidents.** Two incidents are related when their time ranges overlap and they share the value of `app.kubernetes.io/part-of`, `app.kubernetes.io/instance` or the custom key, or a Service in the same namespace. The detail page lists them. A checkout API and its worker that both fail in the same minute are each an incident, and each points to the other.

## 4. The incidents list

The **Incidents** page, under Health in the sidebar, shows the last 1, 3, 6, 12 or 24 hours. Filters:

- severity (the peak: "reached critical" or "warning only")
- signal type, which can repeat
- open or resolved
- namespace, team (owner) and production
- app, service, or any tag (`tag=k=v` in the API)

The type counts are taken before the filters, so they show what else is there. Incidents also appear elsewhere:

- The Overview has an Incidents tile with the open ones by severity. Open incidents also rank first among the "Needs attention" items of the same severity, and the sidebar shows a badge.
- A pod page shows a banner for the incidents of its workload.

The API behind the list is `GET /api/v1/incidents?window=6h` (or `from` and `to`, at most 24 hours apart and within the retention), with `severity`, `type`, `state`, `namespace`, `owner`, `app`, `service`, `tag`, `limit` and `continue`. `docs/contracts.md` has the details.

## 5. Reading an incident

`#/incidents/<id>` opens one incident. The header shows the peak severity and state, owner and production flag, tags, and the signal types with counts. It also lists the pods, Services and nodes involved, and related incidents. A capped incident links to the one that continues it, and a continuation links back through "an earlier incident".

**One time axis.** The charts, the event lanes and the log panel share one horizontal axis, and hovering one shows the same instant in all. The axis covers the padded window. Signals can start earlier than the window: a deploy 30 minutes before the incident attaches through the lookbehind. The axis is then extended back to the earliest attached signal, with a minute of margin, and at most 24 hours before the window.

**Charts.** Memory per container, the request rate and the error ratio of the incident's pods and Services:

- **Lines:** at most 12 per chart, the rest summed as "others". Each line is labelled at its end and drawn with its own dash style, so colour is never the only cue.
- **Thresholds:** horizontal lines at the thresholds of the spikes, such as 85% of a container's memory limit.
- **Markers:** above the charts, ✕ for an OOM kill, ↻ for a restart, ◆ for a deploy or scale, ▲ for a Kubernetes event. Shaded bands show the spikes.
- **Step:** the window divided by 240, between 15 seconds and 5 minutes.

Node incidents have no charts.

**Lanes.** One row per kind of event, in time order:

| Lane | Holds | Needs |
|---|---|---|
| Metric spikes and error logs | request, error and memory spikes, error-log bursts | |
| Restarts, OOM kills and evictions | the pods' trouble | |
| Kubernetes events | events about the workload, its pods and Services | |
| Deploys and scaling | revisions with their image diff, replica changes | |
| Alerts | alert finding episodes | |
| Changes by people (audit log) | writes by people | the audit viewer role |
| AWS changes (CloudTrail) | matched CloudTrail events | the CloudTrail viewer role |

A lane you may not see says so instead of looking empty. Each item adds what its attributes say beyond its title (section 6): a deploy's image change, a scale's replica counts, how often an event repeated.

**Narrowing to a moment (the brush).** Drag across a chart, a lane or the log strip to select a time range; with the keyboard, focus one, press Shift with an arrow key, then Enter. Esc clears it. The selection goes into the address as `from` and `to`, so a link to the page keeps it, and it narrows the logs below.

**Logs.** The log panel reads the incident's container logs in the padded window, or the brush's range. Nothing is stored: every view reads again.

- **Source:** `auto` uses CloudWatch Logs when it is configured, then `pods/log`. Either can be picked.
- **Level** is a **minimum**: `warn` shows warnings and errors (debug < info < warn < error). The level comes from a JSON field (`level`, `lvl`, `severity`), then logfmt, then klog's prefix, then words in the line.
- **Pod and container pickers**, and a text search.
- **The volume strip** above the lines shows how many lines fall in each moment, on the shared axis.
- **Order:** lines come oldest first, with each source's own timestamps.
- **Caps:** 2,000 lines and 1 MiB per read (`logs.maxLines`, `logs.maxBytes`). `pods/log` reads at most 10 pods and 3 containers each, and also the previous container of one that restarted inside the window. CloudWatch makes at most 10 calls per read. A capped read says it was truncated: narrow the brush to read further.
- **Redaction:** every line is redacted (section 6) before it leaves the server.
- **Deleted pods:** `pods/log` cannot read a pod that no longer exists. Its lines remain only where a log shipper sent them, such as CloudWatch Logs.

**Download bundle** saves the agent-ready bundle (next section) as NDJSON, with your own permissions.

## 6. The agent-ready bundle

```bash
curl -sS -H "Authorization: Bearer $TOKEN" \
  "https://kubesentry.example.com/api/v1/incidents/$ID/bundle?format=ndjson" > incident.ndjson
```

`GET /api/v1/incidents/{id}/bundle` returns everything kubesentry knows about one incident, for an agent to read: one JSON document, or with `?format=ndjson` one record per line. The schema is `kubesentry.io/incident-bundle/v1`. Responses carry `Content-Disposition: attachment` and `Cache-Control: no-store`. kubesentry's own AI investigator (off by default) builds its digest from the same bundle: see [docs/investigator.md](investigator.md).

**The header** (the JSON document's top level, and the first NDJSON line):

| Field | Meaning |
|---|---|
| `schema` | `kubesentry.io/incident-bundle/v1` |
| `generatedAt`, `cluster` | when, and which cluster |
| `incident` | the incident, as the list returns it |
| `window` | `{from, to}`, the padded window, in UTC |
| `complete` | `false` when sections were left out |
| `omitted` | sections left out, with why (`forbidden`) |
| `truncated` | sections cut at their cap |

**Records.** The JSON form has arrays `signals`, `metrics`, `events`, `logs`, `audit` and `cloudtrail`. In NDJSON each record is one line with a `kind`:

```json
{"schema":"kubesentry.io/incident-bundle/v1","generatedAt":"2026-10-16T09:30:00Z","cluster":"prod-eks","incident":{"id":"…","subject":{"kind":"Deployment","namespace":"payments","name":"api"},"severity":"critical","peakSeverity":"critical","state":"open","pods":["api-7d9f8c6b5-x2x4z"],"types":["deploy","memory-spike","request-spike"],"counts":{"deploy":1,"memory-spike":2,"request-spike":1}},"window":{"from":"2026-10-16T08:55:00Z","to":"2026-10-16T09:30:00Z"},"complete":true}
{"kind":"signal","id":"…","type":"request-spike","source":"metrics","role":"trigger","severity":"critical","start":"2026-10-16T09:00:00Z","subject":{…},"object":{"kind":"Service","namespace":"payments","name":"api"},"title":"api requests at 412.0/s, 4.6x the baseline of 90.0/s","value":412,"baseline":90,"threshold":180,"attrs":{"source":"nginx","ratio":"4.6","window":"5m0s","baselineWindow":"1h0m0s"}}
{"kind":"metric","metric":"memory","label":"api-7d9f8c6b5-x2x4z/api","unit":"bytes","source":"prometheus","points":[[1792141200000,512000000],…]}
{"kind":"event","uid":"…","type":"Warning","reason":"Unhealthy","message":"Readiness probe failed: …","count":14,"firstSeen":"…","lastSeen":"…","regarding":{"kind":"Pod","namespace":"payments","name":"api-7d9f8c6b5-x2x4z"}}
{"kind":"log","time":"2026-10-16T09:04:12Z","pod":"api-7d9f8c6b5-x2x4z","container":"api","level":"error","text":"upstream timed out, token=[REDACTED]","source":"cloudwatch"}
{"kind":"audit","auditID":"…","time":"…","verb":"patch","username":"erin@example.com","actorKind":"user","apiGroup":"apps","resource":"deployments","namespace":"payments","name":"api","statusCode":200,…}
{"kind":"cloudtrail","id":"…","time":"…","name":"AuthorizeSecurityGroupIngress","source":"ec2.amazonaws.com","actor":"arn:aws:sts::111122223333:assumed-role/…","matched":["sg-0123456789abcdef0"],"raw":"{…}"}
```

`metric` records are the chart series: `points` are `[unix milliseconds, value]`, and `unit` is `bytes`, `rps` or `ratio`. The incident's `pods` and `services` are bare names in `subject.namespace`, and `window` bounds the logs and events only: a signal attached through the lookbehind can start before `window.from`.

**Signal `attrs`** explain each signal: at most 16 keys of at most 512 bytes. Keys by type:

| Type | `attrs` keys |
|---|---|
| `request-spike` | `source` (the profile, or `alb`), `ratio` (peak against the baseline), `window`, `baselineWindow` |
| `error-rate` | `source`, `rps` |
| `memory-spike` | `pod`, `container`, `limit` (bytes, when there is one) |
| `oom-kill`, `restart` | `pod`, `container`, `reason`, `exitCode`, `restarts`, `node` |
| `crashloop` | `pod`, `container`, `restarts`, `lastReason`, `exitCode`, `message` |
| `eviction` | `pod`, `node`, `message` |
| `k8s-event` | `reason`, `type`, `count`, `component`, `message`, `uid` |
| `alert` | `alert`, `check`, `key`, `state`, `owner` |
| `deploy` | `fromRevision`, `toRevision`, `images` (the image diff), `rollback` (`"true"`) |
| `scale` | `from`, `to` (desired replicas) |
| `audit-change` | `user`, `verb`, `resource`, `subresource`, `apiGroup`, `auditID`, `statusCode`, `userAgent`, `sourceIP`, `arn` |
| `cloudtrail-change` | `eventName`, `eventSource`, `eventID`, `actor`, `region`, `resources`, `matched` (comma-separated), `raw` (the redacted event, cut to 512 bytes) |
| `log-errors` | `incident`, `source`, `truncated` |

Keys appear only when they have a value. Signals do not carry the PromQL they came from: request queries are built from the profiles (section 9).

**Caps.** Logs 2,000 lines and 1 MiB, events 2,000, audit events 1,000, CloudTrail records 500, and 4 MiB in all. Past 4 MiB, sections are trimmed from their end: logs first, then events, audit, CloudTrail and metrics. Each cut section is named in `truncated`.

**Redaction.** Logs, event messages, CloudTrail records, audit request URIs and user agents, and titles are redacted before they leave the server. The built-in rules cover AWS access key IDs, `password`, `secret`, `token`, `api_key` and `authorization` values (`key=value` and `"key": "value"`), Bearer tokens, JWTs, PEM private keys and `user:password@` in URLs. Add your own with `incidents.redactPatterns` (RE2 regular expressions). Redaction is best effort, so treat a bundle as sensitive. The AI investigator sends a digest of it, and the records its starter may see, to the model provider only when you turn it on and acknowledge that: what leaves, the egress filter and the recommended Bedrock setup through a VPC endpoint are in [docs/investigator.md](investigator.md).

**Sections you may not see.** The bundle holds only what the caller may see. A section you lack the permission for is left out and named in `omitted`, and `complete` is `false`; its signals are left out too. With `?require=all` the request is refused with 403 instead, naming the sections. An agent that must see everything should ask that way.

## 7. Permissions

kubesentry only reads. Users see incidents through their own Kubernetes RBAC, checked with SubjectAccessReviews as everywhere else:

| To see | They need |
|---|---|
| a namespace's incidents, its charts, events and Kubernetes events | `list pods` in that namespace (as for every page) |
| node incidents, and events about nodes | `list nodes`, cluster-wide |
| an incident's container logs | **`get pods/log` in its namespace**: what `kubectl logs` needs, whichever source the lines come from. The built-in `view`, `edit` and `admin` roles already grant it. The chart also creates `<release>-logs-viewer` for users with narrower roles |
| changes by people (audit) | `<release>-audit-viewer` in the namespace (`docs/deploy-eks.md`, section 8) |
| AWS changes (CloudTrail) | **`<release>-cloudtrail-viewer`**, bound with a ClusterRoleBinding: `list cloudtrail.kubesentry.io`, a virtual resource |

```bash
kubectl create clusterrolebinding kubesentry-cloudtrail-platform \
  --clusterrole=kubesentry-cloudtrail-viewer --group=platform-admins
```

CloudTrail records name AWS principals and resources across the account. The viewer role is therefore cluster-wide, and not part of `view` unless you add it: `rbac.viewerRoles.cloudtrailViewer.aggregateTo: [admin]` lets cluster-wide admins see them. An unknown incident ID, or one in a namespace you may not see, answers 404 without revealing whether it exists.

**kubesentry's own ServiceAccount** gets these read-only additions from the chart:

| Rule | When | Why |
|---|---|---|
| `serviceaccounts` list, watch | always | IRSA role annotations for CloudTrail matching |
| `elbv2.k8s.aws` `targetgroupbindings` list, watch | always (optional CRD) | ALB metrics and CloudTrail matching |
| `events` list, watch | `incidents.enabled` | Warning events, and the Normal reasons kept |
| `pods/log` get | `incidents.enabled`, with `logs.mode` `auto` or `kubernetes` | reading container logs for a user who may read them |

AWS permissions (CloudWatch Logs, CloudWatch metrics, CloudTrail) are in `docs/deploy-eks.md`, section 3.

## 8. Configuration by scenario

### EKS with Container Insights, the ALB and CloudTrail

The setup in `charts/kubesentry/examples/values-eks.yaml`:

- Container logs go to CloudWatch through Container Insights (the `amazon-cloudwatch-observability` add-on).
- Traffic arrives through the AWS Load Balancer Controller's ALB.
- AWS changes come from the CloudTrail event history.

```yaml
clusterName: prod-eks        # or eks.clusterName
eks:
  region: us-east-1
replicas: 2
audit:
  store: postgres            # the incidents lock and store; required with 2 replicas
incidents:
  enabled: true
  alb: true                  # ALB RequestCount and 5xx per target group
  logs:
    mode: cloudwatch         # /aws/containerinsights/prod-eks/application
  cloudtrail:
    mode: lookup             # LookupEvents, 1 call/s
```

- **Memory** comes from Prometheus or AMP (`container_memory_working_set_bytes`), as for leak detection. The built-in `nginx` and `app` request profiles are read too, and are reported `absent` where those metrics do not exist.
- **ALB metrics** come from `GetMetricData` with a `SEARCH` over `AWS/ApplicationELB` per target group of each TargetGroupBinding. The controller creates the bindings for Ingresses with `target-type: ip` or `instance`. They are read with a 2-minute lag (ALB metrics arrive 1 to 3 minutes late) and cached for 60 seconds.
- **Logs from CloudWatch** stay readable after a pod is deleted. With `logs.mode: auto` and `logs.group` set, CloudWatch is read first and `pods/log` serves `source=kubernetes`. Streams named per pod can be read by prefix with `logs.streamPrefix`, for example `{namespace}.{pod}`; otherwise a filter pattern on `kubernetes.namespace_name` and `kubernetes.pod_name` selects the records.
- **CloudTrail lookup** allows about 2 calls per second per account and region, shared with every other tool. kubesentry uses 1 (`cloudtrail.qps`) and backs off when throttled.
- **A trail delivered to CloudWatch Logs** (an organization trail, say) is read instead with `cloudtrail.mode: logs` and `cloudtrail.logGroup`, filtered to `{ $.readOnly IS FALSE }` at the source. It counts against the `FilterLogEvents` quota instead of `LookupEvents`, and backs off together with the audit reader and the container logs. `cloudtrail.region` reads another region's CloudTrail.
- **IAM:** `logs:FilterLogEvents` on the application (and trail) log group, `cloudwatch:GetMetricData` and `cloudwatch:ListMetrics`, and `cloudtrail:LookupEvents`. The policy is in `docs/deploy-eks.md`, section 3. With a restrictive network policy, egress on 443 must reach CloudWatch, CloudWatch Logs and CloudTrail, or their VPC endpoints.

### ingress-nginx and application metrics, logs from the cluster

Clusters with ingress-nginx and kube-prometheus-stack, and logs read through the API server:

```yaml
incidents:
  enabled: true
  requestSources: [nginx, app]   # the default
  logs:
    mode: kubernetes             # pods/log only; the chart grants get pods/log
```

- **`nginx`** reads `nginx_ingress_controller_requests` per backend Service. The namespace comes from `exported_namespace`, else `namespace`, and the status from `status`. Turn on the controller's metrics and ServiceMonitor (`controller.metrics.enabled=true`, `controller.metrics.serviceMonitor.enabled=true`).
- **`app`** reads `http_requests_total` per pod, with the `namespace`, `pod` and `code` labels a ServiceMonitor or PodMonitor adds.
- **`-prometheus-selector`** (`prometheus.selector`) applies to every request query, as to the memory queries.
- **Other counters** need a profile. kubesentry builds the query from label names, never from PromQL you write:

  ```yaml
  incidents:
    requestProfiles:
      - name: spring           # Spring Boot / Micrometer, per pod
        metric: http_server_requests_seconds_count
        namespaceLabel: namespace
        podLabel: pod
        statusLabel: status
      - name: envoy            # per Service, status class only
        metric: envoy_cluster_upstream_rq_xx
        namespaceLabel: namespace
        serviceLabel: service
        statusLabel: envoy_response_code_class
        errorRegex: "5"
  ```

  Each profile sets exactly one of `serviceLabel` and `podLabel`. `errorRegex` (default `5..`) matches failed statuses, anchored, and needs `statusLabel`; without one the error ratio is unknown. A profile with a built-in's name replaces it, and `requestSources: []` turns the built-ins off. The chart writes the profiles to a ConfigMap read with `-incident-request-profiles-file`.
- **Logs from `pods/log`** need no AWS, but end with the pod: a deleted pod's lines are gone, and only the current and previous container are kept by the kubelet.

### Remote mode, from a laptop

kubesentry runs incidents outside the cluster too (`docs/run-remote.md`, "Incidents"). The memory store is used, so incidents last as long as the process:

```bash
kubesentry -kube-context prod-eks -auth-mode none -aws-region us-east-1 -cluster-name prod-eks \
  -prometheus-url https://aps-workspaces.us-east-1.amazonaws.com/workspaces/ws-12345678-abcd-1234-abcd-123456789012 \
  -incidents -incident-alb -incident-logs cloudwatch -cloudtrail lookup
```

Your identity needs the chart's additions above (`events`, `pods/log`, `serviceaccounts`, `targetgroupbindings`), and your AWS credentials the IAM actions of the EKS scenario. Incidents start at launch: the first scan sets the baselines, and the CloudTrail history is read back `-cloudtrail-start` (1h).

## 9. Settings

Every flag has a Helm value under `incidents`; `null` keeps the server's default. `docs/contracts.md` lists the flags.

| Value | Flag | Default |
|---|---|---|
| `enabled` | `-incidents` | off. Needs the cache; more than one replica needs `audit.store=postgres` |
| `interval` | `-incident-interval` | `1m` (at least 10s) |
| `maxRange` | `-incident-max-range` | `24h`, the most allowed |
| `retention`, `eventsRetention` | `-incident-retention`, `-incident-events-retention` | `7d`, `48h` |
| `quiet`, `lookbehind` | `-incident-quiet`, `-incident-lookbehind` | `15m`, `30m` |
| `logLead`, `logLag` | `-incident-log-lead`, `-incident-log-lag` | `5m`, `10m` |
| `namespaces`, `includeSystem` | `-incident-namespaces`, `-incident-include-system` | every namespace but the system ones |
| `appLabel`, `appLabels` | `-incident-app-label`, `-incident-app-labels` | section 3 |
| `thresholds.requestRatio`, `requestCritRatio`, `requestMinRPS` | `-incident-request-ratio`, `-incident-request-crit-ratio`, `-incident-request-min-rps` | 2, 4, 1 |
| `thresholds.errorRatio`, `errorCritRatio` | `-incident-error-ratio`, `-incident-error-crit-ratio` | 0.05, 0.2 |
| `thresholds.memoryLimitPct`, `memoryCritPct` | `-incident-memory-limit-pct`, `-incident-memory-crit-pct` | 85, 95 |
| `thresholds.memoryJumpRatio`, `memoryJumpMin` | `-incident-memory-jump-ratio`, `-incident-memory-jump-min` | 1.5, `128MiB` |
| `thresholds.spikeRecent`, `spikeBaseline` | `-incident-spike-recent`, `-incident-spike-baseline` | `5m`, `1h` |
| `thresholds.eventMinCount` | `-incident-event-min-count` | 3 (in 5 minutes) |
| `requestSources`, `requestProfiles` | `-incident-request-sources`, `-incident-request-profiles-file` | `nginx,app`; none |
| `alb` | `-incident-alb` | off |
| `eventNormalReasons` | `-incident-event-normal-reasons` | `SuccessfulRescale`; `[]` keeps Warnings only |
| `logs.mode`, `logs.group`, `logs.streamPrefix` | `-incident-logs`, `-incident-logs-group`, `-incident-logs-stream-prefix` | `auto`; Container Insights' group with `cloudwatch`; a filter pattern |
| `logs.maxLines`, `logs.maxBytes` | `-incident-logs-max-lines`, `-incident-logs-max-bytes` | 2000, `1MiB` |
| `redactPatterns` | `-incident-redact-patterns` (repeatable) | none besides the built-ins |
| `cloudtrail.mode`, `logGroup`, `region`, `qps`, `start` | `-cloudtrail`, `-cloudtrail-log-group`, `-cloudtrail-region`, `-cloudtrail-qps`, `-cloudtrail-start` | `off`; with `logs` only; `-aws-region`; 1; `1h` |

Incidents without an owner annotation on their namespace belong to `alerts.defaultOwner`, as alerts do.

**The chart refuses:**

- `incidents.enabled` with `server.cache: false`
- `replicas` above 1 with incidents but without `audit.store=postgres`
- a CloudTrail mode with incidents off
- `cloudtrail.mode: logs` without `cloudtrail.logGroup`
- `logs.mode: cloudwatch` with neither `logs.group` nor a cluster name
- `maxRange` above 24 hours (the schema)

**Postgres connections.** The replica that holds a lock (CloudWatch reader, alerts, incidents) keeps one connection per lock besides `-pg-max-conns`. Size `max_connections` for replicas × `maxConns` + 3.

**Monitoring kubesentry itself.** With `metrics.prometheusRule.enabled`, four rules watch the incidents' inputs: `KubesentryCloudTrailFailing`, `KubesentryIncidentEventsFailing`, `KubesentryIncidentLogsFailing` and `KubesentryIncidentSourceDown` (any other source in error on the replica running the engine for 15 minutes). Their runbooks are in `docs/monitoring-eks.md`, which also describes the dashboard's Incidents row. The metrics are `kubesentry_incidents{severity}`, `kubesentry_incident_signals_total{type}`, `kubesentry_k8s_events_total{result}`, `kubesentry_cloudtrail_events_total{result}`, `kubesentry_incident_log_fetches_total{source,result}`, `kubesentry_incident_source_up{source}`, `kubesentry_incidents_leader` and `kubesentry_dependency_up{dependency="cloudtrail"}`.

## 10. Known limits

Some of these only real AWS and EKS can settle:

1. **ALB metrics.** `GetMetricData` with `SEARCH` is used over its JSON protocol, and whether `SEARCH` also needs `cloudwatch:ListMetrics` varies, so grant both. ALB metrics arrive 1 to 3 minutes late, so an ALB spike opens an incident a few minutes after it starts.
2. **CloudTrail.** `LookupEvents` allows about 2 calls per second, shared by everything in the account and region; heavy use elsewhere slows kubesentry's reads. CloudTrail delivers events up to about 15 minutes late, which is why late changes still attach. Organization trails can be very large: read them from CloudWatch Logs (`cloudtrail.mode: logs`), where the filter runs at the source.
3. **Container log formats** differ between Fluent Bit, Container Insights, the CloudWatch Observability add-on and Fluentd, and Fargate differs again. kubesentry reads the common fields (`log`, `kubernetes.pod_name`, `kubernetes.container_name`, `time` or `@timestamp`). For other layouts, `logs.streamPrefix` reads streams named per pod, or use `pods/log`.
4. **EKS Pod Identity** associations are not visible in Kubernetes, so CloudTrail changes to a role used through Pod Identity do not match a workload. Roles used through IRSA do.
5. **Kubernetes events** expire after their TTL (one hour by default) and are rate-limited by the API server, so some are never seen, and only the replica running the engine watches them. Bursts are batched and de-duplicated by UID. A failed write is counted (`kubesentry_k8s_events_total{result="error"}`).
6. **Postgres connections:** each held lock takes one connection (section 9).
7. **Redaction is best effort** (section 6).
8. **Clocks** differ between Prometheus, CloudWatch and the Kubernetes nodes. Each source keeps its own timestamps, and the padding absorbs small offsets.
9. **Failover.** When another replica takes over the engine, context signals that were waiting for an incident to open are lost (the audit poll re-reads the lookbehind, so audit changes come back). A coalesced point signal may be counted twice.
10. **Logs are never stored.** A bundle or a page reads them again, so lines that `pods/log` no longer has (a deleted pod, a container restarted twice since) are gone unless a log shipper kept them.
11. **No notifications.** An incident is never sent anywhere. To be paged, rely on the alerts (`docs/alerts.md`); a firing alert's finding appears in its workload's incident.
