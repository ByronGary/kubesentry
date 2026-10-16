# kubesentry alerts

kubesentry turns its findings into alerts and sends them to Alertmanager, or to the alert manager of an Amazon Managed Prometheus (AMP) workspace. Alertmanager then does the routing, grouping, silencing, inhibition and paging. kubesentry only notifies: it never writes to the cluster, and alerting adds nothing to its RBAC.

This page covers how alerting works, how to configure it, the labels and annotations each alert carries, and a runbook for every alert. Routing the alerts to teams is covered in `docs/monitoring-eks.md`, [section 4](monitoring-eks.md#4-routing-by-owner). The design and its decisions are in `docs/proposals/alerting-automation.md` (Layer 2, phase B).

## Contents

1. [How it works](#1-how-it-works)
2. [Turning it on](#2-turning-it-on)
3. [Labels and annotations](#3-labels-and-annotations)
4. [Watching the alerting itself](#4-watching-the-alerting-itself)
5. [Runbooks](#5-runbooks)
6. [Limits of this release](#6-limits-of-this-release)

## 1. How it works

### Evaluation

1. **When it runs.** After each snapshot build, kubesentry evaluates the view. It does this at most once per `-alerts-interval` (30s). In a quiet cluster, which does not rebuild, it still evaluates once per interval, so resends and resolves happen on time.
2. **What it computes.** It runs the [checks](#the-catalog) over the view, the background leak scan, the audit store and the node agents' reports. Each check yields findings, folded per workload: a workload is its root owner, as the Security page and the Overview group pods, so a Job counts under its CronJob. 300 crash-looping pods of one Deployment make one alert, with the pod count in its annotations.
3. **How it diffs.** It compares those findings with the stored ones and moves each finding along its lifecycle:

| Finding | What kubesentry does | What Alertmanager gets |
|---|---|---|
| **New** | Opens it. For two checks it waits first, like Prometheus's `for:`: certificates not ready wait 10 minutes and unhealthy workloads 5 minutes, so problems that clear by themselves stay quiet | the alert, `startsAt` = first seen |
| **Still there** | Updates it (severity, title, annotations) | the alert again every `-alerts-resend` (1m), with `endsAt` = now + 4 × resend. Alertmanager keeps it while kubesentry runs, and lets it expire on its own if kubesentry stops |
| **Labels changed** (severity, owner, a routing hint) | Alertmanager knows an alert by its label set, so kubesentry retires the old set | the old label set with `endsAt` = now, then the new one at once |
| **Gone** | Resolves it once it has been gone for `-alerts-resolve-grace` (5m), so a finding that drops out of a single view does not flap | the alert with `endsAt` = now, once |

4. **Unreadable data.** When kubesentry cannot read a source (pods, services, certificates or RBAC forbidden, no leak scan yet, the audit store down, no agent reports), it skips the checks that need it. Their findings keep their state: they are neither refreshed nor resolved. An outage of a source therefore never resolves the alerts that depend on it.
5. **Turning checks off.** `-alerts-disable-checks` (chart `alerts.disableChecks`) names checks that never alert, e.g. `nodeport,ingress-no-tls`. Their open findings resolve; a change-based check keeps its baseline as it was.

### Change-based checks and the first run

RBAC drift, exposure changes and privileged workloads alert on what **changed**, not on what stands:

- Each of their checks stores a baseline of the findings it saw (table `alert_baseline`): the Security page's RBAC findings, its exposure findings at warn (internet-facing load balancers and ALBs, NodePorts, external IPs, ingresses without TLS; internal load balancers are info there and never alert), and its privileged and host-namespace workloads. Cluster plumbing (system namespaces, built-in roles) is left out.
- An object missing from the baseline fires. The alert stays open for 24 hours while the object exists, then resolves, and the object becomes standing state.
- The first evaluation after an install, after an upgrade that adds a check, or after an empty store, records the baseline and notifies nothing.

The standing RBAC findings come in the weekly `rbac-posture` digest instead ([Standing-state digests](#standing-state-digests)). The other checks report standing state, so they do fire on the first run, under storm protection (below).

### Audit activity

With an audit store (any audit source, or `audit.store=postgres`), the evaluating replica reads the audit log for `KubesentryAuditActivity`:

- **Reads.** One query per audit tag the enabled checks need (`exec`, `portforward`, `debug-container`, `secret-access`, `rbac-change`, `impersonate`, `denied`, `anonymous`), every evaluation, from where the last one stopped. Each read goes 5 minutes further back, for events stored late, and drops the audit IDs it has already counted. The first read of a leadership term covers the whole hold window, so a new leader rebuilds the open findings.
- **Findings.** One per check, namespace and actor (the request's user), with key `check/User/<namespace>/<actor>` and the label `object="User/<actor>"`, so two people never merge. Cluster-scoped requests (cluster roles, non-resource URLs) make cluster-scoped findings, which only callers who may read the cluster's audit events see.
- **Hold.** A finding stays open while its newest event is younger than `-alerts-audit-hold` (1h), then resolves after the grace.
- **Production.** `-alerts-audit-production-only` (`audit-exec,audit-secret-read`) lists the checks that count only events in production namespaces (`-production-label`): exec and secret reads are routine elsewhere.
- **Store down.** While the audit store cannot be read (Postgres down, or a query fails), the audit checks are skipped: their findings stay as they are, and the events are read once it is back.
- **Examples.** The `examples` annotation names up to three recent requests: time, verb, resource and object, whom an impersonator acted as, and for exec the command, redacted with the incidents redactor (`-incident-redact-patterns` adds patterns). Source IPs and user agents are never included.

### Missing agents

With the node agent (`-agent-token`) and `-agent-daemonset` (the chart sets both), `KubesentryAgentMissing` names the nodes that run a pod of the agent DaemonSet but whose agent has not reported for three report intervals (`-agent-interval`, the chart passes `agent.interval`). Fargate nodes, NotReady nodes and nodes younger than 10 minutes are not expected to report.

Each replica knows only the reports that reach it. `-alerts-agents=auto` (the default) therefore runs the check only where every report reaches the replica: with the memory store's single replica, or with `-agent-fanout`, which the chart sets when `agent.fanout` is on (agents post to every replica) or `replicas` is 1. `on` and `off` force it.

### Standing-state digests

What stands, rather than what changed, goes out on a schedule as `KubesentryStandingDigest` (`severity="info"`, `kubesentry_digest="true"`), one alert per owner and kind:

| Kind (`digest` label) | Lists |
|---|---|
| `rbac-posture` | the Security page's standing RBAC findings outside cluster plumbing, worst first |
| `unused-volumes` | claims no pod mounts, at least `-pvc-min-age` old, most expensive first, with their monthly cost (`monthly_cost_usd`) |
| `certificates` | certificates that are not renewing on schedule but have more than `-alerts-cert-digest-days` (14) left |

- **Schedule.** `-alerts-digest-at` sets the time: `"Mon 09:00"` weekly, `"09:00"` daily, empty (the default) for none, in `-alerts-digest-tz` (UTC). `-alerts-digest-kinds` picks the kinds (all three).
- **Once.** Each digest is sent once, with `endsAt` an hour after `startsAt`, and never re-posted. The last run of each kind is kept (`alert_digest_runs`): a new leader sends nothing twice, and one that took over after missed slots catches up only the latest, once. A first start (or the memory store after a restart) waits for the next scheduled time.
- **Quiet certificates.** With the certificates digest on, a certificate with more than `-alerts-cert-digest-days` left is quiet: listed in the digest, never notified alone and never counted by storm protection. Once fewer days are left it fires on its own as `KubesentryCertificateExpiring` (and counts then).
- **Silenced findings** are left out. `/info.alerts` shows `lastDigestAt` and `nextDigestAt`; `kubesentry_alerts_standing_digests_total{kind}` counts them.
- **Routing.** Route `kubesentry_digest="true"` with `severity="info"` to a quiet receiver, grouped by `owner` and `digest` so each notifies within its hour (`docs/monitoring-eks.md`, section 4).

### Storm protection

New findings that would fire together are summed up per owner in one digest alert, `KubesentryFindingsDigest` with `kubesentry_digest="true"`, in this order:

1. **The global breaker.** If more than `-alerts-max-new` (50) new alerts would fire in one evaluation, every one of them goes into its owner's digest. This happens on a first install, or after a cluster-wide incident.
2. **The per-owner budget.** Otherwise each owner gets at most `-alerts-owner-max-new` (20) new alerts on their own in any `-alerts-owner-window` (15m, a sliding window kept by the evaluating replica); criticals take the budget first, and the rest join that owner's digest. One team's incident therefore never floods another team's pager, and a team's own storm reaches it as one message.
3. **Promotion.** A digested finding that turns from warning to critical leaves the digest and fires on its own (at most `-alerts-max-new` per evaluation; the rest follow at the next ones).
4. **What never counts.** Silenced findings and quiet ones (reported only in a standing digest) neither use a budget nor appear in a digest. A quiet certificate that crosses its threshold counts as a new finding then.

- The monitoring profile routes digests to a quiet receiver, one message per owner per day.
- The digest lists counts by alert and the 10 worst findings. It stays open while any of its findings is open, and ends when all of them have resolved or left it.
- Findings sent in a digest are marked `digest` and are not sent on their own later, unless they turn critical. Later new findings, within the limits, fire on their own as usual.
- `kubesentry_alerts_digested_total{reason}` counts the findings digested by `max_new` and by `owner_budget`.

### Acknowledging and silencing

People act on findings on the Alerts page (`#/alerts`: per row, or on the rows selected; Silence asks how long and why), which uses `POST /api/v1/alerts/actions` (section 4). It needs `update` on the virtual resource `alerts.kubesentry.io` where the finding is: per namespace through a RoleBinding, and cluster-wide (a ClusterRoleBinding) for cluster-scoped findings such as RBAC drift. The chart ships it as the ClusterRole `<release>-alerts-responder`; `rbac.viewerRoles.alertsResponder.aggregateTo: [edit]` adds it to the built-in `edit` (and so `admin`) role.

| Action | Applies to | What Alertmanager gets |
|---|---|---|
| **ack** | the current episode (the finding's `firstSeen`). A new episode after a resolve starts unacknowledged, and an ack taken at warning no longer covers the finding while it is critical | the alert keeps being re-posted every `-alerts-resend`, at once with the annotations `acknowledged_by` and `acknowledged_at`. An ack does **not** stop Alertmanager's `repeat_interval`: to stop the reminders, add an Alertmanager silence |
| **unack** | lifts the ack | the alert again at once, without the annotations |
| **silence** | the finding's key, from 5m to `-alerts-max-silence` (7d, at most 30d), with a reason of 3 to 500 characters. It lasts across a resolve and a reopen | the alert once with `endsAt` = now and the annotations `silenced_by`, `silenced_until`, `silence_reason`, then nothing. Receivers with `send_resolved: true` therefore get a **resolved** notification when a finding is silenced |
| **unsilence**, or the silence expires | lifts the silence | the alert fires again at once (`startsAt` = the episode's first seen) |

- **kubesentry's own log.** Actions go to an append-only log (`alert_actions`) that every replica writes through its connection pool and reads: the leader applies them at its next evaluation, at most `-alerts-interval` later (within about a second when the action was taken on the leader itself), and every replica's board shows them at once on the replica that took them and within 15s elsewhere. kubesentry never writes to Alertmanager's silence API, and never to the cluster.
- **Digests.** A silenced finding leaves its owner's digest; an acknowledged one stays in it.
- **History.** `GET /api/v1/alerts/actions` lists who did what, for the findings the caller may see. The log is kept for the findings' retention (30 days) plus a day.

### Owners

Every alert has an `owner` label, taken in this order:

1. **The object's own** owner annotation (`-owner-annotation`, `kubesentry.io/owner`) on the Deployment, StatefulSet, DaemonSet, Job, CronJob, Service, Ingress, cert-manager Certificate, Role, RoleBinding, ClusterRole or ClusterRoleBinding the finding names. The informer cache keeps this one annotation on these kinds, and no other.
2. **Its namespace's** owner annotation.
3. **`-alerts-default-owner`** (`platform`), also for cluster-scoped objects without one.

Pods carry no annotations in kubesentry's cache: a workload's finding uses the workload's owner, and a bare pod's its namespace's. When the object names an owner other than its namespace's, the namespace's routing hints (`kubesentry_*` labels from `kubesentry.io/*` namespace annotations) are left off: they route the namespace owner's alerts, not another team's.

### Leadership and duplicates

- **With Postgres** (`-audit-store=postgres`), only the replica holding the `alerts` advisory lock evaluates and notifies.
  - That replica keeps the findings in memory. It writes every change to `alert_findings` on the lock's own connection, after checking that it still holds the lock.
  - It commits before it sends, so a replica whose commit fails sends nothing.
  - When the lock is lost, its evaluation stops, its sink drops whatever was queued, and it releases the lock.
  - The other replicas retry for the lock every 30s. Meanwhile they read the findings every 15s, to serve `GET /api/v1/alerts`.
- **With the memory store**, the single replica evaluates. Its state is lost on restart: the next evaluation records the RBAC baselines again (without notifying), and finds the standing problems anew. Those count as new, so storm protection may send them as digests.

**Duplicates are harmless.** A new leader re-sends everything open as soon as it takes over. A replica that lost the lock may also finish one POST it had already started. Alertmanager identifies an alert by its label set, so a repeat only refreshes `endsAt`. Neither causes a second notification.

### The Alertmanager sink

- **Fan-out.** Every alert goes to each `-alertmanager-url`. List both members of an HA pair; they gossip and deduplicate.
- **Queues.** Each URL has its own bounded queue (10,000 alerts) and its own sender, so a slow or failing Alertmanager never blocks the evaluator or the other URLs. A full queue drops alerts and counts them (`kubesentry_alerts_sent_total{result="dropped"}`). Dropped alerts come back with the next resend, because every open alert is re-posted each minute.
- **Retries.** A POST carries up to 500 alerts. It gets up to 4 attempts, with doubling backoff from 1s, on 5xx, 429 and network errors. Any other 4xx is not retried.

## 2. Turning it on

| Flag | Helm value | Default | Meaning |
|---|---|---|---|
| `-alerts` | `alerts.enabled` | `false` | evaluate and notify |
| `-alertmanager-url` | `alerts.alertmanager.urls` | | base URLs, comma-separated; `/api/v2/alerts` is appended. Without any, findings are tracked and listed but nobody is notified (`/info` says `sink: "none"`) |
| `ALERTMANAGER_TOKEN` (env) | `alerts.alertmanager.existingSecret` + `tokenKey` | | bearer token |
| `-alertmanager-basic-auth-user`, `ALERTMANAGER_PASSWORD` (env) | `alerts.alertmanager.basicAuth.username`, `existingSecret` + `basicAuth.passwordKey` | | basic auth |
| `-alertmanager-ca-file` | `alerts.alertmanager.ca.{configMap,secret,key}` | | PEM CA bundle added to the system roots |
| `-alertmanager-sigv4` | `alerts.alertmanager.sigv4` | automatic for `aps-workspaces.*` URLs | sign with SigV4 (service `aps`, region from the URL or `-aws-region`) |
| `-alerts-interval` | `alerts.interval` | `30s` | evaluation interval |
| `-alerts-resend` | `alerts.resend` | `1m` | re-post interval; `endsAt` is 4 × this ahead |
| `-alerts-resolve-grace` | `alerts.resolveGrace` | `5m` | how long a finding must be gone before it resolves |
| `-alerts-max-new` | `alerts.maxNew` | `50` | more new alerts in one evaluation become digests |
| `-alerts-owner-max-new`, `-alerts-owner-window` | `alerts.ownerMaxNew`, `alerts.ownerWindow` | `20`, `15m` | one owner's new alerts on their own per sliding window; more join that owner's digest |
| `-alerts-max-silence` | `alerts.maxSilence` | `7d` | the longest silence a user may set (at most `30d`) |
| `-alerts-default-owner` | `alerts.defaultOwner` | `platform` | owner of findings in namespaces without one, and of cluster-scoped findings |
| `-alerts-leak-crit-hours` | `alerts.leakCritHours` | `-leak-crit-hours` (6) | a leak is critical when its container is closer than this to its limit |
| `-alerts-runbook-url` | `alerts.runbookBaseURL` | this page on GitHub | `runbook_url` is this plus `#<alert name in lower case>` |
| `-external-url` | `externalURL` | | kubesentry's address; each alert links to its finding there (`kubesentry_url`), and to its incident once it has one (`incident_url`). Browsers may send write requests (acknowledge, silence) from its origin |
| `-allowed-origins` | `server.allowedOrigins` | | further origins (`scheme://host[:port]`) browsers may send write requests from, e.g. a portal that embeds kubesentry. Other cross-origin browser requests that change state get 403; requests without `Origin` and `Sec-Fetch-Site` (curl with the API token) are not affected |
| `-owner-annotation` | `alerts.ownerAnnotation` | `kubesentry.io/owner` | the annotation naming the owner, on namespaces and on the objects listed under [Owners](#owners) |
| `-production-label` | `alerts.production.labelKey`/`labelValue` | `environment=production` | the namespace label marking production |
| `-alerts-disable-checks` | `alerts.disableChecks` | | checks that never alert, comma-separated ([the catalog](#the-catalog)); their open findings resolve |
| `-alerts-audit` | `alerts.audit.checks` | `all` | the [audit checks](#audit-activity) to run when an audit store exists; `none` (chart: `[]`) runs none |
| `-alerts-audit-production-only` | `alerts.audit.productionOnly` | `audit-exec,audit-secret-read` | audit checks that count only events in production namespaces |
| `-alerts-audit-hold` | `alerts.audit.hold` | `1h` | an audit finding stays open this long after its newest event (10m to 24h) |
| `-alerts-audit-denied-burst`, `-alerts-audit-denied-window` | `alerts.audit.deniedBurst`, `deniedWindow` | `20`, `10m` | a burst of denied requests: this many by one actor within the window |
| `-alerts-agents` | `alerts.agents` | `auto` | the [agent check](#missing-agents): `auto` (on when every agent report reaches this replica), `on`, `off` |
| `-agent-daemonset` | set from the chart's agent | | the node agent DaemonSet, `namespace/name` |
| `-agent-fanout` | set when `agent.fanout` or `replicas: 1` | `false` | every agent report reaches every replica |
| `-alerts-digest-at` | `alerts.digests.at` | | [standing digests](#standing-state-digests): `"Mon 09:00"` weekly, `"09:00"` daily; empty: off |
| `-alerts-digest-tz` | `alerts.digests.tz` | `UTC` | the time zone of `-alerts-digest-at` (an IANA name) |
| `-alerts-digest-kinds` | `alerts.digests.kinds` | `rbac-posture,unused-volumes,certificates` | the digests sent |
| `-alerts-cert-digest-days` | `alerts.digests.certDays` | `14` | with the certificates digest, certificates with more days left are quiet |

**Constraints:**

- **Replicas and storage.** More than one replica needs `audit.store=postgres`, for the lock. The chart refuses `replicas > 1` with alerts and the memory store.
- **The informer cache.** Alerting needs it: `-cache=false` is refused.
- **Credentials.** Put no credentials in the URLs, and use one kind: a token, basic auth, or SigV4.
- **Mixed URLs.** Mixing AMP and other Alertmanagers needs `-alertmanager-sigv4`, which then signs every request.

**Amazon Managed Prometheus.**

- **URL.** The alert manager of a workspace is `https://aps-workspaces.<region>.amazonaws.com/workspaces/<workspace-id>/alertmanager`.
- **Credentials.** kubesentry signs its requests with the pod's IAM role (IRSA or Pod Identity). The role needs `aps:CreateAlertManagerAlerts` on the workspace.
- **Receivers.** The AMP alert manager sends only to SNS; see `docs/monitoring-eks.md`.

```yaml
alerts:
  enabled: true
  alertmanager:
    urls:
      - https://aps-workspaces.us-east-1.amazonaws.com/workspaces/ws-12345678-abcd-1234-abcd-123456789012/alertmanager
externalURL: https://kubesentry.prod.example.com
```

An in-cluster Alertmanager pair with a token and a private CA:

```yaml
alerts:
  enabled: true
  alertmanager:
    urls:
      - https://alertmanager-0.alertmanager-operated.monitoring:9093
      - https://alertmanager-1.alertmanager-operated.monitoring:9093
    existingSecret: kubesentry-alertmanager   # key "token"
    ca:
      configMap: alertmanager-ca              # key "ca.crt"
networkPolicy:
  egress:
    alertmanager:
      toNamespaces: [monitoring]
```

## 3. Labels and annotations

**Labels** are stable and low-cardinality, so Alertmanager can route and group on them:

| Label | Value |
|---|---|
| `alertname` | one of the alerts below |
| `severity` | `warning` or `critical`; `info` on standing digests only |
| `check` | one of [the catalog](#the-catalog)'s checks; `digest` on findings digests (standing digests have none) |
| `namespace` | the object's namespace; absent for cluster-scoped findings |
| `owner` | the object's `kubesentry.io/owner` annotation (`-owner-annotation`), else its namespace's, else `-alerts-default-owner` ([Owners](#owners)) |
| `production` | `"true"` when the namespace carries the production label, else `"false"` |
| `workload` | `Kind/name` of the workload, for workload, pod, leak and privileged-workload alerts (a bare pod is `Pod/name`) |
| `object` | `Kind/name` of the object, for certificate, RBAC and exposure alerts; `User/<actor>` for audit activity; `DaemonSet/<namespace>/<name>` for missing agents |
| `node` | the node, when every pod of a pod alert runs on one, or a missing agent's only node, so the profile's node-down inhibition mutes it |
| `digest` | the kind of a standing digest: `rbac-posture`, `unused-volumes` or `certificates` |
| `cluster` | `-cluster-name`, when set, so several clusters can share one Alertmanager without their alerts merging |
| `kubesentry_<x>` | every other `kubesentry.io/<x>` namespace annotation, as a routing hint: `kubesentry.io/slack-channel: "#payments"` becomes `kubesentry_slack_channel="#payments"`. Characters a label name cannot hold become `_`. At most 10 per namespace, values cut to 256 bytes. `kubesentry_digest` is reserved. Left off when the object names an owner other than its namespace's |
| `kubesentry_digest` | `"true"`, on findings digests and standing digests only |

**Annotations:**

- **On every alert:**
  - `summary`: one line
  - `description`: the detail
  - `runbook_url`: its section below
  - `kubesentry_url`: the finding's page in the UI, with `-external-url`; it is also the alert's `generatorURL`
  - `dedupe_key`: `check/kind/namespace/name`
- **Per alert:**
  - `pods`, `reasons` (`CrashLoopBackOff=3,ImagePullBackOff=1`): unhealthy workloads
  - `latest_eviction`, `oldest_deletion`: evicted and stuck pods
  - `predicted_oom`, `container`, `pod`, `growth_bytes_per_hour`: memory leaks
  - `expires_at`, `issuer`, `reason` (`issuer-missing` or `not-ready`): certificates
  - `actor`, `actor_kind` (`user`, `serviceaccount` or `system`), `count`, `first_at`, `last_at`, `verbs` (`create pods/exec, get secrets`), `examples` (up to three lines, redacted): audit activity
  - `nodes` (the first 20, comma-separated), `count`: missing agents
  - `findings`: the count on findings digests; on standing digests the 10 worst, one per line, with `count` and, for unused volumes, `monthly_cost_usd`. Standing digests carry no `dedupe_key`; their `kubesentry_url` is the Overview filtered to the owner
- **Acknowledged and silenced** ([section 1](#acknowledging-and-silencing)): `acknowledged_by`, `acknowledged_at` on every post of an acknowledged alert; `silenced_by`, `silenced_until` (RFC 3339), `silence_reason` on the one post that ends a silenced alert.
- **With incidents on** (`-incidents`, `docs/incidents.md`): `incident_url`, the incident the alert's episode joined, with `-external-url`. Workload, pod and leak alerts join their workload's incident within a minute or so; the link goes out with the next resend (`-alerts-resend`) and stays for the episode. It is an annotation, never a label, so it never retires the alert. A link to a capped incident moves to its continuation.

**Example**, as posted to `/api/v2/alerts` (`internal/alerts/testdata/alertmanager-post.golden.json` has one of each phase B alert, `catalog.golden.json` the exposure, privileged, audit and agent alerts, `standing-digests.golden.json` the standing digests):

```json
{
  "labels": {
    "alertname": "KubesentryWorkloadUnhealthy",
    "check": "workload-unhealthy",
    "cluster": "prod-eks",
    "kubesentry_slack_channel": "#payments-alerts",
    "namespace": "payments",
    "owner": "payments",
    "production": "true",
    "severity": "critical",
    "workload": "Deployment/api"
  },
  "annotations": {
    "dedupe_key": "workload-unhealthy/Deployment/payments/api",
    "description": "3 of 4 pods of Deployment payments/api cannot run: CrashLoopBackOff ×3. api-7d9f-0: api: back-off 5m0s restarting failed container",
    "kubesentry_url": "https://kubesentry.example.com/#/workloads?namespace=payments&q=api",
    "pods": "3",
    "reasons": "CrashLoopBackOff=3",
    "runbook_url": "https://github.com/ByronGary/kubesentry/blob/main/docs/alerts.md#kubesentryworkloadunhealthy",
    "summary": "Deployment payments/api: CrashLoopBackOff ×3"
  },
  "startsAt": "2026-10-12T12:00:00Z",
  "endsAt": "2026-10-12T12:14:00Z",
  "generatorURL": "https://kubesentry.example.com/#/workloads?namespace=payments&q=api"
}
```

**Inhibition rules** that compare labels treat a label missing from both alerts as equal. Add `workload` and `object` to the `equal` list of any rule that mutes a warning under a critical alert of the same name. Otherwise a critical alert about one workload mutes the warnings about every other workload in its namespace. The monitoring profile does this.

## 4. Watching the alerting itself

- **`GET /api/v1/alerts`** lists the findings the caller may see: open, acknowledged, silenced, and those resolved in the last 24h. It accepts `?namespace=&owner=&state=&limit=&continue=`.
  - Who may see a finding depends on its kind:

    | Kind | Namespaced finding | Cluster-scoped finding |
    |---|---|---|
    | workloads, pods, leaks, certificates | `list pods` there | (`list pods` in every namespace) |
    | RBAC drift | `list pods` and `list rolebindings` there | `list clusterrolebindings` |
    | audit activity | `list pods` and `list auditevents.kubesentry.io` there | `list auditevents.kubesentry.io` cluster-wide |
    | nodes | (`list pods` there and `list nodes`) | `list nodes` |
    | agents | (`list pods` there and `list agents.kubesentry.io`) | `list agents.kubesentry.io` |

  - Each item carries `actionable` when the caller may acknowledge and silence it, `link` (the UI page that explains it), and the acknowledgement and silence details (`ackBy`, `ackAt`, `silencedBy`, `silencedAt`, `silenceReason`, `silencedUntil`).
  - With incidents on, an item whose episode joined an incident in its namespace carries `incidentId` (open it at `#/incidents/<id>`).
  - The Overview's `alerts` field counts the same findings for its widget.
- **`POST /api/v1/alerts/actions`** takes `{"keys": [...], "action": "ack"|"unack"|"silence"|"unsilence", "for": "4h", "reason": "..."}` (`for` and `reason` for silences only; at most 100 keys; JSON, at most 16 KiB). It answers 403 when the caller may act nowhere, otherwise a result per key: `ok` with the finding as it is now, or `not found` (unknown, or not visible to the caller), `forbidden` (visible, but no `update alerts.kubesentry.io` there), `resolved`, `invalid` (an unack without an ack, an unsilence without a silence). Browsers may send it only from kubesentry's own origin, `-external-url`'s and `-allowed-origins`.
- **`GET /api/v1/alerts/actions?key=&limit=`** lists the actions on findings the caller may see, newest first (at most 200).
- **`/info`** has `alerts: {enabled, sink, leader, lastSentAt, lastError, lastDigestAt, nextDigestAt}`. Only the leader sends, so ask more than once if a load balancer spreads requests over replicas; `lastDigestAt` (the last standing digest sent) is read from the store on every replica, and `nextDigestAt` (the next scheduled time) is absent while digests are off.
- **Metrics:**
  - `kubesentry_findings{check,severity}` on the leader (0 elsewhere)
  - `kubesentry_alerts_sent_total{result}` (`sent`, `failed`, `dropped`)
  - `kubesentry_alerts_queue_depth`
  - `kubesentry_alerts_evaluation_seconds`
  - `kubesentry_alerts_leader`
  - `kubesentry_alerts_digested_total{reason}` (`max_new`, `owner_budget`)
  - `kubesentry_alerts_standing_digests_total{kind}`: standing digests sent, one per owner
  - `kubesentry_alert_actions_total{action,result}` (`ok`, `forbidden`, `not_found`, `invalid`, `resolved`)
  - `kubesentry_dependency_up{dependency="alertmanager"}`
- **Dashboard.** The chart's "kubesentry health" dashboard shows them in the "Alerts and dependencies" row.
- **Alerts on the alerting.** The chart's `PrometheusRule` adds `KubesentryAlertsNotEvaluated` (no replica holds the lock) and `KubesentryAlertmanagerFailing` (deliveries fail on the leader). Their runbooks are in `docs/monitoring-eks.md`.

## 5. Runbooks

Each alert links here. The finding's own page (`kubesentry_url`) shows the detail; the pod page shows the containers, events and memory chart.

### The catalog

| Alert (`alertname`) | `check` | Severity | Seen by ([section 4](#4-watching-the-alerting-itself)) | Rule |
|---|---|---|---|---|
| `KubesentryCertificateExpiring` | `cert-expiring` | the certificate detector's | namespace | standing; quiet with more than 14 days left while the certificates digest is on |
| `KubesentryCertificateNotReady` | `cert-not-ready` | the certificate detector's | namespace | standing, 10m pending |
| `KubesentryMemoryLeak` | `memory-leak` | warning; critical close to the limit | namespace | standing |
| `KubesentryWorkloadUnhealthy` | `workload-unhealthy` | critical with CrashLoopBackOff or no ready pod, else warning | namespace | standing, 5m pending |
| `KubesentryPodEvicted` | `pod-evicted` | warning | namespace | standing |
| `KubesentryPodStuckTerminating` | `pod-stuck-terminating` | warning | namespace | standing |
| `KubesentryRBACDrift` | `cluster-admin`, `anonymous-binding`, `wildcard-rbac`, `aws-auth-masters` | critical | RBAC | change-based |
| `KubesentryExposureChange` | `loadbalancer` (internet-facing), `nodeport`, `external-ip`, `ingress-no-tls` | warning | namespace | change-based |
| `KubesentryPrivilegedWorkload` | `privileged`; `host-namespaces` | critical; warning, critical in production | namespace | change-based, per workload |
| `KubesentryAuditActivity` | `audit-exec`, `audit-secret-read` (people, production only by default), `audit-rbac-change` (people), `audit-impersonation`, `audit-denied-burst`, `audit-anonymous` | warning; `audit-anonymous` critical | audit | open while the newest event is within the hold (1h) |
| `KubesentryAgentMissing` | `agent-missing` | warning | agents | standing, 10m pending |
| `KubesentryFindingsDigest` | `digest` | warning | | storm protection |
| `KubesentryStandingDigest` | (label `digest`: `rbac-posture`, `unused-volumes`, `certificates`) | info | | scheduled, sent once |

### KubesentryCertificateExpiring
**Fires:** a cert-manager Certificate is expired, or close to expiry, and is not renewing on schedule. The thresholds are relative to the certificate's lifetime:
- **Critical** below min(7 days, a tenth of the lifetime), and once expired.
- **Warning** below min(30 days, a third of the lifetime), or when renewal is overdue by more than an hour.

A certificate whose renewal time is still ahead, or passed less than an hour ago, never fires, however short-lived. This is the rule the monitoring profile's `CertManagerCertificateExpiring` follows, so service-mesh and internal-CA certificates that renew every few hours stay quiet.
**Check:**
- The certificate's events and its latest CertificateRequest: `kubectl -n <ns> describe certificate <name>`, `kubectl -n <ns> get certificaterequest`.
- Whether the issuer (annotation `issuer`) is ready.
- For ACME, the Order and Challenge objects.

**Fix:** fix the issuer or the challenge, then `cmctl renew -n <ns> <name>`. Under a few days to expiry, tell the service's owner now: clients fail TLS when the certificate expires.

### KubesentryCertificateNotReady
**Fires:** after 10 minutes, for a Certificate that is not ready:
- its issuer does not exist (`reason=issuer-missing`), or
- its issuer is not ready, issuance failed, or it was never issued (`reason=not-ready`).

The severity is the Certificates page's: critical for a missing or failing issuer and a failed issuance, warning while it is not issued yet.
**Check:**
- `kubectl -n <ns> describe certificate <name>`.
- The Issuer or ClusterIssuer it names.
- The stress run found 9 certificates pointing at issuers that did not exist.

**Fix:**
- Create or fix the issuer, or point the certificate at the right one.
- For a failed issuance, read the CertificateRequest's message (rate limits, DNS, the CA's answer).

### KubesentryMemoryLeak
**Fires:** the background leak scan found a container whose memory grows steadily within each process lifetime. It is one alert per workload, naming the soonest-to-OOM container (annotations `container`, `pod`, `growth_bytes_per_hour`).
- **Warning** by default.
- **Critical** when the container reaches its memory limit sooner than `-alerts-leak-crit-hours`.

`predicted_oom` is the expected OOM time (the scan's time plus the time to the limit). A container without a limit never OOMs, but it keeps growing.
**Check:**
- The pod page's memory chart: a sawtooth that drops at each restart is the leak pattern.
- `/api/v1/oom` for every container the scan flagged.

**Fix:**
- Short term, restart the workload before `predicted_oom` (`kubectl rollout restart`), at a quiet time. kubesentry never does this itself.
- Then find the leak with the owner team. Raising the limit only moves the OOM later.

### KubesentryWorkloadUnhealthy
**Fires:** after 5 minutes, for a workload with pods that cannot run:
- containers in CrashLoopBackOff
- containers in ImagePullBackOff or ErrImagePull
- containers in CreateContainerConfigError and the like
- a failed init container
- pods Pending past `-pending-grace` (Unschedulable, ContainerCreating)

It is one alert per workload. `pods` and `reasons` count the affected pods.
- **Critical** with any CrashLoopBackOff, or when the workload has no ready pods.
- **Warning** otherwise.

**Check:**
- `kubectl -n <ns> describe pod <pod>` for a pod named in the description, and `kubectl logs --previous` for crashes.
- For image pulls: the image name and tag, the registry credentials, and the node's network path to the registry.
- For Unschedulable: the scheduler's message (resources, taints, affinity, volume zones).

**Fix:** roll back a bad release (`kubectl rollout undo`), fix the image or its pull secret, or free capacity. A crash loop that started with a change of config or secret is usually that change.

### KubesentryPodEvicted
**Fires:** pods of the workload were evicted in the last `-recent-pod` (24h), usually under node pressure. `latest_eviction` is the newest eviction. `node` is set when all the evictions were on one node.
**Check:**
- The eviction message in the description: memory, ephemeral storage, or disk pressure.
- The node's conditions and the pods' requests against their usage.

**Fix:**
- Set memory and ephemeral-storage requests that match real use, so the scheduler stops overcommitting the node.
- Delete the evicted pod objects once understood: `kubectl -n <ns> delete pod --field-selector=status.phase=Failed`.
- The alert resolves when no eviction is newer than the window.

### KubesentryPodStuckTerminating
**Fires:** pods of the workload still exist more than `-terminating-grace` (5m) after their deletion time. `node` is set when they are all on one node, so a NotReady node's own alert mutes this one.
**Check:**
- `kubectl -n <ns> get pod <pod> -o jsonpath='{.metadata.finalizers}'` for finalizers.
- Whether the node is NotReady or gone.

**Fix:**
- For a dead node, cordon it and let the node lifecycle (or Karpenter) remove it. The pods go with it.
- For a finalizer, fix the controller that should remove it. Remove the finalizer by hand only when that controller is gone for good.
- Force-deleting (`--grace-period=0 --force`) a pod whose node is still running it can leave two copies of a StatefulSet member running.

### KubesentryRBACDrift
**Fires:** critical, when one of these appeared since the previous evaluation:
- a binding of `cluster-admin` to a subject that is not platform plumbing (`check=cluster-admin`)
- a binding to `system:anonymous` or `system:unauthenticated` (`check=anonymous-binding`)
- a role with `*` verbs or resources that became bound to someone (`check=wildcard-rbac`)
- a `system:masters` mapping in `kube-system/aws-auth` (`check=aws-auth-masters`, with `eks.awsAuth.read`)

Standing state never fires; the first evaluation records it. The alert stays open 24 hours while the object exists, then resolves. Cluster-scoped findings belong to `-alerts-default-owner`, namespaced ones to their namespace's owner.
**Check:**
- Who made the change: kubesentry's Activity page, filtered on `rbac-change`, or the audit log.
- Whether it went through your change process.

**Fix:**
- Revert an unexpected binding (`kubectl delete clusterrolebinding <name>`) and investigate the account that made it.
- For aws-auth, move the principal to an EKS access entry with a bound ClusterRole.
- An expected change needs nothing: the alert resolves after 24 hours.

### KubesentryFindingsDigest
**Fires:** more than `-alerts-max-new` new findings appeared in one evaluation, or one owner had more than `-alerts-owner-max-new` new ones in `-alerts-owner-window`, so they were summed up per owner instead of sent one by one (`kubesentry_digest="true"`). This happens on a first install, after an empty memory store, or in an incident. `findings` is the count. The description lists counts by alert and the 10 worst. A digested finding that turns critical leaves the digest and fires on its own.
**Check:**
- `GET /api/v1/alerts?owner=<owner>` or the Overview filtered by the owner (`kubesentry_url`) for the full list.
- After an install, the digest is the cluster's standing backlog.
- `kubesentry_alerts_digested_total{reason}` says whether the global breaker or the owner's budget sent them here.

**Fix:** work through the findings by severity; the digest ends when all of them have resolved, left it, or been silenced. Raise `-alerts-max-new` or `-alerts-owner-max-new` if your incidents routinely exceed them and your receivers cope.

### KubesentryExposureChange
**Fires:** warning, when something reachable from outside the cluster appeared since the previous evaluation:
- an internet-facing load balancer Service (`check=loadbalancer`); internal NLBs and ELBs (the AWS scheme annotations, or the AWS Load Balancer Controller's default) never fire
- a NodePort Service (`check=nodeport`)
- a Service with external IPs (`check=external-ip`)
- an Ingress serving plain HTTP (`check=ingress-no-tls`), unless it is an internal ALB

Standing exposure never fires; the first evaluation records it. The alert stays open 24 hours while the object exists, then resolves. System namespaces never alert. `object` is the Service or Ingress.
**Check:**
- Who created or changed it: the Activity page or the audit log, filtered on the object.
- Whether it went through your change process, and whether `loadBalancerSourceRanges` or a security group limits who can reach it.

**Fix:**
- An unintended exposure: make the load balancer internal (`service.beta.kubernetes.io/aws-load-balancer-scheme: internal`), switch the Service to ClusterIP, or add TLS to the Ingress.
- An intended one needs nothing: the alert resolves after 24 hours. To stop a whole kind, list its check in `-alerts-disable-checks`.

### KubesentryPrivilegedWorkload
**Fires:** when a workload appeared since the previous evaluation that
- runs a privileged container (`check=privileged`): critical, or
- shares the node's PID, network or IPC namespace (`check=host-namespaces`): warning, critical in production namespaces.

It is one alert per workload (a Job counts under its CronJob), `workload` naming it. Standing workloads never fire; the first evaluation records them. System namespaces, where CNI and CSI plugins run privileged by design, never alert. The alert stays open 24 hours while the workload exists.
**Check:**
- The Security page (`kubesentry_url`) for every risky setting of the workload.
- Who deployed it, and whether the image needs that access (node agents, CNI and CSI plugins do; applications almost never do).

**Fix:**
- Drop `privileged`, `hostPID`, `hostNetwork` and `hostIPC` from the pod spec, and enforce the namespace's Pod Security level (`pod-security.kubernetes.io/enforce: baseline` or `restricted`).
- Infrastructure that needs it belongs in a system namespace (`-system-namespaces-add`).

### KubesentryAuditActivity
**Fires:** the audit log shows sensitive activity by one actor (`actor`, label `object="User/<actor>"`) in one namespace (or cluster-wide):

| `check` | What | Who |
|---|---|---|
| `audit-exec` | exec, attach, port-forward or a debug container | people; production namespaces only by default |
| `audit-secret-read` | reads of Secrets | people; production namespaces only by default |
| `audit-rbac-change` | writes to roles and role bindings | people |
| `audit-impersonation` | requests made as another user | anyone |
| `audit-denied-burst` | at least `-alerts-audit-denied-burst` (20) denied requests within `-alerts-audit-denied-window` (10m); cluster-scoped | anyone |
| `audit-anonymous` | requests without credentials that the API server allowed, besides health checks, the version and OIDC discovery; **critical** | anonymous |

Warning, except `audit-anonymous`. The finding stays open until `-alerts-audit-hold` (1h) passes without another such request, then resolves. `count`, `first_at`, `last_at`, `verbs` and up to three redacted `examples` describe it. Only callers who may read audit events there see it (cluster-wide for cluster-scoped findings).
**Check:**
- The Activity page filtered on the actor (`kubesentry_url`): what else they did around that time.
- Whether there is a ticket or an incident that explains it; for a denied burst, which permissions the actor tried, and from which workload or credential.

**Fix:**
- Expected access: nothing (the alert resolves after the hold), or acknowledge it.
- Unexpected access: revoke the credential (the IAM role or user behind an EKS identity, the ServiceAccount token), review its bindings, and rotate the Secrets that were read.
- Anonymous access: remove bindings to `system:anonymous` and `system:unauthenticated` (`KubesentryRBACDrift` flags new ones), and consider `--anonymous-auth=false` where the platform allows it.

### KubesentryAgentMissing
**Fires:** after 10 minutes, for the node agent DaemonSet (`object="DaemonSet/<namespace>/<name>"`, cluster-scoped), when nodes running its pod have not reported for three report intervals. `nodes` lists the first 20 and `count` all of them; `node` is set when there is one, so the profile's node-down inhibition mutes it. Fargate nodes, NotReady nodes and nodes younger than 10 minutes are left out. Only callers with `list agents.kubesentry.io` see it.
**Check:**
- The Agents page (`kubesentry_url`) and the agent pods on those nodes: `kubectl -n <ns> get pods -o wide --field-selector spec.nodeName=<node>`.
- The agent's log: an unreachable server (network policy, DNS, the ingest Service), a rejected token (401), or an OOM kill.
- With several replicas, that agents fan out (`agent.fanout`): otherwise each replica hears from only some of them, and `-alerts-agents=auto` keeps the check off.

**Fix:** restart the agent pod, or fix what blocks its reports. Process data for the node's pods is missing until it reports again; the alert resolves after the grace.

### KubesentryStandingDigest
**Fires:** at `-alerts-digest-at` (in `-alerts-digest-tz`), once per owner and kind, with `severity="info"` and `kubesentry_digest="true"`; it ends an hour later and is never re-posted. The `digest` label says what it lists:
- `rbac-posture`: standing RBAC findings outside cluster plumbing, worst first.
- `unused-volumes`: claims no pod mounts, most expensive first; `monthly_cost_usd` sums those with a price.
- `certificates`: certificates not renewing on schedule with more than `-alerts-cert-digest-days` (14) left. Each fires on its own as `KubesentryCertificateExpiring` once fewer days are left.

`count` is the number of entries, `findings` the 10 worst. Silenced findings are left out.
**Check:** the Overview filtered to the owner (`kubesentry_url`), and the Security, Storage and Certificates pages for the full lists.
**Fix:** none is urgent. Work through the list at your own pace: remove bindings nobody needs, delete or snapshot claims nobody mounts (a StatefulSet scaled to zero keeps its claims on purpose), fix the issuers of certificates that do not renew. Route these to a quiet receiver (`docs/monitoring-eks.md`, section 4).

## 6. Limits of this release

The catalog, standing digests, acknowledging and silencing (with the Alerts page), full storm protection and per-object owners are in. Limits:

- **Long acknowledgements.** The actions log keeps 31 days, so an episode open longer than that loses its acknowledgement.
- **Audit reads.** Each evaluation reads up to 10,000 events per audit tag; a larger flood within one interval is counted only in part. Audit polling adds Postgres reads on the leader: watch `kubesentry_alerts_evaluation_seconds`.
- **Denied bursts** are counted per actor across the cluster, so they are cluster-scoped findings, which only callers who may read the whole audit log see.
- **Missing agents with several replicas** need agent fan-out (`agent.fanout`, on by default): without it the check stays off under `auto`.
