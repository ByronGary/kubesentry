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
2. **What it computes.** It runs the [checks](#5-runbooks) over the view and over the background leak scan. Each check yields findings, folded per workload: a workload is its root owner, as the Security page and the Overview group pods, so a Job counts under its CronJob. 300 crash-looping pods of one Deployment make one alert, with the pod count in its annotations.
3. **How it diffs.** It compares those findings with the stored ones and moves each finding along its lifecycle:

| Finding | What kubesentry does | What Alertmanager gets |
|---|---|---|
| **New** | Opens it. For two checks it waits first, like Prometheus's `for:`: certificates not ready wait 10 minutes and unhealthy workloads 5 minutes, so problems that clear by themselves stay quiet | the alert, `startsAt` = first seen |
| **Still there** | Updates it (severity, title, annotations) | the alert again every `-alerts-resend` (1m), with `endsAt` = now + 4 × resend. Alertmanager keeps it while kubesentry runs, and lets it expire on its own if kubesentry stops |
| **Labels changed** (severity, owner, a routing hint) | Alertmanager knows an alert by its label set, so kubesentry retires the old set | the old label set with `endsAt` = now, then the new one at once |
| **Gone** | Resolves it once it has been gone for `-alerts-resolve-grace` (5m), so a finding that drops out of a single view does not flap | the alert with `endsAt` = now, once |

4. **Unreadable data.** When kubesentry cannot read a source (pods, certificates or RBAC forbidden, or no leak scan yet), it skips the checks that need it. Their findings keep their state: they are neither refreshed nor resolved. An outage of a source therefore never resolves the alerts that depend on it.

### Change-based checks and the first run

RBAC drift alerts fire on what **changed**, not on what stands:

- Each drift check stores a baseline of the RBAC findings it saw (table `alert_baseline`).
- A binding or role missing from the baseline fires. The alert stays open for 24 hours while the object exists, then resolves, and the object becomes standing state.
- The first evaluation after an install, or after an empty store, records the baseline and notifies nothing.

The other checks report standing state, so they do fire on the first run, under storm protection (below).

### Storm protection

If more than `-alerts-max-new` (50) new alerts would fire in one evaluation, kubesentry sends one digest alert per owner instead, `KubesentryFindingsDigest` with `kubesentry_digest="true"`. This happens on a first install, or after a cluster-wide incident.

- The monitoring profile routes digests to a quiet receiver, one message per owner per day.
- The digest lists counts by alert and the 10 worst findings. It stays open while any of its findings is open, and ends when all of them have resolved.
- Findings sent in a digest are marked `digest` and are not sent on their own later. Later new findings, if there are not too many, fire on their own as usual.

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
| `-alerts-default-owner` | `alerts.defaultOwner` | `platform` | owner of findings in namespaces without one, and of cluster-scoped findings |
| `-alerts-leak-crit-hours` | `alerts.leakCritHours` | `-leak-crit-hours` (6) | a leak is critical when its container is closer than this to its limit |
| `-alerts-runbook-url` | `alerts.runbookBaseURL` | this page on GitHub | `runbook_url` is this plus `#<alert name in lower case>` |
| `-external-url` | `externalURL` | | kubesentry's address; each alert links to its finding there (`kubesentry_url`), and to its incident once it has one (`incident_url`) |
| `-owner-annotation` | `alerts.ownerAnnotation` | `kubesentry.io/owner` | the namespace annotation naming the owner |
| `-production-label` | `alerts.production.labelKey`/`labelValue` | `environment=production` | the namespace label marking production |

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
| `severity` | `warning` or `critical` |
| `check` | `cert-expiring`, `cert-not-ready`, `memory-leak`, `workload-unhealthy`, `pod-evicted`, `pod-stuck-terminating`; for RBAC drift the security check: `cluster-admin`, `anonymous-binding`, `wildcard-rbac`, `aws-auth-masters`; `digest` |
| `namespace` | the object's namespace; absent for cluster-scoped findings |
| `owner` | the namespace's `kubesentry.io/owner` annotation (`-owner-annotation`), else `-alerts-default-owner` |
| `production` | `"true"` when the namespace carries the production label, else `"false"` |
| `workload` | `Kind/name` of the workload, for workload, pod and leak alerts (a bare pod is `Pod/name`) |
| `object` | `Kind/name` of the object, for certificate and RBAC alerts |
| `node` | the node, when every pod of a pod alert runs on one, so the profile's node-down inhibition mutes it |
| `cluster` | `-cluster-name`, when set, so several clusters can share one Alertmanager without their alerts merging |
| `kubesentry_<x>` | every other `kubesentry.io/<x>` namespace annotation, as a routing hint: `kubesentry.io/slack-channel: "#payments"` becomes `kubesentry_slack_channel="#payments"`. Characters a label name cannot hold become `_`. At most 10 per namespace, values cut to 256 bytes. `kubesentry_digest` is reserved |
| `kubesentry_digest` | `"true"`, on digests only |

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
  - `findings`: digests
- **With incidents on** (`-incidents`, `docs/incidents.md`): `incident_url`, the incident the alert's episode joined, with `-external-url`. Workload, pod and leak alerts join their workload's incident within a minute or so; the link goes out with the next resend (`-alerts-resend`) and stays for the episode. It is an annotation, never a label, so it never retires the alert. A link to a capped incident moves to its continuation.

**Example**, as posted to `/api/v2/alerts` (`internal/alerts/testdata/alertmanager-post.golden.json` has one of each):

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
  - A namespaced finding needs the namespace. An RBAC drift finding there also needs `list rolebindings`. A cluster-scoped one needs `clusterRBAC`.
  - With incidents on, an item whose episode joined an incident in its namespace carries `incidentId` (open it at `#/incidents/<id>`).
  - The Overview's `alerts` field counts the same findings for its widget.
- **`/info`** has `alerts: {enabled, sink, leader, lastSentAt, lastError}`. Only the leader sends, so ask more than once if a load balancer spreads requests over replicas.
- **Metrics:**
  - `kubesentry_findings{check,severity}` on the leader (0 elsewhere)
  - `kubesentry_alerts_sent_total{result}` (`sent`, `failed`, `dropped`)
  - `kubesentry_alerts_queue_depth`
  - `kubesentry_alerts_evaluation_seconds`
  - `kubesentry_alerts_leader`
  - `kubesentry_dependency_up{dependency="alertmanager"}`
- **Dashboard.** The chart's "kubesentry health" dashboard shows them in the "Alerts and dependencies" row.
- **Alerts on the alerting.** The chart's `PrometheusRule` adds `KubesentryAlertsNotEvaluated` (no replica holds the lock) and `KubesentryAlertmanagerFailing` (deliveries fail on the leader). Their runbooks are in `docs/monitoring-eks.md`.

## 5. Runbooks

Each alert links here. The finding's own page (`kubesentry_url`) shows the detail; the pod page shows the containers, events and memory chart.

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
**Fires:** more than `-alerts-max-new` new findings appeared in one evaluation, so they were summed up per owner instead of sent one by one (`kubesentry_digest="true"`). This happens on a first install, after an empty memory store, or in a cluster-wide incident. `findings` is the count. The description lists counts by alert and the 10 worst.
**Check:**
- `GET /api/v1/alerts?owner=<owner>` or the Overview filtered by the owner (`kubesentry_url`) for the full list.
- After an install, the digest is the cluster's standing backlog.

**Fix:** work through the findings by severity; the digest ends when all of them have resolved. Raise `-alerts-max-new` if your incidents routinely exceed it and your receivers cope.

## 6. Limits of this release

Phase C of the proposal adds:

- **The UI.** The Alerts page, and acknowledging and silencing with RBAC. The `acknowledged` and `silenced` states exist in the store and the API, but nothing sets them yet.
- **Full storm protection.** Per-owner rate limits, and promoting a digested finding that turns critical to an alert of its own. Today a digested finding stays in the digest until it resolves.
- **Digests of standing state.** Weekly RBAC posture, unused volumes with their cost, and certificates more than 14 days from expiry.
- **The rest of the catalog.** Exposure changes, privileged workloads created, the production-aware audit alerts (exec, port-forward or secret reads in production), and agent and process alerts.
- **Per-object owners.** An owner annotation on the object, overriding its namespace's.
