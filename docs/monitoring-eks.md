# Monitoring an EKS cluster and kubesentry

This guide is for the team that runs Prometheus and Alertmanager. It covers two things:

- **The platform baseline** (Layer 1 of `docs/proposals/alerting-automation.md`). This is a kube-prometheus-stack values profile for EKS, `examples/monitoring-eks.yaml`, plus `examples/cert-manager-eks.yaml` and a "Cluster health (EKS)" dashboard, `examples/grafana/cluster-health-eks.json`. kubesentry's chart installs none of it. It is an example that you adapt and apply with your own values.
- **kubesentry's self-monitoring**, which its chart ships: a `PrometheusRule` and the "kubesentry health" dashboard (`metrics.prometheusRule`, `metrics.grafanaDashboards`).

Every alert from both has a runbook below, and every rule links to it with `runbook_url`.

## Contents

1. [Why the profile looks like this](#1-why-the-profile-looks-like-this)
2. [Applying it](#2-applying-it)
3. [Sizing](#3-sizing)
4. [Routing by owner](#4-routing-by-owner)
5. [kubesentry's own alerts and dashboard](#5-kubesentrys-own-alerts-and-dashboard)
6. [Validation](#6-validation)
7. [Runbooks: platform alerts](#7-runbooks-platform-alerts)
8. [Runbooks: kubesentry alerts](#8-runbooks-kubesentry-alerts)
9. [Metrics proposed for phase B](#9-metrics-proposed-for-phase-b) (shipped)

## 1. Why the profile looks like this

The stress runs (`docs/stress-notes.md`, 500 nodes and about 10,000 pods) used a default kube-prometheus-stack. Each block of the profile answers something those runs showed:

| What the runs showed | What the profile does |
|---|---|
| Alertmanager was not connected, so every alert fired into nothing | Turns Alertmanager on with a routing tree: one branch per owner, critical alerts page, digests stay quiet, and Watchdog feeds a dead man's switch |
| 500+ alerts fired permanently: kube-proxy (501 targets), etcd, scheduler and controller manager cannot be scraped. EKS behaves the same way | `kubeEtcd`, `kubeScheduler`, `kubeControllerManager` and `kubeProxy` are off, with their rules. The kube-proxy patch is the commented alternative |
| (EKS) Fargate pods run on virtual nodes with no reachable kubelet and no DaemonSets | Fargate nodes are left out of the kubelet endpoints (`prometheusOperator.kubeletService.selector`) and node-exporter's affinity |
| `PrometheusMissingRuleEvaluations` in 19 of 20 snapshots at 102k series, with 200m CPU and a 1.5 GiB limit | Prometheus gets resources from the [sizing](#3-sizing) table, rules are evaluated every minute, cAdvisor is scraped every 30s, and the kubelet probe metrics are dropped |
| kube-state-metrics is the largest series source on a big cluster | An allowlist of exactly the series the rules and dashboards read, which `hack/check-rules.sh` enforces |
| cert-manager restarted 3 times (baseline) and 5 times (after run) on failed liveness probes, with no resource requests | cert-manager metrics, requests and a longer liveness tolerance (`examples/cert-manager-eks.yaml`), and a restart alert |
| 117 certificates expiring within 14 days, 9 not ready (missing issuers); kube-prometheus-stack ships no cert-manager rules | Expiry alerts for certificates past their renewal time (so short-lived certificates that renew on schedule stay quiet), plus not-ready and metrics-absent alerts |
| API read p99 up to 1.6s during churn, and error-budget burn and list/watch failures around an API server restart | Read and write latency rules, APF rejections per flow schema, and an inhibition so that `KubeAPIDown` mutes its client-side echoes |
| Events were the largest object type at L2 | An event-volume rule (write rate) and an etcd size rule against EKS's 8 GiB limit |
| `NodeClockNotSynchronising` pending once | The stock clock rules stay on; a critical rule fires before token validation and SigV4 break |
| `NodeDiskIOSaturation` pending during the Postgres and CloudWatch load | Disk rules with gp3's baselines (3,000 IOPS, 125 MiB/s) replace the generic one |
| kubesentry's own Postgres and CloudWatch alerts went pending, correctly, but reached nobody | kubesentry's rules go to the platform team (they carry no owner) and gain eight more; see [section 5](#5-kubesentrys-own-alerts-and-dashboard) |

## 2. Applying it

### With kube-prometheus-stack in the cluster

1. **Copy and adapt the profile.** Replace the placeholders named in its header:
   - `externalLabels.cluster`
   - the gp3 StorageClass name
   - the receiver channels and the example team `payments`
   - the `grafana-admin` Secret

   The profile is written for kube-prometheus-stack 92.3.0. On another version, run `hack/check-rules.sh --kps <chart>` (section 6) before you apply it.
2. **Create the Secrets the profile refers to.** The values file contains no URLs or keys:

   ```bash
   kubectl create namespace monitoring
   kubectl -n monitoring create secret generic alertmanager-receivers \
     --from-literal=slack-platform-url=https://hooks.slack.com/services/... \
     --from-literal=pagerduty-platform-key=... \
     --from-literal=slack-payments-url=... --from-literal=pagerduty-payments-key=... \
     --from-literal=slack-digest-url=... --from-literal=heartbeat-url=https://hc-ping.com/...
   kubectl -n monitoring create secret generic grafana-admin \
     --from-literal=admin-user=admin --from-literal=admin-password="$(openssl rand -base64 24)"
   ```

   Alertmanager reads each receiver's URL or key from `/etc/alertmanager/secrets/alertmanager-receivers/<key>`. External Secrets can produce the same Secret.
3. **Install or upgrade:**

   ```bash
   helm upgrade --install kps prometheus-community/kube-prometheus-stack --version 92.3.0 \
     -n monitoring -f examples/monitoring-eks.yaml -f my-overrides.yaml
   helm upgrade cert-manager jetstack/cert-manager -n cert-manager \
     --reuse-values -f examples/cert-manager-eks.yaml
   ```

4. **Connect kubesentry.** By default the stack selects ServiceMonitors and PrometheusRules labelled `release: kps`, so other namespaces cannot add series or rules by accident. Give kubesentry's objects that label:

   ```yaml
   metrics:
     serviceMonitor:
       enabled: true
       labels: {release: kps}
     prometheusRule:
       enabled: true
       labels: {release: kps}
     grafanaDashboards:
       enabled: true
       annotations: {grafana_folder: kubesentry}
   ```

5. **Add the cluster dashboard.** The Grafana sidecar loads ConfigMaps labelled `grafana_dashboard: "1"` from every namespace:

   ```bash
   kubectl -n monitoring create configmap dashboard-cluster-health-eks \
     --from-file=examples/grafana/cluster-health-eks.json
   kubectl -n monitoring label configmap dashboard-cluster-health-eks grafana_dashboard=1
   kubectl -n monitoring annotate configmap dashboard-cluster-health-eks grafana_folder=platform
   ```

### With Amazon Managed Service for Prometheus and Amazon Managed Grafana

There are two ways to use AMP:

- **Remote write, keep local alerting.** Uncomment the `remoteWrite` block in the profile and give Prometheus's ServiceAccount a role with `aps:RemoteWrite`. Prometheus, its rules and Alertmanager stay in the cluster as above. AMP holds long-term data for Amazon Managed Grafana, so local retention can drop to a day or two. Memory does not shrink, because it follows the series count, not the retention.
- **AMP does the alerting.** An AMP managed collector, or a small in-cluster agent, sends samples to AMP. AMP evaluates the rules, and the AMP alert manager routes the alerts. In this case:

  1. **Rules.** Load the rules as rule groups namespaces: kubesentry's (`docs/deploy-eks.md`, "Alerts with AMP"), the profile's extra rules, and the stock kube-prometheus-stack rules you want. To take one entry out of the profile:

     ```bash
     yq '.additionalPrometheusRulesMap."cert-manager"' examples/monitoring-eks.yaml > cert-manager-rules.yaml
     aws amp create-rule-groups-namespace --workspace-id ws-... --name cert-manager --data fileb://cert-manager-rules.yaml
     ```

  2. **Receivers.** The AMP alert manager sends only to Amazon SNS. Keep the profile's `route` and `inhibit_rules` as they are, and replace each receiver with an SNS topic. Subscribe the topics to the destinations: AWS Chatbot or a Lambda function for Slack, and an HTTPS subscription for PagerDuty. Load the definition with `aws amp create-alert-manager-definition --workspace-id ws-... --data fileb://am.yaml`, where `am.yaml` is:

     ```yaml
     alertmanager_config: |
       route: ...            # the profile's alertmanager.config.route, unchanged
       inhibit_rules: ...    # unchanged
       receivers:
         - name: platform
           sns_configs:
             - topic_arn: arn:aws:sns:us-east-1:111122223333:platform-alerts
               sigv4: {region: us-east-1}
               attributes: {severity: "{{ .CommonLabels.severity }}"}
         # ... one per receiver; "null" stays empty
     ```

  3. **Dashboards.** Import both dashboards into Amazon Managed Grafana (Dashboards, then Import, or the Grafana HTTP API). Both use a `${datasource}` variable, so pick the AMP data source. A ConfigMap sidecar does not reach Managed Grafana, so leave `metrics.grafanaDashboards` off and import `charts/kubesentry/dashboards/kubesentry-health.json` instead. That file's hidden `authz_qps` and `audit_queue_cap` variables default to 200 and 50,000; edit them if your values differ.

## 3. Sizing

**What was measured.** In the stress run, 102k head series took 695 MiB of RSS, which is about **7 KiB per series** with rules and queries running. With 200m CPU and a 1.5 GiB limit, Prometheus still missed evaluations in 35 rule groups. Those 102k series covered only 6 real nodes and a kube-state-metrics cut to one metric. A real cluster scrapes node-exporter, the kubelet and cAdvisor on every node, plus the trimmed kube-state-metrics.

**Estimated for a full cluster.** The figures below are estimates built from typical per-node and per-container series counts, and from the measured 7 KiB per series:

| Cluster | Active series (estimate) | Prometheus CPU request | Memory request / limit | Retention | Volume (gp3) |
|---|---|---|---|---|---|
| up to 100 nodes, 2,000 pods | 0.3–0.5M | 1 | 4Gi / 6Gi | 15d, `retentionSize: 80GB` | 100Gi |
| up to 500 nodes, 10,000 pods (the profile) | 1.5–2.5M | 2 | 12Gi / 16Gi | 7d, `retentionSize: 120GB` | 150Gi |
| up to 1,000 nodes, 20,000 pods | 3–5M | 4 | 24Gi / 32Gi | AMP for history; 2d locally | 100Gi |

- **Check the estimate** after a day. `prometheus_tsdb_head_series` is the series count. Memory should settle near 7 KiB times that, and `prometheus_rule_group_iterations_missed_total` must stay flat. The cluster dashboard shows all three.
- **Where the series come from:**
  - node-exporter: about 500–1,500 per node
  - the kubelet: about 1,000–2,000 per node
  - cAdvisor: about 30–40 per container, after kube-prometheus-stack's default drops
  - kube-state-metrics: about 15–20 per pod with the allowlist
  - the API server: tens of thousands of histogram series
- **Disk.** At a 30s scrape interval, each million series writes about 4 GB a day. Keep `retentionSize` about 20% below the volume size, because it includes the WAL.
- **Above about 2–3 million series,** use AMP for history, or shard (`prometheus.prometheusSpec.shards`). A single Prometheus that misses rule evaluations defeats the whole profile.
- **kube-state-metrics** at 10,000 pods: 200m CPU and 512Mi to 1Gi. node-exporter: 50m and 64Mi to 128Mi per node.

## 4. Routing by owner

**How kubesentry's alerts are routed** (`-alerts`, chart value `alerts.enabled`; `docs/alerts.md` has the details and a runbook per alert):

1. **Finding.** kubesentry evaluates its findings after each snapshot build. It posts each open finding to Alertmanager (`POST /api/v2/alerts`), or to the AMP workspace's alert manager, with these labels:
   - `alertname` (`KubesentryWorkloadUnhealthy`, `KubesentryCertificateExpiring`, ...)
   - `severity` (`warning` or `critical`)
   - `namespace`, absent for cluster-scoped findings
   - `owner`
   - `production` (`"true"` or `"false"`)
   - `workload` or `object` (`Kind/name`)
   - `check`
   - `node` on pod alerts whose pods all run on one node
   - `cluster` (`-cluster-name`)
   - a `kubesentry_<x>` routing hint for every other `kubesentry.io/<x>` namespace annotation
   - `kubesentry_digest="true"` on digests

   The dedupe key (`check/kind/namespace/name`) and a link to the finding (`kubesentry_url`, with `externalURL`) are annotations.
2. **Owner.** The owner comes from the annotation `kubesentry.io/owner` on the namespace:

   ```bash
   kubectl annotate namespace payments kubesentry.io/owner=payments
   kubectl annotate namespace payments kubesentry.io/slack-channel='#payments-alerts'   # becomes kubesentry_slack_channel
   ```

   A finding in a namespace without the annotation, or a cluster-scoped finding such as RBAC drift, gets `alerts.defaultOwner` (`platform`). It then falls through to the platform receivers, unless you give `owner="platform"` a branch of its own.
3. **Production.** The namespace label `environment=production` sets `production="true"`, so a route can page for production only (`matchers: ['production = "true"', 'severity = "critical"']`). Production-only checks, such as exec into a production pod, come in phase C.
4. **Storms.** When more than `alerts.maxNew` (50) new findings appear at once, as on a first install, kubesentry sends one `KubesentryFindingsDigest` per owner with `kubesentry_digest="true"`, which the digest route below keeps quiet.
5. **Alertmanager** does the rest: grouping, silences, inhibition and paging. kubesentry never writes to the cluster, and there is no ticketing integration. Duplicate posts (an HA pair, a leader change) are harmless: Alertmanager knows an alert by its label set.

**Routing hints.** A receiver can take its destination from a hint instead of needing one branch per team. For example, one Slack receiver for every team that set `kubesentry.io/slack-channel`:

```yaml
- receiver: team-slack
  matchers: ['kubesentry_slack_channel =~ ".+"']
  continue: true      # still reach the owner's pager branch below
# receivers:
- name: team-slack
  slack_configs:
    # A Slack app's bot token: incoming webhooks ignore the channel.
    - api_url: https://slack.com/api/chat.postMessage
      http_config:
        authorization:
          credentials_file: /etc/alertmanager/secrets/alertmanager-receivers/slack-bot-token
      channel: '{{ .CommonLabels.kubesentry_slack_channel }}'
      send_resolved: true
```

Group such a route by `kubesentry_slack_channel` as well, so that every notification has a single channel.

**The routing tree in the profile**, in order:

| Route | Matches | Receiver |
|---|---|---|
| dead man's switch | `alertname="Watchdog"` | `deadmans-switch`: pings a heartbeat service every 5 minutes |
| helper | `alertname="InfoInhibitor"` | `null` |
| digests | `kubesentry_digest="true"` | `digest`: one message per owner per day, never a page |
| one branch per team | `owner="payments"`, and within it `severity="critical"` | `team-payments`, `team-payments-pager` |
| unowned critical | `severity="critical"` | `platform-pager` |
| everything else | | `platform` |

**To add a team:**

1. Copy the `owner="payments"` branch and its two receivers.
2. Add the team's keys to the `alertmanager-receivers` Secret.
3. Test the routing (section 6):

   ```bash
   amtool config routes test --config.file=am.yaml owner=<team> severity=critical
   ```

**Inhibitions:**

- A critical alert mutes the warning or info alert with the same name about the same object. The `equal` list includes kubesentry's `workload` and `object` labels: a label missing from both alerts counts as equal, so without them a critical alert about one workload would mute the warnings about every other workload in its namespace.
- A NotReady or unreachable node mutes alerts carrying its `node` label. The profile adds `node` to node-exporter series, and kubesentry sets it on pod alerts whose pods all run on one node (pods stuck terminating, evictions). The rule requires `node` to be set on the muted alert; without that, every alert lacking a `node` label would be muted while any node is down.
- `KubeAPIDown` mutes the client-side errors that follow it, kubesentry's included.

**Prometheus alerts and owners.** Prometheus alerts, unlike kubesentry's, carry no owner, so they all go to the platform team. Two ways to route a team's Prometheus alerts too:

- **Route by namespace.** The profile has a commented branch that sends `namespace=~"payments|payments-.+"` to the team's receivers.
- **Copy the owner onto an alert in its rule.** The profile exposes the annotation as `kube_namespace_annotations{annotation_kubesentry_io_owner}`, so a rule can join it in:

  ```promql
  <your alert expression>
    * on (namespace) group_left (owner)
      label_replace(max by (namespace, annotation_kubesentry_io_owner) (kube_namespace_annotations),
                    "owner", "$1", "annotation_kubesentry_io_owner", "(.+)")
  ```

  A join drops the alert entirely when kube-state-metrics is missing. Use it only on alerts you can afford to lose that way, or prefer the namespace branch.

## 5. kubesentry's own alerts and dashboard

`metrics.prometheusRule.enabled` renders kubesentry's rules. They need prometheus-operator's CRDs; for AMP, see `docs/deploy-eks.md`. Each threshold below is a value under `metrics.prometheusRule`:

| Alert | Fires when | Value (default) |
|---|---|---|
| `KubesentrySnapshotStale` | served view older than the threshold while a cluster change waits for a rebuild, for 5m (a quiet cluster's old view does not count) | `snapshotStaleSeconds` (120) |
| `KubesentrySnapshotBuildSlow` | p90 view rebuild over 15m above the threshold, for 15m | `snapshotBuildSeconds` (5) |
| `KubesentryCloudWatchLag` | CloudWatch reader lag above the threshold for 10m (CloudWatch source only) | `cloudwatchLagSeconds` (300) |
| `KubesentryPostgresErrors` | failed audit store operations for 10m (Postgres only) | |
| `KubesentryAuditQueueFilling` | write queue above a fraction of its capacity for 10m (Postgres only) | `auditQueueRatio` (0.8), `auditQueueCapacity` (50000) |
| `KubesentryAuthzReviewErrors` | share of SubjectAccessReviews that fail, for 10m | `authzErrorRatio` (0.05) |
| `KubesentryAuthzBudgetNearLimit` | reviews per replica above a fraction of `auth.authzQPS` for 15m (proxy mode) | `authzBudgetRatio` (0.8) |
| `KubesentryCacheHitRateCollapsed` | 30m response-cache hit ratio below a fraction of the day's, with enough traffic, for 30m | `cacheHitCollapseRatio` (0.5), `cacheMinLookupsPerSecond` (0.5) |
| `KubesentryRateLimited` | a route answers 429 to more than a share of its requests, for 15m | `rejectedRatio` (0.05), `rejectedMinPerSecond` (0.05) |
| `KubesentryServiceUnavailable` | the same for 503 | same |
| `KubesentryRequestsRejected` | the per-identity rate limit or the in-flight cap turns away more than a share of API requests, before routing, for 15m | `rejectedRatio`, `rejectedMinPerSecond` |
| `KubesentryPrometheusUnreachable` | a replica cannot query its Prometheus for 10m | |
| `KubesentryLeakScanFailing` | no background leak scan succeeded for about an hour while scans fail | |
| `KubesentryAlertsNotEvaluated` | no replica holds the alerts lock for 10m (`alerts.enabled` only) | |
| `KubesentryAlertmanagerFailing` | the replica that notifies fails or drops deliveries for 15m (with `alerts.alertmanager.urls`) | |
| `KubesentryAgentNodesDropped` | nodes reporting processes drop by a fraction within an hour, for 10m (agent only) | `agentDropRatio` (0.2) |
| `KubesentryCrashLooping` | a server, oauth2-proxy or agent container in CrashLoopBackOff, or restarting, for 10m (kube-state-metrics) | `kubeStateMetrics.restarts` (3 in 30m) |
| `KubesentryOOMKilled` | one of those containers restarted after an OOM kill in the last 30m (kube-state-metrics) | |

- **Severity and routing.** All are `warning`. They carry no owner, so they go to the platform team.
- **Label matchers.** `metrics.prometheusRule.matchers` selects kubesentry's series; it defaults to the release namespace. `kubeStateMetrics.matchers` adds matchers for the kube-state-metrics series, for example `cluster="prod-eks"`.
- **Runbooks.** `runbookBaseURL` lets the runbook links point at your own copy of this page.
- **Target down.** When every kubesentry target is down, kube-prometheus-stack's `TargetDown` fires.

`metrics.grafanaDashboards.enabled` adds the "kubesentry health" dashboard as a ConfigMap labelled `grafana_dashboard: "1"`; `label` and `labelValue` change that. The dashboard has these rows:

| Row | Panels |
|---|---|
| Overview | replicas serving, oldest snapshot age, requests per second, 429 and 5xx share, review budget used, nodes reporting processes |
| Snapshot | snapshot age, build time p50/p90/p99, rebuilds per minute, informer objects by resource |
| HTTP | requests by route, p95 latency by route, 429 and 5xx by route and code, requests in flight |
| Caches | response cache hit ratio and lookups by result, authorization cache hit ratio, Prometheus result cache hit ratio |
| Authorization | SubjectAccessReviews per replica against the budget (`auth.authzQPS`), review results, Kubernetes API requests by verb and resource |
| Audit | ingest by source, write queue against its capacity, store errors, CloudWatch lag |
| Agents and Prometheus | nodes with a fresh report, agent reports by status, Prometheus query latency p95 by kind |
| Alerts and dependencies | dependencies up (`kubesentry_dependency_up`), requests rejected before routing, open alert findings by check, alerts posted to Alertmanager by result and queued, evaluation time and the leader, leak scans by result |
| Go runtime | heap, heap goal, memory from the OS and GOMEMLIMIT; container working set; goroutines; GC CPU |

The "Cluster health (EKS)" dashboard in `examples/grafana` has these rows:

- **Alerting pipeline:** firing alerts by severity, missed rule evaluations, head series, failed notifications, rule-group evaluation time.
- **API server:** 429 and 5xx, read and write p99, APF rejections and queues, etcd size against 8 GiB, top objects, event writes and stored events.
- **Nodes:** readiness, pressure, lowest memory available, clock offset, and gp3 IOPS, throughput and queue depth.
- **Workloads:** pods by phase, pending pods, crash loops, OOM kills.
- **cert-manager:** certificates expiring and not ready, restarts, and a table of the soonest expiries.

## 6. Validation

`hack/check-rules.sh` runs promtool and amtool from PATH, or from `prom/prometheus:v3.15.0` and `prom/alertmanager:v0.34.1` with docker. It checks the following:

- **kubesentry's PrometheusRule,** rendered with every optional rule on:
  - `promtool check rules` with warnings fatal
  - the unit tests in `charts/kubesentry/testdata/prometheusrule.test.yaml`
  - every `kubesentry_*` and `go_*` name is checked against `internal/metrics`, in the rules and the dashboard
- **The profile's extra rules:** `promtool check rules` and the unit tests in `examples/testdata/monitoring-eks.test.yaml`.
- **The kube-state-metrics allowlist** contains every `kube_*` metric that a rule or dashboard reads.
- **The profile's Alertmanager configuration:**
  - `amtool check-config`
  - `amtool config routes test` for eight sample alerts, checking the receiver each one reaches

```bash
hack/check-rules.sh
hack/check-rules.sh --kps ./kube-prometheus-stack     # also render the stack with the profile (helm pull --untar first)
```

With `--kps`, the script also checks every rule the stack renders, and its generated Alertmanager Secret. The stock rules are checked without promtool's duplicate-rule lint: kubernetes-mixin records `code_verb:apiserver_request_total:increase1h` once per status-code class on purpose.

**By hand,** on a rule file or an extracted Alertmanager configuration:

```bash
docker run --rm --cpus=1 -v "$PWD:/w" -w /w --entrypoint promtool prom/prometheus:v3.15.0 check rules rules.yaml
docker run --rm --cpus=1 -v "$PWD:/w" -w /w --entrypoint amtool prom/alertmanager:v0.34.1 check-config am.yaml
docker run --rm --cpus=1 -v "$PWD:/w" -w /w --entrypoint amtool prom/alertmanager:v0.34.1 config routes show --config.file=am.yaml
```

**After installing:**

1. **Targets.** In Prometheus, Status, then Targets shows no target down. On day one, `ALERTS{alertstate="firing"}` should show only `Watchdog`, and `InfoInhibitor` if info alerts exist.
2. **Heartbeat.** The heartbeat service receives a ping every 5 minutes.
3. **Test alert.** Send one through Alertmanager and check it reaches the team channel:

   ```bash
   kubectl -n monitoring port-forward svc/kps-kube-prometheus-stack-alertmanager 9093
   amtool alert add --alertmanager.url=http://localhost:9093 alertname=RoutingTest severity=warning owner=payments \
     --annotation=summary="routing test, please ignore"
   ```

4. **kubesentry's rules** appear under Status, then Rules, as the group `kubesentry`. The "kubesentry health" dashboard shows data.

## 7. Runbooks: platform alerts

### CertManagerMetricsAbsent
**Meaning:** no cert-manager controller target has been up for 15 minutes, so the certificate alerts cannot fire.
**Check:**
- cert-manager's ServiceMonitor exists and carries `release: kps` (`examples/cert-manager-eks.yaml`).
- The `cert-manager` Service has its `http-metrics` port.
- `up{job="cert-manager"}` is present in Prometheus.

The rule matches `job="cert-manager"`, the Service's `app.kubernetes.io/name`. Adjust it if your release name differs.

### CertManagerCertificateExpiring
**Meaning:** a certificate expires within 14 days (warning) or 3 days (critical), and its renewal time passed more than an hour ago without a new certificate. Certificates that renew on schedule never fire this, however short-lived they are.
**Check:**
- `kubectl -n <namespace> describe certificate <name>`, and its latest CertificateRequest and Order: issuer errors, ACME challenges, rate limits.
- `kubectl get issuer,clusterissuer`: is the issuer Ready?

**Fix:** fix the issuer or the challenge, then `cmctl renew -n <namespace> <name>`. For an expiry under 3 days, tell the service's owner now: clients fail TLS when the certificate expires.

### CertManagerCertificateNotReady
**Meaning:** a Certificate has not been Ready for 15 minutes. The stress run had 9 of these, all referencing issuers that did not exist (`DoesNotExist`).
**Check:** `kubectl -n <namespace> describe certificate <name>` (conditions and events) and the issuer it names.
**Fix:** create or fix the issuer, or correct `issuerRef`. The old certificate, if any, keeps serving until it expires, so this becomes `CertManagerCertificateExpiring` later.

### CertManagerRestarting
**Meaning:** a cert-manager container restarted twice or more in an hour. In the stress run the controller failed `/livez` (HTTP 500) under API server load and restarted 3 to 5 times. While it is down, nothing is issued or renewed, and with the webhook down, cert-manager resources cannot be changed.
**Check:**
- `kubectl -n cert-manager describe pod <pod>`: OOMKilled, or liveness failures.
- Container memory against its limit.
- API server latency (`KubeAPIServerReadLatencyHigh`).

**Fix:**
- Apply `examples/cert-manager-eks.yaml` for requests and a longer liveness tolerance.
- Raise the memory limit if it was OOM-killed.
- For leader-election timeouts, look at API server health first.

### KubeAPIServerReadLatencyHigh
**Meaning:** p99 of single-object and namespace-scoped reads stayed above 1s for 15 minutes. The stress run saw 1.6s during pod churn. Every controller and every user shares this latency.
**Check:**
- The cluster dashboard: request rate, APF queues and rejections.
- Large LISTs: `topk(10, sum by (resource, verb) (rate(apiserver_request_total[5m])))`.
- The EKS control-plane logs in CloudWatch.

**Fix:**
- Find the client generating the load (often a controller relisting, or a script) and slow it down or give it its own FlowSchema.
- If load is legitimately high, contact AWS support about control-plane scaling.

### KubeAPIServerWriteLatencyHigh
**Meaning:** p99 of writes stayed above 1s for 15 minutes.
**Check:**
- `apiserver_admission_webhook_admission_duration_seconds`: slow webhooks are the usual cause.
- etcd size (`KubeEtcdDatabaseLarge`).
- Event volume (`KubeEventVolumeHigh`).

**Fix:** set short `timeoutSeconds` and the right `failurePolicy` on slow webhooks, and reduce write storms.

### KubeAPIServerFlowControlRejecting
**Meaning:** API Priority and Fairness has answered 429 to a flow schema for 15 minutes. The clients in that flow are throttled and retry.
**Check:**
- Which flow schema and priority level are named in the alert.
- `apiserver_flowcontrol_current_inqueue_requests` and `apiserver_flowcontrol_request_concurrency_limit` for that level.

kubesentry has its own FlowSchema and priority level when its chart sets `apf.enabled`. Rejections there mean kubesentry's start-up LIST burst, or its SubjectAccessReviews, exceed its share.
**Fix:**
- Find and slow down the noisy client.
- Give a legitimate heavy client its own priority level.
- For kubesentry, raise `apf.nominalConcurrencyShares`, or lower `auth.authzQPS` (see `KubesentryAuthzBudgetNearLimit`).

### KubeEtcdDatabaseLarge
**Meaning:** the etcd database is over 70% (warning) or 85% (critical) of EKS's 8 GiB limit. At the limit, etcd refuses writes: no deployments, no scaling, no leader elections.
**Check:** which resources hold the most objects: `topk(10, max by (resource) (apiserver_storage_objects))`. The usual culprits are leaked objects such as completed Jobs, old ReplicaSets, Events, custom resources from a runaway controller, and large ConfigMaps or Secrets.
**Fix:**
- Delete what leaked and fix its source: `ttlSecondsAfterFinished`, `revisionHistoryLimit`.
- EKS compacts and defragments etcd itself.
- At critical, open an AWS support case while you clean up.

### KubeEventVolumeHigh
**Meaning:** events have been written at more than 20 per second for 30 minutes. Events live in etcd for an hour on EKS, so this costs etcd space and API capacity.
**Check:**
- `kubectl get events -A --sort-by=.lastTimestamp | tail -50`: which reasons and objects dominate. The usual ones are failing probes (`Unhealthy`), `BackOff`, `FailedScheduling`, and a controller retrying in a loop.
- kubesentry's findings page lists crash loops and unschedulable pods with their owners.

**Fix:** fix the noisy workload. Raise the threshold only if your cluster's normal rate is higher; measure it on the dashboard first.

### NodeClockOffsetCritical
**Meaning:** a node's clock is more than 10 seconds off. Service account and OIDC token validation (often about 60s of leeway), IRSA and SigV4 (5 minutes) fail as the offset grows.
**Check:**
- On the node (SSM Session Manager): `chronyc tracking` and `chronyc sources`. EKS AMIs sync with the Amazon Time Sync Service at 169.254.169.123.
- Security groups or host firewall rules blocking it.

**Fix:**
- Restart chronyd.
- If the node keeps drifting, cordon and replace it.

### NodeEBSVolumeIOPSNearLimit
**Meaning:** a volume has run above 90% of gp3's 3,000 baseline IOPS for 15 minutes. Beyond the limit EBS queues requests and latency climbs.
**Check:**
- Which pod uses the device: `lsblk` on the node, or the PVC's volume ID in the EBS console.
- The volume's provisioned IOPS: the rule assumes the 3,000 baseline.

**Fix:**
- Raise the volume's provisioned IOPS (`aws ec2 modify-volume --iops`, online), or change the StorageClass for new volumes.
- For kubesentry's Postgres, size IOPS to the audit ingest rate. Stress Phase 4 pushed Postgres hard at 600 events/s.

### NodeEBSVolumeThroughputNearLimit
**Meaning:** a volume has moved more than 90% of gp3's 125 MiB/s baseline for 15 minutes.
**Check:** same as above.
**Fix:**
- Raise provisioned throughput (`--throughput`, up to 1,000 MiB/s on gp3).
- Check that the instance type's EBS bandwidth is not the real limit.

### NodeEBSVolumeQueueDepthHigh
**Meaning:** a device has averaged more than 8 requests in flight for 15 minutes. At gp3 latencies, 3,000 IOPS needs a queue of about 3, so requests are waiting for the volume. It replaces the stock `NodeDiskIOSaturation`, which allows a queue of 10 for 30 minutes. The stress run saw `NodeDiskIOSaturation` pending during the Postgres and CloudWatch load.
**Check:** the IOPS and throughput alerts on the same device, and the instance's EBS bandwidth (`EBSIOBalance%` and `EBSByteBalance%` in CloudWatch for burstable instance types).
**Fix:**
- Raise IOPS or throughput, or move the workload to a larger instance type.
- Instance-store NVMe devices are far faster than the gp3 numbers. Remove them from the rule's device pattern on instance types that have them.

## 8. Runbooks: kubesentry alerts

Most checks below start from the "kubesentry health" dashboard and from the ops listener:

```bash
kubectl -n kubesentry port-forward svc/kubesentry-ops 9090
curl -s localhost:9090/readyz      # degraded dependencies, by name and reason
```

### KubesentrySnapshotStale
**Meaning:** a replica has served a view older than `snapshotStaleSeconds` for 5 minutes while a cluster change waited for a rebuild (`kubesentry_snapshot_last_change_timestamp_seconds` newer than the view). The view rebuilds only when a watched object changes, so in a quiet cluster the age climbs too (stress Phase 4, bug 3). The rule leaves that case out: there, the last change is as old as the view.
**Check:**
- `/readyz` for a `snapshot` or API server problem; `kubesentry_dependency_up{dependency="snapshot"}` is 0 while failed rebuilds keep the last good view.
- `kubesentry_kube_requests_total{code!~"2.."}` for watch errors.
- The pod's logs.

**Fix:** restore API server reachability or RBAC. A replica stuck after that recovers on restart.

### KubesentrySnapshotBuildSlow
**Meaning:** the p90 view rebuild time has stayed above `snapshotBuildSeconds` for 15 minutes, so changes reach the UI late and rebuild CPU rises.
**Check:**
- Rebuilds per minute against build time, on the dashboard.
- CPU throttling of the server container.
- `kubesentry_informer_objects`: did the cluster grow?

**Fix:** give the server more CPU and memory (`docs/deploy-eks.md`, Sizing). If rebuilds are too frequent, raise `server.snapshotMinInterval`.

### KubesentryCloudWatchLag
**Meaning:** audit events from CloudWatch Logs are more than `cloudwatchLagSeconds` behind.
**Check:**
- `FilterLogEvents` throttling and IAM errors in the logs.
- Which replica holds the reader lock (`/readyz`).
- Postgres health: Phase 4 saw 67–70s of lag and the lock moving under 600 events/s of sustained ingest.

**Fix:** request a higher CloudWatch Logs quota, fix IAM, or relieve Postgres (`KubesentryAuditQueueFilling`).

### KubesentryPostgresErrors
**Meaning:** audit store operations have failed for 10 minutes. Events queue in memory; once the queue is full the webhook answers 503. CloudWatch events are not lost: the reader resumes from its checkpoint.
**Check:**
- `/readyz` (`postgres`) and the server logs.
- RDS events, connections against `max_connections`, storage, and TLS (`sslmode`, CA bundle).

**Fix:** restore the database or the network path, or rotate the credentials in the DSN Secret.

### KubesentryAuditQueueFilling
**Meaning:** more than `auditQueueRatio` of the 50,000-event write queue has been in use for 10 minutes. When it is full, the webhook answers 503 and the CloudWatch reader slows down; nothing is lost. Phase 4 filled it under 600 events/s sustained, with Postgres at 4–5 cores.
**Check:**
- Postgres CPU and IOPS: `NodeEBSVolume*`, or RDS Performance Insights.
- `kubesentry_audit_store_errors_total`.
- The ingest rate on the dashboard.

**Fix:**
- Give Postgres more CPU or IOPS.
- Reduce audit volume at the source: the API server audit policy.
- If the server's queue size ever changes, set `auditQueueCapacity` to match.

### KubesentryAuthzReviewErrors
**Meaning:** more than `authzErrorRatio` of SubjectAccessReviews have failed for 10 minutes, so users see less than their RBAC allows. kubesentry fails closed.
**Check:**
- API server health.
- APF rejections for kubesentry's flow (`KubeAPIServerFlowControlRejecting`).
- The ServiceAccount's permission to create `subjectaccessreviews`.

**Fix:** follow the API server or APF runbook above.

### KubesentryAuthzBudgetNearLimit
**Meaning:** a replica has sent more than `authzBudgetRatio` of its `auth.authzQPS` budget of SubjectAccessReviews per second for 15 minutes. At the budget, reviews queue and every page slows down while CPU stays low. Stress Phase 4 saturated it first, at 1,000 to 2,000 distinct users (about 400 reviews/s across 2 replicas, 85% of them denials).
**Check:**
- The review-results panel: a high share of `denied` means short deny caching.
- The authorization cache hit ratio.
- The number of active users.

**Fix:**
- Cache by group set with `auth.shareByGroups`, when no RoleBinding names individual users.
- Lengthen `auth.authzCacheTTL`.
- Add replicas, since the budget is per replica.
- Raise `auth.authzQPS` if the API server has headroom; watch `KubeAPIServerFlowControlRejecting` afterwards.

The deny-cache TTL (`auth.authzDenyTTL`) is a known lever, and changing it is a separate, scheduled decision.

### KubesentryCacheHitRateCollapsed
**Meaning:** the response cache's 30-minute hit ratio fell below `cacheHitCollapseRatio` of its ratio over the last day, while serving at least `cacheMinLookupsPerSecond` lookups. Every miss runs the handler and its authorization lookups. Normal ratios are low (5–30% under load in the stress runs), so the rule compares with the day rather than a fixed number.
**Check:**
- Rebuilds per minute: entries are keyed by the view version, so constant churn invalidates them.
- A deploy with `server.cache=false`.
- A change in how many distinct scopes users have.

**Fix:**
- Find and calm the churning workload (kubesentry's findings, `KubeEventVolumeHigh`).
- Raise `server.snapshotMinInterval` to rebuild less often.

### KubesentryRateLimited
**Meaning:** a route has answered 429 to more than `rejectedRatio` of its requests for 15 minutes. This counts the per-identity cap on the expensive routes (`server.maxInflightPerIdentity`: `/oom`, pod diagnostics, the audit summary). `auth_recheck` is excluded, because users cause its 429s by pressing the button. The per-identity rate limit (`server.rateLimit`) and the global in-flight cap answer before a route is known, so they are not counted here; `KubesentryRequestsRejected` covers them.
**Check:**
- The route's p95 latency: slow Prometheus or Postgres keeps slots busy.
- `kubesentry_prometheus_query_seconds`.
- Which users poll hardest (the access log).

**Fix:**
- Fix the slow backend.
- Raise `server.maxInflightPerIdentity` only if the backend has headroom.

### KubesentryServiceUnavailable
**Meaning:** a route has answered 503 to more than `rejectedRatio` of its requests for 15 minutes. The causes are:
- route timeouts (30s, or 60s for the long routes)
- an overloaded audit store (`audit_events`, `audit_summary`)
- a full audit write queue (`ingest_audit_webhook`)
- an ingest route whose token is not set (`ingest_*`, failing closed)
- no view built yet

**Check:**
- `/readyz`.
- The route in the alert, against the list above.
- `KubesentryAuditQueueFilling` and `KubesentryPostgresErrors`.

**Fix:** follow the matching runbook. For an ingest route, set its token (`tokens.audit` or `tokens.agent`).

### KubesentryRequestsRejected
**Meaning:** for 15 minutes, more than `rejectedRatio` of API requests were turned away before routing (`kubesentry_http_rejected_total`):
- `rate_limit` (429): one identity exceeded `server.rateLimit` and `server.rateBurst`
- `max_inflight` (503): more requests were in flight at once than `server.maxInflight` allows

Requests without credentials (`unauthenticated`) are counted but not alerted on: expired SSO sessions and scanners cause them.
**Check:**
- The access log: which identity sends most requests? A script polling the API, or a UI left open on many tabs, is the usual cause of `rate_limit`.
- For `max_inflight`, the p95 latency by route: slow requests hold slots.

**Fix:** give scripts their own identity and a sensible polling interval. Raise `server.rateLimit` only if the replica has headroom, and `server.maxInflight` only together with CPU and memory.

### KubesentryPrometheusUnreachable
**Meaning:** a replica has failed to query its Prometheus for 10 minutes (`kubesentry_dependency_up{dependency="prometheus"}`, the same judgement as `/readyz`). Memory charts, `/oom` and the background leak scan have no data, so `KubesentryMemoryLeak` alerts cannot fire. A replica that has no Prometheus configured or discovered reports 1, not 0.
**Check:** the reason in `/info` (`unavailable.prometheus`) or the ops `/readyz`: an HTTP status (401 or 403 for credentials or SigV4, 5xx for an overloaded Prometheus) or a network error.
**Fix:** fix the Prometheus, the network policy (`networkPolicy.egress.prometheus`), or the credentials (`PROMETHEUS_TOKEN`, or the IAM role for AMP: `aps:QueryMetrics`).

### KubesentryLeakScanFailing
**Meaning:** a replica's background leak scans keep failing and none succeeded for about an hour (`kubesentry_leak_scan_runs_total`). `/oom` and the leak alerts keep the last good findings, so new leaks go unnoticed.
**Check:** `/api/v1/oom` returns the scan's errors in `warnings`, and the server log has them too. A failing candidate query often means a Prometheus that is too slow for the window: `-leak-scan-window` over many containers.
**Fix:** fix Prometheus (`KubesentryPrometheusUnreachable`), or shorten `prometheus.leakScan.window`.

### KubesentryAlertsNotEvaluated
**Meaning:** for 10 minutes no replica has held the `alerts` lock, so kubesentry's findings are neither evaluated nor sent (`kubesentry_alerts_leader` is 0 everywhere).
**Check:**
- The server log for `alerts: could not try for the lock` (Postgres unreachable) or `alerts: leadership ended`.
- `kubesentry_dependency_up{dependency="postgres"}`.

**Fix:** restore Postgres (`KubesentryPostgresErrors`). A replica retries for the lock every 30 seconds and takes over by itself.

### KubesentryAlertmanagerFailing
**Meaning:** the replica that sends kubesentry's alerts has failed or dropped deliveries for 15 minutes (`kubesentry_alerts_sent_total{result=~"failed|dropped"}`), so findings are not reaching anyone. If Alertmanager itself is down, this alert cannot reach you through it either: watch the dead man's switch.
**Check:** `/info` `alerts.lastError` names the Alertmanager by position (`alertmanager 2 of 2: ...`) and the error:
- `HTTP 401` or `403`: the token, basic auth, or for AMP the IAM role (`aps:CreateAlertManagerAlerts`)
- `HTTP 400`: Alertmanager refused the payload; its message is in the server log
- `unreachable`: DNS, the network policy (`networkPolicy.egress.alertmanager`), or TLS (`alerts.alertmanager.ca`)

`dropped` means the queue was full, because Alertmanager is too slow or down.
**Fix:** fix the credentials, the network path or Alertmanager. Nothing is lost for long: every open alert is posted again each minute.

### KubesentryAgentNodesDropped
**Meaning:** nodes reporting processes dropped by more than `agentDropRatio` within an hour.
**Check:**
- The agent DaemonSet's ready count against the non-Fargate Linux nodes.
- Agent logs for 401 (token) or 413 (report too large).
- `kubesentry_agent_reports_total` by code.

A cluster that scaled down also drops the count.
**Fix:** fix the failing agents, or raise their memory limit on nodes with many processes.

### KubesentryCrashLooping
**Meaning:** a server, oauth2-proxy or agent container of this release is in CrashLoopBackOff, or restarted `kubeStateMetrics.restarts` times in 30 minutes. A restarting server rebuilds its caches. With the memory audit store it also loses its audit history, as in the baseline run's 31 OOM kills.
**Check:**
- `kubectl -n <namespace> describe pod <pod>` and `kubectl logs --previous`: OOMKilled, failed probes, configuration errors.
- `/readyz` on a replica that did start.

**Fix:** follow `KubesentryOOMKilled` for OOMs, and correct the values for configuration errors.

### KubesentryOOMKilled
**Meaning:** a container of this release restarted after an OOM kill in the last 30 minutes.
**Check:**
- Working set against the limit, and the Go heap against GOMEMLIMIT, on the dashboard.
- Cluster growth (`kubesentry_informer_objects`).
- An agent surge after a DaemonSet rollout.

Memory rose slowly over long runs in Phase 4 (bug 4). Heap profiles from `/debug/pprof/heap` (`server.pprof`) help find out why.
**Fix:** raise `resources.limits.memory` using the sizing table in `docs/deploy-eks.md`; the server keeps GOMEMLIMIT at 90% of it. For the agent, raise `agent.resources` or lower `agent.maxProcesses`.

## 9. Metrics proposed for phase B

Some rules here could not be expressed with the metrics phase A had, or had to hard-code a server setting. These metrics would close the gaps. Phase B shipped the ones marked shipped, and the rules and dashboard above use them.

| Proposed metric | Why |
|---|---|
| `kubesentry_http_rejected_total{reason}`, reason `rate_limit`, `max_inflight` or `unauthenticated` (**shipped**: `KubesentryRequestsRejected`) | The per-identity rate limit and the global in-flight cap answer 429 and 503 before a route is known, so `KubesentryRateLimited` and `KubesentryServiceUnavailable` cannot see them |
| `kubesentry_audit_queue_capacity` (gauge) | The queue rule and dashboard would read the real capacity instead of `auditQueueCapacity` |
| `kubesentry_authz_qps_limit` (gauge, the effective `-authz-qps`) | The budget rule and panel would not depend on the values matching the server |
| `kubesentry_authz_review_duration_seconds` (histogram) and `kubesentry_authz_throttled_seconds_total` (time spent waiting for the client-side limiter) | Review latency, and a direct measure of budget saturation rather than a rate near a threshold |
| `kubesentry_dependency_up{dependency}` for `prometheus`, `postgres`, `cloudwatch` and `snapshot`, from the logic behind `/readyz` (**shipped**, plus `alertmanager`: `KubesentryPrometheusUnreachable`) | The "Prometheus disconnected" alert from the proposal; until then only `/readyz` and `/info` showed it |
| `kubesentry_leak_scan_runs_total{result}` (**shipped**, results `ok`, `partial`, `failed`: `KubesentryLeakScanFailing`) and `kubesentry_leak_scan_last_success_timestamp_seconds` | Alert when the background leak scanner fails or stops (the proposal's "leak scan failures") |
| `kubesentry_snapshot_last_change_timestamp_seconds` (**shipped**: `KubesentrySnapshotStale` now needs a change waiting) and `kubesentry_snapshot_build_failures_total` | Tell a quiet cluster from a stuck view (bug 3), so `KubesentrySnapshotStale` stops firing falsely |
| `kubesentry_cloudwatch_reader_leader` (1 on the lock holder) | The lag gauge may be stale on a replica that lost the lock; the lag rule would read only the leader |
| `kubesentry_findings{check, severity}` (**shipped**, without `namespace` and `owner` to keep it small; reported by the replica that evaluates) | Finding counts for teams' own rules |

One more phase B change concerned labels rather than metrics: kubesentry's pod alerts carry a `node` label when their pods all run on one node, so the profile's node-down inhibition mutes them (shipped).
