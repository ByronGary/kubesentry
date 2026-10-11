# Proposal: alerts, automations and monitoring for kubesentry

Status: draft for decision · 2026-10-11 · builds on the enterprise hardening work and on the stress run notes in `docs/stress-notes.md`.

## Summary

kubesentry already finds problems. These include certificates near expiry, memory leaks, crash loops, unused volumes with their cost, risky RBAC, exposed services, sensitive audit events and process anomalies. Today those findings only appear when someone opens the dashboard. The stress runs also showed that the cluster's own alerts reach nobody: Alertmanager is not connected, and a default EKS monitoring stack fires several alerts forever from day one.

This proposal adds four layers. Each one is useful on its own, and they ship in that order:

1. **Platform monitoring baseline.** Make the existing Prometheus alerts trustworthy and routed. This is configuration, not product code, and can start immediately.
2. **Findings become alerts.** kubesentry evaluates its findings after each snapshot. It gives each one a lifecycle (open, acknowledged, silenced, resolved) and an owner, then sends it through Alertmanager or directly to Slack, PagerDuty, a webhook or a ticketing system.
3. **Automations.** A small, safe action framework with tiers: notify, annotate, and remediate with approval. Every action is authorized against the approving person's own RBAC, recorded in the audit trail, and off by default.
4. **Monitoring UI.** An Alerts page scoped by RBAC, a finding timeline, acknowledge and silence actions, and Grafana dashboards and SLOs for kubesentry and the cluster.

The rest of the document gives the evidence, the design, the alert catalog, the phasing, and the decisions needed before work starts.

## Evidence from the stress runs

| Observation (baseline, 500 nodes / 10k pods) | What it means for this build |
|---|---|
| Alertmanager not connected, so every alert fired into nothing | Routing is the first deliverable. Nothing else matters until alerts reach someone |
| 500+ alerts firing permanently because the kube-proxy, etcd, scheduler and controller-manager targets can't be scraped (the same happens on EKS) | An EKS-tuned values profile is needed. Permanent noise trains people to ignore alerts |
| Prometheus missing rule evaluations at 102k series, even with a trimmed kube-state-metrics | Size Prometheus (or use Amazon Managed Prometheus, AMP) before adding rules. Every rule costs evaluation time |
| cert-manager restarted 3× on failed liveness probes under load, and runs with no resource requests | A per-component health rule set, with cert-manager included |
| 117 certificates expiring within 14 days and 9 not ready (missing issuers); no cert-manager rules ship with kube-prometheus-stack | Certificate alerts with owner and issuer are high value, and kubesentry already computes them |
| The monitoring tool itself crash-looped (baseline build), with 4,137 failed readiness probes and no alert | kubesentry needs self-monitoring rules. The chart ships 5; this extends them |
| Planted faults (crash loop, image pull failure, unschedulable, memory leak) produced thousands of warning events but no notification | Findings need to be attributed to an owner and deduplicated, not raised once per pod or per event |

## Layer 1: platform monitoring baseline (configuration)

These are values and rules for kube-prometheus-stack, or for AMP plus Managed Grafana, to be shipped as `examples/monitoring-eks.yaml` next to the chart:

- **Routing:**
  - Alertmanager (or the AMP alert manager on EKS), with one receiver per team plus a default receiver.
  - Routes match the `namespace` label against the owner map described in Layer 2.
  - The Watchdog alert goes to a dead-man's-switch receiver (for example, a heartbeat check), so a dead pipeline is itself noticed.
- **EKS noise removal:**
  - `kubeEtcd`, `kubeScheduler` and `kubeControllerManager` turned off, because EKS manages them and they cannot be scraped.
  - kube-proxy either patched to `metricsBindAddress: 0.0.0.0:10249` or its scraping turned off.
  - Fargate pods excluded from the node exporter and the kubelet.
- **Capacity:**
  - Prometheus sizing guidance per cluster size, taken from the stress numbers, or AMP with a small in-cluster agent.
  - A kube-state-metrics allowlist tuned to what the rules actually use.
- **cert-manager rules:**
  - `certmanager_certificate_expiration_timestamp_seconds` and `certmanager_certificate_ready_status` (cert-manager exposes these when its ServiceMonitor is enabled).
  - Controller restarts.
  - Resource requests for cert-manager itself.
- **Control-plane rules suited to EKS:**
  - API server latency and APF rejections per flow schema (kubesentry's own flow included).
  - Rate of `ClusterIPNotAllocated` events.
  - etcd database size via `apiserver_storage_db_total_size_in_bytes`.
  - Event volume.
  - Node clock synchronisation.
- **kubesentry self-monitoring:** the chart's `PrometheusRule` gains these, in addition to its existing snapshot-stale, CloudWatch-lag, Postgres-errors, authz-errors and agents-dropped rules:
  - crash loop or OOM
  - the response cache hit rate falling
  - rate limiting (429s) per route
  - the audit queue backing up
  - leak scan failures
  - Prometheus disconnected

## Layer 2: findings become alerts (product)

### How it works

1. **Evaluate.** After each snapshot build, an evaluator on the replica holding the Postgres advisory lock compares the current findings with the stored set. That is the same leader mechanism the CloudWatch reader uses, so there are no duplicate alerts across replicas. In memory mode with one replica, it runs in-process.
2. **Track.** Each finding has a stable **dedupe key** made of check, object and owner (for example `cert-expiring/billing-01/api-tls-0`) and a state.
   - States: `open`, `acknowledged`, `silenced-until`, `resolved`.
   - It also records `first_seen`, `last_seen` and `last_notified`.
   - Findings are stored in a Postgres table next to the audit events and are subject to the same retention.
3. **Attribute.** Every finding gets an **owner**, resolved from cluster objects:
   1. a `kubesentry.io/owner` annotation on the object
   2. otherwise the same annotation on its namespace
   3. otherwise an owner map ConfigMap (namespace pattern to team)
   4. otherwise the default team

   The owner also carries routing hints: `kubesentry.io/slack-channel`, `kubesentry.io/pagerduty-service` and `kubesentry.io/jira-project`. Nothing is hardcoded; the owner map is a Helm value.
4. **Notify.** Findings go out through one or more sinks:
   - **Alertmanager v2 API** (`POST /api/v2/alerts`). This is the recommended default, because it reuses existing routing, grouping, silences and inhibition. Labels: `alertname=Kubesentry<Check>`, `severity`, `namespace`, `owner`, `dedupe_key`. Annotations: a summary, a link to the kubesentry finding, and a runbook URL.
   - **Direct sinks** for teams without Alertmanager: Slack incoming webhook, PagerDuty Events v2 (dedupe key = finding key), a generic signed webhook (HMAC), and Jira or ServiceNow through the webhook sink.
   - **Digests:** a daily or weekly summary for low-urgency findings such as unused PVCs with cost, info-level posture and expiring certificates more than 14 days out, sent per owner.
5. **Protect against storms.**
   - Per-sink rate limits, and grouping by owner and check.
   - "N more like this" folding: one alert for 300 pods in the same CrashLoopBackOff workload, attributed to the workload through the ownerRef association.
   - A global circuit breaker that switches to a digest when more than X new findings appear in one snapshot. This happens after a cluster-wide incident or on a first install.
6. **Resolve.** When a finding disappears, it resolves after a grace period (no flapping), and the sink gets a resolve event.

### Metrics for teams that prefer PromQL
`kubesentry_findings{check, severity, namespace, owner}` gives counts with bounded cardinality (no object names), so teams can also write their own PrometheusRules against kubesentry's knowledge.

### Initial alert catalog
These come from detectors kubesentry already has, so the work is wiring, not detection:

| Alert | Source | Default severity | Notes |
|---|---|---|---|
| Certificate expiring | cert detector (thresholds relative to the certificate's lifetime) | warn, then crit | owner and issuer included; digest when more than 14 days out |
| Certificate not ready / issuer missing | cert detector | warn | stress run: 9 certificates had missing issuers |
| Memory leak, OOM predicted | background leak scanner | warn; crit when the predicted time to the limit is under N hours | fires **before** the OOM; links to the memory chart |
| Workload crash-looping / image pull failing / unschedulable past the grace period | container checks + association | crit / warn / warn | one alert per workload, not per pod |
| Pod evicted / stuck terminating | pod-level reason | warn | |
| Unused PVC with cost | storage detector + pricing | info, sent as a digest | monthly cost in the message; "billed by usage" for EFS/FSx |
| RBAC drift: new cluster-admin binding, wildcard role, anonymous binding, aws-auth `system:masters` mapping | security detector, diffed between snapshots | crit | alerts on the **change**, not on the standing state, which goes into a weekly digest |
| Exposure change: new internet-facing load balancer, Ingress without TLS, new NodePort or external IP | exposure checks, diffed | warn | the ALB/NLB internal annotations are honoured |
| Privileged or host-namespace workload created | pod security checks, diffed | crit / warn | |
| Sensitive audit activity: exec, port-forward or debug in a namespace marked production; human secret reads; RBAC changes; impersonation; bursts of denied requests; anonymous requests | audit tags (`exec`, `secret-access`, `rbac-change`, `impersonate`, `denied`, `anonymous` and others) | configurable per tag and namespace label | per-actor rate thresholds; the actor kind (human or system) is already classified |
| Agent missing on a node / process anomaly | process store | warn | Fargate nodes excluded |

### Permissions
Alerts follow the same RBAC as the dashboard.
- A user sees, acknowledges and silences only findings in namespaces where they can `list pods`.
- Acknowledging and silencing need a virtual-resource grant (`update alerts.kubesentry.io`), which the chart ships as ClusterRoles, just like processes and audit events today.

## Layer 3: automations (product, off by default)

### Safety model

| Tier | What it does | Approval | Examples |
|---|---|---|---|
| 0: Notify | Creates or updates a ticket or thread; never touches the cluster | none | Jira or ServiceNow ticket per finding (dedupe key = external ID); Slack thread updates |
| 1: Annotate | Adds or removes kubesentry-owned annotations or labels only | none (opt-in per namespace) | annotate a workload with its active leak finding; label a PVC `kubesentry.io/unused-since` |
| 2: Remediate | Changes cluster state | **a named person approves** in the UI or Slack. The action runs only if that person's own RBAC allows the same verb on that object (checked with a SubjectAccessReview at approval time) | rollout-restart a leaking workload before it OOMs; delete a failed CertificateRequest to retry issuance; cordon and drain a node under pressure; snapshot then delete an unused PVC; remove a risky RoleBinding |

**Guardrails for every action:**
- A dry run shows the exact diff first.
- Writes use a **separate ServiceAccount** (`kubesentry-actions`) whose write permissions are limited to the enabled action types. The read-only server account stays read-only.
- **GitOps awareness.** Objects managed by Argo CD or Flux are detected through their labels and annotations. For those, the action proposes a change (a ticket, or a pull request through a webhook) instead of editing the live object, so a reconciler does not undo it.
- Per-action rate limits and a global kill switch (a Helm value, and a ConfigMap flag read live).
- Every proposal, approval, execution and result is written to the audit store with actor and approver. These records are visible on the Activity page and can be forwarded to SIEM through the same sinks.

**Configuration** is declarative, as `Automation` entries in a ConfigMap (later a CRD): trigger (check, severity, namespace selector), action, tier, approvers (a group), cooldown. No code is needed to add a ticketing rule.

## Layer 4: monitoring and UI

- **Alerts page:** open findings by owner, severity and age, with acknowledge, silence (with a reason and an expiry) and a link to the object's diagnostic page. It is scoped by RBAC like every other page.
- **Finding timeline** on each object page: when it opened, who was notified, who acknowledged it, which automation ran.
- **Grafana dashboards,** shipped as ConfigMaps by the chart:
  - kubesentry health: snapshot age and build time, cache hit rates, authz review rate and latency, ingest rates, agents reporting
  - cluster health using the Layer 1 signals
- **SLOs** for kubesentry itself:
  - snapshot age p99 < 15s
  - list views p95 < 300ms
  - audit ingest lag < 60s
  - alerting multi-window burn rates

## Delivery plan

| Phase | Scope | Size | Depends on |
|---|---|---|---|
| A | Layer 1 values profile and rules; extended kubesentry self-monitoring rules; dashboards | S (about 1 week) | nothing; can start now |
| B | Findings store, evaluator with leader election, owner attribution, Alertmanager sink, the catalog's first 6 alerts, metrics | M (2–3 weeks) | Postgres audit store (done) |
| C | Direct sinks (Slack, PagerDuty, webhook), digests, storm protection, Alerts page, acknowledge and silence with RBAC | M (2–3 weeks) | B |
| D | Automations tiers 0–1, the action ServiceAccount, the audit trail | M (2 weeks) | B |
| E | Tier 2 remediation with approval, GitOps awareness, the first 3 actions | L (3–4 weeks) | C, D, plus security review |

**Testing** extends the existing stress harness:
- **Alert storms:** 10k findings at once must produce bounded notifications through grouping, folding and the circuit breaker.
- **Exactly-once notification** across 2 replicas while the leader is killed.
- **Sink outages:** Alertmanager or Slack down, then queued delivery with retry and no duplicates.
- **Authorization:** a leak test extended to alerts, acknowledgements and silences.
- **Actions:** approval checks, including an approver without RBAC being refused.
- **Golden tests** for every alert's labels and annotations.

## Decisions needed

1. **Where alerts go by default:** through your existing Alertmanager or AMP alert manager (recommended), or straight to Slack and PagerDuty?
2. **Ticketing system,** if any, for tier 0: Jira, ServiceNow, GitHub Issues, or none at first?
3. **Owner mapping source:** namespace annotations, an owner map ConfigMap, or an existing source of truth (team labels already on namespaces, AWS tags, a service catalog)?
4. **Which automations are allowed at all** in your environment. Recommendation: start with tiers 0–1 only, and add tier 2 per action after review.
5. **Production marker:** which namespace label or annotation identifies production, for audit-activity alerts such as exec into production?
6. **Scope of Layer 1:** should kubesentry's chart ship the platform monitoring profile, or should it be handed to the team that runs your Prometheus or AMP?

## Out of scope for this build
- Anomaly detection or ML baselines (thresholds and diffs first).
- Multi-cluster aggregation of alerts. Each cluster keeps its own kubesentry, as decided; a central view can be a later layer on the same sinks.
- Ingesting GuardDuty or Security Hub findings. This is a good candidate for later, through the same findings store.
