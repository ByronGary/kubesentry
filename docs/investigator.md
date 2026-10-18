# AI investigator

The investigator reads one incident and writes a report: the most likely root cause with a confidence, contributing factors, a timeline, the impact, read-only checks for a person to run, remediation ideas with their risks, open questions and data gaps. Every claim cites the evidence it rests on, and each citation is a button on the incident page that takes you to that evidence.

It is **off by default**. When it is on, starting a run sends a redacted digest of the incident, and the logs, events, audit and CloudTrail records the person who started it may see, to the model provider. The recommended setup is **Claude on Amazon Bedrock in your own AWS account, reached through a VPC endpoint**, so requests never cross the public internet. The Anthropic API is supported as the alternative.

`go run ./cmd/demo` shows the whole flow with a scripted, offline investigator: open an incident and press **Investigate**, or open **Settings** and turn it off and on.

## Turn it on from Settings

An admin turns the investigator on and off, and changes its provider, model and limits, on the **Settings** page (bottom of the sidebar). Changes apply at once on every replica, without a restart; running investigations finish on what they started with, and turning it off keeps past runs. Every change is recorded with who made it, when, and the old and new values.

1. **Get the role.** The page needs `update` on `settings.kubesentry.io`, cluster-wide (reading it too: it shows role ARNs and the audit). The chart's role is `<release>-settings-admin`; aggregate it with `rbac.viewerRoles.settingsAdmin.aggregateTo`, or bind it with a ClusterRoleBinding.
2. **Turn incidents on** (`incidents.enabled`): the investigator investigates incidents.
3. **Give kubesentry a way to reach the model.** The page detects where kubesentry runs and where its AWS credentials come from, and generates the steps, with Copy on every block. **You never type AWS credentials into kubesentry**, and kubesentry stores no long-lived AWS keys; the Anthropic API key only ever comes from a Kubernetes Secret.
   - **In EKS: no keys.** Give kubesentry's service account a role, with **IRSA** (the role policy, the trust policy on the cluster's OIDC issuer and the `eks.amazonaws.com/role-arn` annotation) or **EKS Pod Identity** (the same role policy, a trust policy for `pods.eks.amazonaws.com`, and `aws eks create-pod-identity-association`). Reach Bedrock through an **interface VPC endpoint** (`com.amazonaws.<region>.bedrock-mantle`, or `.bedrock-runtime`) with private DNS, 443 from the nodes and an endpoint policy, and enable model access in the Bedrock console. Section 3 has the detail.
   - **Outside EKS.** From a laptop in remote mode (`-kube-context`, `-eks-cluster`), kubesentry calls Bedrock as you: `aws sso login --profile <profile>` and `AWS_PROFILE=<profile>`, with the inference action in your permission set. In another cluster, put a dedicated least-privilege identity's keys in a Kubernetes Secret you manage and rotate, mounted through `extraEnv` (prefer short-lived credentials such as IAM Roles Anywhere).
   - **Anthropic API.** Create the Secret and set `incidents.investigator.existingSecret`; the chart mounts it as `ANTHROPIC_API_KEY` whether or not the investigator is on, so Settings can switch to it. A newly created Secret needs a restart.
4. **Test connection.** It asks STS who kubesentry is (for Bedrock), then sends a one-token request to the model, and shows the identity ARN, the credential source, the region, the endpoint and the model, or what failed: no credentials, access denied (with the missing IAM action), model access not enabled, the model not available in the region, the endpoint unreachable (DNS: the VPC endpoint or its private DNS), or an Anthropic `401`. One test per person every 10 seconds.
5. **Turn it on.** The switch asks you to acknowledge that investigations send redacted incident data to the provider, and records your acknowledgement with your name (with `acknowledgeDataEgress: true` in the chart, the platform has acknowledged it already). Settings that cannot be built, for example Bedrock credentials that do not resolve, are refused and nothing is stored.

Each value shows whether it comes from Helm or was changed on the page (by whom, when); **Reset to Helm values** drops every change. A value saved on the page wins over the chart's; values never changed on the page follow the chart on the next upgrade.

**GitOps: Helm only.** Set `incidents.investigator.settings: locked`: the chart's values are the only source, the page is read-only ("Locked by Helm") and a write answers `409`. Turn it on with `enabled: true` and `acknowledgeDataEgress: true` (sections 3.6 and 4).

## Contents

1. [What it does and does not do](#1-what-it-does-and-does-not-do)
2. [Data that leaves the cluster](#2-data-that-leaves-the-cluster)
3. [Recommended setup: Amazon Bedrock through a VPC endpoint](#3-recommended-setup-amazon-bedrock-through-a-vpc-endpoint)
4. [Alternative: the Anthropic API](#4-alternative-the-anthropic-api)
5. [Using it](#5-using-it)
6. [Permissions](#6-permissions)
7. [Budgets, limits, caching and cost](#7-budgets-limits-caching-and-cost)
8. [Security model](#8-security-model)
9. [Refusals and the fallback model](#9-refusals-and-the-fallback-model)
10. [Flags and Helm values](#10-flags-and-helm-values)
11. [Troubleshooting](#11-troubleshooting)

## 1. What it does and does not do

**Does:**
- Starts from a digest of the incident (at most 64 KiB): its trigger and context signals, metric statistics with a peak-preserving downsample, Kubernetes events grouped by reason, log templates, audit writes and CloudTrail changes. Every record carries a ref such as `signal:<id>`, `log:<n>` or `metric:memory:<pod>/<container>`.
- Asks for more evidence through read-only tools, each limited to the incident's namespace, pods, nodes and padded time window, and to what the person who started the run may see: `list_signals`, `get_logs`, `get_metric_series`, `get_k8s_events`, `get_audit_events`, `get_cloudtrail_events` (from what kubesentry already matched; no new AWS calls) and `get_workload_state` (the cluster as it is now).
- Submits a structured report. kubesentry checks it: refs the model was never shown are marked "not verified", timeline entries far outside the window are dropped, every suggested command must be one of a short list of read-only forms, and lengths are capped.

**Does not:**
- Change anything. It has no write tools and no network tools. kubesentry never runs the suggested commands; it shows them with Copy and "kubesentry does not run this; review before running".
- Notify anyone, or run by itself. A person starts each run from the incident page (or the API).
- Read anything outside the incident, or anything its starter could not read on the incident page.
- Keep the conversation. kubesentry stores the run's steps, report, evidence index (the cited records, redacted, at most 300 characters each) and token counts; prompts and raw tool results are not stored or logged.

## 2. Data that leaves the cluster

Each run sends the provider:
- the digest of the incident;
- the results of the tools the model calls: log lines (each at most 2 KiB), Kubernetes event messages, audit records without source IPs or user agents, CloudTrail summaries and raw records cut to 1 KiB without `sourceIPAddress` and `userAgent`, metric series, and the current workload state;
- the system prompt and the tool definitions (the same for every run).

Everything passes one egress filter first: control and invisible Unicode characters are stripped, the redaction rules of the incidents bundle apply (AWS keys, passwords, tokens, bearer and JWT tokens, PEM keys, GitHub, Slack, Anthropic and Stripe tokens, `aws_secret_access_key=`, URL credentials, and your own `incidents.redactPatterns`), and source IP and user-agent attributes are dropped. Pod and node IPs never leave. **Redaction is best effort**: a secret in a format no rule knows can still be sent. Treat the provider as a processor of your incident data.

That is why the investigator needs an explicit acknowledgement: `-investigator-egress-ack=true`, or `incidents.investigator.acknowledgeDataEgress: true` in the chart. Without it the server, and the chart, refuse to start.

On Bedrock the data stays in your AWS account and region: Bedrock does not use your prompts and completions to train models or share them with model providers. With the Anthropic API it goes to Anthropic under your organisation's agreement with them.

## 3. Recommended setup: Amazon Bedrock through a VPC endpoint

With Bedrock, kubesentry calls Claude with its own pod role (IRSA or EKS Pod Identity), through an interface VPC endpoint in the cluster's VPC. No API key exists, no public egress is needed, and CloudTrail records who called what.

### 3.1 Pick the Bedrock API

kubesentry speaks the Anthropic Messages API to Bedrock through the official Go SDK. `-investigator-bedrock-api` (`incidents.investigator.bedrockAPI`) picks the endpoint:

| `bedrockAPI` | Endpoint | VPC endpoint service | IAM action | Model ID |
|---|---|---|---|---|
| `mantle` (default) | `https://bedrock-mantle.<region>.api.aws/anthropic/v1/messages` | `com.amazonaws.<region>.bedrock-mantle` | `bedrock-mantle:CreateInference` on `arn:aws:bedrock-mantle:<region>:<account>:project/*` | `anthropic.claude-opus-5-5` |
| `runtime` | `https://bedrock-runtime.<region>.amazonaws.com/model/<model>/invoke-with-response-stream` | `com.amazonaws.<region>.bedrock-runtime` | `bedrock:InvokeModelWithResponseStream` on the foundation-model and inference-profile ARNs | `anthropic.claude-opus-5-5`, an inference profile (`us.anthropic.claude-opus-5-5`, `global.anthropic.claude-opus-5-5`) or a profile ARN |

Use `mantle` unless your account or network only offers `bedrock-runtime`. With `runtime`, a model that is offered for cross-Region inference only answers through an inference profile: set `model` to the profile ID or ARN, and allow the action on the profile and on the foundation model in every Region the profile routes to.

### 3.2 Enable model access

In the Bedrock console of the region you use, open **Model access** and request Anthropic's **Claude Opus 5.5**. The first Anthropic model in an account also asks for the use-case form. The refusal fallback (section 9) uses **Claude Opus 5**: request it too, or set `fallback: "off"`.

### 3.3 Create the VPC endpoint

Create an **interface VPC endpoint** for the service of the API you picked, in the cluster's VPC:
- **Subnets:** the private subnets of the nodes (one per Availability Zone the nodes use).
- **Private DNS: enabled.** The public hostname (`bedrock-mantle.<region>.api.aws` or `bedrock-runtime.<region>.amazonaws.com`) then resolves to the endpoint's private addresses inside the VPC, so kubesentry needs no `-investigator-endpoint`.
- **Security group:** allow inbound TCP 443 from the nodes' security group, or from the pods' security group when you use security groups for pods.
- **Endpoint policy:** allow only kubesentry's role and only the models it uses, for example (mantle):

```json
{
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::111122223333:role/kubesentry" },
    "Action": ["bedrock-mantle:CreateInference"],
    "Resource": "arn:aws:bedrock-mantle:us-east-1:111122223333:project/*"
  }]
}
```

For `runtime`, the action is `bedrock:InvokeModelWithResponseStream` and the resources are the foundation-model and inference-profile ARNs, as in the role policy below.

The role also needs STS (`com.amazonaws.<region>.sts`, for IRSA) or EKS Auth (`com.amazonaws.<region>.eks-auth`, for Pod Identity) without internet access; most private clusters already have these.

Set `endpoint` (`-investigator-endpoint`) only when private DNS cannot be used: private DNS turned off, or an endpoint shared from another VPC or account whose private DNS does not reach this VPC. Then point it at the endpoint's DNS name, for Mantle including `/anthropic` (for example `https://vpce-0abc123-xyz.bedrock-mantle.us-east-1.vpce.amazonaws.com/anthropic`).

### 3.4 Grant the role

kubesentry's role (the one the chart's ServiceAccount uses through IRSA or Pod Identity, [docs/deploy-eks.md](deploy-eks.md#irsa-or-eks-pod-identity)) needs the inference action of the chosen API. Keep the statement for the API you use:

```json
{
  "Sid": "InvestigatorBedrockMantle",
  "Effect": "Allow",
  "Action": ["bedrock-mantle:CreateInference"],
  "Resource": "arn:aws:bedrock-mantle:us-east-1:111122223333:project/*",
  "Condition": {
    "StringLike": { "bedrock-mantle:Model": ["anthropic.claude-opus-5-5", "anthropic.claude-opus-5"] }
  }
},
{
  "Sid": "InvestigatorBedrockRuntime",
  "Effect": "Allow",
  "Action": ["bedrock:InvokeModelWithResponseStream", "bedrock:InvokeModel"],
  "Resource": [
    "arn:aws:bedrock:us-east-1:111122223333:inference-profile/us.anthropic.claude-opus-5-5",
    "arn:aws:bedrock:us-east-1:111122223333:inference-profile/us.anthropic.claude-opus-5",
    "arn:aws:bedrock:*::foundation-model/anthropic.claude-opus-5-5",
    "arn:aws:bedrock:*::foundation-model/anthropic.claude-opus-5"
  ]
}
```

Drop the `bedrock-mantle:Model` condition if your account's Mantle policy does not evaluate it. kubesentry streams every turn, so `bedrock:InvokeModel` is only there for tools you may run by hand. A Bedrock API key in `AWS_BEARER_TOKEN_BEDROCK` (through `extraEnv` from a Secret) is used instead of the role when set; the role is the better choice.

### 3.5 Network policy

The chart leaves egress open unless `networkPolicy.egress.enabled` is set, and even then allows 443 to `0.0.0.0/0` (`networkPolicy.egress.https.toCIDRs`), which covers the endpoint. If your team narrows `toCIDRs`, include the VPC CIDR, or at least the endpoint's network interfaces in each subnet, besides the API server and the other AWS endpoints kubesentry uses.

### 3.6 Helm values

```yaml
incidents:
  enabled: true
  investigator:
    enabled: true
    provider: bedrock            # the default
    acknowledgeDataEgress: true
    bedrockAPI: mantle           # or runtime, with model: us.anthropic.claude-opus-5-5
    # region: us-east-1          # default eks.region
    # endpoint: ""               # only without private DNS (3.3)
    # settings: locked           # GitOps: these values only; the Settings page is read-only
rbac:
  viewerRoles:
    investigator:
      aggregateTo: []            # bind <release>-investigator to the people who may start runs
```

The region is `incidents.investigator.region`, else `eks.region` (`-aws-region`), else `AWS_REGION`. Credentials are resolved when the settings are applied: with the investigator on in the chart, at startup (without them the server stops with an error rather than failing on the first run); when an admin turns it on in Settings, at the save (which is refused without them).

### 3.7 Verify

1. **Try the demo first.** `go run ./cmd/demo`, open an incident, press **Investigate**: the same UI and checks with a scripted model and no egress.
2. **Startup log.** The server logs a warning `AI investigator on: investigations send redacted incident data to the model provider` with `provider=bedrock`, the model, `region`, `bedrockAPI` and the fallback.
3. **`/info`.** `GET /api/v1/info` shows `"investigator": {"enabled": true, "provider": "bedrock", "model": "anthropic.claude-opus-5-5", "effort": "high", "perHour": 10}`.
4. **DNS.** From a pod in the cluster, the Bedrock hostname resolves to private addresses in the VPC.
5. **A test run.** As someone bound to `<release>-investigator`, start an investigation of a small, resolved incident. `kubesentry_llm_requests_total{provider="bedrock",code="200"}` rises and the run completes. A `403` names the missing IAM action or model access; a timeout usually means the endpoint's security group or the NetworkPolicy.

### 3.8 Keep it private: checklist

- [ ] Interface VPC endpoint for `bedrock-mantle` (or `bedrock-runtime`) in the nodes' private subnets.
- [ ] Private DNS on, so no `endpoint` override and no public hostname resolution to the internet.
- [ ] No public egress needed: the investigator needs no NAT or internet route; with `networkPolicy.egress`, its 443 traffic stays inside the VPC CIDR.
- [ ] Endpoint policy limited to kubesentry's role and the model (and inference-profile) ARNs.
- [ ] Role policy limited to the inference action of the chosen API and the models.
- [ ] CloudTrail logs the Bedrock calls kubesentry's role makes; keep the trail, and check in the Bedrock documentation whether your API's inference calls are management or data events (data events must be enabled on the trail).

## 4. Alternative: the Anthropic API

`provider: anthropic` calls `https://api.anthropic.com` with an API key. The key comes only from the `ANTHROPIC_API_KEY` environment variable; the chart sets it from a Secret you create:

```bash
kubectl -n kubesentry create secret generic kubesentry-anthropic --from-literal=api-key="$ANTHROPIC_API_KEY"
```

```yaml
incidents:
  investigator:
    enabled: true
    provider: anthropic
    acknowledgeDataEgress: true
    existingSecret: kubesentry-anthropic
    # apiKeyKey: api-key
```

The chart refuses `provider: anthropic` without `existingSecret`. The pod needs egress on 443 to `api.anthropic.com` (an egress proxy through `HTTPS_PROXY` in `extraEnv` works). `endpoint` points at a proxy in front of the API. Outside the chart: `-investigator=anthropic -investigator-egress-ack=true` with `ANTHROPIC_API_KEY` set.

## 5. Using it

On an incident page, **Investigate** sits beside **Download bundle**. Before the first run of an incident it shows what is sent and where. Pressing it starts a run:

- **While it runs** the panel lists the steps, one line each: each model turn, each tool call with what it read (`get_logs checkout-web-… error 12:01–12:20 UTC: 48 lines`) and its result shape (done, not permitted, invalid input, failed). The starter can **Cancel**. The page asks every 2 seconds.
- **The report**: the outcome (root cause identified, likely cause or inconclusive) and the confidence (high, medium, low, shown as a word and a three-dot meter), the summary, the root cause, contributing factors, timeline, impact, suggested checks, remediation ideas, open questions and data gaps.
  - **Evidence buttons** under each claim: a signal or event highlights its line in "What happened" and moves the crosshair to it; a log line narrows the logs to its pod and container and selects two minutes either side; a log pattern searches the logs for it; a metric selects two minutes either side of its peak on the charts; an audit or CloudTrail record opens in place.
  - **Timeline times** select two minutes either side on the charts, lanes and logs.
  - Refs the model was never shown are plain text marked **not verified**.
  - A suggested command that was not read-only is removed: its description stays, with "Command removed: it was not read-only".
  - Sections left out are listed, for example "Logs: not permitted for you".
  - The last line gives turns, tool calls, tokens and the model (and which turns a fallback model answered).
- **Declined**, **failed** and **cancelled** runs say so, with the reason and the steps.
- **Cached**: pressing Investigate again on an incident whose input has not changed (in practice a resolved incident) answers within a second from the earlier run: "From an earlier run at …". **Run again** asks the model anew.
- **Runs of this incident** lists the earlier runs you may read; choose one to show it.

The report is plain text: no markdown, no HTML, no links. Nothing it contains is loaded or opened automatically.

The API is in [docs/contracts.md](contracts.md) ("AI investigator"): `POST /api/v1/incidents/{id}/investigations` (`{"fresh": true}` skips the cache), `GET …/investigations`, `GET …/investigations/{iid}`, `POST …/investigations/{iid}/cancel`.

## 6. Permissions

- **Starting a run** needs the incident to be visible, then `create` on `investigations.kubesentry.io` (a virtual resource) in the incident's namespace; node and cluster incidents need it cluster-wide. The chart's role is `<release>-investigator`; aggregate it with `rbac.viewerRoles.investigator.aggregateTo` or bind it per namespace. The UI shows the button when `/info` reports the investigator and the `investigate` capability.
- **What a run may read is frozen at start**: the starter's pod logs (`get pods/log`), audit (`ViewAudit`, or cluster audit for node incidents), CloudTrail and nodes. A tool the starter lacks answers "not permitted" without reading its source, and the section is listed as left out. A permission revoked during a run (at most `-investigator-timeout`) is not seen.
- **Reading a run** needs the incident to be visible and every access the run used. Others do not see it; the list says how many runs are hidden.
- **Cancelling** is for the starter only.

## 7. Budgets, limits, caching and cost

| Limit | Flag (default) |
|---|---|
| Model turns per run | `-investigator-max-turns` (16), then one turn to report and a final turn without tools |
| Tool calls per run | `-investigator-max-tool-calls` (24) |
| Tokens per run, every kind summed | `-investigator-max-tokens` (1,500,000) |
| Output tokens per turn | `-investigator-max-output-tokens` (16,000) |
| Run time | `-investigator-timeout` (10m) |
| Runs one person may start per hour | `-investigator-per-hour` (10) |
| Runs everyone may start per hour | `-investigator-per-hour-total` (60) |
| Runs one replica runs at once | `-investigator-concurrency` (2) |

One run per incident runs at a time. The quotas count stored runs, so with Postgres they hold across replicas. When a budget runs out, the model gets one turn to report with what it has; a run that still has no valid report fails with `budget: …`.

**Caching.** A completed run answers a new start with the same input for 24 hours: the same digest (without its timestamp), model, effort, prompt version and access. Cached answers make no model call and do not count against the quotas. Open incidents change as time passes, so they rarely hit the cache.

**Cost.** Tokens are stored per run, shown on the run, and exported as `kubesentry_investigation_tokens_total{provider,model,kind}`. The system prompt, tools and the conversation so far are cached by the provider between turns, so most input tokens of later turns are cache reads. A first estimate is about $1.5 to $3 per run at effort `high`; **measured figures follow in M8** (one real run per backend).

**Storage.** With Postgres, runs are kept with their incident (deleted with it). With the memory store, the newest 1,000 runs are kept, and runs are lost on restart.

## 8. Security model

- **Untrusted data.** Log lines, event messages, titles, audit and CloudTrail records can be written by anyone who can write a log line or name a resource. They reach the model only inside the digest or tool results, JSON-encoded inside `<untrusted>` markers, and the system prompt tells the model to treat them as evidence, never as instructions.
- **Read-only tools.** There is no tool that writes, calls the network, or reaches outside the incident. A prompt injection can at worst make the model read more of the same incident or write a misleading report.
- **The command check.** Every suggested command is parsed as a shell would parse it and must be one of: `kubectl get|describe|logs|top|events|explain|auth can-i|rollout history|rollout status|api-resources|version`, `cmctl status`, `helm status|history|get`, `aws <service> describe-*|get-*|list-*|lookup-*`, with display flags only. Operators, expansions, globs, redirections, `--server`, `--kubeconfig`, `--token`, `--endpoint-url`, file inputs and downloads are refused, and such a command is removed. Still review every command: a read-only command can still read something sensitive with your credentials.
- **Plain-text rendering.** The UI renders the report as React text: no markdown, no `innerHTML`, no clickable URLs. Refs are in-app buttons.
- **Verified refs.** Citations the run never showed the model are marked not verified.
- **Redaction is best effort** (section 2), and the stored evidence index and steps are redacted the same way.
- **Logging.** Each start writes one log line (identity, incident, provider, model, run). Prompts, tool results and response bodies are never logged; provider errors keep only the status and error type.

## 9. Refusals and the fallback model

Claude's safety classifiers can decline a request, for example when a log line quotes something that looks like an attack. `-investigator-fallback` (`incidents.investigator.fallback`) decides what happens:
- `auto` (default): on the Anthropic API, the API's server-side fallback answers the declined turn with its default fallback model; on Bedrock, the SDK retries the turn on Claude Opus 5 (`anthropic.claude-opus-5`, or the same inference-profile prefix as the model). An inference-profile ARN has no automatic fallback.
- a model ID: that model answers declined turns.
- `off`: a declined turn ends the run as **declined**, with the refusal's category and explanation.

The run's steps note each turn a fallback model answered, and the report's last line names it.

## 10. Flags and Helm values

| Flag | Helm (`incidents.investigator.`) | Default |
|---|---|---|
| `-investigator` | `enabled`, `provider` | `off`; chart `provider: bedrock` |
| `-investigator-settings` | `settings` | `ui` (`locked`: Helm only, the Settings page read-only) |
| `-investigator-default-provider` | `provider` while `enabled: false` | `bedrock` (the provider Settings starts from) |
| `-investigator-egress-ack` | `acknowledgeDataEgress` | false (required with `-investigator`; otherwise turning it on in Settings asks the admin) |
| `-investigator-model` | `model` | `claude-opus-5-5`; Bedrock `anthropic.claude-opus-5-5` |
| `-investigator-effort` | `effort` | `high` (`low`, `medium`, `high`, `xhigh`, `max`) |
| `-investigator-region` | `region` | `-aws-region` (`eks.region`), then `AWS_REGION` |
| `-investigator-bedrock-api` | `bedrockAPI` | `mantle` |
| `-investigator-endpoint` | `endpoint` | none |
| `-investigator-fallback` | `fallback` | `auto` |
| `-investigator-timeout` | `timeout` | 10m (1m to 1h) |
| `-investigator-max-turns`, `-max-tool-calls`, `-max-tokens` | `limits.maxTurns`, `limits.maxToolCalls`, `limits.maxTokens` | 16, 24, 1,500,000 |
| `-investigator-max-output-tokens` | none | 16,000 |
| `-investigator-digest-bytes` | none | 65,536 |
| `-investigator-per-hour`, `-per-hour-total`, `-concurrency` | `limits.perHour`, `limits.perHourTotal`, `limits.concurrency` | 10, 60, 2 |
| `ANTHROPIC_API_KEY` (environment) | `existingSecret`, `apiKeyKey` | none, `api-key` (mounted whenever `existingSecret` is set) |

With `settings: ui` (the default) the flags are the starting values: an admin's changes on the Settings page win over them field by field and are applied live by every replica (each reads the stored version every 15 seconds; the saving replica at once). The chart passes the investigator's values even while `enabled: false`, so the page starts from them. `rbac.viewerRoles.settingsAdmin.aggregateTo` (default `[]`) aggregates `<release>-settings-admin` (`update settings.kubesentry.io`).

The investigator also needs `-incidents` (`incidents.enabled`). The chart refuses it without the acknowledgement, without incidents, and with `provider: anthropic` but no Secret. Metrics: `kubesentry_investigations_total{provider,result}`, `kubesentry_investigations_running`, `kubesentry_investigation_duration_seconds`, `kubesentry_investigation_tokens_total`, `kubesentry_investigation_tool_calls_total{tool,result}`, `kubesentry_llm_requests_total{provider,code}`.

## 11. Troubleshooting

| What you see | Why, and what to do |
|---|---|
| No Investigate button | `/info` has no `investigator` (it is off, or `-incidents` is off), or you lack the `investigate` capability: bind `<release>-investigator`. An admin may turn it on in Settings. |
| No Settings in the sidebar | You lack `update settings.kubesentry.io` cluster-wide: bind `<release>-settings-admin`. |
| "Locked by Helm" on the Settings page | `incidents.investigator.settings: locked`: change the chart's values instead. |
| Settings: "changed by someone else" | Another admin saved first (the version moved): reload and apply your change again. |
| Settings: "could not be applied" | The settings could not be built on this replica, for example Bedrock credentials that do not resolve: run Test connection and follow its hint. Nothing was stored. |
| Settings: "Not applied on this replica" | Another replica saved settings this one cannot build; it keeps what it ran before and retries every 15 seconds. |
| "You may not investigate this incident" | You can see the incident but lack `create investigations.kubesentry.io` in its namespace (cluster-wide for node incidents). |
| "You have started 10 investigations in the last hour…" | The per-person quota; the message says when to try again. "Everyone together…" is the total quota. Cached answers are free. |
| "This server is running as many investigations as it may" | `-investigator-concurrency` runs are busy on this replica, or it is shutting down; try again in 30 seconds. |
| "An investigation of this incident is already running" | One run per incident; the page shows the running one. |
| Declined by the model | A safety classifier declined. With `fallback: off`, turn the fallback on; otherwise the fallback model declined too. Look at the steps for the tool result that preceded it. |
| Failed: "budget: tool calls" (or turns, tokens) | The model kept reading without reporting; raise `limits.*`, or start again (another run may take another path). |
| Failed: "timeout" | The run took longer than `-investigator-timeout`; effort-high turns can take a minute each. Raise `timeout` or lower `effort`. |
| Failed: "interrupted" | The replica running it stopped (deploy, eviction) or lost its heartbeat for 2 minutes. Start it again. |
| Failed: "HTTP 403 permission" | Bedrock: the role lacks the inference action, the endpoint policy refuses it, or model access is not granted in the region. Anthropic: the key is invalid. |
| Failed: "HTTP 404 not found" | The model ID is unknown in the region, or with `runtime` it needs an inference profile. |
| Failed: "HTTP 429 …" / "HTTP 529 overloaded" | The provider throttled or was overloaded after the SDK's retries; try later, or raise your Bedrock quotas. |
| Failed: "model request failed" | No connection: check the VPC endpoint, private DNS, its security group and the NetworkPolicy (or the route to `api.anthropic.com`). |
| "Logs: not permitted for you" | You may not read pod logs in the namespace, so the run did not read them either. |
