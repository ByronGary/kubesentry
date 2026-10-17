# Proposal: an in-house AI SRE agent

Status: proposed 2026-10-17. Builds on the AI investigator (`docs/contracts.md`, "AI investigator", milestones M5–M8). Starts after M7 is merged; M8's real-provider numbers (latency, tokens, cost per run) set its budgets.

## Summary

The investigator explains one incident from the data kubesentry already holds. The SRE agent widens that in two directions:

1. **What it reads.** It adds ArgoCD (application health, sync status and history, and the difference between Git and the live cluster), Helm releases (through ArgoCD or Git), and the Git repository at the revision that is deployed (manifests, charts, values, Dockerfiles, application code).
2. **What it produces.** Besides a diagnosis, it suggests a **fix as a diff** against that repository. With a Git token configured, a person can turn the diff into a **draft pull request** with one click. kubesentry never merges, and never writes to the cluster; ArgoCD applies the change only after a person merges it.

It is the same agent, not a second system. It reuses the investigator's:
- tool framework, scoped to the caller's own permissions;
- egress filter and redaction;
- budgets and quotas;
- prompt-injection handling and report validation;
- Claude backends: the Anthropic API or Amazon Bedrock, through the official Go SDK in `internal/llm`.

## Decisions taken (2026-10-17)

| Topic | Decision |
|---|---|
| Fixes | Shown as diffs in the UI. Draft PRs are opt-in: they need a configured Git token and a person clicking "Open draft PR". Never auto-merge; never a cluster write |
| Git host | GitHub (the deploy-time scans also run in GitHub Actions) |

## Triggers

| Trigger | Example | Scope |
|---|---|---|
| An incident | the existing Investigate button | the incident's workload, window and namespace |
| An alert | "Investigate" on an Alerts page row | the finding's object and its workload root |
| A question | "Why is checkout OutOfSync?", "Review the shop namespace's charts" | a namespace or an ArgoCD application the caller can see |
| A scan finding | "Fix this" on a `kubesentry scan` finding (see `deploy-security-scans.md`) | the file and line the scanner reported |

## New read-only sources

**ArgoCD.**
- **Application objects** (`argoproj.io/v1alpha1` `Application`, `ApplicationSet`) through a dynamic informer in `internal/kube`, as cert-manager's are read today:
  - health and sync status;
  - operation state and sync history (revision, time, initiator);
  - source repo, path, target revision, Helm value files and parameters;
  - the managed resources with their status.

  This needs only `list/watch` on those resources, and no ArgoCD credentials.
- **The diff between Git and the live cluster** needs ArgoCD's own API (`/api/v1/applications/{name}/managed-resources`). It is optional, with a read-only ArgoCD account (`applications, get`). Without it, the agent sees "OutOfSync" and which resources, but not the field-level diff.

**Helm.**
- **For releases ArgoCD manages:** the chart, version and values come from the Application and the repo.
- **For plain `helm install` releases:** the release name and chart come from the labels and annotations Helm puts on every object (`helm.sh/chart`, `meta.helm.sh/release-name`), which the informer transform would keep.
- **Helm's release Secrets are never read.** Reading them needs `get secrets`, and they hold rendered values, which often include credentials.

**Git (GitHub).**
- **Calls:** the GitHub REST API over plain HTTP from a new stdlib package `internal/gitprovider/github`: contents, trees, commits, compare, and code search within allowed repos.
- **Repo for a workload, in this order:**
  1. its ArgoCD Application's source;
  2. an annotation `kubesentry.io/source-repo` (`owner/repo[/path][@ref]`) on the workload or its namespace;
  3. the OCI image label `org.opencontainers.image.source`, when the scan feature has recorded it.
- **Allowed repos:** only repos on an allowlist (`-sre-repos`, globs per org). Everything read from a repo is untrusted data, like logs.

## New tools (added to the investigator's eight)

| Tool | Reads | Gate |
|---|---|---|
| `get_argocd_app` | health, sync, history, sources, managed resources | `get applications.argoproj.io` in the app's namespace (the caller's own RBAC, by SubjectAccessReview) |
| `get_argocd_diff` | field-level Git vs live diff for one resource | as above, plus the ArgoCD API configured |
| `get_helm_release` | chart, version, values file names, revision history (from ArgoCD or labels) | namespace visibility |
| `list_repo_files` / `read_repo_file` | a directory listing, or one file at the deployed revision, capped at 64 KiB | the repo on the allowlist, plus a new virtual capability `get repos.kubesentry.io` |
| `search_repo` | code search in one allowed repo | as above |
| `repo_history` | commits touching a path between two revisions (what changed since the last good sync) | as above |
| `propose_change` | submits a fix: unified diff, rationale, risk, rollback note | ends the run with a report that carries a patch |

Every tool keeps the investigator's rules:
- the caller's access is frozen at start;
- answers are capped, redacted and passed through the egress filter;
- cluster and repo content is wrapped as untrusted;
- a tool the caller lacks answers "not permitted" without reading anything.

## Suggested fixes

**Validation before the UI shows a patch.**
1. **It must apply.** It applies cleanly to the file contents at the deployed revision (an in-memory patch apply, no checkout).
2. **Path limits.** It changes at most `-sre-max-files` (10) files and 400 lines. It touches only allowed paths. These are always refused:
   - `.github/**` and other CI definitions;
   - `CODEOWNERS`;
   - `**/*.pem`, `**/*.key`;
   - anything matching `-sre-deny-paths`.

   A fix that edits a workflow could run code with the repository's secrets.
3. **No secrets.** It adds no secret: the diff goes through the redaction rules and the secret scanner from `deploy-security-scans.md`.
4. **Renders.** Changes to manifests or charts must still render (`helm template` / `kustomize build` against the same values, run in a sandboxed subprocess with no network). They are linted with kubeconform and with `kubesentry scan`'s config rules, so the agent's own fix is checked by the same gate as everyone else's.

A patch that fails any check is shown with the reason, and the "Open draft PR" button is disabled.

**Draft pull requests (opt-in).**
- **Who and how:**
  - "Open draft PR" is a human action, gated by a new capability `create pullrequests.kubesentry.io`.
  - kubesentry creates branch `kubesentry/<incident-or-finding-id>`, commits the validated patch, and opens a **draft** PR.
  - The PR body holds the diagnosis, the evidence refs, who asked, the model, and a note that kubesentry does not merge.
- **Credentials:** a GitHub App installed on the allowed repos (preferred: per-repo, short-lived tokens, a bot identity), or a fine-grained token with `contents:write` and `pull_requests:write` on those repos only. Without one, the button is hidden and the diff can be copied or downloaded.
- **Branch protection, review rules and CODEOWNERS** apply as for any PR. kubesentry never pushes to the default branch and never merges.

## Proactive reviews (phase 2)

Opt-in, scheduled like the standing digests, per owner. The agent reviews each owner's applications for:
- OutOfSync or degraded apps;
- charts without resource requests or probes;
- images on `latest`;
- findings that keep recurring.

It produces one report per owner, with suggested diffs. These are never opened as PRs automatically.

## Data egress and safety

- **Source code leaves the cluster.** Reading application code sends it to the model provider. A separate opt-in, `-sre-read-code` (default: manifests, charts and values only), and the per-repo allowlist keep that explicit. Bedrock in the user's own AWS account keeps the data inside it.
- **Prompt injection:**
  - Repos, logs and ArgoCD messages are untrusted.
  - The agent cannot run anything: no shell, no network beyond the listed read-only tools.
  - Patches are checked by rules, not by trust.
  - CI files are off limits.
  - A person reviews every PR.
- **Audit:** every run and every PR is recorded with the requesting identity, the model, the repos read and the files changed.

## Architecture

| Package | Role | Dependencies |
|---|---|---|
| `internal/investigate` | grows the tool set, adds `propose_change` and patch validation | stdlib |
| `internal/gitprovider`, `internal/gitprovider/github` | `Repo` interface (read file, list, search, history, create branch/commit/draft PR) and the GitHub REST client | stdlib (`net/http`, JWT signing for the GitHub App with `crypto`) |
| `internal/kube` | ArgoCD Application/ApplicationSet informers; keep Helm's labels and annotations | client-go (already) |
| `internal/argocd` | optional ArgoCD API client for diffs | stdlib |
| `internal/patch` | unified-diff parse and apply, path rules | stdlib |
| render sandbox | `helm template`, `kustomize build`, kubeconform as subprocesses with a timeout, no network, a temp dir | external binaries in the image (optional) |

## Phasing

| Phase | Delivers |
|---|---|
| A | ArgoCD informers and `get_argocd_app` / `get_helm_release`; alerts and questions as triggers; the Ask box on namespace and app pages |
| B | GitHub read tools, repo mapping, `propose_change` with patch validation; diffs in the UI |
| C | Draft PRs through a GitHub App; the `pullrequests` capability; PR audit |
| D | Render-and-lint validation, the ArgoCD diff API, proactive reviews |

## Open questions

1. **GitHub App or fine-grained token?** The App is recommended for an organisation.
2. **Should the agent read application code** (`-sre-read-code`), or stay with manifests, charts and values to begin with?
3. **ArgoCD API access for field-level diffs.** Is a read-only ArgoCD account acceptable?
4. **Proactive reviews:** wanted, and how often?
5. **Who may open PRs:** the same people who may investigate, or a narrower group?

## Risks

- **Cost:** wider context costs more tokens per run (repo files are large). Budgets come from M8's measurements, and file reads are capped.
- **Suggestions that look right and are wrong.** Validation proves a patch applies and renders, not that it is correct. Reviews stay human.
- **Repo mapping** fails for workloads without ArgoCD or annotations; the agent then says so and stays diagnostic.
- **GitHub API rate limits** (code search especially) on large organisations.
- **ArgoCD versions** differ in API shape; only the Application CRD fields are relied on in phase A.
