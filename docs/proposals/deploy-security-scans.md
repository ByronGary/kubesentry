# Proposal: deploy-time security scans

Status: proposed 2026-10-17. A separate feature from the dashboard. It shares the policy language, the report format and the AI agent (`ai-sre-agent.md`).

## Summary

`kubesentry scan` checks code, images and Kubernetes manifests before they are deployed, and fails the deploy on serious findings. It runs in two places:

1. **GitHub Actions.** It scans the repository, the image the workflow built, and the rendered manifests or chart. Results go to the pull request and to GitHub code scanning, and a signed attestation of a passing scan is attached to the image.
2. **ArgoCD PreSync hook.** Before ArgoCD applies a revision, a short Job checks that every image the revision deploys has a passing scan attestation, and re-scans those images for vulnerabilities published since they were built. If it fails, the sync stops.

kubesentry does not write its own vulnerability scanners. It runs proven open-source ones and adds:
- one policy for all of them;
- baselines and suppressions with a reason;
- one report;
- the pass/fail decision;
- a dashboard view of what is actually running;
- the AI agent, which explains a finding and suggests the fix.

The dashboard itself stays notify-only. Blocking happens in the pipeline and in ArgoCD, by the exit code of a Job those tools run; kubesentry never adds an admission webhook.

## Decisions taken (2026-10-17)

| Topic | Decision |
|---|---|
| Where | GitHub Actions and an ArgoCD PreSync hook (no GitLab CI, no admission webhook) |
| On findings | Fail on critical and high findings, and on any secret. Lower findings are reported. Baselines and suppressions need a reason |
| "IP" leaks | Both hardcoded IP addresses (and internal hostnames and URLs) and intellectual property |

## What it checks

| Check | Engine | Fails by default |
|---|---|---|
| **Secrets** in the repo (including history on the first run), in image layers and in rendered manifests: cloud keys, tokens, private keys, passwords in config, `.env` files | gitleaks (repo history), Trivy (image layers, files), kubesentry's redaction rules | any |
| **Vulnerabilities** in OS and language packages of the image, and in lock files in the repo | Trivy | critical, high (fixed versions available) |
| **Kubernetes and Helm misconfiguration**: privileged or root containers, host namespaces, no resource limits, `latest` tags, missing probes, writable root filesystem, Ingress without TLS, Services of type LoadBalancer without the internal annotation | Trivy config rules plus kubesentry's own checks (the same ones the Security page uses) | critical, high |
| **Dockerfile** problems: running as root, `ADD` from URLs, secrets in `ENV`/`ARG` | Trivy config rules | high |
| **Web and form flaws** in application code: XSS sinks (`innerHTML`, `dangerouslySetInnerHTML`), SQL and command injection, form handlers without CSRF protection, forms posting over `http://`, open redirects, `CORS: *` with credentials, keys in front-end environment variables (`NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*`) | Semgrep-compatible engine with kubesentry's rule pack | high |
| **Hardcoded IP addresses and internal endpoints**: private ranges (10/8, 172.16/12, 192.168/16, 100.64/10), the cloud metadata address 169.254.169.254, internal domains from the policy (e.g. `*.corp.example.com`, `*.internal`, `*.svc.cluster.local`) | kubesentry rules (in code and images; manifests are allowed cluster DNS names) | in public artifacts (web bundles, images served to clients); reported elsewhere |
| **Intellectual property** | see below | per rule |

**Intellectual property.**
- **Licences:** packages in the image and the repo, classified by Trivy. The policy has allow and deny lists, for example denying AGPL and GPL in images that are shipped to customers. Unknown licences are reported.
- **Source that shouldn't ship:**
  - source maps (`*.map`) and unminified source in production web bundles;
  - `.git` directories, editor backups and test fixtures inside images;
  - paths the policy marks internal-only (for example `docs/internal/**`, `research/**`).
- **Confidential markers:** files in shipped artifacts carrying markers from the policy ("CONFIDENTIAL", "Internal use only").
- **Customer and personal data** in fixtures, seeds and images:
  - email addresses outside allowed example domains;
  - phone numbers;
  - card numbers (Luhn-checked);
  - IBANs;
  - national ID formats chosen per region in the policy.

## Policy

A file in the repo, `.kubesentry/scan.yaml`, layered over an organisation default (a URL or a file in a central repo):

```yaml
fail: {severity: high, secrets: any}       # the default decision
artifacts: {public: ["web/dist/**", "image:*/frontend*"]}
internalDomains: ["*.corp.example.com", "*.internal"]
licences: {deny: ["AGPL-*", "GPL-*"], unknown: report}
internalOnly: ["docs/internal/**", "research/**"]
markers: ["CONFIDENTIAL", "Internal use only"]
pii: {regions: [US, EU], allowEmailDomains: [example.com, example.org]}
suppress:                                  # each needs a reason, an owner and an expiry
  - {id: CVE-2026-1234, path: "image:api", reason: "not reachable: no XML parsing", owner: team-shop, until: 2026-12-01}
baseline: .kubesentry/baseline.json        # existing findings; only new ones fail
```

- Suppressions without a reason, or past their expiry, are themselves findings.
- A baseline lets an existing repo adopt the gate: only new findings fail, and the baseline shrinks as findings are fixed.

## Running it

**Packaging.**
- `cmd/kubesentry-scan`: a stdlib Go CLI that orchestrates the scanners as subprocesses (never as Go libraries, which would pull large dependency trees into the module), normalises their output, applies the policy and sets the exit code.
- Image `ghcr.io/byrongary/kubesentry-scan`: the CLI with pinned versions of Trivy, gitleaks, the Semgrep-compatible engine and kubeconform. Multi-arch and signed, like the other images.
- Exit codes:
  - 0: pass;
  - 1: policy failure;
  - 2: the scan could not run (scanner error, vulnerability database unreachable).

**GitHub Actions.**
- An action in this repo, `uses: ByronGary/kubesentry/actions/scan@v<version>`. Typical job steps:
  1. checkout;
  2. build the image;
  3. `kubesentry-scan repo .`;
  4. `kubesentry-scan image $IMAGE`;
  5. `kubesentry-scan manifests` (runs `helm template` / `kustomize build` with the deploy values);
  6. on pass, sign an attestation of the result to the image digest (cosign, keyless through GitHub's OIDC token, or a KMS key).
- Outputs:
  - a summary comment on the PR;
  - SARIF uploaded to GitHub code scanning;
  - the JSON report (`kubesentry.io/scan-report/v1`) as an artifact, optionally posted to the kubesentry server's ingest listener for the dashboard.

**ArgoCD PreSync hook.**
- A Job annotated `argocd.argoproj.io/hook: PreSync`, which the app's chart includes from a snippet kubesentry provides. It gets the image references the revision deploys from the same Helm values.
- For each image it:
  1. verifies a passing scan attestation for that digest and policy;
  2. re-scans for vulnerabilities published since the build, against the same policy and baseline.
- A failed Job stops the sync; ArgoCD shows the Job's log, which names each failing finding.
- Typical run time is seconds for the attestation check and under a minute for an image re-scan with a cached database.
- **Break glass:** an annotation on the Application (`kubesentry.io/scan-bypass: "<reason>"`) lets one sync through. The bypass is logged in the Job output, shows on the dashboard, and raises an audit-activity alert.

## Dashboard and alerts

- **A "Supply chain" view per workload:** the image digests actually running, each image's last scan (from CI reports and PreSync results posted to kubesentry, or from Trivy Operator's `VulnerabilityReport`, `ConfigAuditReport` and `ExposedSecretReport` resources when that operator is installed, read-only), the counts by severity, licence findings, and the scan's age.
- **Images running without a passing scan** are highlighted. They show that a deploy bypassed the gate.
- **New alerts:**
  - `KubesentryUnscannedImage`: a running image with no passing scan;
  - `KubesentryCriticalVulnerabilityDeployed`: a new critical vulnerability with a fix in a running image;
  - `KubesentryScanBypassed`.

  All three follow the phase C rules: owner routing, storm protection, ack and silence.
- **AI agent:** "Explain" and "Fix" on a finding hand it to the SRE agent, which proposes the diff:
  - a dependency or base-image bump;
  - a manifest change;
  - removing a leaked file and rotating the secret (a person rotates; the agent writes the steps).

## Phasing

| Phase | Delivers |
|---|---|
| A | The CLI, policy, secrets, IP, PII, licence and misconfiguration checks; SARIF and JSON reports; the GitHub Action with PR summary |
| B | Image vulnerability scans, signed attestations in CI, the ArgoCD PreSync verify-and-rescan Job, break glass |
| C | Reports posted to kubesentry, the Supply chain view, Trivy Operator resources, the three alerts |
| D | Web and form rule pack; AI explain and fix through the SRE agent |

## Open questions

1. **GitHub code scanning for private repos** needs GitHub's paid code security product. Is it available? Without it, results go to the PR comment, the job summary and the dashboard instead.
2. **Rules for web and form flaws.** Semgrep's own registry rules are under a licence that restricts redistribution. The proposal ships kubesentry's own Apache-2.0 rule pack and lets teams add registry rules themselves. Is that acceptable, or is a licensed Semgrep setup available?
3. **Scanner outage in PreSync** (the vulnerability database unreachable): fail the sync (safest), or pass with a warning and an alert (keeps deploys flowing during an incident)? The proposal defaults to failing in CI and warning in PreSync.
4. **Air-gapped clusters:** is a mirror of Trivy's vulnerability database needed?
5. **Personal-data formats:** which regions' ID and phone formats matter?
6. **Attestation signing:** keyless through GitHub's OIDC (recorded in the public Sigstore log, revealing image names) or a private KMS key?

## Risks

- **False positives** at first, especially PII and IP rules. Baselines, per-path scoping and suppressions with expiry keep adoption practical; the rule pack ships with tests.
- **Scan time** in CI for large images (minutes for the first database download). Caching the database between runs keeps it short.
- **Blocking deploys during an incident.** Break glass plus the PreSync warning mode on scanner outages.
- **Scanner version drift** changes results; the image pins versions and the report records them.
