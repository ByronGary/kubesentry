# kubesentry: notes for Claude Code

Open-source, standalone Kubernetes dashboard. Four features that Headlamp lacks: audit-log user activity, OOMKilled and memory-leak detection, process monitoring, unused PVC detection. UI is modelled on headlamp-kubevirt's "VM Doctor": a per-pod diagnostic page. Read README.md for flags, API and security notes.

## First steps on a new machine
1. `go mod tidy`. client-go could not be downloaded where this was written, so `internal/kube` and `cmd/server` have never been compiled against the real library. Expect to fix small compile errors there.
2. `go test ./...`, then `cd web && npm install && npm test && npm run build`.
3. `go run ./cmd/demo` shows every feature with synthetic data, no cluster needed.

## Status
Done: architecture map (app topology + node view), workloads, storage, security posture (pod security, RBAC, PSA labels, exposure), cert-manager page (2026-10); PVC, OOM, leak detectors; Prometheus client; audit ingestion (webhook, file tail, bulk import, journal); JSON API; embedded React UI (Findings, Pods, pod page, Memory, Volumes, Activity); demo mode; process agent (`cmd/agent`, `internal/procmon`, DaemonSet manifest).
Next, in rough order: process history and per-process memory trend (name the leaking child process in leak findings); alerting on tagged audit events; native CloudWatch polling for EKS; persistent store (SQLite/Postgres); shared informers instead of per-request LISTs; real container image and Helm chart; CI.

## Conventions
- Module path is `github.com/ByronGary/kubesentry` (repo https://github.com/ByronGary/kubesentry).
- Commits in this project carry no Claude co-author or "Generated with Claude" trailer.
- Only `internal/kube` imports client-go. Everything else is stdlib, so tests need no cluster. Keep it that way.
- Detectors work on plain `internal/model` types.
- Endpoints that accept pushed data (`/audit/webhook`, `/agent/report`) fail closed with 503 until their token is set. `/api/` routes use `-api-token`. Default listen is 127.0.0.1.
- Names reaching PromQL are validated (DNS-1123) and quoted. Audit bodies are never decoded. Agent never reads environ and redacts command lines.
- UI: system fonts only (works air-gapped), hash routing, status never by colour alone (shape plus label), light/dark via CSS variables. Built output in `internal/web/dist` is committed and embedded with go:embed; rebuild with `npm run build` after UI changes.
- Frontend logic lives in testable pure modules (`format.ts`, `chartMath.ts`, `findings.ts`, `mapLayout.ts`, `inventory.ts`).
- Contract for the inventory pages (Map, Workloads, Storage, Security, Certificates): Go output types in `internal/detectors/inventory.go` and responses in `internal/api/inventory.go` are mirrored in `web/src/types.ts`; change them together. Findings in system namespaces or about built-in `system:`/`kubeadm:` RBAC are marked `system` and hidden by default.
- Verified 2026-10-11: `go test -race ./...` (including client-go fakes in internal/kube); vitest 59 tests; the new pages checked in headless Chromium against the demo in light, dark and 390px width.
