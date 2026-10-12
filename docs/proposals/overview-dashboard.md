# Scope: an Overview dashboard and sidebar navigation for kubesentry's React UI

Status: scoping draft · 2026-10-11 · for decision. This is not implementation. It covers the Overview dashboard and moving the top tabs into a sidebar menu.

## Why

Today the UI opens on **Findings**: a long list of everything wrong. Ten tabs then go deep on one subject each. What's missing is the one screen that answers, in five seconds: *is the cluster healthy, what needs attention right now, and whose is it?*

The stress runs show the data is already there and cheap to serve: every inventory route answers in under 25 ms at p95 with 500 users. The alerting build adds owners, alert state and history.

The Overview is where those come together. It becomes the landing page, and the place an on-call engineer, a platform admin or a team lead checks first.

## Who it's for

The same RBAC scoping as every other page applies, so one dashboard serves everyone.

| Persona | Sees | Typical question |
|---|---|---|
| Platform admin or on-call (cluster-wide) | everything, grouped by pool and zone and by owning team | "Is anything burning? Is the control plane or monitoring itself degraded?" |
| Team member (a few namespaces) | only their namespaces; cluster tiles degrade to "not visible to you" | "Is my stuff OK? What do I need to fix this week?" |
| Security reviewer (cluster viewer + audit) | posture and sensitive activity | "Any new cluster-admin bindings, exec into production, or secret reads?" |

## What's on it

### Wireframe (desktop: sidebar plus content; on a phone the sidebar becomes a drawer and tiles stack)

```
┌──────────────────────┐┌───────────────────────────────────────────────────────────────────────────────┐
│ ◆ kubesentry      «  ││ kind-kubesentry · EKS 1.36 · us-east-1        Data 2s old ● · Prometheus ● ·   │
│ kind-kubesentry      ││ Scope: All namespaces ▾  Owner: All teams ▾    Postgres ● · CloudWatch lag 34s │
│──────────────────────│├──────────────┬──────────────┬──────────────┬──────────────┬───────────────────┤
│ ▣ Overview        ●  ││ Nodes        │ Pods         │ Workloads    │ Certificates │ Security          │
│ ⚑ Alerts        7 ✕ ││ 506 ▲ 0 ✕    │ 9,542 run    │ 2,494        │ 117 < 14d ▲  │ 3 crit ✕          │
│                      ││ 3 pools ·    │ 2 pending    │ 4 unhealthy  │ 9 not ready ✕│ 41 warn ▲         │
│ CLUSTER              ││ 3 zones      │ 3 failing ✕  │ ▁▂▁▁▃▂ 24h   │              │ +1 since 24h      │
│   Map                │├──────────────┴──────────────┴──────────────┼──────────────┴───────────────────┤
│   Workloads     4 ▲  ││ Needs attention (top 10, worst first)      │ Capacity by pool                 │
│   Pods          3 ✕  ││ …                                          │ …                                │
│   Nodes              ││                                            │                                  │
│   Agents             ││                                            │                                  │
│ HEALTH               ││                                            │                                  │
│   Findings     12 ✕  ││                                            │                                  │
│   Memory        1 ▲  ││                                            │                                  │
│   Storage            ││                                            │                                  │
│ SECURITY             ││                                            │                                  │
│   Security      3 ✕  ││                                            │                                  │
│   Certificates  9 ✕  ││                                            │                                  │
│   Activity           ││                                            │                                  │
│──────────────────────││                                            │                                  │
│ alice@corp ▾  ◐ theme││                                            │                                  │
└──────────────────────┘└───────────────────────────────────────────────────────────────────────────────┘
```

The content area alone:

```
┌───────────────────────────────────────────────────────────────────────────────┐
│ kind-kubesentry · EKS 1.36 · us-east-1        Data 2s old ● · Prometheus ● ·   │
│ Scope: All namespaces ▾  Owner: All teams ▾    Postgres ● · CloudWatch lag 34s │
├──────────────┬──────────────┬──────────────┬──────────────┬───────────────────┤
│ Nodes        │ Pods         │ Workloads    │ Certificates │ Security          │
│ 506 ▲ 0 ✕    │ 9,542 run    │ 2,494        │ 117 < 14d ▲  │ 3 crit ✕          │
│ 3 pools ·    │ 2 pending    │ 4 unhealthy  │ 9 not ready ✕│ 41 warn ▲         │
│ 3 zones      │ 3 failing ✕  │ ▁▂▁▁▃▂ 24h   │              │ +1 since 24h      │
├──────────────┴──────────────┴──────────────┼──────────────┴───────────────────┤
│ Needs attention (top 10, worst first)      │ Capacity by pool                 │
│ ✕ crit  payments/checkout  CrashLoop ×3    │ ng-general  CPU ███████░ 82%    │
│         owner: team-payments · 14m         │             Mem █████░░░ 61%    │
│ ✕ crit  billing-01/api-tls  expires in 1d  │ karpenter   CPU ████░░░░ 48%    │
│ ▲ warn  shop/web  leak: OOM in ~6h         │ fargate     4 pods (not metered)│
│ ▲ warn  tax-05  internet-facing LB (new)   │ zone a/b/c  ███ ███ ██          │
│ … see all in Findings →                    │                                  │
├────────────────────────────────────────────┼──────────────────────────────────┤
│ Sensitive activity (last 24h)              │ Cost and waste                   │
│ exec into production  2  ·  secret reads 14│ Unused PVCs 41 · $312/month      │
│ RBAC changes 6 · denied bursts 1           │ Billed by usage (EFS/FSx): 3     │
│ latest: alice exec prod/api-7f… 3m ago →   │                                  │
├────────────────────────────────────────────┴──────────────────────────────────┤
│ Alerts (after alerting phase B): open 7 · acknowledged 2 · silenced 1 · by team│
└───────────────────────────────────────────────────────────────────────────────┘
```

Status is never shown by colour alone: shape plus label (✕ crit, ▲ warn, ● ok), as everywhere else in the UI.

### Widgets and their data sources
All of these come from the snapshot view and stores that already exist. No extra Kubernetes API calls are needed.

| Widget | Source today | Notes |
|---|---|---|
| Health strip (data age, Prometheus, Postgres, CloudWatch lag, agents) | `/info` (snapshot, unavailable, auditStore), ops health | Reuses the staleness and Prometheus notices |
| Nodes tile | nodes summary + placement | ready / not ready / cordoned, pools and zones. Degrades without `nodes` capability |
| Pods tile | pod summaries | running / pending past grace / failing (CrashLoop, ImagePull, Evicted, OOM) |
| Workloads tile | workload summaries | unhealthy count, with a sparkline (see History) |
| Certificates tile | cert summaries | expiring under 14d, not ready, issuer missing |
| Security tile | security findings + posture | crit and warn counts, plus "new since 24h" (needs History) |
| Needs attention | the same ranking as Findings, folded per workload by association | top 10, with owner (namespace annotation `kubesentry.io/owner`, from the alerting decisions) and age |
| Capacity by pool and zone | node summaries (requested vs allocatable) | scoped totals already handled; Fargate shown as "not metered" |
| Sensitive activity | audit summary + tag counts (exec, secret-access, rbac-change, denied, impersonate) | "production" follows the `environment=production` label decision. Needs `audit` capability |
| Cost and waste | unused PVCs + pricing | "billed by usage" for EFS/FSx; only priced items summed |
| Alerts | alerting phase B findings store | placeholder until then |

### Filters
- **Scope:** all visible namespaces, or one namespace. **Owner:** all teams, or one team, from the owner annotation.
- Both are kept in the URL, so a team can bookmark "my team's overview".
- The default is "all I can see".

### History (the one new backend capability)
Sparklines and "new since 24h" need a little history; today the snapshot is point-in-time. Options:
1. **In-process ring buffer (recommended for v1).** After each snapshot build, keep per-namespace counters (unhealthy workloads, failing pods, crit/warn findings, expiring certs) in 5-minute buckets for 24h. That is about 300 namespaces × 8 counters × 288 buckets ≈ 700k integers, a few MB. It is lost on restart, and each replica keeps its own (acceptable for sparklines).
2. **Prometheus.** Expose `kubesentry_findings{check,severity,namespace}` (already planned for alerting phase B) and query it for trends. It survives restarts, but depends on Prometheus being up.
3. **Postgres findings store (alerting phase B).** It gives exact "new since" from first-seen times. That's the most accurate, but it waits for phase B.

Recommendation: ring buffer in v1. Switch "new since 24h" to the findings store once phase B lands.

## API

One aggregate route replaces about 10 page loads:

```
GET /api/v1/overview?namespace=&owner=
→ {
  version, builtAt, ageSeconds,
  health:   { prometheus, auditStore, cloudwatch, agents },        // from /info and ops
  nodes:    { total, ready, notReady, cordoned, pools: [{name, kind, nodes, cpuPct, memPct}], zones: [...] } | null,
  pods:     { running, pending, failing, byReason: {CrashLoopBackOff: n, ...} },
  workloads:{ total, unhealthy, history: [n, ...] },
  certs:    { expiringSoon, notReady, issuerMissing },
  security: { crit, warn, newSince24h, history: [...] },
  attention:[ { severity, kind, namespace, name, title, owner, since, href } ]  // top 10
  activity: { exec, execProduction, secretReads, rbacChanges, denied, latest: [...] } | null,
  waste:    { unusedPVCs, monthlyUSD, usageBilled },
  owners:   [ "team-payments", ... ]          // for the filter, from visible namespaces only
}
```

- **Scoping:** computed from the snapshot view, filtered by the caller's scope like every other route, and memoised per (scope, view version). It goes through the existing response cache and ETag, and is added to the authorization leak test, because aggregates are exactly where leaks hide.
- **Size and speed:** the response stays under 30 KB. Target p95 < 50 ms at 2,000 users, polled every 30 s, with polling paused while the tab is hidden.
- **Contract:** the shapes go in `web/src/types.ts` and `docs/contracts.md`, mirrored from Go.

## UI and navigation: a sidebar replaces the top tabs

**Routes.** Overview becomes `#/`, and Findings moves to `#/findings`. The old link redirects for a release.

**Sidebar layout.** The 10 top tabs, which already scroll sideways below 1280 px, move into a left sidebar with grouped sections:

| Section | Items |
|---|---|
| (top) | **Overview**, **Alerts** (after alerting phase B) |
| Cluster | Map, Workloads, Pods, Nodes (a node view promoted from the Map toggle), Agents |
| Health | Findings, Memory, Storage |
| Security | Security, Certificates, Activity |
| (footer) | the signed-in user (identity menu: groups, recheck access, sign out), theme toggle, version |

**Behaviour:**
- **Badges:** each item can show a count with severity shape (✕ crit, ▲ warn), e.g. "Pods 3 ✕". The counts come from the same `/overview` response, so the sidebar costs no extra requests. Badges respect scope: a team member sees their own counts.
- **Capability gating:** items the caller can't use are hidden, exactly as tabs are today (`access.ts` `visibleNav`). A section with nothing visible disappears.
- **Collapsible:**
  - Sections fold and unfold.
  - The whole sidebar can shrink to an icon rail (« / »). The choice is remembered in localStorage, wrapped in try/catch, as everywhere.
  - Desktop defaults to expanded. Between 768 and 1280 px it defaults to the rail.
- **Phone width (< 768 px):** the sidebar becomes an off-canvas drawer opened from a ☰ button in a slim top bar. It closes on navigation and on Esc, and focus is trapped while it is open. The page keeps the 16 px gutter with no horizontal scroll.
- **Accessibility:**
  - `<nav aria-label="Main">` with real links, and `aria-current="page"` on the active item.
  - Sections are buttons with `aria-expanded`.
  - Arrow keys move within the list.
  - A visible focus ring, and a "Skip to content" link.
- **Wide pages:** the existing wide-table and Map pages get the full content width. With the rail collapsed they gain about 200 px over today.
- **Header:** the cluster bar and the staleness and Prometheus notices move into a slim header above the content. The identity menu moves to the sidebar footer.

**Build rules (the existing conventions):**
- React 19 and TypeScript, with no new runtime dependencies: no component library and no icon font. Icons are a handful of inline SVGs. Sparklines and bars are hand-rolled SVG on the existing `chartMath.ts`.
- Logic lives in pure, tested modules: `overview.ts`, and `nav.ts` for grouping, gating, badges and the collapsed state.
- System fonts, light and dark through CSS variables, keyboard accessible.

**Interaction:** every number on the Overview and in the sidebar links to the page that explains it, already filtered: for example, "Workloads 4 ▲" goes to Workloads filtered to unhealthy.

## Out of scope (v1)
- Dashboards where users drag and drop or configure their own widgets.
- Replacing Grafana. Long-range metrics stay there, and the alerting build ships Grafana dashboards for those.
- Multi-cluster rollup. Each cluster keeps its own kubesentry, as decided.

## Delivery

| Step | Scope | Size |
|---|---|---|
| 1 | `/overview` aggregate (Go): scoped, memoised and cached; leak-test coverage; contract | S–M (3–4 days) |
| 2a | App shell: sidebar with grouped sections, badges, capability gating, collapse to rail, phone drawer, header bar, route change. Every existing page moves into the new shell unchanged | M (3–4 days) |
| 2b | Overview page: health strip, tiles, Needs attention, capacity, cost | M (3–4 days) |
| 3 | History ring buffer, sparklines, "new since 24h"; sensitive-activity widget with the production label | S–M (3 days) |
| 4 | Alerts widget and owner filter wired to the alerting phase B findings store | S (2 days, after phase B) |
| 5 | Verify: `/overview` added to the stress users mix (target p95 < 50 ms at 2,000 users); leak test including the sidebar badges; screenshots of the sidebar expanded, as a rail and as a drawer, in light and dark and at 390 px | S (1–2 days) |

That is about 3–3.5 weeks in total. Step 2a can ship first on its own: it is useful immediately, and the Overview drops into it. It fits naturally alongside alerting phase B, and step 4 depends on it.

## Decisions needed
1. **Home page:** should Overview replace Findings as the landing page? (Recommended: yes.)
2. **Which tiles matter most** to your team? The proposed set is nodes, pods, workloads, certificates, security, sensitive activity, cost. Drop or add any?
3. **History source for v1:** the in-process ring buffer (recommended), or wait for Prometheus or the findings store?
4. **Sidebar grouping:** are the sections right (Cluster, Health, Security, plus Overview and Alerts at the top)? Should Nodes become its own sidebar item, rather than a toggle inside Map?
5. **Sequencing:** build it inside the alerting build (Overview ships with alerting phase B), or as its own small project before it?
