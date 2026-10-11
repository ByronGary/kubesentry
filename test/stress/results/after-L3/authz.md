# Authorization leaks (verify authz)

15 personas checked in 84s: **0 leaks**, 0 other problems.

Truth comes from SubjectAccessReviews as each persona (list pods per namespace for namespaced data; kubesentry.io auditevents/processes; list rolebindings for RBAC findings; cluster-wide nodes, persistentvolumes, storageclasses, clusterrolebindings, clusterissuers, agents, auditevents). Every list route is then paged through as that persona; any item outside its scope is a leak. "Problems" are not leaks (e.g. less shown than RBAC allows, or an unexpected status).

| Persona | Kind | pods ns | audit ns | rbac ns | cluster caps | leaks | problems |
|---|---|---:|---:|---:|---|---:|---:|
| admin0@corp.example | admin | all | all | all | agents,clusterAudit,clusterIssuers,clusterRBAC,nodes,pvs,storageClasses | 0 | 0 |
| admin1@corp.example | admin | all | all | all | agents,clusterAudit,clusterIssuers,clusterRBAC,nodes,pvs,storageClasses | 0 | 0 |
| viewer5@corp.example | viewer | all | all | 0 | agents,clusterAudit | 0 | 0 |
| viewer6@corp.example | viewer | all | all | 0 | agents,clusterAudit | 0 | 0 |
| viewer7@corp.example | viewer | all | all | 0 | agents,clusterAudit | 0 | 0 |
| support.dev20@corp.example | team | 1 | 1 | 0 |  | 0 | 0 |
| reporting.dev21@corp.example | team | 1 | 0 | 0 |  | 0 | 0 |
| risk.dev22@corp.example | team | 1 | 1 | 0 |  | 0 | 0 |
| onboarding.dev23@corp.example | team | 1 | 0 | 0 |  | 0 | 0 |
| messaging.dev24@corp.example | team | 1 | 1 | 0 |  | 0 | 0 |
| content.dev25@corp.example | team | 1 | 0 | 0 |  | 0 | 0 |
| partners.dev26@corp.example | team | 1 | 1 | 0 |  | 0 | 0 |
| tax.dev27@corp.example | team | 1 | 0 | 0 |  | 0 | 0 |
| many.groups@corp.example | many-groups | 1 | 1 | 0 |  | 0 | 0 |
| nobody@corp.example | no-grants | 0 | 0 | 0 |  | 0 | 0 |

## Routes with leaks or problems

None.

## Items checked per route (all personas)

| Route | items | leaks | median ms |
|---|---:|---:|---:|
| /api/v1/agents | 30 | 0 | 1 |
| /api/v1/audit/events?since=24h | 32749 | 0 | 78 |
| /api/v1/audit/events?since=24h&includeReads=true&actors=user,serviceaccount,system | 37521 | 0 | 24 |
| /api/v1/audit/summary?since=24h | 0 | 0 | 3 |
| /api/v1/certificates | 1217 | 0 | 1 |
| /api/v1/info | 0 | 0 | 5 |
| /api/v1/map | 3992 | 0 | 2 |
| /api/v1/map?namespace=… | 752 | 0 | 1 |
| /api/v1/nodes | 51149 | 0 | 6 |
| /api/v1/nodes?summary=true | 2953 | 0 | 2 |
| /api/v1/oom?window=24h | 526 | 0 | 1 |
| /api/v1/pods | 48201 | 0 | 8 |
| /api/v1/pvcs/unused | 2588 | 0 | 1 |
| /api/v1/security | 33052 | 0 | 6 |
| /api/v1/security?view=summary | 1273 | 0 | 1 |
| /api/v1/storage | 16883 | 0 | 2 |
| /api/v1/workloads | 12622 | 0 | 3 |
