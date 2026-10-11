# Association verification

Run 2026-10-11 17:22:14Z, 141s. Ground truth: map[cronjobs:75 daemonsets:12 deployments:870 endpointslices:575 ingresses:118 jobs:162 namespacesWithPods:88 pods:5048 replicasets:877 services:586 statefulsets:112].

Map checked for 44 of 88 namespaces with pods.

## Precision and recall

Truth is taken before and after kubesentry is queried: edges in both are required, edges in only one (churn, e.g. CronJob runs) are volatile and accepted either way.

| Relation | Source | Truth | Volatile | Reported | Matched | Precision | Recall |
|---|---|---:|---:|---:|---:|---:|---:|
| pod-owner | map | 2239 | 2 | 2234 | 2231 | 99.9% | 99.6% |
| service-pods | map | 1550 | 0 | 1549 | 1549 | 100.0% | 99.9% |
| pod-node | map | 2253 | 2 | 2254 | 2253 | 100.0% | 100.0% |
| pod-pvc | map | 113 | 0 | 113 | 113 | 100.0% | 100.0% |
| cronjob-job | map | 17 | 2 | 18 | 17 | 100.0% | 100.0% |
| ingress-service | map | 52 | 0 | 52 | 52 | 100.0% | 100.0% |
| pod-owner | nodes | 5013 | 2 | 5008 | 5005 | 100.0% | 99.8% |
| pod-node | nodes | 5046 | 2 | 5047 | 5046 | 100.0% | 100.0% |
| security-group | security | 677 | 0 | 678 | 672 | 99.1% | 99.3% |
| workload pod counts | workloads | 1230 workloads | 1 | 1230 listed | 1227 exact | 99.8% | |

Workload pod counts by kind (exact/total): CronJob 75/75; DaemonSet 12/12; Deployment 869/870; Job 159/161; StatefulSet 112/112; live pods truth 4746, reported 4749.

## Tricky cases

| Case | Relation | From | Want | Truth | | kubesentry | |
|---|---|---|---|---|---|---|---|
| overlap-selectors | pod-owner | Deployment/stress-tricky/web web- | 2 pods | 2 | pass | 3 | FAIL |
| overlap-selectors | pod-owner | Deployment/stress-tricky/web-canary web-canary- | 1 pods | 1 | pass | 0 | FAIL |
| overlap-selectors | workload-pods | Deployment/stress-tricky/web  | 2 live pods | 2 | pass | 3 | FAIL |
| overlap-selectors | workload-pods | Deployment/stress-tricky/web-canary  | 1 live pods | 1 | pass | 1 | pass |
| overlap-selectors | service-pods | Service/stress-tricky/web web- | 3 pods | 3 (3 ready, 0 not ready, 0 terminating) | pass | 3 | pass |
| overlap-selectors | ingress-service | Ingress/stress-tricky/web Service/stress-tricky/web | → Service/stress-tricky/web | 1 | pass | 1 | pass |
| jobs-identical-labels | pod-owner | Job/stress-tricky/batch-a batch-a- | 1 pods | 1 | pass | 1 | pass |
| jobs-identical-labels | pod-owner | Job/stress-tricky/batch-b batch-b- | 1 pods | 1 | pass | 1 | pass |
| jobs-manual-selector | pod-owner | Job/stress-tricky/manual-a manual-a- | 1 pods | 1 | pass | 2 | FAIL |
| jobs-manual-selector | pod-owner | Job/stress-tricky/manual-b manual-b- | 1 pods | 1 | pass | 0 | FAIL |
| jobs-manual-selector | workload-pods | Job/stress-tricky/manual-a  | 1 live pods | 1 | pass | 2 | FAIL |
| jobs-manual-selector | workload-pods | Job/stress-tricky/manual-b  | 1 live pods | 1 | pass | 2 | FAIL |
| orphan-replicaset | pod-owner | ReplicaSet/stress-tricky/orphan-src-* orphan-src- | 2 pods | 2 | pass | 0 | FAIL |
| custom-owner | pod-owner | Widget/stress-tricky/widget-a widget-a- | 2 pods | 2 | pass | 0 | FAIL |
| rollout-like | pod-owner | Rollout/stress-tricky/checkout checkout-rs- | 2 pods | 2 | pass | 0 | FAIL |
| rollout-like | service-pods | Service/stress-tricky/checkout checkout-rs- | 2 pods | 2 (2 ready, 0 not ready, 0 terminating) | pass | 2 | pass |
| failing-readiness | service-pods | Service/stress-tricky/unready unready- | 2 pods | 2 (0 ready, 2 not ready, 0 terminating) | pass | 2 | pass |
| failing-readiness | status | Pod/stress-tricky/unready- NotReady | NotReady (not ok) | NotReady,NotReady | pass | ok,ok | FAIL |
| terminating-endpoint | service-pods | Service/stress-tricky/term term- | 3 pods | 2 (2 ready, 0 not ready, 0 terminating) | FAIL | 2 | FAIL |
| terminating-endpoint | workload-pods | Deployment/stress-tricky/term  | 2 live pods | 2 | pass | 2 | pass |
| publish-not-ready | service-pods | Service/stress-tricky/pnra pnra- | 1 pods | 1 (1 ready, 0 not ready, 0 terminating) | pass | 1 | pass |
| crashloop | pod-owner | Deployment/stress-tricky/crashloop crashloop- | 1 pods | 1 | pass | 1 | pass |
| crashloop | status | Pod/stress-tricky/crashloop- CrashLoopBackOff | CrashLoopBackOff (not ok) | CrashLoopBackOff | pass | warn | pass |
| image-pull | pod-owner | Deployment/stress-tricky/imagepull imagepull- | 1 pods | 1 | pass | 1 | pass |
| image-pull | status | Pod/stress-tricky/imagepull- ImagePullBackOff | ImagePullBackOff (not ok) | ImagePullBackOff | pass | warn | pass |
| unschedulable | pod-owner | Deployment/stress-tricky/unschedulable unschedulable- | 1 pods | 1 | pass | 1 | pass |
| unschedulable | pod-node | Pod/stress-tricky/unschedulable-  | no node | 0 node edges | pass | 0 node edges | pass |
| unschedulable | status | Pod/stress-tricky/unschedulable- Unschedulable | Unschedulable (not ok) | Unschedulable | pass | warn | pass |
| bare-pod | pod-owner |  bare-1 | no owner | 1 pods, 0 owner edges | pass | 0 owner edges | pass |
| static-pod | pod-owner |  static-web-kubesentry-worker | no owner | 1 pods, 0 owner edges | pass | 0 owner edges | pass |
| static-pod | pod-node | Pod/stress-tricky/static-web-kubesentry-worker Node/kubesentry-worker | on Node/kubesentry-worker | 1 | pass | 1 | pass |
| succeeded-selected | service-pods | Service/stress-tricky/done done-1 | 1 pods | 1 (0 ready, 1 not ready, 0 terminating) | pass | 0 | FAIL |
| mid-rollout | pod-owner | Deployment/stress-tricky/rollout rollout- | 4 pods | 4 | pass | 4 | pass |
| mid-rollout | service-pods | Service/stress-tricky/rollout rollout- | 4 pods | 4 (3 ready, 1 not ready, 0 terminating) | pass | 4 | pass |
| multi-workload-service | service-pods | Service/stress-tricky/backend  | 2 pods | 2 (2 ready, 0 not ready, 0 terminating) | pass | 2 | pass |
| statefulset | pod-owner | StatefulSet/stress-tricky/db db- | 2 pods | 2 | pass | 2 | pass |
| statefulset | service-pods | Service/stress-tricky/db db- | 2 pods | 2 (2 ready, 0 not ready, 0 terminating) | pass | 2 | pass |
| cronjob | cronjob-job | CronJob/stress-tricky/tick tick- | at least 1 Job | 2 | pass | 2 | pass |
| pvc-mount | pod-pvc | Pod/stress-tricky/pvc-user- PVC/stress-tricky/tricky-data | mounts PVC/stress-tricky/tricky-data | 1 | pass | 1 | pass |
| pvc-mount | ingress-service | Ingress/stress-tricky/ghost  | no backend edge | 0 | pass | 0 | pass |
| wide-service | service-pods | Service/stress-wide/wide wide- | 300 pods | 300 (300 ready, 0 not ready, 0 terminating) | pass | 300 | pass |
| wide-service | workload-pods | Deployment/stress-wide/wide  | 300 live pods | 300 | pass | 300 | pass |

Truth columns check that the cluster really has the intended shape; kubesentry columns are the verdict.

## Mismatches by case and category

| Case | Category | Count | Sources | Example |
|---|---|---:|---|---|
| custom-owner | pod-owner: owner not reported (Widget) | 4 | map,nodes | Pod/stress-tricky/widget-a-0 owned by Widget/stress-tricky/widget-a |
| custom-owner | security: unexpected group (Pod) | 2 | security | Pod/stress-tricky/widget-a-0 |
| custom-owner | security: group not reported (Widget) | 1 | security | Widget/stress-tricky/widget-a |
| jobs-manual-selector | pod-owner: wrong owner (Job instead of Job) | 2 | map,nodes | Pod/stress-tricky/manual-b-vrx55 owned by Job/stress-tricky/manual-b, reported Job/stress-tricky/manual-a |
| jobs-manual-selector | workload-pods: count differs (Job) | 2 | workloads | Job/stress-tricky/manual-a: 1 live pods, reported 2 |
| jobs-manual-selector | security: group not reported (Job) | 1 | security | Job/stress-tricky/manual-b |
| orphan-replicaset | pod-owner: owner not reported (ReplicaSet) | 4 | map,nodes | Pod/stress-tricky/orphan-src-7c448bf6cf-6cz5s owned by ReplicaSet/stress-tricky/orphan-src-7c448bf6cf |
| orphan-replicaset | security: unexpected group (Pod) | 2 | security | Pod/stress-tricky/orphan-src-7c448bf6cf-6cz5s |
| orphan-replicaset | security: group not reported (ReplicaSet) | 1 | security | ReplicaSet/stress-tricky/orphan-src-7c448bf6cf |
| overlap-selectors | pod-owner: wrong owner (Deployment instead of Deployment) | 2 | map,nodes | Pod/stress-tricky/web-canary-7785cc787d-vk49m owned by Deployment/stress-tricky/web-canary, reported Deployment/stress-tricky/web |
| overlap-selectors | security: group not reported (Deployment) | 1 | security | Deployment/stress-tricky/web-canary |
| overlap-selectors | workload-pods: count differs (Deployment) | 1 | workloads | Deployment/stress-tricky/web: 2 live pods, reported 3 |
| rollout-like | pod-owner: owner not reported (Rollout) | 4 | map,nodes | Pod/stress-tricky/checkout-rs-pvprt owned by Rollout/stress-tricky/checkout |
| rollout-like | security: unexpected group (Pod) | 2 | security | Pod/stress-tricky/checkout-rs-pvprt |
| rollout-like | security: group not reported (Rollout) | 1 | security | Rollout/stress-tricky/checkout |
| succeeded-selected | service-pods: not-ready endpoint not reported | 1 | map | Service/stress-tricky/done → Pod/stress-tricky/done-1 |

## kubesentry calls made by the verifier

| Path | ms | bytes | status |
|---|---:|---:|---:|
| /api/v1/map | 1013 | 11267 | 200 |
| /api/v1/map?namespace=amazon-cloudwatch | 2999 | 11267 | 200 |
| /api/v1/map?namespace=analytics-02 | 3001 | 17815 | 200 |
| /api/v1/map?namespace=analytics-03 | 3001 | 36057 | 200 |
| /api/v1/map?namespace=auth-01 | 2999 | 28672 | 200 |
| /api/v1/map?namespace=aws-observability | 3002 | 2245 | 200 |
| /api/v1/map?namespace=billing-01 | 2999 | 31371 | 200 |
| /api/v1/map?namespace=billing-02 | 3000 | 26671 | 200 |
| /api/v1/map?namespace=billing-03 | 3000 | 21415 | 200 |
| /api/v1/map?namespace=checkout-01 | 3002 | 24049 | 200 |
| /api/v1/map?namespace=checkout-02 | 3002 | 28581 | 200 |
| /api/v1/map?namespace=checkout-03 | 2998 | 25557 | 200 |
| /api/v1/map?namespace=content-02 | 3002 | 26828 | 200 |
| /api/v1/map?namespace=demo-apps | 2997 | 4203 | 200 |
| /api/v1/map?namespace=fraud-01 | 3001 | 24923 | 200 |
| /api/v1/map?namespace=identity-01 | 2999 | 40253 | 200 |
| /api/v1/map?namespace=inventory-03 | 3000 | 34469 | 200 |
| /api/v1/map?namespace=ledger-02 | 3000 | 25301 | 200 |
| /api/v1/map?namespace=ledger-03 | 3001 | 40424 | 200 |
| /api/v1/map?namespace=media-01 | 2999 | 19558 | 200 |
| /api/v1/map?namespace=messaging-01 | 2999 | 25810 | 200 |
| /api/v1/map?namespace=monitoring | 3000 | 7870 | 200 |
| /api/v1/map?namespace=notify-02 | 3000 | 30407 | 200 |
| /api/v1/map?namespace=onboarding-02 | 3000 | 38927 | 200 |
| /api/v1/map?namespace=orders-02 | 3000 | 31490 | 200 |
| /api/v1/map?namespace=partners-01 | 3000 | 31858 | 200 |
| /api/v1/map?namespace=pricing-01 | 3003 | 27487 | 200 |
| /api/v1/map?namespace=pricing-03 | 2996 | 34739 | 200 |
| /api/v1/map?namespace=recommend-01 | 3001 | 27413 | 200 |
| /api/v1/map?namespace=reviews-01 | 2999 | 38487 | 200 |
| /api/v1/map?namespace=reviews-02 | 3001 | 28840 | 200 |
| /api/v1/map?namespace=risk-01 | 3000 | 27811 | 200 |
| /api/v1/map?namespace=risk-02 | 3000 | 24398 | 200 |
| /api/v1/map?namespace=search-01 | 2999 | 31403 | 200 |
| /api/v1/map?namespace=search-02 | 3001 | 26884 | 200 |
| /api/v1/map?namespace=shipping-01 | 3002 | 23416 | 200 |
| /api/v1/map?namespace=shipping-03 | 3001 | 28143 | 200 |
| /api/v1/map?namespace=stress-conn | 2998 | 5802 | 200 |
| /api/v1/map?namespace=stress-load | 3001 | 5025 | 200 |
| /api/v1/map?namespace=stress-tricky | 2997 | 17921 | 200 |
| /api/v1/map?namespace=stress-wide | 3003 | 111190 | 200 |
| /api/v1/map?namespace=support-01 | 2998 | 33216 | 200 |
| /api/v1/map?namespace=support-02 | 2997 | 25957 | 200 |
| /api/v1/map?namespace=tax-02 | 3003 | 20029 | 200 |
| /api/v1/map?namespace=warehouse-02 | 2997 | 24268 | 200 |
| /api/v1/workloads | 2229 | 394261 | 200 |
| /api/v1/nodes | 2486 | 726062 | 200 |
| /api/v1/security | 2726 | 956377 | 200 |
