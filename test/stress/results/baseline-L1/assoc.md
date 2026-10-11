# Association verification

Run 2026-10-11 15:38:29Z, 64s. Ground truth: map[cronjobs:26 daemonsets:8 deployments:311 endpointslices:214 ingresses:43 jobs:44 namespacesWithPods:38 pods:2008 replicasets:316 services:216 statefulsets:41].

Map checked for 38 of 38 namespaces with pods.

## Precision and recall

| Relation | Source | Truth | Reported | Matched | Precision | Recall |
|---|---|---:|---:|---:|---:|---:|
| pod-owner | map | 1991 | 1985 | 1983 | 99.9% | 99.6% |
| service-pods | map | 1304 | 1303 | 1303 | 100.0% | 99.9% |
| pod-node | map | 2007 | 2007 | 2007 | 100.0% | 100.0% |
| pod-pvc | map | 85 | 85 | 85 | 100.0% | 100.0% |
| cronjob-job | map | 2 | 2 | 2 | 100.0% | 100.0% |
| ingress-service | map | 40 | 40 | 40 | 100.0% | 100.0% |
| pod-owner | nodes | 1990 | 1984 | 1982 | 99.9% | 99.6% |
| pod-node | nodes | 2007 | 2007 | 2007 | 100.0% | 100.0% |
| security-group | security | 237 | 238 | 232 | 97.5% | 97.9% |
| workload pod counts | workloads | 430 workloads | 430 listed | 426 exact | 99.1% | |

Workload pod counts by kind (exact/total): Deployment 309/311; Job 42/44; StatefulSet 41/41; CronJob 26/26; DaemonSet 8/8; live pods truth 1910, reported 1914.

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
| terminating-endpoint | service-pods | Service/stress-tricky/term term- | 3 pods | 3 (2 ready, 0 not ready, 1 terminating) | pass | 3 | pass |
| terminating-endpoint | workload-pods | Deployment/stress-tricky/term  | 2 live pods | 2 | pass | 3 | FAIL |
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
| terminating-endpoint | workload-pods: count differs (Deployment) | 1 | workloads | Deployment/stress-tricky/term: 2 live pods, reported 3 |

## kubesentry calls made by the verifier

| Path | ms | bytes | status |
|---|---:|---:|---:|
| /api/v1/map | 141 | 6383 | 200 |
| /api/v1/map?namespace=amazon-cloudwatch | 1069 | 6383 | 200 |
| /api/v1/map?namespace=amazon-guardduty | 1601 | 3339 | 200 |
| /api/v1/map?namespace=analytics-01 | 1600 | 23723 | 200 |
| /api/v1/map?namespace=auth-01 | 1601 | 28017 | 200 |
| /api/v1/map?namespace=aws-observability | 1599 | 1590 | 200 |
| /api/v1/map?namespace=billing-01 | 1602 | 30716 | 200 |
| /api/v1/map?namespace=catalog-01 | 1598 | 31317 | 200 |
| /api/v1/map?namespace=cert-manager | 1599 | 3317 | 200 |
| /api/v1/map?namespace=checkout-01 | 1600 | 22634 | 200 |
| /api/v1/map?namespace=demo-apps | 1600 | 3548 | 200 |
| /api/v1/map?namespace=fraud-01 | 1602 | 23535 | 200 |
| /api/v1/map?namespace=gateway-01 | 1599 | 32256 | 200 |
| /api/v1/map?namespace=identity-01 | 1600 | 36621 | 200 |
| /api/v1/map?namespace=inventory-01 | 1598 | 26881 | 200 |
| /api/v1/map?namespace=karpenter | 1600 | 1913 | 200 |
| /api/v1/map?namespace=kube-system | 1605 | 83599 | 200 |
| /api/v1/map?namespace=kubesentry | 1596 | 50625 | 200 |
| /api/v1/map?namespace=ledger-01 | 1602 | 27296 | 200 |
| /api/v1/map?namespace=local-path-storage | 1598 | 1362 | 200 |
| /api/v1/map?namespace=loyalty-01 | 1600 | 32894 | 200 |
| /api/v1/map?namespace=media-01 | 1601 | 18170 | 200 |
| /api/v1/map?namespace=messaging-01 | 1643 | 25155 | 200 |
| /api/v1/map?namespace=monitoring | 1555 | 7215 | 200 |
| /api/v1/map?namespace=notify-01 | 1599 | 22289 | 200 |
| /api/v1/map?namespace=onboarding-01 | 1600 | 29278 | 200 |
| /api/v1/map?namespace=orders-01 | 1600 | 23798 | 200 |
| /api/v1/map?namespace=payments-01 | 1600 | 36283 | 200 |
| /api/v1/map?namespace=pricing-01 | 1599 | 26081 | 200 |
| /api/v1/map?namespace=recommend-01 | 1603 | 26758 | 200 |
| /api/v1/map?namespace=reporting-01 | 1597 | 21936 | 200 |
| /api/v1/map?namespace=reviews-01 | 1600 | 37081 | 200 |
| /api/v1/map?namespace=risk-01 | 1605 | 27156 | 200 |
| /api/v1/map?namespace=search-01 | 1597 | 30748 | 200 |
| /api/v1/map?namespace=shipping-01 | 1598 | 22761 | 200 |
| /api/v1/map?namespace=stress-load | 1599 | 1843 | 200 |
| /api/v1/map?namespace=stress-tricky | 1602 | 17295 | 200 |
| /api/v1/map?namespace=stress-wide | 1601 | 110535 | 200 |
| /api/v1/map?namespace=support-01 | 1597 | 32561 | 200 |
| /api/v1/workloads | 1002 | 135722 | 200 |
| /api/v1/nodes | 1240 | 290470 | 200 |
| /api/v1/security | 1365 | 357904 | 200 |
