# Association verification

Run 2026-10-11 17:39:00Z, 275s. Ground truth: map[cronjobs:157 daemonsets:16 deployments:1753 endpointslices:1155 ingresses:244 jobs:290 namespacesWithPods:170 pods:10002 replicasets:1761 services:1180 statefulsets:239].

Map checked for 44 of 170 namespaces with pods.

## Precision and recall

Truth is taken before and after kubesentry is queried: edges in both are required, edges in only one (churn, e.g. CronJob runs) are volatile and accepted either way.

| Relation | Source | Truth | Volatile | Reported | Matched | Precision | Recall |
|---|---|---:|---:|---:|---:|---:|---:|
| pod-owner | map | 3273 | 4 | 3269 | 3265 | 99.9% | 99.8% |
| service-pods | map | 2021 | 0 | 2020 | 2020 | 100.0% | 100.0% |
| pod-node | map | 3287 | 4 | 3289 | 3287 | 100.0% | 100.0% |
| pod-pvc | map | 144 | 0 | 144 | 144 | 100.0% | 100.0% |
| cronjob-job | map | 7 | 4 | 9 | 7 | 100.0% | 100.0% |
| ingress-service | map | 48 | 0 | 48 | 48 | 100.0% | 100.0% |
| pod-owner | nodes | 9939 | 4 | 9935 | 9931 | 100.0% | 99.9% |
| pod-node | nodes | 9999 | 4 | 10001 | 9999 | 100.0% | 100.0% |
| security-group | security | 1350 | 0 | 1351 | 1345 | 99.6% | 99.6% |
| workload pod counts | workloads | 2453 workloads | 2 | 2453 listed | 2449 exact | 99.8% | |

Workload pod counts by kind (exact/total): DaemonSet 16/16; Deployment 1751/1753; Job 286/288; StatefulSet 239/239; CronJob 157/157; live pods truth 9419, reported 9423.

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
| /api/v1/map | 3825 | 22457 | 200 |
| /api/v1/map?namespace=aws-observability | 5791 | 3315 | 200 |
| /api/v1/map?namespace=billing-01 | 5801 | 32441 | 200 |
| /api/v1/map?namespace=checkout-02 | 5799 | 29651 | 200 |
| /api/v1/map?namespace=content-02 | 5801 | 27898 | 200 |
| /api/v1/map?namespace=gateway-01 | 5799 | 34732 | 200 |
| /api/v1/map?namespace=gateway-02 | 5800 | 27005 | 200 |
| /api/v1/map?namespace=gateway-03 | 5800 | 28441 | 200 |
| /api/v1/map?namespace=gateway-05 | 5805 | 29171 | 200 |
| /api/v1/map?namespace=identity-04 | 5799 | 27671 | 200 |
| /api/v1/map?namespace=identity-05 | 5797 | 38262 | 200 |
| /api/v1/map?namespace=inventory-02 | 5799 | 18863 | 200 |
| /api/v1/map?namespace=inventory-05 | 5800 | 34316 | 200 |
| /api/v1/map?namespace=kube-system | 5808 | 377196 | 200 |
| /api/v1/map?namespace=ledger-02 | 5791 | 26371 | 200 |
| /api/v1/map?namespace=loyalty-01 | 5800 | 35371 | 200 |
| /api/v1/map?namespace=loyalty-03 | 5803 | 30263 | 200 |
| /api/v1/map?namespace=loyalty-04 | 5797 | 22827 | 200 |
| /api/v1/map?namespace=notify-04 | 5799 | 23772 | 200 |
| /api/v1/map?namespace=onboarding-05 | 5802 | 35144 | 200 |
| /api/v1/map?namespace=orders-01 | 5798 | 25523 | 200 |
| /api/v1/map?namespace=orders-02 | 5802 | 32560 | 200 |
| /api/v1/map?namespace=partners-01 | 5798 | 32928 | 200 |
| /api/v1/map?namespace=partners-03 | 5799 | 28388 | 200 |
| /api/v1/map?namespace=partners-04 | 5802 | 34506 | 200 |
| /api/v1/map?namespace=partners-05 | 5798 | 27282 | 200 |
| /api/v1/map?namespace=pricing-02 | 5800 | 27365 | 200 |
| /api/v1/map?namespace=pricing-05 | 5802 | 18609 | 200 |
| /api/v1/map?namespace=recommend-01 | 5799 | 28483 | 200 |
| /api/v1/map?namespace=recommend-03 | 5800 | 31434 | 200 |
| /api/v1/map?namespace=recommend-04 | 5799 | 32294 | 200 |
| /api/v1/map?namespace=recommend-05 | 5802 | 26474 | 200 |
| /api/v1/map?namespace=reporting-03 | 5799 | 27151 | 200 |
| /api/v1/map?namespace=returns-04 | 5799 | 21792 | 200 |
| /api/v1/map?namespace=risk-01 | 5800 | 28881 | 200 |
| /api/v1/map?namespace=search-01 | 5802 | 32473 | 200 |
| /api/v1/map?namespace=search-06 | 5799 | 33352 | 200 |
| /api/v1/map?namespace=shipping-02 | 5799 | 35032 | 200 |
| /api/v1/map?namespace=shipping-05 | 5800 | 30978 | 200 |
| /api/v1/map?namespace=stress-conn | 5800 | 6872 | 200 |
| /api/v1/map?namespace=stress-load | 5798 | 6095 | 200 |
| /api/v1/map?namespace=stress-tricky | 5801 | 19309 | 200 |
| /api/v1/map?namespace=stress-wide | 5803 | 112260 | 200 |
| /api/v1/map?namespace=warehouse-02 | 5795 | 25339 | 200 |
| /api/v1/map?namespace=warehouse-05 | 5801 | 36434 | 200 |
| /api/v1/workloads | 4347 | 784105 | 200 |
| /api/v1/nodes | 4852 | 1436986 | 200 |
| /api/v1/security | 4784 | 1864542 | 200 |
