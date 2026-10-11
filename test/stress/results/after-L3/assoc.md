# Association verification

Run 2026-10-11 21:15:05Z, 9s. Ground truth: map[cronjobs:157 daemonsets:16 deployments:1755 endpointslices:1161 ingresses:244 jobs:328 namespacesWithPods:173 pods:9544 replicasets:1769 services:1186 statefulsets:240].

Map checked for 173 of 173 namespaces with pods.

## Precision and recall

Truth is taken before and after kubesentry is queried: edges in both are required, edges in only one (churn, e.g. CronJob runs) are volatile and accepted either way.

| Relation | Source | Truth | Volatile | Reported | Matched | Precision | Recall |
|---|---|---:|---:|---:|---:|---:|---:|
| pod-owner | map | 9484 | 0 | 9484 | 9484 | 100.0% | 100.0% |
| service-pods | map | 6029 | 0 | 6029 | 6029 | 100.0% | 100.0% |
| pod-node | map | 9543 | 0 | 9543 | 9543 | 100.0% | 100.0% |
| pod-pvc | map | 497 | 0 | 497 | 497 | 100.0% | 100.0% |
| cronjob-job | map | 80 | 0 | 80 | 80 | 100.0% | 100.0% |
| ingress-service | map | 233 | 0 | 233 | 233 | 100.0% | 100.0% |
| pod-owner | nodes | 9483 | 0 | 9488 | 9483 | 99.9% | 100.0% |
| pod-node | nodes | 9543 | 0 | 9543 | 9543 | 100.0% | 100.0% |
| security-group | security | 1380 | 0 | 1380 | 1380 | 100.0% | 100.0% |
| workload pod counts | workloads | 2496 workloads | 0 | 2496 listed | 2496 exact | 100.0% | |

Workload pod counts by kind (exact/total): CronJob 157/157; DaemonSet 16/16; Deployment 1755/1755; Job 328/328; StatefulSet 240/240; live pods truth 8923, reported 8923.

## Tricky cases

| Case | Relation | From | Want | Truth | | kubesentry | |
|---|---|---|---|---|---|---|---|
| overlap-selectors | pod-owner | Deployment/stress-tricky/web web- | 2 pods | 2 | pass | 2 | pass |
| overlap-selectors | pod-owner | Deployment/stress-tricky/web-canary web-canary- | 1 pods | 1 | pass | 1 | pass |
| overlap-selectors | workload-pods | Deployment/stress-tricky/web  | 2 live pods | 2 | pass | 2 | pass |
| overlap-selectors | workload-pods | Deployment/stress-tricky/web-canary  | 1 live pods | 1 | pass | 1 | pass |
| overlap-selectors | service-pods | Service/stress-tricky/web web- | 3 pods | 3 (3 ready, 0 not ready, 0 terminating) | pass | 3 | pass |
| overlap-selectors | ingress-service | Ingress/stress-tricky/web Service/stress-tricky/web | → Service/stress-tricky/web | 1 | pass | 1 | pass |
| jobs-identical-labels | pod-owner | Job/stress-tricky/batch-a batch-a- | 1 pods | 1 | pass | 1 | pass |
| jobs-identical-labels | pod-owner | Job/stress-tricky/batch-b batch-b- | 1 pods | 1 | pass | 1 | pass |
| jobs-manual-selector | pod-owner | Job/stress-tricky/manual-a manual-a- | 1 pods | 1 | pass | 1 | pass |
| jobs-manual-selector | pod-owner | Job/stress-tricky/manual-b manual-b- | 1 pods | 1 | pass | 1 | pass |
| jobs-manual-selector | workload-pods | Job/stress-tricky/manual-a  | 1 live pods | 1 | pass | 1 | pass |
| jobs-manual-selector | workload-pods | Job/stress-tricky/manual-b  | 1 live pods | 1 | pass | 1 | pass |
| orphan-replicaset | pod-owner | ReplicaSet/stress-tricky/orphan-src-* orphan-src- | 2 pods | 2 | pass | 2 | pass |
| custom-owner | pod-owner | Widget/stress-tricky/widget-a widget-a- | 2 pods | 2 | pass | 2 | pass |
| rollout-like | pod-owner | Rollout/stress-tricky/checkout checkout-rs- | 2 pods | 2 | pass | 2 | pass |
| rollout-like | service-pods | Service/stress-tricky/checkout checkout-rs- | 2 pods | 2 (2 ready, 0 not ready, 0 terminating) | pass | 2 | pass |
| failing-readiness | service-pods | Service/stress-tricky/unready unready- | 2 pods | 2 (0 ready, 2 not ready, 0 terminating) | pass | 2 | pass |
| failing-readiness | status | Pod/stress-tricky/unready- NotReady | NotReady (not ok) | NotReady,NotReady | pass | warn,warn | pass |
| terminating-endpoint | service-pods | Service/stress-tricky/term term- | 3 pods | 3 (2 ready, 0 not ready, 1 terminating) | pass | 3 | pass |
| terminating-endpoint | workload-pods | Deployment/stress-tricky/term  | 2 live pods | 2 | pass | 2 | pass |
| publish-not-ready | service-pods | Service/stress-tricky/pnra pnra- | 1 pods | 1 (1 ready, 0 not ready, 0 terminating) | pass | 1 | pass |
| crashloop | pod-owner | Deployment/stress-tricky/crashloop crashloop- | 1 pods | 1 | pass | 1 | pass |
| crashloop | status | Pod/stress-tricky/crashloop- CrashLoopBackOff | CrashLoopBackOff (not ok) | CrashLoopBackOff | pass | crit | pass |
| image-pull | pod-owner | Deployment/stress-tricky/imagepull imagepull- | 1 pods | 1 | pass | 1 | pass |
| image-pull | status | Pod/stress-tricky/imagepull- ImagePullBackOff | ImagePullBackOff (not ok) | ImagePullBackOff | pass | crit | pass |
| unschedulable | pod-owner | Deployment/stress-tricky/unschedulable unschedulable- | 1 pods | 1 | pass | 1 | pass |
| unschedulable | pod-node | Pod/stress-tricky/unschedulable-  | no node | 0 node edges | pass | 0 node edges | pass |
| unschedulable | status | Pod/stress-tricky/unschedulable- Unschedulable | Unschedulable (not ok) | Unschedulable | pass | warn | pass |
| bare-pod | pod-owner |  bare-1 | no owner | 1 pods, 0 owner edges | pass | 0 owner edges | pass |
| static-pod | pod-owner |  static-web-kubesentry-worker | no owner | 1 pods, 0 owner edges | pass | 0 owner edges | pass |
| static-pod | pod-node | Pod/stress-tricky/static-web-kubesentry-worker Node/kubesentry-worker | on Node/kubesentry-worker | 1 | pass | 1 | pass |
| succeeded-selected | service-pods | Service/stress-tricky/done done-1 | as the EndpointSlice: 0 pods | 0 | pass | 0 | pass |
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
| static-pod | pod-owner: spurious owner | 1 | nodes | Pod/stress-tricky/static-web-kubesentry-worker reported under Node/stress-tricky/kubesentry-worker; pod has no workload owner |
| system | pod-owner: spurious owner | 4 | nodes | Pod/kube-system/etcd-kubesentry-control-plane reported under Node/kube-system/kubesentry-control-plane; pod has no workload owner |

## kubesentry calls made by the verifier

| Path | ms | bytes | status |
|---|---:|---:|---:|
| /api/v1/map | 30 | 124701 | 200 |
| /api/v1/map?namespace=amazon-cloudwatch | 2 | 31327 | 200 |
| /api/v1/map?namespace=amazon-guardduty | 2 | 22298 | 200 |
| /api/v1/map?namespace=analytics-01 | 2 | 35195 | 200 |
| /api/v1/map?namespace=analytics-02 | 2 | 27676 | 200 |
| /api/v1/map?namespace=analytics-03 | 2 | 46566 | 200 |
| /api/v1/map?namespace=analytics-04 | 2 | 32613 | 200 |
| /api/v1/map?namespace=analytics-05 | 2 | 37568 | 200 |
| /api/v1/map?namespace=auth-01 | 2 | 38920 | 200 |
| /api/v1/map?namespace=auth-02 | 2 | 38578 | 200 |
| /api/v1/map?namespace=auth-03 | 2 | 35426 | 200 |
| /api/v1/map?namespace=auth-04 | 2 | 38595 | 200 |
| /api/v1/map?namespace=auth-05 | 2 | 37417 | 200 |
| /api/v1/map?namespace=aws-observability | 1 | 11569 | 200 |
| /api/v1/map?namespace=billing-01 | 2 | 41638 | 200 |
| /api/v1/map?namespace=billing-02 | 2 | 36710 | 200 |
| /api/v1/map?namespace=billing-03 | 2 | 31352 | 200 |
| /api/v1/map?namespace=billing-04 | 2 | 39702 | 200 |
| /api/v1/map?namespace=billing-05 | 2 | 42641 | 200 |
| /api/v1/map?namespace=catalog-01 | 2 | 43013 | 200 |
| /api/v1/map?namespace=catalog-02 | 2 | 38817 | 200 |
| /api/v1/map?namespace=catalog-03 | 2 | 43997 | 200 |
| /api/v1/map?namespace=catalog-04 | 2 | 32295 | 200 |
| /api/v1/map?namespace=catalog-05 | 3 | 26453 | 200 |
| /api/v1/map?namespace=catalog-06 | 2 | 28382 | 200 |
| /api/v1/map?namespace=cert-manager | 1 | 13373 | 200 |
| /api/v1/map?namespace=checkout-01 | 2 | 34106 | 200 |
| /api/v1/map?namespace=checkout-02 | 2 | 38702 | 200 |
| /api/v1/map?namespace=checkout-03 | 2 | 35734 | 200 |
| /api/v1/map?namespace=checkout-04 | 2 | 45660 | 200 |
| /api/v1/map?namespace=checkout-05 | 2 | 32279 | 200 |
| /api/v1/map?namespace=checkout-06 | 2 | 48841 | 200 |
| /api/v1/map?namespace=content-01 | 2 | 39108 | 200 |
| /api/v1/map?namespace=content-02 | 2 | 36892 | 200 |
| /api/v1/map?namespace=content-03 | 2 | 37352 | 200 |
| /api/v1/map?namespace=content-04 | 2 | 40924 | 200 |
| /api/v1/map?namespace=content-05 | 2 | 36515 | 200 |
| /api/v1/map?namespace=demo-apps | 1 | 13576 | 200 |
| /api/v1/map?namespace=fraud-01 | 2 | 35052 | 200 |
| /api/v1/map?namespace=fraud-02 | 2 | 30794 | 200 |
| /api/v1/map?namespace=fraud-03 | 2 | 40921 | 200 |
| /api/v1/map?namespace=fraud-04 | 1004 | 30442 | 200 |
| /api/v1/map?namespace=fraud-05 | 2 | 25781 | 200 |
| /api/v1/map?namespace=gateway-01 | 2 | 44003 | 200 |
| /api/v1/map?namespace=gateway-02 | 2 | 36136 | 200 |
| /api/v1/map?namespace=gateway-03 | 2 | 38264 | 200 |
| /api/v1/map?namespace=gateway-04 | 2 | 36922 | 200 |
| /api/v1/map?namespace=gateway-05 | 2 | 39045 | 200 |
| /api/v1/map?namespace=identity-01 | 2 | 56228 | 200 |
| /api/v1/map?namespace=identity-02 | 2 | 43968 | 200 |
| /api/v1/map?namespace=identity-03 | 2 | 32460 | 200 |
| /api/v1/map?namespace=identity-04 | 2 | 37476 | 200 |
| /api/v1/map?namespace=identity-05 | 2 | 48342 | 200 |
| /api/v1/map?namespace=identity-06 | 2 | 49648 | 200 |
| /api/v1/map?namespace=inventory-01 | 2 | 37615 | 200 |
| /api/v1/map?namespace=inventory-02 | 2 | 27586 | 200 |
| /api/v1/map?namespace=inventory-03 | 2 | 44833 | 200 |
| /api/v1/map?namespace=inventory-04 | 2 | 27721 | 200 |
| /api/v1/map?namespace=inventory-05 | 2 | 43469 | 200 |
| /api/v1/map?namespace=karpenter | 1 | 11905 | 200 |
| /api/v1/map?namespace=kube-system | 9 | 399626 | 200 |
| /api/v1/map?namespace=kubesentry | 1 | 15360 | 200 |
| /api/v1/map?namespace=ledger-01 | 1003 | 38112 | 200 |
| /api/v1/map?namespace=ledger-02 | 2 | 35360 | 200 |
| /api/v1/map?namespace=ledger-03 | 2 | 50978 | 200 |
| /api/v1/map?namespace=ledger-04 | 2 | 46769 | 200 |
| /api/v1/map?namespace=ledger-05 | 2 | 26943 | 200 |
| /api/v1/map?namespace=ledger-06 | 2 | 42991 | 200 |
| /api/v1/map?namespace=local-path-storage | 1 | 11319 | 200 |
| /api/v1/map?namespace=loyalty-01 | 2 | 44630 | 200 |
| /api/v1/map?namespace=loyalty-02 | 2 | 42155 | 200 |
| /api/v1/map?namespace=loyalty-03 | 2 | 40124 | 200 |
| /api/v1/map?namespace=loyalty-04 | 2 | 32474 | 200 |
| /api/v1/map?namespace=loyalty-05 | 2 | 39739 | 200 |
| /api/v1/map?namespace=media-01 | 2 | 29450 | 200 |
| /api/v1/map?namespace=media-02 | 2 | 44684 | 200 |
| /api/v1/map?namespace=media-03 | 2 | 43157 | 200 |
| /api/v1/map?namespace=media-04 | 2 | 43605 | 200 |
| /api/v1/map?namespace=media-05 | 2 | 30058 | 200 |
| /api/v1/map?namespace=messaging-01 | 2 | 35880 | 200 |
| /api/v1/map?namespace=messaging-02 | 2 | 39227 | 200 |
| /api/v1/map?namespace=messaging-03 | 2 | 32906 | 200 |
| /api/v1/map?namespace=messaging-04 | 2 | 54080 | 200 |
| /api/v1/map?namespace=messaging-05 | 1003 | 35413 | 200 |
| /api/v1/map?namespace=monitoring | 2 | 17393 | 200 |
| /api/v1/map?namespace=notify-01 | 2 | 32911 | 200 |
| /api/v1/map?namespace=notify-02 | 2 | 40649 | 200 |
| /api/v1/map?namespace=notify-03 | 2 | 35404 | 200 |
| /api/v1/map?namespace=notify-04 | 2 | 32635 | 200 |
| /api/v1/map?namespace=notify-05 | 2 | 45345 | 200 |
| /api/v1/map?namespace=onboarding-01 | 2 | 40939 | 200 |
| /api/v1/map?namespace=onboarding-02 | 2 | 55138 | 200 |
| /api/v1/map?namespace=onboarding-03 | 2 | 35963 | 200 |
| /api/v1/map?namespace=onboarding-04 | 2 | 28736 | 200 |
| /api/v1/map?namespace=onboarding-05 | 2 | 45144 | 200 |
| /api/v1/map?namespace=orders-01 | 2 | 34430 | 200 |
| /api/v1/map?namespace=orders-02 | 2 | 41731 | 200 |
| /api/v1/map?namespace=orders-03 | 2 | 53567 | 200 |
| /api/v1/map?namespace=orders-04 | 2 | 44994 | 200 |
| /api/v1/map?namespace=orders-05 | 2 | 45952 | 200 |
| /api/v1/map?namespace=partners-01 | 2 | 42079 | 200 |
| /api/v1/map?namespace=partners-02 | 2 | 40237 | 200 |
| /api/v1/map?namespace=partners-03 | 2 | 37364 | 200 |
| /api/v1/map?namespace=partners-04 | 2 | 43688 | 200 |
| /api/v1/map?namespace=partners-05 | 1004 | 36250 | 200 |
| /api/v1/map?namespace=payments-01 | 2 | 47327 | 200 |
| /api/v1/map?namespace=payments-02 | 2 | 41881 | 200 |
| /api/v1/map?namespace=payments-03 | 2 | 33476 | 200 |
| /api/v1/map?namespace=payments-04 | 2 | 37658 | 200 |
| /api/v1/map?namespace=payments-05 | 2 | 41587 | 200 |
| /api/v1/map?namespace=payments-06 | 2 | 35716 | 200 |
| /api/v1/map?namespace=pricing-01 | 2 | 37615 | 200 |
| /api/v1/map?namespace=pricing-02 | 2 | 36421 | 200 |
| /api/v1/map?namespace=pricing-03 | 2 | 45052 | 200 |
| /api/v1/map?namespace=pricing-04 | 2 | 39126 | 200 |
| /api/v1/map?namespace=pricing-05 | 2 | 28094 | 200 |
| /api/v1/map?namespace=recommend-01 | 2 | 37515 | 200 |
| /api/v1/map?namespace=recommend-02 | 2 | 37129 | 200 |
| /api/v1/map?namespace=recommend-03 | 2 | 40578 | 200 |
| /api/v1/map?namespace=recommend-04 | 2 | 41463 | 200 |
| /api/v1/map?namespace=recommend-05 | 2 | 35413 | 200 |
| /api/v1/map?namespace=reporting-01 | 2 | 33354 | 200 |
| /api/v1/map?namespace=reporting-02 | 2 | 43078 | 200 |
| /api/v1/map?namespace=reporting-03 | 2 | 36955 | 200 |
| /api/v1/map?namespace=reporting-04 | 2 | 40500 | 200 |
| /api/v1/map?namespace=reporting-05 | 1004 | 45693 | 200 |
| /api/v1/map?namespace=returns-01 | 2 | 45352 | 200 |
| /api/v1/map?namespace=returns-02 | 2 | 42548 | 200 |
| /api/v1/map?namespace=returns-03 | 2 | 32706 | 200 |
| /api/v1/map?namespace=returns-04 | 2 | 30635 | 200 |
| /api/v1/map?namespace=returns-05 | 2 | 41400 | 200 |
| /api/v1/map?namespace=reviews-01 | 3 | 49005 | 200 |
| /api/v1/map?namespace=reviews-02 | 2 | 39019 | 200 |
| /api/v1/map?namespace=reviews-03 | 2 | 47731 | 200 |
| /api/v1/map?namespace=reviews-04 | 2 | 42839 | 200 |
| /api/v1/map?namespace=reviews-05 | 2 | 39317 | 200 |
| /api/v1/map?namespace=risk-01 | 2 | 37982 | 200 |
| /api/v1/map?namespace=risk-02 | 2 | 34433 | 200 |
| /api/v1/map?namespace=risk-03 | 2 | 46466 | 200 |
| /api/v1/map?namespace=risk-04 | 2 | 33660 | 200 |
| /api/v1/map?namespace=risk-05 | 2 | 37260 | 200 |
| /api/v1/map?namespace=search-01 | 2 | 41708 | 200 |
| /api/v1/map?namespace=search-02 | 2 | 37023 | 200 |
| /api/v1/map?namespace=search-03 | 2 | 41839 | 200 |
| /api/v1/map?namespace=search-04 | 2 | 40595 | 200 |
| /api/v1/map?namespace=search-05 | 2 | 27893 | 200 |
| /api/v1/map?namespace=search-06 | 1003 | 42569 | 200 |
| /api/v1/map?namespace=shipping-01 | 2 | 33349 | 200 |
| /api/v1/map?namespace=shipping-02 | 2 | 44273 | 200 |
| /api/v1/map?namespace=shipping-03 | 2 | 38230 | 200 |
| /api/v1/map?namespace=shipping-04 | 2 | 43998 | 200 |
| /api/v1/map?namespace=shipping-05 | 2 | 40081 | 200 |
| /api/v1/map?namespace=stress-conn | 1 | 15279 | 200 |
| /api/v1/map?namespace=stress-cw | 1 | 11352 | 200 |
| /api/v1/map?namespace=stress-load | 1 | 13180 | 200 |
| /api/v1/map?namespace=stress-oidc | 1 | 11354 | 200 |
| /api/v1/map?namespace=stress-pg | 2 | 11540 | 200 |
| /api/v1/map?namespace=stress-tricky | 2 | 30079 | 200 |
| /api/v1/map?namespace=stress-wide | 4 | 124701 | 200 |
| /api/v1/map?namespace=support-01 | 2 | 43605 | 200 |
| /api/v1/map?namespace=support-02 | 2 | 36016 | 200 |
| /api/v1/map?namespace=support-03 | 2 | 34131 | 200 |
| /api/v1/map?namespace=support-04 | 2 | 48884 | 200 |
| /api/v1/map?namespace=support-05 | 2 | 43528 | 200 |
| /api/v1/map?namespace=tax-01 | 2 | 43018 | 200 |
| /api/v1/map?namespace=tax-02 | 2 | 29995 | 200 |
| /api/v1/map?namespace=tax-03 | 2 | 37302 | 200 |
| /api/v1/map?namespace=tax-04 | 1004 | 37637 | 200 |
| /api/v1/map?namespace=tax-05 | 3 | 39164 | 200 |
| /api/v1/map?namespace=warehouse-01 | 2 | 44736 | 200 |
| /api/v1/map?namespace=warehouse-02 | 2 | 34249 | 200 |
| /api/v1/map?namespace=warehouse-03 | 3 | 43358 | 200 |
| /api/v1/map?namespace=warehouse-04 | 3 | 42077 | 200 |
| /api/v1/map?namespace=warehouse-05 | 2 | 46547 | 200 |
| /api/v1/workloads (3 pages) | 18 | 833610 | 200 |
| /api/v1/nodes | 33 | 1633102 | 200 |
| /api/v1/security (6 pages) | 35 | 1961426 | 200 |
