# Deploying kubesentry on Amazon EKS

This guide installs kubesentry on an EKS cluster with the Helm chart in `charts/kubesentry`. The target setup:

- **Sign-in:** SSO through an oauth2-proxy sidecar, behind an internal ALB.
- **Visibility:** each user sees what their Kubernetes RBAC allows. kubesentry asks the API server with SubjectAccessReviews.
- **Metrics:** Amazon Managed Service for Prometheus (AMP), signed with SigV4.
- **Audit:** the EKS control-plane audit log is read from CloudWatch Logs and stored in RDS for PostgreSQL.
- **Availability:** two replicas spread across zones, with a PodDisruptionBudget, NetworkPolicy and API Priority and Fairness.

`charts/kubesentry/examples/values-eks.yaml` is the matching values file. Each section below explains one part of it.

```
browser ──HTTPS──> ALB (internal, ACM cert) ──> pod:4180 oauth2-proxy ──unix socket──> kubesentry (UI, /api)    
                                                     │ OIDC                              │ informers, SubjectAccessReviews ──> EKS API server
                                                     └──> Okta / Entra ID / Cognito      │ SigV4 queries ──────────────────> AMP workspace
node agents (DaemonSet) ──token──> kubesentry-ingest :8081 (every replica)              │ FilterLogEvents ────────────────> CloudWatch Logs
Prometheus / ADOT ───────────────> kubesentry-ops :9090 (/metrics)                       └ audit store ────────────────────> RDS PostgreSQL (TLS)
```

## Contents

1. [Prerequisites](#1-prerequisites)
2. [Images](#2-images)
3. [IAM: policy, and IRSA or Pod Identity](#3-iam)
4. [EKS control-plane audit logging](#4-eks-control-plane-audit-logging)
5. [RDS for PostgreSQL](#5-rds-for-postgresql)
6. [SSO with oauth2-proxy behind the ALB](#6-sso-with-oauth2-proxy-behind-the-alb)
7. [Mapping IdP groups to Kubernetes RBAC](#7-mapping-idp-groups-to-kubernetes-rbac)
8. [Granting access to kubesentry's own data](#8-granting-access-to-kubesentrys-own-data)
9. [Network policy with the VPC CNI](#9-network-policy-with-the-vpc-cni)
10. [The agent: namespace, Pod Security, Bottlerocket](#10-the-agent)
11. [Install](#11-install)
12. [Sizing](#12-sizing)
13. [Upgrade and rollback](#13-upgrade-and-rollback)
14. [First-run checklist](#14-first-run-checklist)

## 1. Prerequisites

- **EKS 1.30 or later.** The chart uses the native `preStop` sleep action so the ALB can deregister a pod before it stops. On older versions the chart leaves the action out.
- **[AWS Load Balancer Controller](https://kubernetes-sigs.github.io/aws-load-balancer-controller/)**, for the ALB Ingress (`ingressClassName: alb`).
- **An AMP workspace**, with a collector that writes this cluster's metrics to it. The collector can be the AMP managed scraper, ADOT or a Prometheus agent. Leak detection needs `container_memory_working_set_bytes` from cAdvisor, so check that the collector scrapes the kubelet's cAdvisor endpoint. If several clusters share the workspace, give each a `cluster` external label.
- **RDS for PostgreSQL 15 or later**, reachable from the pods' subnets. You can skip it and use the in-memory audit store, but only with one replica, and history is lost on restart.
- **An OIDC application** in your IdP (Okta, Entra ID or Cognito; see section 6), and an ACM certificate for the host name.
- **Optional:**
  - ElastiCache for Redis, for oauth2-proxy sessions when users are in many groups.
  - The VPC CNI with network policy enabled (section 9).
  - prometheus-operator CRDs, for the ServiceMonitor and PrometheusRule.
- **Tools:** `helm` 3.14 or later (or 4.x), `kubectl`, `aws` CLI v2 and `docker buildx`.

## 2. Images

Build multi-arch images (linux/amd64 and linux/arm64) with an SBOM and provenance attestations, and push them to ECR:

```bash
aws ecr create-repository --repository-name kubesentry
aws ecr create-repository --repository-name kubesentry-agent
aws ecr get-login-password --region us-east-1 \
  | docker login --username AWS --password-stdin 111122223333.dkr.ecr.us-east-1.amazonaws.com
hack/build-images.sh --push --registry 111122223333.dkr.ecr.us-east-1.amazonaws.com --version v0.1.0
```

Then point the chart at the images, preferably by digest:

```yaml
image:
  repository: 111122223333.dkr.ecr.us-east-1.amazonaws.com/kubesentry
  tag: v0.1.0
agent:
  image:
    repository: 111122223333.dkr.ecr.us-east-1.amazonaws.com/kubesentry-agent
    tag: v0.1.0
```

Both images are distroless `static:nonroot`, run as uid 65532, and contain one static binary each.

## 3. IAM

kubesentry calls three AWS APIs, all with the pod's own role:

- CloudWatch Logs, for the audit log
- AMP, for metrics
- RDS IAM authentication, which is optional and only applies when you use it

The agent needs no AWS access.

### Permissions policy

Replace the region, account, cluster name and workspace ID.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadClusterAuditLog",
      "Effect": "Allow",
      "Action": ["logs:FilterLogEvents"],
      "Resource": "arn:aws:logs:us-east-1:111122223333:log-group:/aws/eks/prod-eks/cluster:*"
    },
    {
      "Sid": "FindClusterLogGroup",
      "Effect": "Allow",
      "Action": ["logs:DescribeLogGroups"],
      "Resource": "arn:aws:logs:us-east-1:111122223333:log-group:*"
    },
    {
      "Sid": "QueryManagedPrometheus",
      "Effect": "Allow",
      "Action": ["aps:QueryMetrics", "aps:GetSeries", "aps:GetLabels", "aps:GetMetricMetadata"],
      "Resource": "arn:aws:aps:us-east-1:111122223333:workspace/ws-12345678-abcd-1234-abcd-123456789012"
    }
  ]
}
```

`DescribeLogGroups` only returns log group names and settings. AWS evaluates it against `log-group:*`, so you cannot reliably scope it to a single group.

Add these statements only for the features that use them:

```json
{
  "Sid": "RdsIamAuthentication",
  "Effect": "Allow",
  "Action": "rds-db:connect",
  "Resource": "arn:aws:rds-db:us-east-1:111122223333:dbuser:db-ABCDEFGHIJKLMNOPQRSTUVWXYZ/kubesentry"
},
{
  "Sid": "ReadAccessEntries",
  "Effect": "Allow",
  "Action": ["eks:ListAccessEntries", "eks:ListAssociatedAccessPolicies"],
  "Resource": [
    "arn:aws:eks:us-east-1:111122223333:cluster/prod-eks",
    "arn:aws:eks:us-east-1:111122223333:access-entry/prod-eks/*"
  ]
}
```

- **`rds-db:connect`** is for RDS IAM authentication instead of a password. The resource is the DB instance's resource ID, not its name.
- **`eks:ListAccessEntries`** and **`eks:ListAssociatedAccessPolicies`** are for a future view of EKS access entries.

This version uses neither: it connects to Postgres with the password in the DSN.

### IRSA or EKS Pod Identity

Both give the `kubesentry` ServiceAccount the role above, and the AWS SDK in kubesentry picks up either automatically.

| | IRSA | EKS Pod Identity |
|---|---|---|
| Cluster setup | an IAM OIDC provider for the cluster | the `eks-pod-identity-agent` add-on |
| Role trust | `sts:AssumeRoleWithWebIdentity` from the cluster's OIDC provider, conditioned on the ServiceAccount | `sts:AssumeRole` and `sts:TagSession` from `pods.eks.amazonaws.com` |
| Binding to the pod | ServiceAccount annotation `eks.amazonaws.com/role-arn` | an EKS pod identity association; **no annotation** |
| Reusing a role across clusters | needs a trust statement per cluster's OIDC provider | the same trust policy works everywhere |
| NetworkPolicy egress | STS on 443 | the node-local agent on 169.254.170.23:80 (`networkPolicy.egress.podIdentityAgent: true`) |

**IRSA:**

```bash
eksctl utils associate-iam-oidc-provider --cluster prod-eks --approve   # once per cluster
OIDC=$(aws eks describe-cluster --name prod-eks --query 'cluster.identity.oidc.issuer' --output text | sed 's#https://##')
cat > trust.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Federated": "arn:aws:iam::111122223333:oidc-provider/${OIDC}"},
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {"StringEquals": {
      "${OIDC}:sub": "system:serviceaccount:kubesentry:kubesentry",
      "${OIDC}:aud": "sts.amazonaws.com"
    }}
  }]
}
EOF
aws iam create-role --role-name kubesentry-prod-eks --assume-role-policy-document file://trust.json
aws iam put-role-policy --role-name kubesentry-prod-eks --policy-name kubesentry --policy-document file://policy.json
```

Then set the annotation in the values:

```yaml
serviceAccount:
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::111122223333:role/kubesentry-prod-eks
```

**EKS Pod Identity:**

```bash
aws eks create-addon --cluster-name prod-eks --addon-name eks-pod-identity-agent   # once per cluster
cat > trust.json <<'EOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "pods.eks.amazonaws.com"},
    "Action": ["sts:AssumeRole", "sts:TagSession"]
  }]
}
EOF
aws iam create-role --role-name kubesentry-prod-eks --assume-role-policy-document file://trust.json
aws iam put-role-policy --role-name kubesentry-prod-eks --policy-name kubesentry --policy-document file://policy.json
aws eks create-pod-identity-association --cluster-name prod-eks \
  --namespace kubesentry --service-account kubesentry \
  --role-arn arn:aws:iam::111122223333:role/kubesentry-prod-eks
```

Leave `serviceAccount.annotations` empty. The association names the ServiceAccount, which is `<release>` by default (`kubesentry` for the release name `kubesentry`).

## 4. EKS control-plane audit logging

EKS writes the API server audit log to CloudWatch Logs once audit logging is enabled. The log group is `/aws/eks/<cluster>/cluster` and the streams are named `kube-apiserver-audit-*`.

```bash
aws eks update-cluster-config --region us-east-1 --name prod-eks \
  --logging '{"clusterLogging":[{"types":["audit"],"enabled":true}]}'
# CloudWatch keeps logs forever by default; kubesentry keeps its own copy in Postgres.
aws logs put-retention-policy --log-group-name /aws/eks/prod-eks/cluster --retention-in-days 30
```

- **Audit policy:** EKS's audit policy is fixed. Request and response bodies are not written for most resources, and kubesentry never decodes them anyway.
- **Cost:** a busy cluster produces millions of events a day, and CloudWatch ingestion is billed per GB.
- **Values:**

  ```yaml
  eks:
    clusterName: prod-eks       # gives the log group /aws/eks/prod-eks/cluster
    region: us-east-1
  audit:
    store: postgres
    sources:
      cloudwatch:
        enabled: true
        start: 24h              # first start reads back this far, then follows a checkpoint
        # logGroup, streamPrefix and endpoint (a VPC endpoint) only when they differ from the defaults
  ```

- **Which replica reads:** only the replica holding a Postgres advisory lock reads CloudWatch. When that replica stops, another takes the lock and resumes from the stored checkpoint.
- **Quota:** `FilterLogEvents` has a low request quota per account and Region, shared with every other tool that calls it. Throttling shows up as `kubesentry_cloudwatch_lag_seconds` rising. The `KubesentryCloudWatchLag` alert fires when the lag stays above 5 minutes for 10 minutes.
- **Without CloudWatch:** the chart refuses `audit.sources.cloudwatch.enabled` unless `eks.clusterName` or an explicit `logGroup` is set.

## 5. RDS for PostgreSQL

Create a database and an owner role. kubesentry creates its schema (`audit.postgres.schema`, one per cluster if clusters share a database), runs embedded migrations under an advisory lock, and creates and drops daily partitions according to `audit.retention`.

```sql
CREATE ROLE kubesentry LOGIN PASSWORD 'change-me';
CREATE DATABASE kubesentry OWNER kubesentry;
```

**TLS with `verify-full`.** This checks both the certificate chain and that the host name matches. Three things are needed:

1. Connect to the RDS endpoint name itself, not a CNAME.
2. Trust the RDS CA bundle.
3. Keep `rds.force_ssl=1`, which is the default for RDS for PostgreSQL 15 and later, so the server refuses plaintext.

```bash
kubectl create namespace kubesentry
curl -fsSLo global-bundle.pem https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem
kubectl -n kubesentry create configmap rds-ca --from-file=global-bundle.pem
# URL-encode the password if it contains reserved characters.
kubectl -n kubesentry create secret generic kubesentry-pg \
  --from-literal=dsn='postgres://kubesentry:change-me@prod-eks-audit.abcdefghijkl.us-east-1.rds.amazonaws.com:5432/kubesentry'
```

```yaml
audit:
  store: postgres
  retention: 30d
  postgres:
    existingSecret: kubesentry-pg
    schema: prod_eks
    sslmode: verify-full          # PGSSLMODE; an sslmode in the DSN wins
    sslRootCert:
      configMap: rds-ca           # PGSSLROOTCERT=/etc/kubesentry/pg-ca/global-bundle.pem
      key: global-bundle.pem
```

- **Connection pooling:** connect directly, or through a proxy in session-pooling mode. Transaction pooling (PgBouncer `pool_mode=transaction`) breaks the session advisory lock that elects the CloudWatch reader and the retention job.
- **Backups:** turn on automated backups with point-in-time recovery. Take a snapshot before every kubesentry upgrade (section 13).
- **Writes under pressure:** the writer batches inserts. While Postgres is unreachable, events queue in memory. When the queue is full, the webhook answers 503 with `Retry-After`. The CloudWatch reader commits its checkpoint in the same transaction as the events, so it resumes where it stopped and no events are lost. The `KubesentryPostgresErrors` alert fires after 10 minutes of failures.

## 6. SSO with oauth2-proxy behind the ALB

With `oauth2Proxy.enabled`, each pod runs an oauth2-proxy sidecar on port 4180. It is the only thing the web Service and the ALB reach. kubesentry has no TCP web port: in proxy mode it listens on a Unix socket, `/var/run/kubesentry/web.sock` (mode 0660), in an in-memory `emptyDir` only the two containers mount, and oauth2-proxy forwards to it (`--upstream=unix:///var/run/kubesentry/web.sock`; oauth2-proxy supports Unix socket upstreams since v7.6.0). Identity headers (`X-Forwarded-Email`, `X-Forwarded-Groups`) are trusted on that socket and nowhere else. A TCP listener trusting loopback would not do: `kubectl port-forward` arrives from loopback, so anyone allowed `pods/portforward` in the kubesentry namespace could claim any identity. The sidecar strips any identity headers a client sends (`--skip-auth-strip-headers`). API calls without a session get 401 instead of a redirect (`--api-route=^/api/`).

- `X-Forwarded-Groups` is comma-separated (oauth2-proxy joins a user's groups with commas), so group names containing commas are not supported. A repeated `X-Forwarded-Email` is refused (401). IdP groups starting with a platform prefix (`system:`, `eks:`, or whatever `server.systemPrincipalPrefixes` lists) are dropped; groups your `auth.groupMap` produces are kept.
- The chart's schema accepts only the headers oauth2-proxy sets and strips for `auth.userHeader` and `auth.groupsHeader`; set `auth.allowCustomHeaders: true` for an SSO proxy of your own.
- `server.allowedHosts` (`-allowed-hosts`) optionally limits the Host names kubesentry answers, e.g. `[kubesentry.example.com]`.

Secrets, created before installing:

```bash
kubectl -n kubesentry create secret generic kubesentry-oauth2 \
  --from-literal=client-secret='<from the IdP>' \
  --from-literal=cookie-secret="$(openssl rand -base64 32 | tr -- '+/' '-_')"
```

ALB Ingress (in the example values):

```yaml
ingress:
  enabled: true
  className: alb
  host: kubesentry.prod.example.com     # also gives --redirect-url https://<host>/oauth2/callback
  annotations:
    alb.ingress.kubernetes.io/scheme: internal
    alb.ingress.kubernetes.io/target-type: ip
    alb.ingress.kubernetes.io/listen-ports: '[{"HTTPS":443}]'
    alb.ingress.kubernetes.io/certificate-arn: arn:aws:acm:us-east-1:111122223333:certificate/...
    alb.ingress.kubernetes.io/ssl-policy: ELBSecurityPolicy-TLS13-1-2-2021-06
    alb.ingress.kubernetes.io/healthcheck-path: /ping     # oauth2-proxy's health endpoint; /healthz without the sidecar
    alb.ingress.kubernetes.io/target-group-attributes: deregistration_delay.timeout_seconds=10
    alb.ingress.kubernetes.io/load-balancer-attributes: idle_timeout.timeout_seconds=75
```

**Timeouts.** A request passes three timeouts, and each must be longer than the one above it in this table:

| Hop | Timeout | Setting |
|---|---|---|
| kubesentry | 30s for API routes, 60s for the pod page (`/diagnostics`) and `/oom`; then it answers 503 `timeout` | built in |
| oauth2-proxy | 65s by default; then it answers 502 | `oauth2Proxy.upstreamTimeout` (`--upstream-timeout`; oauth2-proxy's own default is 30s) |
| ALB | 60s by default; then it answers 504 | `idle_timeout.timeout_seconds` in `alb.ingress.kubernetes.io/load-balancer-attributes` |

With the ALB default of 60s, the pod page and `/oom` can end in the ALB's 504 before kubesentry's own answer arrives, so raise the idle timeout above `upstreamTimeout`, e.g. to 75. The idle timeout is an attribute of the whole load balancer: with `group.name`, set it on one Ingress of the group, or give every Ingress the same value. oauth2-proxy sets no idle timeout on its keep-alive connections, so a longer ALB idle timeout does not cause 502s from connections the target closed first.

**Trusted proxies.** The sidecar runs with `--reverse-proxy`, so it believes forwarded headers: `X-Forwarded-Proto` and `X-Forwarded-Host` for redirects, and the client address header for its logs and IP rules. `oauth2Proxy.trustedProxyIPs` (`--trusted-proxy-ip`, one per entry) limits which direct peers may set them; from any other peer they are ignored. Left empty, oauth2-proxy trusts them from every peer (`0.0.0.0/0`, `::/0`) and logs a warning at startup, and the chart's install notes repeat it. With `target-type: ip` the ALB connects to the pods from its ENIs in the ALB's subnets, so list those subnets' CIDRs, the same list as `networkPolicy.ingress.web.fromCIDRs` (section 9), or the VPC CIDR if you prefer one entry:

```yaml
oauth2Proxy:
  trustedProxyIPs:      # the ALB's subnets
    - 10.20.0.0/22
    - 10.20.4.0/22
    - 10.20.8.0/22
```

- Identity headers (`X-Forwarded-Email`, `X-Forwarded-Groups`) do not depend on this setting: the sidecar always strips them from the request and sets its own.
- Kubelet probes (`/ping`) come from the node's IP and send no forwarded headers, so they keep working whatever the list holds.
- `alb.ingress.kubernetes.io/inbound-cidrs` is a different setting: it limits which clients may reach the ALB's listener (its security group). `trustedProxyIPs` limits which peers oauth2-proxy believes about the original client. Set both.

Label the namespace for [pod readiness gates](https://kubernetes-sigs.github.io/aws-load-balancer-controller/latest/deploy/pod_readiness_gate/) so a rolling update waits until new pods are healthy in the target group:

```bash
kubectl label namespace kubesentry elbv2.k8s.aws/pod-readiness-gate-inject=enabled
```

Keep `preStopSleepSeconds` (15 by default) above the deregistration delay, so a stopping pod finishes in-flight requests after the ALB stops sending new ones.

### Okta

1. Create an OIDC **Web Application**:
   - Grant types: Authorization Code, and Refresh Token if you set `cookie.refresh`.
   - Sign-in redirect URI: `https://kubesentry.prod.example.com/oauth2/callback`.
   - Assign the groups that may use kubesentry.
2. Add a `groups` claim to the custom authorization server (Security → API → default → Claims):
   - Include it in the ID token, value type Groups.
   - Add a filter, for example "Starts with `k8s-`", so the claim stays small.

```yaml
oauth2Proxy:
  enabled: true
  provider: oidc
  issuerURL: https://example.okta.com/oauth2/default
  clientID: 0oa1example2kubesentry3
  existingSecret: kubesentry-oauth2
  scope: openid email profile groups     # add offline_access for cookie.refresh
  groupsClaim: groups
  allowedGroups: [k8s-platform, k8s-payments]
```

### Microsoft Entra ID

1. Register an application:
   - Web redirect URI: `https://kubesentry.prod.example.com/oauth2/callback`.
   - Create a client secret.
2. Under **Token configuration**, add a groups claim. Prefer "Groups assigned to the application" over all security groups, to keep tokens small.
3. Entra ID sends group **object IDs** (GUIDs), not names. Synced on-premises groups are the exception, and can send `sAMAccountName`. Either write RoleBindings for the GUIDs, or map them in `auth.groupMap`:

```yaml
oauth2Proxy:
  enabled: true
  provider: entra-id
  issuerURL: https://login.microsoftonline.com/<tenant-id>/v2.0
  clientID: <application-client-id>
  existingSecret: kubesentry-oauth2
  # User.Read lets the provider resolve group overage through Microsoft Graph.
  scope: openid email profile User.Read
  groupsClaim: groups
  sessionStore:
    type: redis                      # see "Group overage and cookie size"
    redis:
      connectionURL: rediss://master.kubesentry-sessions.abcdef.use1.cache.amazonaws.com:6379
      existingSecret: kubesentry-redis
auth:
  groupMap:
    "3f2a9c4e-0000-0000-0000-000000000001": ["platform-admins"]
    "8b7d1e2f-0000-0000-0000-000000000002": ["payments-viewers"]
```

**Group overage:** when a user is in more than 200 groups, Entra ID leaves the groups out of the token and sends an overage marker instead. oauth2-proxy's `entra-id` provider then reads the full list from Microsoft Graph (`transitiveMemberOf`). Without the `User.Read` scope it cannot, and such users sign in with no groups. They then see nothing, because kubesentry fails closed. See the [oauth2-proxy Entra ID provider docs](https://oauth2-proxy.github.io/oauth2-proxy/configuration/providers/ms_entra_id) for multi-tenant settings and federated credentials.

### Amazon Cognito

1. Create an app client with a client secret:
   - OAuth flow: authorization code grant.
   - Scopes: `openid`, `email`, `profile`.
   - Callback URL: `https://kubesentry.prod.example.com/oauth2/callback`.
2. Give the user pool a domain.
3. Cognito user pool groups arrive in the `cognito:groups` claim.

```yaml
oauth2Proxy:
  enabled: true
  provider: oidc
  issuerURL: https://cognito-idp.us-east-1.amazonaws.com/us-east-1_AbCdEfGhI
  clientID: <app-client-id>
  existingSecret: kubesentry-oauth2
  scope: openid email profile
  groupsClaim: cognito:groups
```

oauth2-proxy rejects users whose `email_verified` claim is false. Verify the emails of users you import, or federate Cognito to your corporate IdP and map its groups.

### Group overage and cookie size

oauth2-proxy keeps the session, including the ID token with every group, in an encrypted cookie. It splits large cookies into several. A user in hundreds of groups can exceed what browsers and the ALB accept for request headers, and then gets errors at sign-in. Use a server-side session store, which leaves only a small ticket in the cookie:

```yaml
oauth2Proxy:
  sessionStore:
    type: redis
    redis:
      connectionURL: rediss://master.kubesentry-sessions.abcdef.use1.cache.amazonaws.com:6379   # TLS
      existingSecret: kubesentry-redis       # key redis-password: the ElastiCache AUTH token
      # cluster mode enabled:
      # useCluster: true
      # clusterConnectionURLs: [rediss://node1:6379, rediss://node2:6379]
```

```bash
kubectl -n kubesentry create secret generic kubesentry-redis --from-literal=redis-password='<auth token>'
```

Filtering the groups claim at the IdP, as in the Okta and Entra ID steps above, also helps. kubesentry only needs the groups your RBAC refers to.

## 7. Mapping IdP groups to Kubernetes RBAC

kubesentry never decides access itself. For every signed-in user it asks the API server what that user may do, with SubjectAccessReviews:

- **user:** `auth.usernamePrefix` + the email from oauth2-proxy
- **groups:** `auth.groupsPrefix` + each IdP group, plus any mapped groups from `auth.groupMap`, plus `system:authenticated`

The API server answers with its full authorizer chain. A user sees a namespace's pods, workloads and findings only if they could `list pods` there with kubectl. The cluster-wide pages need cluster-wide `list` on nodes, persistentvolumes, storageclasses, clusterrolebindings and clusterissuers respectively. Results are cached for `auth.authzCacheTTL` (5m), and denials for `auth.authzDenyTTL` (1m).

So the RBAC subjects must use the names kubesentry sends. There are two common ways to line them up on EKS.

**A. Access entries with Kubernetes groups.** This fits when engineers use kubectl through IAM roles, for example IAM Identity Center permission sets. Give each role's access entry a Kubernetes group, write RBAC for that group, and map the IdP group to the same name in kubesentry:

```bash
aws eks create-access-entry --cluster-name prod-eks \
  --principal-arn arn:aws:iam::111122223333:role/payments-engineer \
  --kubernetes-groups payments-viewers
kubectl create rolebinding payments-view -n payments --clusterrole=view --group=payments-viewers
```

```yaml
auth:
  groupMap:
    payments-engineers: ["payments-viewers"]   # IdP group -> the access entry's Kubernetes group
```

kubectl (through IAM) and kubesentry (through SSO) then rely on the same RoleBinding.

**B. An EKS OIDC identity provider.** This fits when kubectl users already sign in with the same IdP, for example through kubelogin. Associate the IdP with the cluster, using prefixes:

```bash
aws eks associate-identity-provider-config --cluster-name prod-eks --oidc \
  identityProviderConfigName=okta,issuerUrl=https://example.okta.com/oauth2/default,clientId=0oa1example2kubesentry3,usernameClaim=email,usernamePrefix=oidc:,groupsClaim=groups,groupsPrefix=oidc:
kubectl create rolebinding payments-view -n payments --clusterrole=view --group=oidc:k8s-payments
```

```yaml
auth:
  usernamePrefix: "oidc:"
  groupsPrefix: "oidc:"
```

Use prefixes for B and `groupMap` for A. Pick one per group, so the names stay easy to follow.

> **Caveat: EKS access *policies* are invisible to kubesentry.** Access policies such as `AmazonEKSViewPolicy` or `AmazonEKSClusterAdminPolicy` are associated with an IAM principal's access entry. EKS's authorizer applies them only to requests from that IAM principal's Kubernetes identity. A SubjectAccessReview for an SSO identity (an email and IdP groups) matches no IAM principal, so access policies grant it nothing. Only Kubernetes RBAC objects count. These are Roles and ClusterRoles bound to users or groups, including groups you attach to access entries with `--kubernetes-groups`. If a team's access today comes only from access policies, add an equivalent RoleBinding (for example `view` for `AmazonEKSViewPolicy`) for their group.

**Many users, few groups.** With thousands of users who share a few dozen groups, set `auth.shareByGroups: true`. Reviews are then cached per group set rather than per user. A user whom any RoleBinding or ClusterRoleBinding names personally is still cached on their own, so their grants never reach the rest of their groups; an authorizer that decides by user name outside RBAC (an EKS access entry for one IAM principal) is not visible to kubesentry, so with such entries leave this off. `auth.authzQPS` (default 200) caps how fast kubesentry sends reviews. Watch `kubesentry_authz_reviews_total` and the `KubesentryAuthzReviewErrors` alert.

## 8. Granting access to kubesentry's own data

Some data has no Kubernetes API of its own. For that, kubesentry checks virtual resources in the `kubesentry.io` API group. No such API is served, but RBAC can grant them and SubjectAccessReviews evaluate them. The chart creates one ClusterRole for each. The names below are for the release name `kubesentry`.

| ClusterRole | Grants | Bind with |
|---|---|---|
| `kubesentry-audit-viewer` | `list auditevents.kubesentry.io`: the audit trail | a RoleBinding for one namespace's events. A ClusterRoleBinding for all namespaces, plus events without a namespace (RBAC, nodes, cluster-scoped objects) |
| `kubesentry-process-viewer` | `get processes.kubesentry.io`: the processes inside pods | a RoleBinding per namespace, or a ClusterRoleBinding |
| `kubesentry-agents-viewer` | `list agents.kubesentry.io`: node agent health | a ClusterRoleBinding (it is cluster-scoped) |

```yaml
# The payments team: its namespace's audit events and processes.
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: kubesentry-audit, namespace: payments}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: kubesentry-audit-viewer}
subjects: [{apiGroup: rbac.authorization.k8s.io, kind: Group, name: payments-viewers}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: kubesentry-processes, namespace: payments}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: kubesentry-process-viewer}
subjects: [{apiGroup: rbac.authorization.k8s.io, kind: Group, name: payments-viewers}]
---
# The platform team: everything, cluster-wide.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: kubesentry-platform-audit}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: kubesentry-audit-viewer}
subjects: [{apiGroup: rbac.authorization.k8s.io, kind: Group, name: platform-admins}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: kubesentry-platform-agents}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: kubesentry-agents-viewer}
subjects: [{apiGroup: rbac.authorization.k8s.io, kind: Group, name: platform-admins}]
```

**Aggregation.** To give these with the built-in roles instead, list the roles under `rbac.viewerRoles.<role>.aggregateTo`:

- `view` reaches `edit` and `admin` too, since they include `view`.
- A reasonable choice is `processViewer.aggregateTo: [edit]` and `auditViewer.aggregateTo: [admin]`. Command lines are redacted, but treat them as sensitive. The audit trail shows who did what in a namespace.

**Cluster pages.** The built-in `view` role does not include nodes, persistent volumes or storage classes. Users without cluster-wide `list` on these still see the pages, degraded to names with status unknown. To show the cluster pages fully to a group, bind it a ClusterRole that grants `list` on `nodes`, `persistentvolumes`, `storage.k8s.io/storageclasses`, `rbac.authorization.k8s.io/clusterrolebindings` and `cert-manager.io/clusterissuers`.

## 9. Network policy with the VPC CNI

Enable network policy enforcement in the VPC CNI add-on (VPC CNI 1.14 or later):

```bash
aws eks update-addon --cluster-name prod-eks --addon-name vpc-cni \
  --configuration-values '{"enableNetworkPolicy":"true"}'
```

Then turn on `networkPolicy`, which is off by default. Each listener is open only to the peers you list, and a listener with no peers is closed.

| Listener | Port | Typical peers |
|---|---|---|
| web | 4180 (with oauth2-proxy), else 8080 | the ALB's subnets (`target-type: ip` connects from the ALB's ENIs) |
| ingest | 8081 | the chart's agent pods (always allowed). Add CIDRs only for webhook senders or bulk importers |
| ops | 9090 | the namespace of your metrics collector |

With `egress.enabled`, the pods may reach only:

- DNS (CoreDNS in kube-system)
- 443 and 6443 to `https.toCIDRs`: the API server, STS, CloudWatch Logs, AMP and the IdP
- Postgres and Redis at their CIDRs
- with Pod Identity, the node-local agent (`podIdentityAgent: true`)

`0.0.0.0/0` on 443 is the pragmatic default. If you narrow it, include:

- the VPC subnets that hold the cluster's API server endpoint ENIs
- the cluster's service CIDR, since CNIs differ in whether they see the `kubernetes` Service's ClusterIP or the translated address
- your VPC endpoints for STS, CloudWatch Logs and AMP

`kubectl port-forward` does not cross the pod network, so the break-glass path (token mode, port 8080) keeps working under any policy. With the sidecar there is no TCP port to forward to kubesentry itself: see the break-glass step in section 14.

## 10. The agent

The node agent reads `/proc` to report the processes inside pods. It needs `hostPID: true`, and nothing else from the host: it is not privileged, runs as uid 65532, drops all capabilities and has a read-only root filesystem.

**Namespaces and Pod Security.** Only the Pod Security `privileged` level admits `hostPID`. Give the agent its own namespace, so the server's namespace can enforce `restricted`:

```yaml
agent:
  namespace: kubesentry-agent
  createNamespace: true        # labels it pod-security.kubernetes.io/enforce=privileged
```

```bash
kubectl label namespace kubesentry pod-security.kubernetes.io/enforce=restricted --overwrite
```

- **Token:** the chart writes the agent token Secret into both namespaces. With `tokens.agent.existingSecret`, create that Secret in both yourself.
- **System namespace:** the agent namespace is added to `-system-namespaces-add` automatically.

**Placement.** The agent requires `kubernetes.io/os=linux` and skips Fargate (`eks.amazonaws.com/compute-type=fargate`), which runs no DaemonSets. It tolerates every taint by default. Exclude more nodes with `agent.nodeAffinity.excludeLabels`.

**Bottlerocket and SELinux (untested).** Bottlerocket enforces SELinux. Each container runs as `container_t` with its own MCS categories, which can stop the agent from reading other containers' `/proc/<pid>` entries. On such nodes the agent may report few or no processes. That is not an error, just missing data. Your options:

- Exclude those nodes with `agent.nodeAffinity.excludeLabels`, using a label your node groups or NodePools put on Bottlerocket nodes.
- Give the agent a more privileged SELinux type through `agent.securityContext.seLinuxOptions`. Bottlerocket's `super_t` is effectively unconfined, so weigh that against the benefit.

Amazon Linux 2023 nodes do not enforce SELinux by default.

**TLS.** Agents post to `kubesentry-ingest.<namespace>.svc:8081`, and with `agent.fanout` to every replica through the headless Service. To encrypt this traffic:

1. Set `tls.enabled` and `tls.existingSecret` to a `kubernetes.io/tls` Secret for that name. A cert-manager Certificate works.
2. Give the agent the CA:
   - same namespace: the Secret's `ca.crt` is used automatically
   - other namespaces: `agent.tls.caSecret` or `agent.tls.caConfigMap`, for example a trust-manager bundle

## 11. Install

```bash
kubectl create namespace kubesentry   # if section 5 did not already
kubectl label namespace kubesentry \
  pod-security.kubernetes.io/enforce=restricted \
  elbv2.k8s.aws/pod-readiness-gate-inject=enabled --overwrite
# Secrets and ConfigMaps from sections 5 and 6: kubesentry-pg, rds-ca, kubesentry-oauth2, kubesentry-redis
helm upgrade --install kubesentry charts/kubesentry -n kubesentry \
  -f charts/kubesentry/examples/values-eks.yaml \
  -f my-overrides.yaml
```

The chart refuses some configurations with an explanation (`helm template` shows the same errors):

- **More than one replica with the memory audit store** and any audit source. Each replica would keep a partial history.
- **`auth.mode=proxy` with neither the sidecar nor `auth.trustedProxyCIDRs`.**
- **The CloudWatch source without `eks.clusterName` or `logGroup`.**
- **Missing required values:** `audit.store=postgres` without a DSN Secret, and the oauth2-proxy sidecar without a client ID, issuer or Secret.

**Generated tokens.** The API (break-glass), agent and audit webhook tokens are generated on first install and kept on upgrades: the chart looks up the existing Secrets. Argo CD and other tools that render with `helm template` cannot look Secrets up, and would generate new tokens on every sync. With them, create the Secrets yourself, for example with External Secrets, and set `tokens.<name>.existingSecret`.

**Alerts with AMP.** The PrometheusRule object only works with prometheus-operator. For AMP's managed rules, render the rules and load them as a rule groups namespace:

```bash
helm template kubesentry charts/kubesentry -n kubesentry -f values.yaml -s templates/prometheusrule.yaml \
  --set metrics.prometheusRule.enabled=true \
  --api-versions monitoring.coreos.com/v1/PrometheusRule | yq '.spec' > rules.yaml
aws amp create-rule-groups-namespace --workspace-id ws-... --name kubesentry --data fileb://rules.yaml
```

`docs/monitoring-eks.md` has a runbook for each of kubesentry's alerts and describes the "kubesentry health" Grafana dashboard (`metrics.grafanaDashboards`). It also covers an example kube-prometheus-stack profile for the cluster itself, with routing by owner.

## 12. Sizing

These are starting points until the stress report in `test/stress` replaces them with measured numbers. Each replica holds informers for the whole cluster, so its memory grows with object count, not with users.

| Cluster | Replicas | Server requests / limit | Agent per node | Postgres (30 days of audit) |
|---|---|---|---|---|
| up to 100 nodes, 2,000 pods | 1, or 2 with Postgres | 100m, 256Mi / 512Mi | 20m, 32Mi / 128Mi | db.t4g.small, 20 GiB |
| up to 500 nodes, 10,000 pods | 2 | 250m, 512Mi / 1.5Gi | same | db.t4g.medium, 50 GiB |
| up to 1,000 nodes, 20,000 pods | 2 or 3 | 500m, 1Gi / 2Gi | same | db.m7g.large, 100 GiB+ |

- **Memory:** the server sets GOMEMLIMIT to 90% of its memory limit, so the Go GC works harder near the limit instead of the pod being OOM-killed. Setting `GOMEMLIMIT` through `extraEnv` overrides it. Watch `kubesentry_snapshot_build_seconds` and container memory, then adjust.
- **Users:** user count drives SubjectAccessReviews and CPU, not memory. Thousands of users sharing groups are cheap with `auth.shareByGroups`.
- **Authorization cache and review rate:** each replica caches up to 100,000 access decisions (fixed; LRU), shared by all users. An active user needs about one entry per cluster-wide capability the UI checks (around 10), one scope per namespaced capability (pods, audit, processes, rolebindings), and one decision per namespace their RoleBindings propose for each of those: a user with 10 namespaces holds about 55 entries. Every entry is re-reviewed when it expires (`auth.authzCacheTTL`, default 5m), so the steady review rate is roughly *active users × entries per user ÷ TTL*: 1,000 such users need about 180 reviews/s, within the default `auth.authzQPS` of 200; 5,000 need about 900/s, and the cache (5,000 × 55 = 275,000 entries) no longer holds them, so evicted entries are reviewed again on the next request. At that scale use `auth.shareByGroups` (entries then scale with distinct group sets, not users), a longer `authzCacheTTL`, or a higher `authzQPS` if the API server has the headroom. Watch `kubesentry_authz_cache_total{result="miss"}` against `hit`, and `kubesentry_authz_reviews_total`.
- **Audit volume:** this depends on the cluster's write rate and controllers. Count roughly 1–2 KB per stored event, indexes included. Measure the first day (`kubesentry_audit_ingested_total`) and size storage from that.
- **Agents:** nodes with many thousands of processes need a higher agent memory limit. `agent.maxProcesses` caps what is sent.
- **API Priority and Fairness:** `apf.enabled` gives kubesentry its own priority level, so its initial LIST burst after a restart queues against its own share.

## 13. Upgrade and rollback

**Upgrading:**

1. Snapshot the RDS instance.
2. Read the release notes for schema migrations.
3. Run `helm upgrade` with the new chart and image tags.

How the rollout goes:

- New pods start next to the old ones (`maxUnavailable: 0`, `maxSurge: 1`). They become ready only after their caches have synced and the first view is built.
- The ALB stops sending traffic to an old pod before it exits (readiness gates, then the preStop sleep).
- The PDB keeps one replica up through node drains.
- The agent DaemonSet rolls 10% of nodes at a time.

**Migrations.** They run at startup under an advisory lock and are forward-only. A rollback to an older kubesentry is safe only when the newer release's notes say its migrations are backward compatible. Otherwise, restore the snapshot (or use point-in-time recovery) along with `helm rollback`.

**Rolling back:**

```bash
helm history kubesentry -n kubesentry
helm rollback kubesentry <revision> -n kubesentry
```

**Tokens** survive upgrades and rollbacks, because the Secrets are looked up rather than regenerated.

**Renaming.** Changing the release name or `fullnameOverride` creates new objects with new names, including the virtual-resource ClusterRoles your bindings refer to. Avoid it, or update the bindings.

## 14. First-run checklist

1. **Pods ready:** `kubectl -n kubesentry get pods` shows both containers ready (2/2) on every replica, in different zones.
2. **Data sources:** open `/readyz` with `kubectl -n kubesentry port-forward svc/kubesentry-ops 9090` and `curl -s localhost:9090/readyz`. It is 200 and lists no degraded sources: API server, Prometheus (AMP), Postgres and CloudWatch.
3. **Sign-in:** `https://<host>/` redirects to the IdP and back. `GET /api/v1/info` shows your identity and groups as kubesentry sees them, after prefixes and the group map.
4. **Scoping:**
   - A member of one team sees only that team's namespaces.
   - A platform admin sees every namespace and the cluster pages.
   - Someone with no bindings sees an empty but working UI.
5. **Audit:**
   - The Activity page shows events from the last minutes.
   - `kubesentry_cloudwatch_lag_seconds` stays under a minute.
   - `kubesentry_audit_store_errors_total` stays flat.
6. **Agents:**
   - The DaemonSet's ready count equals the number of non-Fargate Linux nodes.
   - `GET /api/v1/agents`, as an agents viewer, shows no stale nodes.
   - A pod page shows a Processes table.
7. **Metrics:** your collector scrapes `kubesentry-ops`, `kubesentry_snapshot_age_seconds` stays low, and the alert rules are loaded.
8. **Postgres TLS:** `SELECT ssl, version FROM pg_stat_ssl JOIN pg_stat_activity USING (pid) WHERE usename = 'kubesentry';` shows `ssl = t`.
9. **Network policy:**
   - From a pod in another namespace, `curl kubesentry.kubesentry.svc:4180` times out.
   - Through the ALB the UI still works.
10. **Break-glass:** with the sidecar, kubesentry listens only on the Unix socket inside the pod, so neither the token nor forged identity headers reach it from outside: `kubectl -n kubesentry port-forward deploy/kubesentry 8080` fails to connect. When SSO is down, `helm upgrade --reuse-values --set oauth2Proxy.enabled=false` switches to token mode on port 8080; then that port-forward with the API token from `kubectl -n kubesentry get secret kubesentry-api -o jsonpath='{.data.token}' | base64 -d` reaches `/api/v1/info`. Store the token in your vault, or set `tokens.api.enabled: false` if you do not want one.
11. **Pod Security:** `kubectl label --dry-run=server --overwrite namespace kubesentry pod-security.kubernetes.io/enforce=restricted` prints no warnings.
