# Running kubesentry from your workstation

kubesentry does not have to run inside the cluster. On a laptop (macOS, Windows or Linux) it reads the cluster with your own Kubernetes identity, like `kubectl` does, and serves the UI on `http://127.0.0.1:8080` for you alone. Nothing is installed in the cluster and nothing has to be exposed: the in-cluster Prometheus is reached through the API server.

This guide covers EKS. Any cluster that kubectl reaches works the same way, without the AWS parts.

```
your browser ──> kubesentry (127.0.0.1:8080, -auth-mode none)
                    │ list/watch with your identity ───────────> EKS API server
                    │ queries through services/<prometheus>/proxy ─┘ └──> in-cluster Prometheus
                    │ or SigV4 queries ──────────────────────────> Amazon Managed Prometheus
                    └ FilterLogEvents ───────────────────────────> CloudWatch Logs (EKS audit log)
```

## Contents

1. [Install](#1-install)
2. [EKS walkthrough](#2-eks-walkthrough)
3. [The permissions your identity needs](#3-the-permissions-your-identity-needs)
4. [What is not available remotely](#4-what-is-not-available-remotely)
5. [Several clusters](#5-several-clusters)
6. [A team setup on EC2 or ECS](#6-a-team-setup-on-ec2-or-ecs)
7. [Incidents](#7-incidents)
8. [Flags for remote mode](#8-flags-for-remote-mode)

## 1. Install

### A release binary

Each [release](https://github.com/ByronGary/kubesentry/releases) has a `kubesentry` binary with the UI built in, for macOS (`darwin_arm64` for Apple Silicon, `darwin_amd64` for Intel), Linux (`linux_amd64`, `linux_arm64`) and Windows (`windows_amd64`), plus `SHA256SUMS`.

macOS and Linux:

```bash
V=0.1.0
OS_ARCH=darwin_arm64          # or darwin_amd64, linux_amd64, linux_arm64
curl -fLO "https://github.com/ByronGary/kubesentry/releases/download/v$V/kubesentry_${V}_${OS_ARCH}.tar.gz"
curl -fLO "https://github.com/ByronGary/kubesentry/releases/download/v$V/SHA256SUMS"
shasum -a 256 -c SHA256SUMS --ignore-missing      # Linux: sha256sum -c SHA256SUMS --ignore-missing
tar -xzf "kubesentry_${V}_${OS_ARCH}.tar.gz" kubesentry
sudo install kubesentry /usr/local/bin/           # or anywhere on your PATH
kubesentry -version
```

The macOS binaries are not notarized. `curl` downloads are not quarantined, but a file downloaded with a browser is: clear the flag with `xattr -d com.apple.quarantine kubesentry`.

Windows (PowerShell):

```powershell
$V = "0.1.0"
$base = "https://github.com/ByronGary/kubesentry/releases/download/v$V"
Invoke-WebRequest "$base/kubesentry_${V}_windows_amd64.zip" -OutFile kubesentry.zip
Invoke-WebRequest "$base/SHA256SUMS" -OutFile SHA256SUMS
$want = (Select-String "kubesentry_${V}_windows_amd64.zip" SHA256SUMS).Line.Split(" ")[0]
if ((Get-FileHash kubesentry.zip -Algorithm SHA256).Hash.ToLower() -ne $want) { throw "checksum mismatch" }
Expand-Archive kubesentry.zip -DestinationPath "$env:LOCALAPPDATA\kubesentry"
& "$env:LOCALAPPDATA\kubesentry\kubesentry.exe" -version
```

SmartScreen may warn about an unsigned program the first time. `docs/release.md` shows how to check the images' signatures.

### The container image

The same server runs from `ghcr.io/byrongary/kubesentry`. The image has no AWS CLI, so give kubesentry AWS credentials and let it sign in to EKS itself with `-eks-cluster`:

```bash
docker run --rm -p 127.0.0.1:8080:8080 \
  -v "$HOME/.aws:/home/nonroot/.aws" -e HOME=/home/nonroot -e AWS_PROFILE=work \
  ghcr.io/byrongary/kubesentry:0.1.0 \
  -addr :8080 -api-token "$(openssl rand -hex 16 | tee /dev/stderr)" \
  -eks-cluster prod-eks -aws-region us-east-1
```

- **Listening.** Inside a container kubesentry must listen on all interfaces (`-addr :8080`), which needs `-api-token`: `-auth-mode none` is refused off loopback. Publishing the port on `127.0.0.1` keeps it to your machine. The UI asks for the token (printed above) once per browser tab.
- **Credentials.** The container runs as uid 65532. On Linux your `~/.aws` files are readable only by you, so add `--user "$(id -u):$(id -g)"`. Docker Desktop on macOS and Windows maps file ownership for you. With IAM Identity Center (`aws sso login`), mount `~/.aws` read-write: the SDK writes the refreshed SSO token back to `~/.aws/sso/cache`. Without a mount, pass short-lived keys instead: `eval "$(aws configure export-credentials --profile work --format env)"` and `-e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN`; kubesentry stops being able to sign in when they expire.
- **The endpoint.** Without a kubeconfig, `-eks-cluster` asks EKS for the API server endpoint and CA (`eks:DescribeCluster`). To use your kubeconfig instead, mount it and pick the context: `-v "$HOME/.kube/config:/kube/config:ro" -e KUBECONFIG=/kube/config ... -kube-context prod-eks`. Its `aws eks get-token` plugin cannot run in the image, so kubesentry mints the same token itself, with the cluster, region and `AWS_PROFILE` the plugin names.

## 2. EKS walkthrough

**1. Sign in to AWS** (IAM Identity Center shown; any credentials the AWS CLI accepts work):

```bash
aws configure sso --profile work      # once
aws sso login --profile work
```

**2. Add the cluster to your kubeconfig** and check you can read it:

```bash
aws eks update-kubeconfig --name prod-eks --region us-east-1 --profile work --alias prod-eks
kubectl --context prod-eks auth can-i list pods --all-namespaces
```

**3. Run kubesentry** on loopback without sign-in, the local mode:

```bash
kubesentry -kube-context prod-eks -auth-mode none
```

Open `http://127.0.0.1:8080`. The log says `running="outside the cluster"`. With `-auth-mode none` everyone who can reach loopback on this machine sees everything your identity can list: fine on your own laptop, not on a shared host (use `-api-token` there). Only the Host names `localhost`, `127.0.0.1` and `[::1]` are answered, so a web page cannot reach kubesentry through DNS rebinding.

kubesentry signs in as the kubeconfig does: the `aws eks get-token` plugin runs with the profile that `update-kubeconfig --profile` wrote into the kubeconfig. Without the AWS CLI, or to skip the kubeconfig's user, add `-eks-cluster prod-eks`: kubesentry then mints the token from your AWS credentials (`AWS_PROFILE`, environment or `~/.aws`) for that cluster and region (`-aws-region`).

**4. Metrics, for leak detection and the memory charts.** Pick one:

- **Amazon Managed Prometheus.** Queries are signed with SigV4 from your local AWS credentials. IAM: `aps:QueryMetrics`, `aps:GetSeries`, `aps:GetLabels`, `aps:GetMetricMetadata` on the workspace. If several clusters write to the workspace, select this one.

  ```bash
  kubesentry -kube-context prod-eks -auth-mode none \
    -prometheus-url https://aps-workspaces.us-east-1.amazonaws.com/workspaces/ws-12345678-abcd-1234-abcd-123456789012 \
    -prometheus-selector 'cluster="prod-eks"'
  ```

- **The in-cluster Prometheus, through the API server.** Outside the cluster, kubesentry finds the Prometheus Service as usual (annotation `kubesentry.io/prometheus=true`, or the kube-prometheus-stack and `app.kubernetes.io/name=prometheus` labels) and queries it at `https://<api server>/api/v1/namespaces/<ns>/services/<name>:<port>/proxy`, with your Kubernetes credentials. Nothing is port-forwarded or exposed. Name the Service to skip the search:

  ```bash
  kubesentry -kube-context prod-eks -auth-mode none \
    -prometheus-service monitoring/kube-prometheus-stack-prometheus:9090
  ```

  This needs `get` and `create` on `services/proxy` (create because queries are POSTs) for that Service, and `list services` cluster-wide for the search; see [section 3](#3-the-permissions-your-identity-needs). `-prometheus-via-apiserver=false` turns the proxy off (when your network resolves `*.svc` names, e.g. over a VPN into the cluster network); `=true` forces it, in the cluster too. `PROMETHEUS_TOKEN` is not sent through the proxy: the API server would take it as your credentials.

**5. Audit activity from CloudWatch Logs.** With control-plane audit logging on (`docs/deploy-eks.md`, section 4), kubesentry reads `/aws/eks/<cluster>/cluster` itself. The cluster name comes from `-cluster-name`, or from `-eks-cluster`. IAM: `logs:FilterLogEvents` on the log group and `logs:DescribeLogGroups`.

```bash
kubesentry -kube-context prod-eks -auth-mode none -aws-region us-east-1 \
  -prometheus-url https://aps-workspaces.us-east-1.amazonaws.com/workspaces/ws-12345678-abcd-1234-abcd-123456789012 \
  -cloudwatch -cluster-name prod-eks
```

History is kept in memory: each start reads back `-cloudwatch-start` (24h by default), and up to `-audit-max-events` (50,000) are kept. `hack/run-remote.sh` wraps these flags:

```bash
hack/run-remote.sh -c prod-eks --region us-east-1 --cloudwatch --cluster-name prod-eks \
  --amp https://aps-workspaces.us-east-1.amazonaws.com/workspaces/ws-12345678-abcd-1234-abcd-123456789012
```

## 3. The permissions your identity needs

kubesentry only reads. Its informers **list and watch cluster-wide** the resources in the chart's ClusterRole (`charts/kubesentry/templates/rbac.yaml`; the "Required RBAC" section of `docs/reference.md` has it as plain YAML): pods, persistentvolumeclaims, persistentvolumes, services, serviceaccounts, nodes, namespaces, endpointslices, deployments, replicasets, statefulsets, daemonsets, jobs, cronjobs, ingresses, storageclasses, the four RBAC kinds, cert-manager's resources and the AWS Load Balancer Controller's TargetGroupBindings when installed. With incidents it also watches events and reads `pods/log` (section 7). It creates `selfsubjectaccessreviews` to check those permissions at startup. It never reads Secrets.

On top of that, for the in-cluster Prometheus:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: kubesentry-prometheus-proxy, namespace: monitoring}
rules:
  - apiGroups: [""]
    resources: ["services/proxy"]
    # The name kubesentry asks for is <service>:<port>.
    resourceNames: ["kube-prometheus-stack-prometheus:9090"]
    verbs: ["get", "create"]
```

**Granting it on EKS.** Your IAM role (for example an IAM Identity Center permission set role) reaches Kubernetes through an access entry. Either:

- Associate the `AmazonEKSAdminViewPolicy` access policy: `get`, `list` and `watch` on every resource, Secrets included. Access policies cannot be narrowed to resources, and since they only read, the services/proxy grant above still needs a RoleBinding.
- Or, narrower: give the access entry a Kubernetes group, and bind the ClusterRole from `docs/reference.md` and the Role above to it.

  ```bash
  # An IAM Identity Center role goes in without its path (aws-reserved/sso.amazonaws.com/).
  aws eks create-access-entry --cluster-name prod-eks \
    --principal-arn arn:aws:iam::111122223333:role/AWSReservedSSO_PlatformEngineer_0123456789abcdef \
    --kubernetes-groups kubesentry-readers
  kubectl apply -f kubesentry-reader.yaml     # the ClusterRole from docs/reference.md, renamed kubesentry-reader
  kubectl create clusterrolebinding kubesentry-readers --clusterrole=kubesentry-reader --group=kubesentry-readers
  kubectl -n monitoring create rolebinding kubesentry-prometheus-proxy --role=kubesentry-prometheus-proxy --group=kubesentry-readers
  ```

`AmazonEKSViewPolicy` is not enough on its own: like Kubernetes' `view` role, it does not include nodes, persistent volumes, storage classes or RBAC objects.

**When a permission is missing**, kubesentry still starts. The resource it cannot list cluster-wide is logged (`informer cannot list; marking it unavailable`), listed under `unavailable` in `/api/v1/info`, and the checks that need it are skipped: without `nodes` the node view is empty, without the RBAC kinds the security page has no RBAC findings, and so on. Access to only some namespaces does not help: the informers list across all namespaces, so a namespace-scoped grant leaves the resource unavailable. Without `services/proxy`, the Prometheus candidates are rejected (the log names the 403), and leak detection stays off while OOM kills still show. To test your identity before starting:

```bash
kubectl --context prod-eks auth can-i --list | head -50
kubectl --context prod-eks auth can-i create services/proxy -n monitoring
```

## 4. What is not available remotely

- **Process monitoring.** The node agents run in the cluster and push their reports to kubesentry (`POST /agent/report`); they cannot reach your laptop. If you run kubesentry somewhere the cluster can reach (section 6), deploy the agents in the cluster and point them at it.
- **The audit webhook and audit log file.** Both are for self-managed API servers. On EKS use `-cloudwatch`.
- **Per-user scoping.** Locally there is one user, you, and kubesentry shows what your identity can list. Per-user scoping by RBAC needs an SSO proxy (`-auth-mode proxy`), as in section 6 or the Helm chart.
- **History across restarts.** The memory audit store starts empty, and is filled again from CloudWatch on each start. Findings and charts come from the cluster and Prometheus, so they are complete at once. Incidents start empty too (section 7).

## 5. Several clusters

Run one kubesentry per cluster, each on its own port, and keep a browser tab per cluster:

```bash
kubesentry -kube-context prod-eks    -auth-mode none -addr 127.0.0.1:8081 -cloudwatch -cluster-name prod-eks &
kubesentry -kube-context staging-eks -auth-mode none -addr 127.0.0.1:8082 -cloudwatch -cluster-name staging-eks &
```

Each process holds its own informer cache, so memory grows with each cluster's object count (sizing in `docs/deploy-eks.md`, section 12). `-cluster-name` shows in the UI's sidebar, so the tabs are easy to tell apart.

## 6. A team setup on EC2 or ECS

To share one kubesentry without installing it in the cluster, run the same image next to the cluster, inside the VPC:

1. **An IAM role** for the instance profile (EC2) or task role (ECS), with the CloudWatch Logs and AMP permissions from `docs/deploy-eks.md` section 3, and `eks:DescribeCluster` on the cluster.
2. **An access entry** mapping that role to a Kubernetes group bound to the read-only ClusterRole (section 3). For per-user scoping, the ClusterRole must also allow `create` on `subjectaccessreviews`, as the one in `docs/reference.md` does.

   ```bash
   aws eks create-access-entry --cluster-name prod-eks \
     --principal-arn arn:aws:iam::111122223333:role/kubesentry-prod-eks --kubernetes-groups kubesentry-readers
   ```

3. **kubesentry** signs in with that role, with no kubeconfig:

   ```bash
   kubesentry -eks-cluster prod-eks -aws-region us-east-1 \
     -addr 127.0.0.1:8080 -auth-mode proxy \
     -prometheus-url https://aps-workspaces.us-east-1.amazonaws.com/workspaces/ws-12345678-abcd-1234-abcd-123456789012 \
     -cloudwatch -audit-store postgres -pg-dsn "$KUBESENTRY_PG_DSN"
   ```

4. **oauth2-proxy in front**, as the Helm chart runs it: in the same ECS task (the containers share loopback) or on the same instance, with `--upstream=http://127.0.0.1:8080 --reverse-proxy --pass-user-headers --set-xauthrequest --skip-auth-strip-headers --api-route=^/api/` and your IdP's settings (`docs/deploy-eks.md`, section 6). kubesentry trusts identity headers only from loopback (`-auth-trusted-proxy-cidrs`, default `127.0.0.1/32,::1/128`), so only that proxy can assert who the user is. Put an internal ALB with an ACM certificate in front of oauth2-proxy, and map IdP groups to Kubernetes groups as in `docs/deploy-eks.md` section 7.
5. **Optional:** with `-ingest-addr :8081 -agent-token "$TOKEN"`, node agents in the cluster can report processes to it, if the security groups let them reach port 8081.

For one replica the memory audit store is enough; use Postgres (`docs/deploy-eks.md`, section 5) to keep history across restarts or to run two.

## 7. Incidents

Incidents (`docs/incidents.md`) work from a laptop too. With your identity, kubesentry watches Warning events, reads container logs through the API server (`kubectl logs`), and reads ALB metrics, CloudWatch Logs and CloudTrail with your AWS credentials. Nothing is installed in the cluster.

```bash
kubesentry -kube-context prod-eks -auth-mode none -aws-region us-east-1 -cluster-name prod-eks \
  -prometheus-url https://aps-workspaces.us-east-1.amazonaws.com/workspaces/ws-12345678-abcd-1234-abcd-123456789012 \
  -prometheus-selector 'cluster="prod-eks"' \
  -incidents -incident-alb -incident-logs cloudwatch -cloudtrail lookup -cloudtrail-qps 0.5
```

`hack/run-remote.sh` passes flags after `--` through: `hack/run-remote.sh -c prod-eks ... -- -incidents -cloudtrail lookup`.

**What changes on a laptop:**

- **Incidents last as long as the process.** The memory store is used, and a restart starts empty. At startup the first cluster view only sets a baseline, so existing restarts are not reported again. The request baselines come from Prometheus history, so spikes are detected from the first scan. CloudTrail is read back `-cloudtrail-start` (1h), and the audit log the lookbehind (30m).
- **The minimal start** is `-incidents` alone: Warning events, memory from your Prometheus, logs through `pods/log`, and no AWS calls besides those you already make. Add the AWS sources one at a time.
- **CloudTrail's limit is shared.** `LookupEvents` allows about 2 calls per second per account and region, for everyone. Several people running kubesentry against one account add up, as does the console. Use `-cloudtrail-qps 0.5` or less on a laptop, and leave the history to the in-cluster install where there is one.
- **Container logs** come from CloudWatch Logs with `-incident-logs cloudwatch` (Container Insights' group, from `-cluster-name`), or from the API server with `-incident-logs kubernetes`. `auto` (the default) uses CloudWatch when `-incident-logs-group` is set, then `pods/log`.

**Your Kubernetes identity** needs, besides section 3:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: kubesentry-reader-incidents}
rules:
  - apiGroups: [""]
    resources: ["events"]
    verbs: ["list", "watch"]
  - apiGroups: [""]
    resources: ["pods/log"]
    verbs: ["get"]
```

Bind it to the same group as the reader role. `serviceaccounts` and `targetgroupbindings` are already in that role. `AmazonEKSAdminViewPolicy` covers all of these. Without `events`, `/api/v1/info` shows `incidents.sources.events` (and `unavailable["incidents:events"]`) as an `error: …` naming the missing permission, and incidents open from metrics, restarts and OOM kills only. Without `pods/log`, the log panel shows the API server's refusal when it reads from `kubernetes`.

**Your AWS credentials** need the IAM actions of `docs/deploy-eks.md`, section 3, "Incidents": `logs:FilterLogEvents` on the container log group, `cloudwatch:GetMetricData` and `cloudwatch:ListMetrics` for `-incident-alb`, and `cloudtrail:LookupEvents`.

| Flag | Default | Purpose |
|---|---|---|
| `-incidents` | off | group critical and warning signals per workload into incidents. Needs `-cache` (the default) |
| `-incident-alb` | off | ALB request counts and 5xx per TargetGroupBinding, from CloudWatch |
| `-incident-logs` | `auto` | `auto`, `kubernetes`, `cloudwatch` or `off` |
| `-incident-logs-group` | Container Insights' group with `cloudwatch` | the CloudWatch Logs group of container logs |
| `-cloudtrail` | `off` | `lookup` (the event history) or `logs` (a trail in `-cloudtrail-log-group`) |
| `-cloudtrail-region`, `-cloudtrail-qps`, `-cloudtrail-start` | `-aws-region`, 1, `1h` | which region, how many `LookupEvents` calls per second, how far back the first read goes |

`docs/incidents.md`, section 9, lists the thresholds and the other settings.

## 8. Flags for remote mode

| Flag | Default | Purpose |
|---|---|---|
| `-kube-context` | current context | kubeconfig context to use (`-kubeconfig`, else `KUBECONFIG` or `~/.kube/config`). Setting it skips the in-cluster configuration |
| `-eks-cluster` | | EKS cluster to sign in to with kubesentry's own token, minted from AWS credentials (no AWS CLI needed). Without `-kubeconfig` or `-kube-context`, the endpoint and CA come from `eks:DescribeCluster`. Also the default `-cluster-name` |
| `-aws-region` | from `AWS_REGION` or the profile | region for the EKS token, DescribeCluster, CloudWatch Logs and AMP signing, and with incidents for CloudWatch metrics and CloudTrail |
| `-prometheus-via-apiserver` | `auto` | reach discovered Prometheus Services and `-prometheus-service` through the API server's service proxy: `auto` when running outside the cluster, `true`, `false` |
| `-auth-mode none` | | the local mode: no sign-in, loopback only |

**How the EKS token works.** It is what `aws eks get-token` prints: `k8s-aws-v1.` followed by an STS `GetCallerIdentity` URL presigned with SigV4 (base64url, without padding). The cluster name is signed into it as the `x-k8s-aws-id` header, so the token works only for that cluster. EKS forwards the URL to STS to learn who signed it, then maps that IAM identity through its access entries. EKS accepts a token for 15 minutes; kubesentry treats it as valid for 14 (or until the AWS credentials it was signed with expire, if sooner), makes a new one a minute before that, and right away when the API server answers 401. The AWS SDK refreshes the credentials themselves (SSO, assumed roles, instance and task roles).

If the kubeconfig's `aws eks get-token` plugin assumes a role with `--role-arn`, kubesentry does not repeat that: use an AWS profile that assumes the role (`role_arn` and `source_profile` in `~/.aws/config`) and pass it with `AWS_PROFILE` and `-eks-cluster`.
