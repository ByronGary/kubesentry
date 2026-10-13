#!/usr/bin/env bash
# Runs kubesentry on this machine against a remote cluster, on loopback with
# no sign-in (-auth-mode none): see docs/run-remote.md.
#
#   hack/run-remote.sh -c prod-eks
#   hack/run-remote.sh -c prod-eks --amp https://aps-workspaces.us-east-1.amazonaws.com/workspaces/ws-1234 --cloudwatch
#   hack/run-remote.sh --eks prod-eks --region us-east-1 --profile work
#   hack/run-remote.sh -c staging-eks --port 8082 -- -pvc-min-age 1h
#
# Options:
#   -c, --context NAME     kubeconfig context (-kube-context)
#   --kubeconfig PATH      kubeconfig file (default: KUBECONFIG, then ~/.kube/config)
#   --eks NAME             sign in to this EKS cluster with kubesentry's own token
#                          (-eks-cluster); without --context or --kubeconfig the
#                          endpoint and CA come from eks:DescribeCluster
#   --region REGION        AWS region (-aws-region)
#   --profile PROFILE      AWS profile (exported as AWS_PROFILE)
#   --amp URL              Amazon Managed Prometheus workspace URL, signed with
#                          SigV4 from your AWS credentials (-prometheus-url)
#   --prometheus URL       another Prometheus reachable from here (-prometheus-url)
#   --prometheus-service NS/NAME:PORT
#                          the in-cluster Prometheus, reached through the API
#                          server's proxy; default: discovered
#   --cloudwatch           read the EKS audit log from CloudWatch Logs (needs
#                          --eks or --cluster-name)
#   --cluster-name NAME    shown in the UI; names the CloudWatch log group
#   --port N               listen on 127.0.0.1:N (default 8080); one per cluster
#   --bin PATH             the kubesentry binary (default: kubesentry on PATH,
#                          else go run ./cmd/server from this repository)
#   --dry-run              print the command instead of running it
#   -- FLAGS...            any other server flags
set -euo pipefail

usage() { sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; }

port=8080 bin="" dry=false
args=()
while [ $# -gt 0 ]; do
  case "$1" in
    -c|--context) args+=(-kube-context "$2"); shift 2 ;;
    --kubeconfig) args+=(-kubeconfig "$2"); shift 2 ;;
    --eks) args+=(-eks-cluster "$2"); shift 2 ;;
    --region) args+=(-aws-region "$2"); shift 2 ;;
    --profile) export AWS_PROFILE="$2"; shift 2 ;;
    --amp|--prometheus) args+=(-prometheus-url "$2"); shift 2 ;;
    --prometheus-service) args+=(-prometheus-service "$2"); shift 2 ;;
    --cloudwatch) args+=(-cloudwatch); shift ;;
    --cluster-name) args+=(-cluster-name "$2"); shift 2 ;;
    --port) port=$2; shift 2 ;;
    --bin) bin=$2; shift 2 ;;
    --dry-run) dry=true; shift ;;
    --) shift; args+=("$@"); break ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done
case "$port" in ''|*[!0-9]*) echo "--port must be a number" >&2; exit 2 ;; esac

cmd=()
if [ -n "$bin" ]; then
  cmd=("$bin")
elif command -v kubesentry >/dev/null; then
  cmd=(kubesentry)
else
  cd "$(dirname "$0")/.."
  command -v go >/dev/null || { echo "kubesentry is not on PATH and Go is not installed: download a release (docs/run-remote.md)" >&2; exit 1; }
  cmd=(go run ./cmd/server)
fi
cmd+=(-addr "127.0.0.1:$port" -auth-mode none "${args[@]}")

if $dry; then
  printf '%q ' "${cmd[@]}"
  echo
  exit 0
fi
echo "kubesentry on http://127.0.0.1:$port (Ctrl-C stops it)" >&2
exec "${cmd[@]}"
