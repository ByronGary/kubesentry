#!/usr/bin/env bash
# Builds the kubesentry server and agent images with docker buildx.
# Release images are built and signed by .github/workflows/release.yml
# (docs/release.md); --push here is for a registry of your own.
#
#   hack/build-images.sh                       host arch, loaded into the local docker as
#                                              kubesentry:<tag> and kubesentry-agent:<tag>
#   hack/build-images.sh --kind                same, tag "dev", then `kind load` into the
#                                              kind cluster "kubesentry" (--kind NAME for another)
#   hack/build-images.sh --push --registry ghcr.io/byrongary --version v0.2.0
#                                              linux/amd64 + linux/arm64, with SBOM and
#                                              provenance attestations, pushed to the registry
#
# Options:
#   --version V     stamped into the binaries (-X main.version) and used as the tag;
#                   default: git describe, or "dev" with --kind
#   --tag T         image tag (default: the version)
#   --registry R    repository prefix, e.g. ghcr.io/byrongary (required with --push)
#   --push          multi-arch build pushed to --registry
#   --platforms P   platforms for --push (default linux/amd64,linux/arm64)
#   --kind [NAME]   load the host-arch images into a kind cluster (default kubesentry)
#   --only C        build only "server" or "agent"
#   --go-jobs N     limit parallel compile jobs (go build -p N), for a busy machine
set -euo pipefail
cd "$(dirname "$0")/.."

version="" tag="" registry="" push=false kind_cluster="" only="" go_jobs=""
platforms=linux/amd64,linux/arm64

usage() { sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --version) version=$2; shift 2 ;;
    --tag) tag=$2; shift 2 ;;
    --registry) registry=${2%/}; shift 2 ;;
    --push) push=true; shift ;;
    --platforms) platforms=$2; shift 2 ;;
    --kind)
      if [ $# -gt 1 ] && [ "${2#-}" = "$2" ]; then kind_cluster=$2; shift 2; else kind_cluster=kubesentry; shift; fi ;;
    --only) only=$2; shift 2 ;;
    --go-jobs) go_jobs=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if $push && [ -z "$registry" ]; then echo "--push needs --registry" >&2; exit 2; fi
if $push && [ -n "$kind_cluster" ]; then echo "--push and --kind are exclusive" >&2; exit 2; fi
case "$only" in ""|server|agent) ;; *) echo "--only must be server or agent" >&2; exit 2 ;; esac

command -v docker >/dev/null || { echo "missing tool: docker" >&2; exit 1; }
docker buildx version >/dev/null 2>&1 || { echo "docker buildx is required" >&2; exit 1; }
[ -z "$kind_cluster" ] || command -v kind >/dev/null || { echo "missing tool: kind" >&2; exit 1; }

if [ -z "$version" ]; then
  if [ -n "$kind_cluster" ]; then
    version=dev
  else
    version=$(git describe --tags --always --dirty 2>/dev/null || echo dev)
  fi
fi
tag=${tag:-$version}
revision=$(git rev-parse HEAD 2>/dev/null || echo unknown)
# The commit time, not the build time, so rebuilding a commit gives the same label.
created=$(git log -1 --format=%cI 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)

image_name() { # cmd -> repository:tag
  local repo=kubesentry
  [ "$1" = agent ] && repo=kubesentry-agent
  echo "${registry:+$registry/}$repo:$tag"
}

builder_args=()
output_args=()
if $push; then
  # Multi-platform builds with attestations need a docker-container builder.
  builder=kubesentry-builder
  if ! docker buildx inspect "$builder" >/dev/null 2>&1; then
    docker buildx create --name "$builder" --driver docker-container --bootstrap >/dev/null
  fi
  builder_args=(--builder "$builder")
  output_args=(--platform "$platforms" --sbom=true --provenance=mode=max --push
    --annotation "index:org.opencontainers.image.source=https://github.com/ByronGary/kubesentry"
    --annotation "index:org.opencontainers.image.version=$version"
    --annotation "index:org.opencontainers.image.revision=$revision")
else
  # Host architecture only, straight into the local image store.
  host_platform="linux/$(docker version --format '{{.Server.Arch}}')"
  output_args=(--platform "$host_platform" --load)
fi

built=()
for cmd in server agent; do
  [ -z "$only" ] || [ "$only" = "$cmd" ] || continue
  image=$(image_name "$cmd")
  echo "==> $image (${output_args[1]})"
  docker buildx build ${builder_args[@]+"${builder_args[@]}"} "${output_args[@]}" \
    --build-arg CMD="$cmd" \
    --build-arg VERSION="$version" \
    --build-arg REVISION="$revision" \
    --build-arg CREATED="$created" \
    ${go_jobs:+--build-arg GOFLAGS=-p=$go_jobs} \
    --tag "$image" \
    .
  built+=("$image")
done

if [ -n "$kind_cluster" ]; then
  echo "==> loading into kind cluster $kind_cluster"
  kind load docker-image --name "$kind_cluster" "${built[@]}"
fi

printf 'built %s\n' "${built[@]}"
