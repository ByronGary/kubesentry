#!/usr/bin/env bash
# Builds the release binaries and archives, as .github/workflows/release.yml
# does for a tag:
#
#   kubesentry        darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 windows/amd64
#   kubesentry-agent  linux/amd64 linux/arm64
#
#   hack/release-binaries.sh v0.1.0            writes dist/
#   hack/release-binaries.sh v0.1.0 out/       another directory (emptied first)
#
# Each archive holds the binary (static, CGO off, the UI embedded from the
# committed internal/web/dist), LICENSE and README.md: <name>_<version>_<os>_<arch>.tar.gz,
# or .zip for Windows. SHA256SUMS lists them all. The version is stamped into
# the binaries (-X main.version) as given, e.g. v0.1.0, and the archive names
# drop the v. Files carry the commit time and archives no owner, so a rebuild
# of the same commit gives the same archives.
#
# Needs Go, GNU tar, gzip, sha256sum, and zip or python3. GOFLAGS=-p=2 limits
# parallel compile jobs on a busy machine.
set -euo pipefail
cd "$(dirname "$0")/.."

version=${1:-}
out=${2:-dist}
if [[ ! "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "usage: $0 vMAJOR.MINOR.PATCH[-PRERELEASE] [outdir]" >&2
  exit 2
fi
num=${version#v}
for tool in go tar gzip sha256sum; do
  command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 1; }
done
tar --version 2>/dev/null | grep -q 'GNU tar' || { echo "needs GNU tar (--sort, --mtime)" >&2; exit 1; }

rm -rf "$out"
mkdir -p "$out"
out=$(cd "$out" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
epoch=$(git log -1 --format=%ct 2>/dev/null || date +%s)

zipfiles() { # archive dir files...: the files, at the archive's root
  local archive=$1 dir=$2
  shift 2
  if command -v zip >/dev/null; then
    (cd "$dir" && zip -q -X "$archive" "$@")
  else
    (cd "$dir" && python3 -I -m zipfile -c "$archive" "$@")
  fi
}

# build cmd binary-name os arch
build() {
  local cmd=$1 name=$2 os=$3 arch=$4 ext=""
  [ "$os" = windows ] && ext=.exe
  local base="${name}_${num}_${os}_${arch}"
  local dir="$work/$base"
  mkdir -p "$dir"
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch \
    go build -trimpath -ldflags "-s -w -X main.version=$version" -o "$dir/$name$ext" "./cmd/$cmd"
  cp LICENSE README.md "$dir/"
  touch -d "@$epoch" "$dir"/*
  if [ "$os" = windows ]; then
    zipfiles "$out/$base.zip" "$dir" "$name$ext" LICENSE README.md
  else
    tar -C "$dir" --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$epoch" -cf - "$name" LICENSE README.md |
      gzip -n -9 >"$out/$base.tar.gz"
  fi
  echo "built $base"
}

for target in darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 windows/amd64; do
  build server kubesentry "${target%/*}" "${target#*/}"
done
for target in linux/amd64 linux/arm64; do
  build agent kubesentry-agent "${target%/*}" "${target#*/}"
done

(cd "$out" && sha256sum -- *.tar.gz *.zip >SHA256SUMS)
echo "wrote $out:"
ls -l "$out"
