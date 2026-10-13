# syntax=docker/dockerfile:1
# Builds either binary as a static, non-root, multi-arch image. The Go
# toolchain runs on the build host's platform and cross-compiles, so arm64
# images build without emulation. hack/build-images.sh wraps this:
#   docker build -t kubesentry:dev .
#   docker build -t kubesentry-agent:dev --build-arg CMD=agent .
#   docker buildx build --platform linux/amd64,linux/arm64 --build-arg VERSION=v0.1.0 ...
FROM --platform=$BUILDPLATFORM golang:1.27 AS build
ARG TARGETOS TARGETARCH
# Which command to build: server or agent.
ARG CMD=server
# Stamped into the binary as main.version.
ARG VERSION=dev
# Extra go build flags, e.g. -p=2 to build with fewer parallel jobs.
ARG GOFLAGS=""
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/app ./cmd/${CMD}

FROM gcr.io/distroless/static:nonroot
ARG CMD=server
ARG VERSION=dev
ARG REVISION=""
ARG CREATED=""
LABEL org.opencontainers.image.title="kubesentry-${CMD}" \
      org.opencontainers.image.description="kubesentry ${CMD}: self-hosted Kubernetes observability dashboard" \
      org.opencontainers.image.source="https://github.com/ByronGary/kubesentry" \
      org.opencontainers.image.url="https://github.com/ByronGary/kubesentry" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.base.name="gcr.io/distroless/static:nonroot" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY LICENSE /licenses/LICENSE
COPY --from=build /out/app /app
USER 65532:65532
ENTRYPOINT ["/app"]
