# The stress harness image (never shipped). Build from test/stress:
#   docker build -t kubesentry-stress:dev test/stress
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/stress ./cmd/stress

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/stress /stress
USER 65532:65532
ENTRYPOINT ["/stress"]
