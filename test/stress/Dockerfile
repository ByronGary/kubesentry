# The stress harness image (never shipped). It imports kubesentry's cwfake, so
# build it from the repository root:
#   docker build -t kubesentry-stress:dev -f test/stress/Dockerfile .
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY test/stress/go.mod test/stress/go.sum ./test/stress/
RUN --mount=type=cache,target=/go/pkg/mod cd test/stress && go mod download
COPY internal ./internal
COPY test/stress/cmd ./test/stress/cmd
COPY test/stress/internal ./test/stress/internal
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    cd test/stress && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/stress ./cmd/stress

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/stress /stress
USER 65532:65532
ENTRYPOINT ["/stress"]
