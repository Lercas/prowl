# Static Go binary with embedded taxonomy/models and Git-enabled runtime.
# Multi-arch: the build stage is pinned to the native build platform and cross-compiles to the
# target arch via Go's GOARCH. Runtime package installation follows the target platform.
FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine AS build
WORKDIR /src
COPY . .
ARG VERSION=dev
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /prowl ./cmd/prowl

FROM debian:bookworm-slim
ARG TARGETARCH
RUN --mount=type=cache,id=prowl-apt-lists-${TARGETARCH},target=/var/lib/apt/lists,sharing=locked --mount=type=cache,id=prowl-apt-archives-${TARGETARCH},target=/var/cache/apt,sharing=locked apt-get update && apt-get install --no-install-recommends -y git ca-certificates && git config --system --add safe.directory /src
ENV PROWL_HOME=/tmp/prowl
USER 65532:65532
COPY --from=build /prowl /usr/local/bin/prowl
ENTRYPOINT ["/usr/local/bin/prowl"]
CMD ["scan", "."]
