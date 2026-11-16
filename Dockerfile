# GitHub Docker actions build from the repository root.
FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine AS build
WORKDIR /src
COPY tool/ .
ARG VERSION=dev
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /prowl ./cmd/prowl

FROM debian:bookworm-slim
ARG TARGETARCH
RUN --mount=type=cache,id=prowl-apt-lists-${TARGETARCH},target=/var/lib/apt/lists,sharing=locked --mount=type=cache,id=prowl-apt-archives-${TARGETARCH},target=/var/cache/apt,sharing=locked apt-get update && apt-get install --no-install-recommends -y git ca-certificates util-linux && git config --system --add safe.directory /github/workspace
ENV PROWL_HOME=/tmp/prowl
COPY --from=build /prowl /usr/local/bin/prowl
COPY tool/action-entrypoint.sh /usr/local/bin/prowl-action
ENTRYPOINT ["/usr/local/bin/prowl-action"]
