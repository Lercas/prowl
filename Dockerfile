# GitHub Docker actions build from the repository root.
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build
WORKDIR /src
COPY tool/ .
ARG VERSION=1.4.0
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /prowl ./cmd/prowl

FROM debian:bookworm-slim
RUN --mount=type=cache,target=/var/lib/apt/lists --mount=type=cache,target=/var/cache/apt apt-get update && apt-get install --no-install-recommends -y git ca-certificates util-linux && git config --system --add safe.directory /github/workspace
ENV PROWL_HOME=/tmp/prowl
COPY --from=build /prowl /usr/local/bin/prowl
COPY tool/action-entrypoint.sh /usr/local/bin/prowl-action
ENTRYPOINT ["/usr/local/bin/prowl-action"]
