# Tiny self-contained prowl image (taxonomy + models embedded; no runtime deps).
# Multi-arch: the build stage is pinned to the native build platform and cross-compiles to the
# target arch via Go's GOARCH, so neither the Go compiler nor the final stage needs QEMU emulation.
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build
WORKDIR /src
COPY . .
ARG VERSION=dev
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /prowl ./cmd/prowl

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /prowl /usr/local/bin/prowl
ENTRYPOINT ["/usr/local/bin/prowl"]
CMD ["scan", "."]
