# Tiny self-contained prowl image (taxonomy + models embedded; no runtime deps).
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /prowl ./cmd/prowl

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /prowl /usr/local/bin/prowl
ENTRYPOINT ["/usr/local/bin/prowl"]
CMD ["scan", "."]
