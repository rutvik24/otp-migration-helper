# syntax=docker/dockerfile:1

# The build runs on the build machine's own architecture and cross-compiles for
# each target, so every platform builds quickly without emulation.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} GOARM=${TARGETVARIANT#v} \
    go build -trimpath -ldflags="-s -w" -o /out/otpmh ./cmd/otpmh
# The vault directory, owned by the unprivileged user the image runs as.
RUN mkdir /data && chown 65532:65532 /data

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=build --chown=65532:65532 /data /data
COPY --from=build /out/otpmh /otpmh

USER 65532:65532
ENV OTPMH_LISTEN=:8080 \
    OTPMH_VAULT_PATH=/data/vault.db
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD ["/otpmh", "healthcheck"]
ENTRYPOINT ["/otpmh", "gui", "--no-open"]
