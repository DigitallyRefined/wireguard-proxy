# syntax=docker/dockerfile:1
#
# Multi-platform build:
#   docker buildx build --platform linux/amd64,linux/arm64 -t wg-proxy:latest --push .
#
# ── Build stage ────────────────────────────────────────────────────────────────
FROM --platform=$BUILDPLATFORM golang:1.26.3 AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Static binary: no CGO, no libc dependency, runs in scratch or distroless
# Optimization: GOAMD64=v3 enables AVX2 for amd64. Go ignores this for other architectures.
RUN if [ "$TARGETARCH" = "amd64" ]; then \
        export GOAMD64=v3; \
    fi; \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w" -trimpath \
    -o /usr/bin/wg-proxy ./wg-proxy

# ── Runtime stage ──────────────────────────────────────────────────────────────
# scratch = zero OS overhead, no shell, minimal attack surface.
# Switch to "alpine" if you need a shell for debugging.
FROM scratch
ARG TARGETOS
ARG TARGETARCH

LABEL org.opencontainers.image.source https://github.com/DigitallyRefined/wireguard-proxy
LABEL org.opencontainers.image.description "A zero-privilege WireGuard port forwarder using userspace networking"
LABEL org.opencontainers.image.base.name "scratch"
LABEL com.digitallyrefined.platform "${TARGETOS}/${TARGETARCH}"

COPY --from=builder /usr/bin/wg-proxy /usr/bin/wg-proxy

# If you use a file, mount it at /etc/wg-proxy/wg-proxy.conf and set:
#   WG_PROXY_CONFIG=/etc/wg-proxy/wg-proxy.conf

ENTRYPOINT ["/usr/bin/wg-proxy"]
# Default config path; override with -config flag or WG_PROXY_CONFIG env var
CMD ["-config", "/etc/wg-proxy/wg-proxy.conf"]
