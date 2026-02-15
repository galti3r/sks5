# Local dev build — static musl binary → scratch
# Compatible with both Podman and Docker
FROM rust:1.88-alpine AS builder

RUN apk add --no-cache musl-dev
WORKDIR /build
COPY Cargo.toml Cargo.lock* ./
COPY src/ src/
COPY assets/ assets/
COPY benches/ benches/
RUN cargo build --release && strip target/release/sks5

FROM alpine:3.21 AS certs
RUN apk add --no-cache ca-certificates

FROM scratch

LABEL org.opencontainers.image.title="sks5" \
      org.opencontainers.image.description="Lightweight SSH server with SOCKS5 proxy" \
      org.opencontainers.image.source="https://github.com/galti3r/sks5" \
      org.opencontainers.image.licenses="MIT"

COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /build/target/release/sks5 /sks5

EXPOSE 2222 1080 9090 9091

USER 65534

ENTRYPOINT ["/sks5"]
CMD ["--config", "/etc/sks5/config.toml"]
