FROM golang:1.26.6-bookworm AS trust
FROM debian:bookworm-slim
COPY --from=trust /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources \
    && apt-get update && apt-get install -y --no-install-recommends ppp systemd \
    && rm -rf /var/lib/apt/lists/*
