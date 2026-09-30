# ---- Stage 1: build the Go binary ----
FROM golang:1.27-alpine AS build

WORKDIR /app
ENV GOTOOLCHAIN=local

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go test ./... \
 && CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w" -o /trivyboard-backend .

# ---- Stage 2: runtime image with Trivy ----
FROM alpine:3.24

LABEL org.opencontainers.image.title="trivyboard-backend" \
      org.opencontainers.image.source="https://github.com/fatihsaracoglu/trivyboard"

ENV TRIVY_VERSION=0.74.0

RUN apk add --no-cache ca-certificates tzdata wget \
 && wget -q "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
 && wget -q "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_checksums.txt" \
 && grep "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz\$" "trivy_${TRIVY_VERSION}_checksums.txt" | sha256sum -c - \
 && tar xz -C /usr/local/bin trivy -f "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
 && rm trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz trivy_${TRIVY_VERSION}_checksums.txt \
 && apk del wget

COPY --from=build --chown=1000:1000 /trivyboard-backend /usr/local/bin/trivyboard-backend

RUN addgroup -g 1000 trivyboard \
 && adduser -D -u 1000 -G trivyboard trivyboard \
 && mkdir -p /var/cache/trivy /data /var/run/docker-proxy \
 && chown -R trivyboard:trivyboard /var/cache/trivy /data /var/run/docker-proxy

ENV TRIVY_CACHE_DIR=/var/cache/trivy

ENV PORT=3030 \
    SCAN_PERSISTENCE=sqlite \
    SCAN_MODE=async \
    DATABASE_URL=/data/trivyboard.db \
    DOCKER_SOCKET=/var/run/docker-proxy/docker.sock

# Volume for the SQLite database
VOLUME ["/data", "/var/cache/trivy"]

USER trivyboard

EXPOSE 3030

STOPSIGNAL SIGTERM

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD wget -qO- http://localhost:3030/api/health || exit 1

CMD ["/usr/local/bin/trivyboard-backend"]
