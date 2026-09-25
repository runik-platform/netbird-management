FROM golang:1.26.7-bookworm AS builder

ARG NETBIRD_VERSION=0.78.2-runik.0
ARG VCS_REF

RUN test -n "${VCS_REF}" && test "${VCS_REF}" != "unknown"

WORKDIR /app

RUN apt-get update \
    && apt-get install --yes --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w \
      -X github.com/netbirdio/netbird/version.version=${NETBIRD_VERSION} \
      -X main.commit=${VCS_REF} \
      -X main.builtBy=runik" \
    -o /out/netbird-mgmt ./management

FROM ubuntu:24.04

ARG NETBIRD_VERSION=0.78.2-runik.0
ARG NETBIRD_UPSTREAM_VERSION=v0.78.2
ARG VCS_REF

LABEL org.opencontainers.image.title="Runik NetBird Management Server" \
      org.opencontainers.image.description="Minimal Runik patch series over NetBird Community" \
      org.opencontainers.image.source="https://github.com/runik-platform/netbird-management" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.version="${NETBIRD_VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      io.runik.netbird.upstream-version="${NETBIRD_UPSTREAM_VERSION}"

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/netbird-mgmt /go/bin/netbird-mgmt

ENTRYPOINT ["/go/bin/netbird-mgmt", "management"]
CMD ["--log-file", "console"]
