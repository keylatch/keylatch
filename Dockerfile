# syntax=docker/dockerfile:1
#
# Keylatch CLI container image — multi-stage build from source.
#
# Stage 1 (builder): golang:1.25-alpine compiles the CLI binary.
# Stage 2 (runtime): distroless/static, non-root user, /keylatch ENTRYPOINT.
#
# The image ships ONLY the `keylatch` CLI. The Tauri desktop shell is
# produced by goreleaser into platform-native bundles (.app, .msi,
# .AppImage) and is intentionally not part of any container image.
#
# Build locally:
#   docker build -t keylatch:dev .
#
# Run:
#   docker run --rm -it keylatch:dev --help
#
# Goreleaser uses Dockerfile.release (not this file) — it pre-builds the
# binary outside the container and copies it in directly. See
# .goreleaser.yml `dockers` stanza.

# -----------------------------------------------------------------------
# Stage 1: builder.
# -----------------------------------------------------------------------
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src

# Copy module manifests first to maximize layer cache hits during
# iterative development. The `go mod download` step is cached unless
# go.mod or go.sum changes.
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source tree.
COPY . .

# Version metadata. Override with --build-arg at build time; defaults
# are usable but not informative.
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux \
    go build -trimpath -ldflags " \
        -s -w \
        -X 'github.com/keylatch/keylatch/internal/version.Version=${VERSION}' \
        -X 'github.com/keylatch/keylatch/internal/version.Commit=${COMMIT}' \
        -X 'github.com/keylatch/keylatch/internal/version.BuildDate=${BUILD_DATE}' \
    " \
    -o /out/keylatch ./cmd/keylatch

# -----------------------------------------------------------------------
# Stage 2: runtime.
#
# distroless/static is ~2 MiB. No shell, no libc, no package manager —
# minimum attack surface. The `nonroot` variant runs as UID 65532.
# -----------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot AS runtime

COPY --from=builder /out/keylatch /keylatch

USER nonroot:nonroot
ENTRYPOINT ["/keylatch"]

LABEL org.opencontainers.image.title="keylatch"
LABEL org.opencontainers.image.description="Zero-trust credential vault CLI for AI-assisted workflows"
LABEL org.opencontainers.image.source="https://github.com/keylatch/keylatch"
LABEL org.opencontainers.image.licenses="Apache-2.0"
