# syntax=docker/dockerfile:1
#
# Keylatch CLI container image — multi-stage build from source.
#
# Stage 1 (web):     oven/bun builds the embedded SPA (web/dist).
# Stage 2 (builder): golang:1.26-alpine compiles the CLI binary with the
#                     embedded_ui build tag, embedding the SPA build from
#                     stage 1 via internal/ui/web/dist.
# Stage 3 (runtime): distroless/static, non-root user, /keylatch ENTRYPOINT.
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
# Stage 1: web — build the embedded SPA (Vite/bun).
#
# Kept as its own stage so the (slow) `bun install` layer only rebuilds
# when web/ changes, independent of Go source changes.
# -----------------------------------------------------------------------
FROM oven/bun:1 AS web

WORKDIR /src/web

# Copy manifests first to maximize layer cache hits.
COPY web/package.json web/bun.lock ./
RUN bun install --frozen-lockfile

# Copy the rest of the web source and build.
COPY web/ .
RUN bun run build

# -----------------------------------------------------------------------
# Stage 2: builder — compile the Go binary with the embedded UI.
# -----------------------------------------------------------------------
FROM golang:1.26-alpine AS builder

RUN apk add --no-cache git ca-certificates bash

WORKDIR /src

# Copy module manifests first to maximize layer cache hits during
# iterative development. The `go mod download` step is cached unless
# go.mod or go.sum changes.
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source tree.
COPY . .

# Pull in the SPA build produced by the `web` stage before running the
# embed sync script — sync-embedded-ui.sh normally builds the SPA itself,
# so here we only need the copy step it performs (web/dist -> internal/ui/web/dist).
COPY --from=web /src/web/dist ./web/dist
RUN rm -rf internal/ui/web/dist \
    && mkdir -p internal/ui/web \
    && cp -R web/dist internal/ui/web/dist \
    && bash web/scripts/verify-bundle.sh

# Version metadata. Override with --build-arg at build time; defaults
# are usable but not informative.
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux \
    go build -trimpath -tags embedded_ui -ldflags " \
        -s -w \
        -X 'github.com/keylatch/keylatch/internal/version.Version=${VERSION}' \
        -X 'github.com/keylatch/keylatch/internal/version.Commit=${COMMIT}' \
        -X 'github.com/keylatch/keylatch/internal/version.BuildDate=${BUILD_DATE}' \
    " \
    -o /out/keylatch ./cmd/keylatch

# distroless has no shell, so the nonroot-owned home/config directory must
# be pre-created (with correct ownership) here in the builder stage and
# copied over verbatim — `RUN mkdir`/`chown` are not available in the
# runtime stage below.
RUN mkdir -p /home/nonroot/.keylatch && chown -R 65532:65532 /home/nonroot

# -----------------------------------------------------------------------
# Stage 3: runtime.
#
# distroless/static is ~2 MiB. No shell, no libc, no package manager —
# minimum attack surface. The `nonroot` variant runs as UID 65532.
# -----------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot AS runtime

COPY --from=builder /out/keylatch /keylatch
COPY --from=builder --chown=65532:65532 /home/nonroot /home/nonroot

# The image runs as UID 65532 (nonroot) with no $HOME by default in
# distroless, which makes config resolution fall back to an unwritable
# relative directory. Set HOME and an explicit, writable config dir, and
# declare it as a volume so config/vault state persists across container
# recreation.
ENV HOME=/home/nonroot
ENV KEYLATCH_CONFIG_DIR=/home/nonroot/.keylatch
VOLUME ["/home/nonroot/.keylatch"]

# Documentation only — distroless has no shell to bind ports from, and
# these do not publish anything by themselves. 7890 = local UI, 7878 = gateway.
EXPOSE 7890 7878

USER nonroot:nonroot
ENTRYPOINT ["/keylatch"]

# `keylatch health` is a lightweight self-check subcommand (added
# alongside this container work) intended for container orchestrators.
HEALTHCHECK CMD ["/keylatch", "health"]

LABEL org.opencontainers.image.title="keylatch"
LABEL org.opencontainers.image.description="Zero-trust credential vault CLI for AI-assisted workflows"
LABEL org.opencontainers.image.source="https://github.com/keylatch/keylatch"
LABEL org.opencontainers.image.licenses="Apache-2.0"
