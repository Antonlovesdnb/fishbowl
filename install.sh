#!/usr/bin/env sh
# Fishbowl installer / uninstaller
#
# Install:
#   curl -fsSL https://raw.githubusercontent.com/Antonlovesdnb/fishbowl/main/install.sh | sh
#
# Uninstall:
#   curl -fsSL https://raw.githubusercontent.com/Antonlovesdnb/fishbowl/main/install.sh | sh -s -- --uninstall
#
# Environment variables:
#   FISHBOWL_VERSION   Specific tag to install (default: latest)
#   FISHBOWL_BIN_DIR   Install directory (default: /usr/local/bin, falling
#                        back to ~/.local/bin if not writable)

set -eu

REPO="Antonlovesdnb/fishbowl"
VERSION="${FISHBOWL_VERSION:-latest}"

err() { printf 'error: %s\n' "$*" >&2; exit 1; }
info() { printf '==> %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }

# ── Uninstall ──────────────────────────────────────────────────────
if [ "${1:-}" = "--uninstall" ]; then
  info "uninstalling Fishbowl"

  # Remove binary
  for dir in /usr/local/bin "$HOME/.local/bin"; do
    if [ -f "$dir/fishbowl" ]; then
      info "removing $dir/fishbowl"
      rm -f "$dir/fishbowl" 2>/dev/null || sudo rm -f "$dir/fishbowl"
    fi
  done

  # Remove Docker images
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    for image in fishbowl:dev fishbowl-collector:dev; do
      if docker image inspect "$image" >/dev/null 2>&1; then
        info "removing Docker image $image"
        docker rmi "$image" 2>/dev/null || true
      fi
    done
  fi

  # Remove data directory (session logs, host scans, runtime auth, collector images)
  if [ -d "$HOME/.fishbowl" ]; then
    printf '==> Remove session data at %s? (y/N): ' "$HOME/.fishbowl"
    read -r answer </dev/tty 2>/dev/null || answer="n"
    case "$answer" in
      [yY]|[yY][eE][sS])
        info "removing $HOME/.fishbowl"
        rm -rf "$HOME/.fishbowl"
        ;;
      *)
        info "keeping $HOME/.fishbowl"
        ;;
    esac
  fi

  info "Fishbowl uninstalled."
  exit 0
fi
# ── End uninstall ──────────────────────────────────────────────────

need() { command -v "$1" >/dev/null 2>&1 || err "missing required command: $1"; }
need curl
need tar
need uname

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Darwin)
    case "$ARCH" in
      arm64|aarch64) TARGET="aarch64-apple-darwin" ;;
      *) err "unsupported macOS architecture: $ARCH (only Apple Silicon is supported)" ;;
    esac
    ;;
  Linux)
    case "$ARCH" in
      x86_64|amd64)  TARGET="x86_64-unknown-linux-musl" ;;
      arm64|aarch64) TARGET="aarch64-unknown-linux-musl" ;;
      *) err "unsupported Linux architecture: $ARCH" ;;
    esac
    ;;
  *)
    err "unsupported OS: $OS (Fishbowl supports macOS and Linux)"
    ;;
esac

# Resolve "latest" to a concrete tag.
if [ "$VERSION" = "latest" ]; then
  info "resolving latest release"
  TAG=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
    | head -n1)
  [ -n "$TAG" ] || err "could not resolve latest release tag"
else
  TAG="$VERSION"
fi
info "installing Fishbowl ${TAG} (${TARGET})"

# Pick install directory.
USE_SUDO=0
if [ -n "${FISHBOWL_BIN_DIR:-}" ]; then
  BIN_DIR="$FISHBOWL_BIN_DIR"
  mkdir -p "$BIN_DIR"
elif [ -w /usr/local/bin ]; then
  BIN_DIR="/usr/local/bin"
elif [ -d /usr/local/bin ] && command -v sudo >/dev/null 2>&1; then
  BIN_DIR="/usr/local/bin"
  USE_SUDO=1
else
  BIN_DIR="$HOME/.local/bin"
  mkdir -p "$BIN_DIR"
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

ARCHIVE="fishbowl-${TAG}-${TARGET}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${TAG}/${ARCHIVE}"
SUMS_URL="https://github.com/${REPO}/releases/download/${TAG}/SHA256SUMS"
SUMS_FILE="${TMP_DIR}/SHA256SUMS"
SUMS_OK=0

# Verifies an archive against the previously-downloaded SHA256SUMS file.
# Args: 1=archive path on disk, 2=archive basename used in SHA256SUMS.
# Aborts the install on any mismatch — never silently skip when SUMS_OK=1.
verify_archive() {
  archive_path="$1"
  archive_name="$2"
  expected=$(awk -v f="$archive_name" '$2 == f {print $1}' "$SUMS_FILE")
  [ -n "$expected" ] || err "no checksum entry for ${archive_name} in SHA256SUMS"
  if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$archive_path" | awk '{print $1}')
  elif command -v shasum >/dev/null 2>&1; then
    actual=$(shasum -a 256 "$archive_path" | awk '{print $1}')
  else
    err "no sha256sum/shasum tool available to verify the download"
  fi
  [ "$expected" = "$actual" ] || err "checksum mismatch for ${archive_name}: expected ${expected}, got ${actual}"
}

info "downloading ${URL}"
curl -fsSL "$URL" -o "${TMP_DIR}/${ARCHIVE}" || err "download failed: $URL"

# Fetch SHA256SUMS once and reuse it for every archive in this release.
if curl -fsSL "$SUMS_URL" -o "$SUMS_FILE" 2>/dev/null; then
  SUMS_OK=1
  info "verifying checksum"
  verify_archive "${TMP_DIR}/${ARCHIVE}" "$ARCHIVE"
else
  warn "SHA256SUMS not found at ${SUMS_URL}, skipping checksum verification"
fi

info "extracting"
tar -xzf "${TMP_DIR}/${ARCHIVE}" -C "${TMP_DIR}"
EXTRACTED="${TMP_DIR}/fishbowl-${TAG}-${TARGET}"
[ -f "${EXTRACTED}/fishbowl" ] || err "binary not found in archive"

info "installing to ${BIN_DIR}/fishbowl"
if [ "$USE_SUDO" = "1" ]; then
  sudo install -m 0755 "${EXTRACTED}/fishbowl" "${BIN_DIR}/fishbowl"
else
  install -m 0755 "${EXTRACTED}/fishbowl" "${BIN_DIR}/fishbowl"
fi

case ":$PATH:" in
  *":${BIN_DIR}:"*) ;;
  *) warn "${BIN_DIR} is not in PATH. Add it to your shell profile:
    export PATH=\"${BIN_DIR}:\$PATH\"" ;;
esac

# Download the collector image for strong monitoring on macOS.
# On Linux, bpftrace runs on the host kernel directly and doesn't need this.
# The collector image runs inside the Docker VM on macOS.
# The collector tarball is always a Linux image (the Docker VM runs Linux),
# so map the host arch to the Linux naming used by the release workflow:
# Apple Silicon `arm64` → `aarch64`, Linux `x86_64`/`aarch64` pass through.
case "$ARCH" in
  arm64|aarch64) COLLECTOR_ARCH="aarch64" ;;
  x86_64|amd64)  COLLECTOR_ARCH="x86_64" ;;
  *)             COLLECTOR_ARCH="$ARCH" ;;
esac
COLLECTOR_ARCHIVE="fishbowl-collector-linux-${COLLECTOR_ARCH}.tar.gz"
COLLECTOR_URL="https://github.com/${REPO}/releases/download/${TAG}/${COLLECTOR_ARCHIVE}"
COLLECTOR_DIR="$HOME/.fishbowl/collector-images"

info "downloading collector image for strong monitoring"
mkdir -p "${COLLECTOR_DIR}"
if curl -fsSL "${COLLECTOR_URL}" -o "${COLLECTOR_DIR}/${COLLECTOR_ARCHIVE}" 2>/dev/null; then
  # Verify the collector tarball against the same SHA256SUMS used for the
  # binary. The collector image runs with elevated privileges inside the
  # Docker VM (privileged sidecar with bpftrace), so a tampered tarball
  # would be a much higher-impact compromise than the user binary itself.
  # Treat verification failure as fatal — never docker-load an unverified
  # image. If SHA256SUMS wasn't available at all, fall through to the same
  # "warn and continue" behavior used for the binary archive.
  if [ "$SUMS_OK" = "1" ]; then
    info "verifying collector checksum"
    verify_archive "${COLLECTOR_DIR}/${COLLECTOR_ARCHIVE}" "$COLLECTOR_ARCHIVE"
  else
    warn "SHA256SUMS unavailable; skipping collector checksum verification"
  fi
  info "collector image saved to ${COLLECTOR_DIR}/${COLLECTOR_ARCHIVE}"
  # Pre-load into Docker if the daemon is running
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    info "loading collector image into Docker"
    if docker load --input "${COLLECTOR_DIR}/${COLLECTOR_ARCHIVE}" >/dev/null 2>&1; then
      info "collector image loaded — strong monitoring available"
    else
      warn "docker load failed; fishbowl build-image will retry on first run"
    fi
  fi
else
  warn "could not download collector image (private repo or network issue); strong monitoring on macOS will require a source install"
fi

cat <<EOF

Fishbowl ${TAG} installed.

Next step:
  fishbowl run            # run the current directory in the sandbox

The first run auto-builds the container image (a few minutes; one-time).
To build it up front instead: fishbowl build-image

Docs: https://github.com/${REPO}
EOF
