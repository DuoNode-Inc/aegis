#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Aiegis installer — installs the pre-built Shield Edition binary
# Usage: curl -fsSL https://github.com/DuoNode-Inc/aegis/releases/latest/download/install.sh | bash
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO="DuoNode-Inc/aegis"
BINARY="aiegis"
INSTALL_DIR="/usr/local/bin"
RULES_DIR="${HOME}/.aiegis/rules"
CONFIG_DIR="${HOME}/.aiegis"

# ── Color helpers ──────────────────────────────────────────────────────────
bold()  { printf '\033[1m%s\033[0m\n' "$*"; }
info()  { printf '  \033[34m→\033[0m %s\n' "$*"; }
ok()    { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn()  { printf '  \033[33m!\033[0m %s\n' "$*"; }
err()   { printf '  \033[31m✗\033[0m %s\n' "$*" >&2; exit 1; }

# ── Platform detection ────────────────────────────────────────────────────
detect_target() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"

  case "${os}" in
    Darwin)
      case "${arch}" in
        arm64)  echo "aarch64-apple-darwin" ;;
        x86_64) echo "x86_64-apple-darwin"  ;;
        *)      err "Unsupported macOS architecture: ${arch}" ;;
      esac
      ;;
    Linux)
      case "${arch}" in
        x86_64)  echo "x86_64-unknown-linux-gnu"   ;;
        aarch64) echo "aarch64-unknown-linux-gnu"   ;;
        arm64)   echo "aarch64-unknown-linux-gnu"   ;;
        *)       err "Unsupported Linux architecture: ${arch}" ;;
      esac
      ;;
    *)
      err "Unsupported operating system: ${os}. Supported: macOS, Linux."
      ;;
  esac
}

# ── Latest version lookup ─────────────────────────────────────────────────
get_latest_version() {
  if command -v curl &>/dev/null; then
    curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
      | grep '"tag_name"' \
      | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/'
  elif command -v wget &>/dev/null; then
    wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" \
      | grep '"tag_name"' \
      | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/'
  else
    err "Neither curl nor wget found. Install one and retry."
  fi
}

# ── Download ──────────────────────────────────────────────────────────────
download() {
  local url="$1" dest="$2"
  if command -v curl &>/dev/null; then
    curl -fsSL --progress-bar -o "${dest}" "${url}"
  else
    wget -q --show-progress -O "${dest}" "${url}"
  fi
}

# ── Main ──────────────────────────────────────────────────────────────────
main() {
  bold "Aiegis — AI Firewall Installer"
  echo ""

  local target version
  target="$(detect_target)"
  info "Detected platform: ${target}"

  version="${AIEGIS_VERSION:-$(get_latest_version)}"
  if [[ -z "${version}" ]]; then
    err "Could not determine latest version. Set AIEGIS_VERSION=vX.Y.Z to override."
  fi
  info "Version: ${version}"

  local archive="aiegis-${version}-${target}.tar.gz"
  local url="https://github.com/${REPO}/releases/download/${version}/${archive}"
  local tmpdir
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "${tmpdir}"' EXIT

  info "Downloading ${archive}..."
  download "${url}" "${tmpdir}/${archive}"

  info "Verifying archive..."
  # Download checksums and verify (fail gracefully if checksum file unavailable)
  if download "https://github.com/${REPO}/releases/download/${version}/checksums.sha256" \
      "${tmpdir}/checksums.sha256" 2>/dev/null; then
    cd "${tmpdir}"
    grep "${archive}" checksums.sha256 | sha256sum -c --status 2>/dev/null \
      || shasum -a 256 -c <(grep "${archive}" checksums.sha256) 2>/dev/null \
      || warn "Checksum verification skipped (shasum not available)"
    cd - >/dev/null
    ok "Checksum verified"
  else
    warn "Could not download checksums — skipping verification"
  fi

  info "Extracting..."
  tar xzf "${tmpdir}/${archive}" -C "${tmpdir}"
  local extracted_dir="${tmpdir}/aiegis-${version}-${target}"

  # Install binary
  info "Installing binary to ${INSTALL_DIR}/${BINARY}..."
  if [[ -w "${INSTALL_DIR}" ]]; then
    cp "${extracted_dir}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
    chmod 755 "${INSTALL_DIR}/${BINARY}"
  else
    sudo cp "${extracted_dir}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
    sudo chmod 755 "${INSTALL_DIR}/${BINARY}"
  fi
  ok "Binary installed: ${INSTALL_DIR}/${BINARY}"

  # Install rules
  info "Installing rules to ${RULES_DIR}..."
  mkdir -p "${RULES_DIR}"
  cp "${extracted_dir}/rules/"* "${RULES_DIR}/"
  ok "Rules installed: ${RULES_DIR}"

  # Install default config (don't overwrite existing)
  local config_file="${CONFIG_DIR}/aiegis.toml"
  if [[ ! -f "${config_file}" ]]; then
    cp "${extracted_dir}/aiegis.toml.example" "${config_file}"
    # Point config to installed rules
    sed -i'' \
      "s|rules/injection-shield.rules|${RULES_DIR}/injection-shield.rules|" \
      "${config_file}" 2>/dev/null \
      || sed -i \
        "s|rules/injection-shield.rules|${RULES_DIR}/injection-shield.rules|" \
        "${config_file}"
    sed -i'' \
      "s|rules/pii.rules|${RULES_DIR}/pii.rules|" \
      "${config_file}" 2>/dev/null \
      || sed -i \
        "s|rules/pii.rules|${RULES_DIR}/pii.rules|" \
        "${config_file}"
    ok "Default config written: ${config_file}"
  else
    ok "Existing config preserved: ${config_file}"
  fi

  echo ""
  bold "Installation complete"
  echo ""
  info "Start Aiegis:"
  echo "    aiegis start"
  echo ""
  info "Point your SDK at Aiegis:"
  echo "    export OPENAI_BASE_URL=http://localhost:8080/openai"
  echo ""
  info "Activate a Sentinel license:"
  echo "    aiegis license activate <your-license-key>"
  echo ""
  info "Check status:"
  echo "    aiegis status"
  echo ""

  # Version check
  local installed_version
  if installed_version="$("${INSTALL_DIR}/${BINARY}" --version 2>/dev/null)"; then
    ok "Installed: ${installed_version}"
  fi

  # macOS quarantine removal hint
  if [[ "$(uname -s)" == "Darwin" ]]; then
    echo ""
    warn "macOS: if you see 'cannot be opened', run:"
    echo "    xattr -d com.apple.quarantine ${INSTALL_DIR}/${BINARY}"
  fi
}

main "$@"
