#!/usr/bin/env bash
# build.sh — Package Aiegis browser extension for developer preview
#
# Usage:
#   bash build.sh          # production build → dist/ + aiegis-extension-v*.zip
#   bash build.sh --dev    # dev build (skips zip, prints load-unpacked path)
#
# Output:
#   dist/                  → load-unpacked in Chrome: chrome://extensions
#   aiegis-extension-v0.2.0-dev.zip  (or -release.zip)

set -euo pipefail

VERSION=$(node -e "process.stdout.write(require('./package.json').version)" 2>/dev/null || echo "0.2.0")
DEV=false
[[ "${1:-}" == "--dev" ]] && DEV=true

DIST="$(pwd)/dist"
ICON_DIR="$DIST/icons"

echo "▲ Aiegis extension build — v${VERSION} (dev=${DEV})"
echo "──────────────────────────────────────────"

# Clean
rm -rf "$DIST"
mkdir -p "$DIST" "$ICON_DIR"

# ─── Copy source files ──────────────────────────────────────────────────────
SOURCES=(
  manifest.json
  background.js
  bridge.js
  content.js
  wallet-interceptor.js
  wallet-risk.js
  popup.html
  popup.js
)

for f in "${SOURCES[@]}"; do
  if [[ -f "$f" ]]; then
    cp "$f" "$DIST/$f"
    echo "  copied: $f"
  else
    echo "  WARN: $f not found — skipping"
  fi
done

# ─── Generate placeholder icons if none exist ───────────────────────────────
# In production replace with real PNGs. For dev preview, use SVG→PNG if
# Inkscape/rsvg is available, otherwise copy a tiny 1×1 transparent PNG.
generate_icon() {
  local size=$1
  local out="$ICON_DIR/icon${size}.png"
  if command -v rsvg-convert &>/dev/null; then
    rsvg-convert -w "$size" -h "$size" - < /dev/stdin > "$out" <<'SVG'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
  <rect width="24" height="24" fill="#0C0C0C"/>
  <text x="12" y="17" text-anchor="middle"
        font-family="monospace" font-size="14" font-weight="bold" fill="#00FF88">A</text>
</svg>
SVG
  else
    # Minimal 1×1 transparent PNG (89-byte PNG magic + IHDR + IDAT + IEND)
    printf '\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82' > "$out"
  fi
}

if [[ ! -d "icons" ]]; then
  echo "  generating placeholder icons (replace with real assets before release)"
  for size in 16 48 128; do
    generate_icon "$size"
  done
else
  cp -r icons/ "$ICON_DIR/"
fi

# ─── Inject build metadata into manifest ────────────────────────────────────
# Stamp version from package.json into the copied manifest
node -e "
  const fs = require('fs');
  const m = JSON.parse(fs.readFileSync('$DIST/manifest.json', 'utf8'));
  m.version = '${VERSION}';
  fs.writeFileSync('$DIST/manifest.json', JSON.stringify(m, null, 2));
  console.log('  stamped manifest version:', m.version);
"

echo ""
echo "✓ dist/ ready"
echo "  Load in Chrome: chrome://extensions → Developer mode → Load unpacked → select dist/"
echo ""

# ─── Zip for distribution ───────────────────────────────────────────────────
if [[ "$DEV" == "false" ]]; then
  ZIP="aiegis-extension-v${VERSION}-release.zip"
  (cd "$DIST" && zip -r "../$ZIP" . -x "*.DS_Store")
  echo "✓ $ZIP"
  echo "  Install: drag-drop onto chrome://extensions or submit to Chrome Web Store"
else
  ZIP="aiegis-extension-v${VERSION}-dev.zip"
  (cd "$DIST" && zip -r "../$ZIP" . -x "*.DS_Store")
  echo "✓ $ZIP (dev build)"
fi

echo ""
echo "Extension files:"
find "$DIST" -type f | sed "s|$DIST/||" | sort | awk '{print "  " $0}'
