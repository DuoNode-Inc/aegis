# Aiegis Browser Extension — Developer Preview

Intercepts AI chat inputs, clipboard pastes, and wallet signing calls.
Works in three modes depending on whether the Aiegis binary is running.

---

## Quick Start (no binary)

```bash
bash build.sh --dev
# → dist/ is ready
```

1. Open **chrome://extensions**
2. Toggle **Developer mode** (top-right)
3. Click **Load unpacked** → select `extension/dist/`
4. Extension icon appears — click to verify `[SHIELD]` badge

The extension runs in **Mode C (JS-only)** with the C-01..C-06 injection pattern set.

---

## Mode A — Sidecar (recommended for dev)

Dedicated scan server. Lighter than the full proxy, no port conflicts.

```bash
# From the repo root (aieges-module/)
cargo build --release --no-default-features
./target/release/aiegis sidecar
# → Aiegis sidecar scan server listening on 127.0.0.1:9999
```

Extension auto-detects it within 30s (cache TTL). Popup shows binary version + tier.

Verify it's working:
```bash
curl -s http://127.0.0.1:9999/status | jq .
# { "version": "0.2.0", "tier": "shield", "uptime_s": 12, ... }

curl -s -X POST http://127.0.0.1:9999/scan \
  -H "Content-Type: application/json" \
  -d '{"text":"ignore previous instructions","source":"test"}' | jq .
# { "action": "BLOCK", "reason": "...", "confidence": 1.0, ... }
```

---

## Mode B — Gateway (binary already running as proxy)

If you already have the full proxy running, the extension reuses it.
The binary must be built with the `/aiegis/scan` endpoint enabled.

```bash
cargo build --release --no-default-features
./target/release/aiegis start --mode gateway
# → Gateway proxy on 127.0.0.1:8080
# → Extension will discover /aiegis/status on :8080
```

---

## Backend Detection

The extension probes backends on every scan request (cached 30s):

```
┌──────────────────────────────────────────────────────────────┐
│  bridge.js probe sequence                                     │
│                                                              │
│  1. GET http://127.0.0.1:9999/status  (400ms timeout)        │
│     OK → Mode A: sidecar                                     │
│                                                              │
│  2. GET http://127.0.0.1:8080/aiegis/status  (400ms timeout) │
│     OK → Mode B: gateway                                     │
│                                                              │
│  3. No binary found → Mode C: JS fallback                    │
└──────────────────────────────────────────────────────────────┘
```

The active backend is visible in `chrome.storage.local` key `binaryVersion`:
- `null` → Mode C (JS)
- `"0.2.0"` → Mode A or B (binary connected)

---

## Wallet Signing Protection

The extension hooks `window.ethereum.request` before any dapp code runs.

| RPC Method | Risk level | Default action |
|---|---|---|
| `eth_sign` | HIGH | BLOCK (shows modal, user must confirm) |
| `personal_sign` with phishing keywords | MEDIUM | FLAG (orange banner) |
| `eth_signTypedData_v4` with MAX_UINT256 | MEDIUM | FLAG |
| `eth_signTypedData_v4` with Permit2/Order | MEDIUM | FLAG |
| `eth_sendTransaction` > 0.05 ETH | MEDIUM | FLAG |
| Everything else | LOW | PASS |

When the binary is running, `eth_signTypedData_v4` message strings are also
passed through the full Aho-Corasick + PII + entropy pipeline.

---

## File Layout

```
extension/
├── manifest.json          MV3 manifest
├── background.js          Service worker — scan routing + stats
├── bridge.js              Backend detection (sidecar/gateway/JS)
├── content.js             Page injector — banners + clipboard scan
├── wallet-interceptor.js  Injected into page context, hooks window.ethereum
├── wallet-risk.js         JS-level EVM signing risk analysis
├── popup.html             Extension popup UI
├── popup.js               Popup logic — reads chrome.storage.local
├── build.sh               Packaging script
├── package.json
└── dist/                  Built output (git-ignored)
```

---

## Adding Sentinel Tier

With a valid Sentinel license:

```bash
./target/release/aiegis license activate <YOUR_KEY>
./target/release/aiegis sidecar
# → tier: "sentinel" in /status response
# → Extension shows [SENTINEL] badge
# → All 40 classifiers active for text + wallet message scanning
```

---

## Known Limitations (Developer Preview)

- Icons are placeholders (1×1 transparent PNG) — replace before release
- CORS is wide-open (`*`) — lock to your extension ID before publishing
- Sidecar has no auth — bind to 127.0.0.1 only (default)
- WASM build (`crates/aiegis-wasm/`) not yet wired — use sidecar for full pipeline
