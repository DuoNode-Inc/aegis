/**
 * background.js — Aiegis service worker
 *
 * Handles messages from content.js:
 *   WALLET_SCAN  → wallet-risk.js (JS analysis) + bridge (binary if running)
 *   SCAN_TEXT    → bridge.js (binary sidecar/gateway → JS fallback)
 *
 * Backend priority (auto-detected by bridge.js):
 *   A. aiegis sidecar  — localhost:9999, scan-only server
 *   B. aiegis gateway  — localhost:8080, full proxy with /aiegis/scan
 *   C. JS fallback     — inline pattern matching, no binary needed
 *
 * Stats are stored in chrome.storage.local and surfaced by popup.js.
 */

importScripts("wallet-risk.js");
importScripts("bridge.js");

// ─── Stats ────────────────────────────────────────────────────────────────────
async function incrementStat(key) {
  return new Promise((resolve) => {
    chrome.storage.local.get(["stats"], (r) => {
      const stats = r.stats ?? { scanned: 0, blocked: 0, flagged: 0, wallet_flagged: 0, wallet_blocked: 0 };
      stats[key] = (stats[key] ?? 0) + 1;
      chrome.storage.local.set({ stats }, resolve);
    });
  });
}

async function recordEvent(event) {
  return new Promise((resolve) => {
    chrome.storage.local.get(["events"], (r) => {
      const events = r.events ?? [];
      events.unshift(event);
      // Keep last 100 events
      chrome.storage.local.set({ events: events.slice(0, 100) }, resolve);
    });
  });
}

// ─── Message handler ──────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  switch (message.type) {
    case "WALLET_SCAN":
      handleWalletScan(message).then(sendResponse);
      return true; // keep channel open for async

    case "SCAN_TEXT":
      handleTextScan(message).then(sendResponse);
      return true;

    default:
      sendResponse(null);
  }
});

async function handleWalletScan({ method, params }) {
  // JS-level analysis runs first (synchronous, catches eth_sign immediately)
  const jsResult = analyzeWalletRequest(method, params);

  // If binary is available, also run through full pipeline (catches more edge cases)
  // For BLOCK verdicts from JS, skip the binary call — no need.
  let result = jsResult;
  if (jsResult.action !== "BLOCK") {
    try {
      const binaryResult = await AiegisBridge.scanWallet(method, params);
      // Escalate if binary found something the JS missed
      if (binaryResult.action === "BLOCK" || binaryResult.action === "FLAG") {
        result = { ...binaryResult, level: binaryResult.action === "BLOCK" ? 3 : 2 };
      }
    } catch (_) {
      // Binary unavailable — JS result stands
    }
  }

  await incrementStat("scanned");

  if (result.action === "BLOCK") {
    await incrementStat("wallet_blocked");
    await recordEvent({
      ts: Date.now(),
      action: "BLOCK",
      type: "wallet",
      method,
      reason: result.reason,
      detail: result.detail,
    });
  } else if (result.action === "FLAG") {
    await incrementStat("wallet_flagged");
    await recordEvent({
      ts: Date.now(),
      action: "FLAG",
      type: "wallet",
      method,
      reason: result.reason,
      detail: result.detail,
    });
  }

  return result;
}

async function handleTextScan({ text, source }) {
  // Route through bridge: sidecar → gateway → JS fallback (auto-detected)
  const result = await AiegisBridge.scanText(text, source ?? "extension");

  await incrementStat("scanned");

  if (result.action === "BLOCK") {
    await incrementStat("blocked");
    await recordEvent({
      ts: Date.now(),
      action: "BLOCK",
      type: source ?? "text",
      reason: result.reason,
      backend: result.backend,
    });
  } else if (result.action === "FLAG") {
    await incrementStat("flagged");
    await recordEvent({
      ts: Date.now(),
      action: "FLAG",
      type: source ?? "text",
      reason: result.reason,
      backend: result.backend,
    });
  }

  return result;
}
