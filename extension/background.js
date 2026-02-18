/**
 * background.js — Aiegis service worker
 *
 * Handles messages from content.js:
 *   WALLET_SCAN  → run wallet-risk.js analysis
 *   SCAN_TEXT    → run WASM injection/PII scan (once WASM is integrated)
 *
 * Stats are stored in chrome.storage.local and surfaced by popup.js.
 */

importScripts("wallet-risk.js");

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
  const result = analyzeWalletRequest(method, params);

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
  // TODO(wasm): Route through AiegisScanner WASM once crates/aiegis-wasm is built.
  // For now, run a lightweight JS fallback using the same phishing patterns.
  const result = lightweightTextScan(text);

  await incrementStat("scanned");

  if (result.action === "BLOCK") {
    await incrementStat("blocked");
    await recordEvent({
      ts: Date.now(),
      action: "BLOCK",
      type: source ?? "text",
      reason: result.reason,
    });
  } else if (result.action === "FLAG") {
    await incrementStat("flagged");
    await recordEvent({
      ts: Date.now(),
      action: "FLAG",
      type: source ?? "text",
      reason: result.reason,
    });
  }

  return result;
}

// ─── Lightweight JS text scanner (pre-WASM fallback) ─────────────────────────
// These mirror the C-01..C-06 injection-shield.rules patterns
const INJECTION_PATTERNS = [
  // C-01: Instruction override
  /ignore\s+(previous|all|your)\s+(instructions?|rules?)/i,
  /disregard\s+(previous|your|the)\s+(instructions?|rules?)/i,
  /forget\s+(previous|your|all|prior)\s+(instructions?|rules?)/i,
  /override\s+(previous|your|the)\s+(instructions?|rules?)/i,
  // C-02: Jailbreak
  /you\s+are\s+now\s+(DAN|jailbroken|in\s+developer\s+mode)/i,
  /act\s+as\s+(DAN|an\s+unrestricted|if\s+you\s+have\s+no)/i,
  /enter\s+(developer|DAN)\s+mode/i,
  /do\s+anything\s+now/i,
  // C-03: System prompt extraction
  /reveal\s+your\s+system\s+prompt/i,
  /show\s+(me\s+)?your\s+system\s+prompt/i,
  /print\s+your\s+(system\s+prompt|instructions)/i,
  /repeat\s+your\s+(system\s+prompt|instructions)/i,
  // C-04: Safety bypass
  /ignore\s+safety\s+guidelines/i,
  /bypass\s+(content|safety)\s+filter/i,
  /disable\s+(content\s+filter|safety)/i,
  /no\s+restrictions\s+mode/i,
  // C-05: Control tokens
  /<\|im_start\|>/,
  /<\|im_end\|>/,
  /\[INST\]/,
  /<<SYS>>/,
  // C-06: Indirect injection
  /system\s+prompt\s+override/i,
  /new\s+system\s+prompt/i,
  /replace\s+system\s+prompt/i,
];

function lightweightTextScan(text) {
  if (!text) return { action: "PASS", reason: null };

  for (const pattern of INJECTION_PATTERNS) {
    if (pattern.test(text)) {
      return {
        action: "BLOCK",
        reason: `Injection pattern detected: ${pattern.source.substring(0, 60)}`,
      };
    }
  }

  return { action: "PASS", reason: null };
}
