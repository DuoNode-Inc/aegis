/**
 * bridge.js — Backend abstraction layer for Aiegis extension
 *
 * Detects which Aiegis binary mode is available and routes scan requests
 * accordingly. Priority order:
 *
 *   Mode A — Sidecar  : aiegis sidecar (port 9999, scan-only server)
 *   Mode B — Gateway  : aiegis start --mode gateway (port 8080, has /aiegis/scan)
 *   Mode C — JS only  : no binary; lightweight JS pattern fallback
 *
 * The detected mode is cached for CACHE_TTL_MS then re-probed.
 * All public functions return { action, reason, confidence, latency_us, backend }.
 */

const SIDECAR_URL  = "http://127.0.0.1:9999";
const GATEWAY_URL  = "http://127.0.0.1:8080";
const PROBE_TIMEOUT_MS = 400;
const CACHE_TTL_MS     = 30_000;

// Backend mode cache
let cachedBackend   = null; // "sidecar" | "gateway" | "js"
let cacheExpiresAt  = 0;

/**
 * Probe available backends and cache the result.
 * @returns {Promise<"sidecar"|"gateway"|"js">}
 */
async function detectBackend() {
  const now = Date.now();
  if (cachedBackend && now < cacheExpiresAt) return cachedBackend;

  // Try sidecar first (dedicated scan port, lowest overhead)
  try {
    const r = await fetch(`${SIDECAR_URL}/status`, {
      signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
    });
    if (r.ok) {
      const data = await r.json();
      cachedBackend  = "sidecar";
      cacheExpiresAt = now + CACHE_TTL_MS;
      // Surface binary tier to storage so popup can show it
      if (data.tier) chrome.storage.local.set({ tier: data.tier, binaryVersion: data.version });
      return "sidecar";
    }
  } catch (_) {}

  // Try gateway (binary in gateway/proxy mode — exposes /aiegis/scan)
  try {
    const r = await fetch(`${GATEWAY_URL}/aiegis/status`, {
      signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
    });
    if (r.ok) {
      const data = await r.json();
      cachedBackend  = "gateway";
      cacheExpiresAt = now + CACHE_TTL_MS;
      if (data.tier) chrome.storage.local.set({ tier: data.tier, binaryVersion: data.version });
      return "gateway";
    }
  } catch (_) {}

  cachedBackend  = "js";
  cacheExpiresAt = now + CACHE_TTL_MS;
  chrome.storage.local.set({ tier: "shield", binaryVersion: null });
  return "js";
}

/**
 * Scan text for injection / PII threats.
 * @param {string} text
 * @param {string} source  e.g. "clipboard_paste"
 * @returns {Promise<ScanResult>}
 */
async function scanText(text, source = "extension") {
  const backend = await detectBackend();

  if (backend === "sidecar") {
    return fetchScan(`${SIDECAR_URL}/scan`, { text, source });
  }

  if (backend === "gateway") {
    return fetchScan(`${GATEWAY_URL}/aiegis/scan`, { text, source });
  }

  return jsScan(text);
}

/**
 * Analyze a wallet signing request.
 * @param {string} method  EVM RPC method
 * @param {Array}  params  Call parameters
 * @returns {Promise<ScanResult>}
 */
async function scanWallet(method, params) {
  const backend = await detectBackend();

  if (backend === "sidecar") {
    return fetchScan(`${SIDECAR_URL}/scan/wallet`, { method, params });
  }

  if (backend === "gateway") {
    return fetchScan(`${GATEWAY_URL}/aiegis/scan/wallet`, { method, params });
  }

  // JS fallback for wallet is handled entirely in wallet-risk.js
  return { action: "PASS", reason: null, confidence: 0, latency_us: 0, backend: "js" };
}

/**
 * Return cached backend status without triggering a probe.
 */
function getBackendStatus() {
  return {
    backend: cachedBackend ?? "unknown",
    cacheValid: Date.now() < cacheExpiresAt,
  };
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

async function fetchScan(url, body) {
  try {
    const t0 = Date.now();
    const r = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(5000),
    });

    if (!r.ok) {
      return { action: "PASS", reason: null, confidence: 0, latency_us: Date.now() - t0, backend: cachedBackend };
    }

    const data = await r.json();
    return {
      action:     data.action     ?? "PASS",
      reason:     data.reason     ?? null,
      confidence: data.confidence ?? 0,
      latency_us: data.latency_us ?? (Date.now() - t0) * 1000,
      backend:    cachedBackend,
      detector:   data.detector   ?? null,
    };
  } catch (_) {
    // Binary went away mid-session — invalidate cache
    cachedBackend  = null;
    cacheExpiresAt = 0;
    return jsScan(typeof body.text === "string" ? body.text : "");
  }
}

// ─── JS-only pattern fallback (mirrors injection-shield.rules C-01..C-06) ─────
const JS_PATTERNS = [
  /ignore\s+(previous|all|your)\s+(instructions?|rules?)/i,
  /disregard\s+(previous|your|the)\s+(instructions?|rules?)/i,
  /forget\s+(previous|all|prior)\s+(instructions?|rules?)/i,
  /override\s+(previous|your|the)\s+(instructions?|rules?)/i,
  /you\s+are\s+now\s+(DAN|jailbroken|in\s+developer\s+mode)/i,
  /act\s+as\s+(DAN|an\s+unrestricted|if\s+you\s+have\s+no)/i,
  /enter\s+(developer|DAN)\s+mode/i,
  /reveal\s+your\s+system\s+prompt/i,
  /show\s+(me\s+)?your\s+system\s+prompt/i,
  /print\s+your\s+(system\s+prompt|instructions)/i,
  /ignore\s+safety\s+guidelines/i,
  /bypass\s+(content|safety)\s+filter/i,
  /<\|im_start\|>/,
  /<\|im_end\|>/,
  /\[INST\]/,
  /<<SYS>>/,
  /system\s+prompt\s+override/i,
  /new\s+system\s+prompt/i,
];

function jsScan(text) {
  const t0 = Date.now();
  if (!text) return { action: "PASS", reason: null, confidence: 0, latency_us: 0, backend: "js" };

  for (const pat of JS_PATTERNS) {
    if (pat.test(text)) {
      return {
        action:     "BLOCK",
        reason:     `Injection pattern: ${pat.source.substring(0, 60)}`,
        confidence: 1.0,
        latency_us: (Date.now() - t0) * 1000,
        backend:    "js",
        detector:   "injection",
      };
    }
  }

  return { action: "PASS", reason: null, confidence: 0, latency_us: (Date.now() - t0) * 1000, backend: "js" };
}

// Export
self.AiegisBridge = { scanText, scanWallet, detectBackend, getBackendStatus };
