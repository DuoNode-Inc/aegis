/**
 * content.js — Aiegis content script
 *
 * Responsibilities:
 *   1. Inject wallet-interceptor.js into the PAGE context so it can hook
 *      window.ethereum before any dapp code runs.
 *   2. Bridge wallet scan requests from the page → background (WASM + JS analysis).
 *   3. Show warning banners and blocking confirmation modals.
 *   4. Monitor AI chat inputs for prompt injection (clipboard + paste events).
 */

// ─── Inject wallet interceptor into page context ─────────────────────────────
(function injectWalletInterceptor() {
  const script = document.createElement("script");
  script.src = chrome.runtime.getURL("wallet-interceptor.js");
  script.onload = () => script.remove();
  (document.head || document.documentElement).prepend(script);
})();

// ─── AI chat site detection ───────────────────────────────────────────────────
const AI_CHAT_SITES = [
  "chat.openai.com",
  "chatgpt.com",
  "claude.ai",
  "gemini.google.com",
  "bard.google.com",
  "copilot.microsoft.com",
  "poe.com",
  "character.ai",
  "perplexity.ai",
];
const isAIChatSite = AI_CHAT_SITES.some((h) => location.hostname.includes(h));

// ─── State ────────────────────────────────────────────────────────────────────
let aiegisEnabled = true;

chrome.storage.local.get(["enabled"], (r) => {
  if (r.enabled === false) aiegisEnabled = false;
});

chrome.storage.onChanged.addListener((changes) => {
  if (changes.enabled) aiegisEnabled = changes.enabled.newValue;
});

// ─── Bridge: page ↔ content ↔ background ─────────────────────────────────────
window.addEventListener("message", async (event) => {
  if (event.source !== window || !event.data) return;

  if (event.data.type === "AIEGIS_WALLET_SCAN") {
    if (!aiegisEnabled) {
      replyWalletVerdict(event.data.requestId, "PASS", null);
      return;
    }
    await handleWalletScan(event.data);
  }
});

async function handleWalletScan({ requestId, method, params }) {
  // Ask background.js to run risk analysis (has access to WASM + wallet-risk.js)
  const result = await chrome.runtime.sendMessage({
    type: "WALLET_SCAN",
    method,
    params,
  });

  if (!result || result.action === "PASS") {
    replyWalletVerdict(requestId, "PASS", null);
    return;
  }

  if (result.action === "FLAG") {
    showWalletBanner(method, result);
    replyWalletVerdict(requestId, "PASS", result.reason); // FLAG = warn, not block
    return;
  }

  if (result.action === "BLOCK") {
    // Show confirmation modal — user must explicitly allow or deny
    const allowed = await showWalletBlockModal(method, result);
    replyWalletVerdict(requestId, allowed ? "PASS" : "BLOCK", result.reason);
  }
}

function replyWalletVerdict(requestId, action, reason) {
  window.postMessage({ type: "AIEGIS_WALLET_VERDICT", requestId, action, reason }, "*");
}

// ─── AI chat: clipboard / paste scanning ─────────────────────────────────────
if (isAIChatSite) {
  document.addEventListener(
    "paste",
    async (event) => {
      if (!aiegisEnabled) return;
      const text = event.clipboardData?.getData("text/plain");
      if (!text || text.length < 20) return;

      const result = await chrome.runtime.sendMessage({
        type: "SCAN_TEXT",
        text,
        source: "clipboard_paste",
      });

      if (result?.action === "BLOCK") {
        event.preventDefault();
        showInlineBanner("BLOCKED", result.reason ?? "Injection pattern detected in clipboard content");
      } else if (result?.action === "FLAG") {
        showInlineBanner("FLAGGED", result.reason ?? "Potentially risky content detected");
      }
    },
    true
  );
}

// ─── UI: Warning banner (inline, non-blocking) ───────────────────────────────
let activeBanner = null;

function showInlineBanner(level, reason) {
  if (activeBanner) activeBanner.remove();

  const banner = document.createElement("div");
  banner.id = "aiegis-banner";

  const isBlock = level === "BLOCKED";
  const accent = isBlock ? "#FF4444" : "#FF8800";
  const label = isBlock ? "AIEGIS BLOCKED" : "AIEGIS FLAGGED";

  banner.innerHTML = `
    <div class="aiegis-accent"></div>
    <div class="aiegis-body">
      <svg class="aiegis-icon" viewBox="0 0 24 24" fill="none" stroke="${accent}" stroke-width="2">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        <line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
      </svg>
      <div class="aiegis-text">
        <span class="aiegis-title">${label} —</span>
        <span class="aiegis-detail">${escapeHtml(reason)}</span>
      </div>
    </div>
    <button class="aiegis-dismiss" aria-label="Dismiss">✕</button>
  `;

  injectBannerStyles(accent);
  document.body.prepend(banner);
  activeBanner = banner;

  banner.querySelector(".aiegis-dismiss").addEventListener("click", () => banner.remove());
  setTimeout(() => { if (banner.isConnected) banner.remove(); }, 8000);
}

function showWalletBanner(method, result) {
  showInlineBanner(
    "FLAGGED",
    `${method} — ${result.reason}${result.detail ? ` · ${result.detail}` : ""}`
  );
}

// ─── UI: Blocking confirmation modal ─────────────────────────────────────────
function showWalletBlockModal(method, result) {
  return new Promise((resolve) => {
    injectModalStyles();

    const overlay = document.createElement("div");
    overlay.id = "aiegis-modal-overlay";

    overlay.innerHTML = `
      <div id="aiegis-modal">
        <div class="am-header">
          <span class="am-logo">▲ AIEGIS</span>
          <span class="am-badge am-badge-block">[BLOCK]</span>
        </div>
        <div class="am-body">
          <div class="am-alert-row">
            <svg class="am-icon" viewBox="0 0 24 24" fill="none" stroke="#FF4444" stroke-width="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              <line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
            </svg>
            <span class="am-method">${escapeHtml(method)}</span>
          </div>
          <p class="am-reason">${escapeHtml(result.reason)}</p>
          ${result.detail ? `<p class="am-detail">${escapeHtml(result.detail)}</p>` : ""}
        </div>
        <div class="am-footer">
          <button id="aiegis-modal-cancel" class="am-btn am-btn-cancel">
            CANCEL (RECOMMENDED)
          </button>
          <button id="aiegis-modal-allow" class="am-btn am-btn-allow">
            SIGN ANYWAY
          </button>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    overlay.querySelector("#aiegis-modal-cancel").addEventListener("click", () => {
      overlay.remove();
      resolve(false);
    });

    overlay.querySelector("#aiegis-modal-allow").addEventListener("click", () => {
      overlay.remove();
      resolve(true);
    });

    // Clicking outside the modal cancels
    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) { overlay.remove(); resolve(false); }
    });
  });
}

// ─── Styles ───────────────────────────────────────────────────────────────────
let bannerStylesInjected = false;
function injectBannerStyles(accentColor) {
  if (bannerStylesInjected) {
    // Update accent variable only
    document.getElementById("aiegis-banner-style")?.remove();
  }
  const style = document.createElement("style");
  style.id = "aiegis-banner-style";
  style.textContent = `
    #aiegis-banner {
      position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647;
      display: flex; align-items: stretch; height: 64px;
      font-family: 'JetBrains Mono', 'Fira Code', monospace;
      background: #0f0808; border-bottom: 1px solid ${accentColor}40;
      box-shadow: 0 4px 24px rgba(0,0,0,0.6);
    }
    #aiegis-banner .aiegis-accent {
      width: 4px; background: ${accentColor}; flex-shrink: 0;
    }
    #aiegis-banner .aiegis-body {
      flex: 1; display: flex; align-items: center; gap: 12px; padding: 0 16px;
    }
    #aiegis-banner .aiegis-icon { width: 18px; height: 18px; flex-shrink: 0; }
    #aiegis-banner .aiegis-text { font-size: 12px; line-height: 1.4; }
    #aiegis-banner .aiegis-title { color: ${accentColor}; font-weight: 700; }
    #aiegis-banner .aiegis-detail { color: #8a8a8a; margin-left: 4px; }
    #aiegis-banner .aiegis-dismiss {
      background: none; border: none; color: #5a5a5a; font-size: 14px;
      padding: 0 16px; cursor: pointer; font-family: inherit;
    }
    #aiegis-banner .aiegis-dismiss:hover { color: #aaa; }
  `;
  document.head.appendChild(style);
  bannerStylesInjected = true;
}

let modalStylesInjected = false;
function injectModalStyles() {
  if (modalStylesInjected) return;
  modalStylesInjected = true;
  const style = document.createElement("style");
  style.textContent = `
    #aiegis-modal-overlay {
      position: fixed; inset: 0; z-index: 2147483647;
      background: rgba(0,0,0,0.75);
      display: flex; align-items: center; justify-content: center;
      font-family: 'JetBrains Mono', 'Fira Code', monospace;
    }
    #aiegis-modal {
      background: #0C0C0C; border: 1px solid #2f2f2f;
      width: 420px; max-width: 90vw; overflow: hidden;
    }
    .am-header {
      background: #080808; padding: 14px 16px;
      display: flex; align-items: center; justify-content: space-between;
      border-bottom: 1px solid #2f2f2f;
    }
    .am-logo { color: #FFFFFF; font-size: 13px; font-weight: 600; letter-spacing: 1px; }
    .am-badge { padding: 3px 8px; font-size: 9px; font-weight: 700; }
    .am-badge-block {
      background: #FF444420; color: #FF4444;
      border: 1px solid #FF4444;
    }
    .am-body { padding: 20px 16px 16px; }
    .am-alert-row {
      display: flex; align-items: center; gap: 10px; margin-bottom: 12px;
    }
    .am-icon { width: 16px; height: 16px; flex-shrink: 0; }
    .am-method { color: #FF4444; font-size: 12px; font-weight: 700; }
    .am-reason { color: #FFFFFF; font-size: 11px; margin: 0 0 8px; line-height: 1.5; }
    .am-detail { color: #6a6a6a; font-size: 10px; margin: 0; line-height: 1.5; }
    .am-footer {
      display: flex; gap: 1px; border-top: 1px solid #2f2f2f;
    }
    .am-btn {
      flex: 1; padding: 14px 8px; border: none; cursor: pointer;
      font-family: inherit; font-size: 10px; font-weight: 700; letter-spacing: 1px;
    }
    .am-btn-cancel { background: #FF4444; color: #000000; }
    .am-btn-cancel:hover { background: #ff6666; }
    .am-btn-allow {
      background: #141414; color: #5a5a5a;
      border-left: 1px solid #2f2f2f;
    }
    .am-btn-allow:hover { color: #FF4444; }
  `;
  document.head.appendChild(style);
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
