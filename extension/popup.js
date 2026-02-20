/**
 * popup.js — Aiegis popup UI logic
 */

const $ = (id) => document.getElementById(id);

// ─── Load state ───────────────────────────────────────────────────────────────
chrome.storage.local.get(["enabled", "stats", "events", "tier"], (r) => {
  const enabled = r.enabled !== false;
  const stats = r.stats ?? { scanned: 0, blocked: 0, flagged: 0, wallet_flagged: 0, wallet_blocked: 0 };
  const events = r.events ?? [];
  const tier = r.tier ?? "shield";

  // Toggle
  $("enabled-toggle").checked = enabled;
  updateStatusDisplay(enabled);

  // Tier badge
  $("tier-badge").textContent = tier === "sentinel" ? "[SENTINEL]" : "[SHIELD]";
  if (tier === "sentinel") {
    $("tier-badge").style.cssText =
      "background:#00FF8830;color:#00FF88;border:1px solid #00FF88;padding:3px 8px;font-size:9px;font-weight:700;";
    $("upgrade-box").style.display = "none";
  }

  // Stats
  $("stat-scanned").textContent = formatNumber(stats.scanned);
  $("stat-blocked").textContent = formatNumber(stats.blocked + (stats.wallet_blocked ?? 0));
  $("stat-flagged").textContent = formatNumber(stats.flagged + (stats.wallet_flagged ?? 0));

  // Events feed
  const walletEvents = events.filter((e) => e.type === "wallet");
  const aiEvents = events.filter((e) => e.type !== "wallet");
  renderFeed("wallet-feed", walletEvents, true);
  renderFeed("ai-feed", aiEvents, false);

  // Last scan time
  if (events.length > 0) {
    $("last-scan").textContent = `Last: ${timeAgo(events[0].ts)}`;
  }

  // Version footer
  $("footer-version").textContent = `v0.2.0 · ${tier === "sentinel" ? "Sentinel" : "Shield"}`;
});

// ─── Toggle ───────────────────────────────────────────────────────────────────
$("enabled-toggle").addEventListener("change", (e) => {
  const enabled = e.target.checked;
  chrome.storage.local.set({ enabled });
  updateStatusDisplay(enabled);
});

function updateStatusDisplay(enabled) {
  $("status-dot").className = `dot${enabled ? "" : " inactive"}`;
  $("status-txt").textContent = enabled ? "ACTIVE" : "DISABLED";
  $("status-txt").className = `status-txt${enabled ? "" : " inactive"}`;
}

// ─── Feed rendering ───────────────────────────────────────────────────────────
function renderFeed(containerId, events, isWallet) {
  const container = $(containerId);
  if (!events || events.length === 0) {
    container.innerHTML = `<div class="empty-feed">No ${isWallet ? "wallet " : ""}events yet</div>`;
    return;
  }

  container.innerHTML = events
    .slice(0, 3)
    .map((e) => {
      const badgeClass = e.action === "BLOCK" ? "block" : e.action === "FLAG" ? "flag" : "pass";
      const badgeLabel = `[${e.action}]`;
      const dest = isWallet
        ? (e.method ?? "wallet signing")
        : (e.reason ? e.reason.substring(0, 28) : "clean");
      const reason = isWallet
        ? (e.reason ?? "")
        : (e.type ?? "scan");
      return `
        <div class="event">
          <div class="event-l">
            <span class="badge ${badgeClass}${isWallet ? " wallet" : ""}">${escapeHtml(badgeLabel)}</span>
            <div class="event-info">
              <span class="event-dest">${escapeHtml(dest)}</span>
              <span class="event-reason">${escapeHtml(reason)}</span>
            </div>
          </div>
          <span class="event-time">${timeAgo(e.ts)}</span>
        </div>
      `;
    })
    .join("");
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function formatNumber(n) {
  if (n === undefined || n === null) return "0";
  if (n >= 1000) return (n / 1000).toFixed(1) + "k";
  return String(n);
}

function timeAgo(ts) {
  if (!ts) return "—";
  const secs = Math.round((Date.now() - ts) / 1000);
  if (secs < 5) return "NOW";
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m`;
  return `${Math.floor(secs / 3600)}h`;
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}
