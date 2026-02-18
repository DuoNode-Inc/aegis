/**
 * wallet-interceptor.js
 *
 * Injected into the PAGE context (not extension context) via a <script> tag.
 * Hooks window.ethereum.request before any dapp code can call it.
 *
 * Flow:
 *   dapp calls window.ethereum.request({ method, params })
 *     → interceptor posts AIEGIS_WALLET_SCAN to window
 *     → content.js receives it, runs risk analysis, posts back AIEGIS_WALLET_VERDICT
 *     → interceptor resolves original promise (or rejects if blocked)
 *
 * All message traffic uses a unique requestId to match verdicts to pending calls.
 * Timeout: if no verdict arrives in 15s, we default to PASS (fail-open).
 */

(function interceptEthereum() {
  const SIGNING_METHODS = new Set([
    "eth_sign",
    "personal_sign",
    "eth_signTypedData",
    "eth_signTypedData_v1",
    "eth_signTypedData_v3",
    "eth_signTypedData_v4",
    "eth_sendTransaction",
  ]);

  const VERDICT_TIMEOUT_MS = 15_000;
  let requestCounter = 0;
  const pendingVerdicts = new Map(); // requestId → { resolve, reject }

  function hookProvider(provider) {
    if (provider.__aiegis_hooked) return;
    provider.__aiegis_hooked = true;

    const _originalRequest = provider.request.bind(provider);

    provider.request = async function aiegisRequest(args) {
      if (!args || !SIGNING_METHODS.has(args.method)) {
        return _originalRequest(args);
      }

      const requestId = `aiegis-${Date.now()}-${++requestCounter}`;

      const verdictPromise = new Promise((resolve, reject) => {
        pendingVerdicts.set(requestId, { resolve, reject });

        setTimeout(() => {
          if (pendingVerdicts.has(requestId)) {
            pendingVerdicts.delete(requestId);
            resolve({ action: "PASS", reason: "timeout" });
          }
        }, VERDICT_TIMEOUT_MS);
      });

      window.postMessage(
        {
          type: "AIEGIS_WALLET_SCAN",
          requestId,
          method: args.method,
          params: args.params,
        },
        "*"
      );

      const verdict = await verdictPromise;

      if (verdict.action === "BLOCK") {
        const err = new Error(
          `[Aiegis] Signing request blocked: ${verdict.reason}`
        );
        err.code = 4001; // EIP-1193 user rejected
        throw err;
      }

      return _originalRequest(args);
    };
  }

  // Listen for verdicts coming back from content.js
  window.addEventListener("message", (event) => {
    if (
      event.source !== window ||
      !event.data ||
      event.data.type !== "AIEGIS_WALLET_VERDICT"
    ) {
      return;
    }

    const { requestId, action, reason } = event.data;
    const pending = pendingVerdicts.get(requestId);
    if (!pending) return;

    pendingVerdicts.delete(requestId);
    pending.resolve({ action, reason });
  });

  // Hook whatever is already there
  if (window.ethereum) {
    hookProvider(window.ethereum);
  }

  // Watch for late injection (some wallets set window.ethereum asynchronously)
  Object.defineProperty(window, "ethereum", {
    configurable: true,
    enumerable: true,
    get() {
      return this._aiegis_ethereum;
    },
    set(newProvider) {
      this._aiegis_ethereum = newProvider;
      if (newProvider && !newProvider.__aiegis_hooked) {
        hookProvider(newProvider);
      }
    },
  });
})();
