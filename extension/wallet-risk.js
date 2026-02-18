/**
 * wallet-risk.js
 *
 * Risk analysis for wallet signing requests.
 * Runs in the content script context (NOT page context).
 * No external deps — pure JS analysis of EIP-712 / transaction payloads.
 *
 * Returns a RiskResult:
 *   { action: "BLOCK"|"FLAG"|"PASS", level: 0-3, reason, detail }
 */

const MAX_UINT256 =
  "115792089237316195423570985008687907853269984665640564039457584007913129639935";

// 4-byte selectors for risky contract calls
const RISKY_SELECTORS = {
  "0x095ea7b3": "ERC-20 approve(spender, amount)",
  "0x23b872dd": "transferFrom(from, to, amount)",
  "0x2e1a7d4d": "WETH withdraw(amount)",
  "0xa22cb465": "setApprovalForAll(operator, approved)",
  "0x42842e0e": "safeTransferFrom(from, to, tokenId)",
  "0xb88d4fde": "safeTransferFrom(from, to, tokenId, data)",
};

// EIP-712 primaryTypes that indicate significant value flow
const HIGH_RISK_PRIMARY_TYPES = new Set([
  "PermitBatch",
  "PermitSingle",
  "Permit",
  "Order",
  "BulkOrder",
  "BasicOrderParameters",
  "MakerOrder",
  "TakerOrder",
  "BatchListing",
  "ContractWideCollectionBid",
  "CollectionOffer",
  "OfferItem",
  "ConsiderationItem",
]);

// Phishing keywords commonly seen in social-engineering signed messages
const PHISHING_PATTERNS = [
  /verify\s+(your\s+)?(wallet|account|ownership)/i,
  /claim\s+(your\s+)?(reward|prize|airdrop|nft|tokens?)/i,
  /you\s+(have\s+)?won/i,
  /urgent[:\s]/i,
  /limited\s+time/i,
  /act\s+now/i,
  /free\s+(nft|tokens?|mint)/i,
  /connect\s+(your\s+)?wallet\s+to/i,
  /authorize\s+(all|unlimited)/i,
  /grant\s+(full\s+)?access/i,
  /sign\s+to\s+(unlock|claim|receive)/i,
  // Prompt injection in signed messages is a novel attack vector
  /ignore\s+(previous|all|your)\s+(instructions?|rules?)/i,
  /system\s+prompt/i,
  /developer\s+mode/i,
];

/**
 * Analyze a personal_sign message (hex-encoded or plain text).
 */
function analyzePersonalSign(params) {
  if (!params || params.length < 1) {
    return { action: "PASS", level: 0, reason: null, detail: null };
  }

  let message = params[0];

  // Decode hex message to text if possible
  if (typeof message === "string" && message.startsWith("0x")) {
    try {
      const hex = message.slice(2);
      const bytes = new Uint8Array(hex.match(/.{2}/g).map((b) => parseInt(b, 16)));
      message = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    } catch (_) {
      // Leave as-is if decode fails
    }
  }

  for (const pattern of PHISHING_PATTERNS) {
    if (pattern.test(message)) {
      return {
        action: "FLAG",
        level: 2,
        reason: "Phishing pattern in signed message",
        detail: `Pattern matched: ${pattern.source.substring(0, 60)}`,
      };
    }
  }

  return { action: "PASS", level: 0, reason: null, detail: null };
}

/**
 * Analyze an eth_signTypedData_v4 (EIP-712) payload.
 */
function analyzeTypedData(params) {
  if (!params || params.length < 2) {
    return { action: "PASS", level: 0, reason: null, detail: null };
  }

  let typedData;
  try {
    typedData = typeof params[1] === "string" ? JSON.parse(params[1]) : params[1];
  } catch (_) {
    return { action: "FLAG", level: 1, reason: "Malformed EIP-712 payload", detail: null };
  }

  const primaryType = typedData?.primaryType;
  const message = typedData?.message;
  const domain = typedData?.domain;

  // High-risk primaryType (marketplace orders, bulk permits)
  if (primaryType && HIGH_RISK_PRIMARY_TYPES.has(primaryType)) {
    return {
      action: "FLAG",
      level: 2,
      reason: `EIP-712 approval request: ${primaryType}`,
      detail: `verifyingContract: ${domain?.verifyingContract ?? "unknown"}`,
    };
  }

  // Unlimited token approval (Permit / approve)
  if (message) {
    const valueFields = ["value", "amount", "allowance"];
    for (const field of valueFields) {
      const val = message[field];
      if (val !== undefined) {
        const valStr = val.toString();
        if (valStr === MAX_UINT256 || valStr === "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff") {
          return {
            action: "FLAG",
            level: 2,
            reason: "Unlimited token approval (MAX_UINT256)",
            detail: `${primaryType ?? "Permit"} · spender: ${message.spender ?? "unknown"}`,
          };
        }
        // Flag approvals ≥ 1e18 tokens (likely large approval)
        try {
          if (BigInt(valStr) >= BigInt("1000000000000000000")) {
            return {
              action: "FLAG",
              level: 1,
              reason: "Large token approval",
              detail: `${primaryType ?? "Permit"} · amount: ${valStr}`,
            };
          }
        } catch (_) {}
      }
    }

    // Deadline in the past (replay attack)
    if (message.deadline !== undefined) {
      try {
        const deadline = Number(message.deadline);
        if (deadline > 0 && deadline < Date.now() / 1000) {
          return {
            action: "FLAG",
            level: 1,
            reason: "Permit with expired deadline",
            detail: `deadline: ${new Date(deadline * 1000).toISOString()}`,
          };
        }
      } catch (_) {}
    }
  }

  return { action: "PASS", level: 0, reason: null, detail: null };
}

/**
 * Analyze an eth_sendTransaction payload.
 */
function analyzeTransaction(params) {
  if (!params || params.length < 1) {
    return { action: "PASS", level: 0, reason: null, detail: null };
  }

  const tx = params[0];
  if (!tx) return { action: "PASS", level: 0, reason: null, detail: null };

  // Contract deployment
  if (!tx.to) {
    return {
      action: "FLAG",
      level: 1,
      reason: "Contract deployment",
      detail: "Transaction deploys a new contract",
    };
  }

  // High ETH value (> 0.05 ETH = 50000000000000000 wei)
  if (tx.value) {
    try {
      const weiValue = BigInt(tx.value);
      const threshold = BigInt("50000000000000000"); // 0.05 ETH
      if (weiValue >= threshold) {
        const eth = Number(weiValue) / 1e18;
        return {
          action: "FLAG",
          level: 2,
          reason: `High-value transaction: ${eth.toFixed(4)} ETH`,
          detail: `to: ${tx.to}`,
        };
      }
    } catch (_) {}
  }

  // Risky call selector in data
  if (tx.data && tx.data.length >= 10) {
    const selector = tx.data.slice(0, 10).toLowerCase();
    const selectorName = RISKY_SELECTORS[selector];
    if (selectorName) {
      // Check for unlimited approval inside data
      if (selector === "0x095ea7b3" && tx.data.length >= 74) {
        const amountHex = tx.data.slice(34, 74);
        if (amountHex === "f".repeat(40) || BigInt("0x" + amountHex) >= BigInt("0x" + "f".repeat(38))) {
          return {
            action: "FLAG",
            level: 2,
            reason: "Unlimited ERC-20 approval",
            detail: `approve() · spender: 0x${tx.data.slice(10, 34)} · amount: MAX`,
          };
        }
      }
      return {
        action: "FLAG",
        level: 1,
        reason: `Risky contract call: ${selectorName}`,
        detail: `to: ${tx.to} · selector: ${selector}`,
      };
    }
  }

  return { action: "PASS", level: 0, reason: null, detail: null };
}

/**
 * Top-level entry point.
 * @param {string} method  - The ethereum RPC method
 * @param {Array}  params  - The call parameters
 * @returns {RiskResult}
 */
function analyzeWalletRequest(method, params) {
  switch (method) {
    case "eth_sign":
      // Raw 32-byte hash signing — no human-readable context.
      // MetaMask itself warns this is dangerous. We BLOCK by default.
      return {
        action: "BLOCK",
        level: 3,
        reason: "eth_sign is a phishing vector",
        detail:
          "Raw hash signing provides no human-readable context. " +
          "Attackers use this to sign arbitrary transactions disguised as harmless messages. " +
          "Use personal_sign or eth_signTypedData_v4 instead.",
      };

    case "personal_sign":
      return analyzePersonalSign(params);

    case "eth_signTypedData":
    case "eth_signTypedData_v1":
    case "eth_signTypedData_v3":
    case "eth_signTypedData_v4":
      return analyzeTypedData(params);

    case "eth_sendTransaction":
      return analyzeTransaction(params);

    default:
      return { action: "PASS", level: 0, reason: null, detail: null };
  }
}

// Export for content.js (CommonJS-style, works in MV3 service workers too)
if (typeof module !== "undefined") {
  module.exports = { analyzeWalletRequest };
} else {
  self.analyzeWalletRequest = analyzeWalletRequest;
}
