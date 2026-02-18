//! Web3 JSON-RPC detection scanner.
//!
//! Detects dangerous Web3/EVM operations embedded in AI proxy traffic.
//! Scans for: scam addresses, unlimited token approvals, ERC-2612 permit
//! phishing, high-value transfers, dangerous function selectors, and
//! insecure RPC endpoints.
//!
//! The scanner tries to parse input text as JSON-RPC or searches for
//! embedded JSON-RPC payloads within larger text bodies.

use serde::Deserialize;
use std::collections::{HashMap, HashSet};

/// Severity of a Web3 detection finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Web3Action {
    Block,
    Flag,
    Pass,
}

/// A Web3 detection match.
#[derive(Debug, Clone)]
pub struct Web3Match {
    /// Detector identifier (e.g. "web3_blocklist", "web3_approval").
    pub detector: String,
    /// Recommended action.
    pub action: Web3Action,
    /// Human-readable reason.
    pub reason: String,
}

/// Sensitivity mode for the scanner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sensitivity {
    /// Blocks more aggressively — all approvals flagged, high-value blocked.
    Strict,
    /// Default — unlimited approvals blocked, high-value flagged.
    Normal,
    /// Permissive — only clear threats blocked.
    Permissive,
}

impl Default for Sensitivity {
    fn default() -> Self {
        Self::Normal
    }
}

/// Web3 JSON-RPC scanner.
pub struct Web3Scanner {
    scam_addresses: HashSet<String>,
    dangerous_selectors: HashMap<&'static str, &'static str>,
    sensitivity: Sensitivity,
}

/// Max-uint256 hex suffix used in unlimited approvals.
const MAX_UINT256_SUFFIX: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

/// 10 ETH in wei.
const HIGH_VALUE_THRESHOLD_WEI: u128 = 10_000_000_000_000_000_000;

// ERC-20 function selectors (first 4 bytes of keccak256).
const SELECTOR_APPROVE: &str = "095ea7b3";
const SELECTOR_TRANSFER_FROM: &str = "23b872dd";
const SELECTOR_SET_APPROVAL_FOR_ALL: &str = "a22cb465";

/// JSON-RPC request shape (partial — only what we need).
#[derive(Deserialize)]
struct JsonRpcRequest {
    method: Option<String>,
    params: Option<serde_json::Value>,
}

/// eth_sendTransaction params shape.
#[derive(Deserialize, Default)]
struct TxParams {
    to: Option<String>,
    value: Option<String>,
    data: Option<String>,
}

/// wallet_addEthereumChain params shape.
#[derive(Deserialize, Default)]
struct ChainParams {
    #[serde(default, rename = "rpcUrls")]
    rpc_urls: Vec<String>,
}

/// wallet_watchAsset params shape.
#[derive(Deserialize, Default)]
struct WatchAssetParams {
    options: Option<WatchAssetOptions>,
}

#[derive(Deserialize, Default)]
struct WatchAssetOptions {
    address: Option<String>,
}

/// EIP-712 typed data envelope (partial).
#[derive(Deserialize)]
struct TypedDataEnvelope {
    #[serde(rename = "primaryType")]
    primary_type: Option<String>,
    message: Option<serde_json::Value>,
}

impl Web3Scanner {
    /// Create a new Web3 scanner with default scam list and selectors.
    pub fn new(sensitivity: Sensitivity) -> Self {
        let mut scam_addresses = HashSet::new();
        // Null address — common phishing target.
        scam_addresses.insert("0x0000000000000000000000000000000000000000".to_lowercase());
        // Dead address.
        scam_addresses.insert("0x000000000000000000000000000000000000dead".to_lowercase());

        let mut dangerous_selectors = HashMap::new();
        dangerous_selectors.insert(SELECTOR_APPROVE, "approve");
        dangerous_selectors.insert(SELECTOR_TRANSFER_FROM, "transferFrom");
        dangerous_selectors.insert(SELECTOR_SET_APPROVAL_FOR_ALL, "setApprovalForAll");

        Self {
            scam_addresses,
            dangerous_selectors,
            sensitivity,
        }
    }

    /// Add a scam address to the blocklist (lowercase hex, with 0x prefix).
    pub fn add_scam_address(&mut self, addr: &str) {
        self.scam_addresses.insert(addr.to_lowercase());
    }

    /// Scan input text for embedded Web3 JSON-RPC payloads.
    ///
    /// Tries to parse the full input as JSON-RPC first. If that fails,
    /// searches for embedded JSON objects that look like RPC calls.
    pub fn scan(&self, input: &str) -> Vec<Web3Match> {
        let mut results = Vec::new();

        // Try full input as JSON-RPC.
        if let Ok(rpc) = serde_json::from_str::<JsonRpcRequest>(input) {
            if let Some(method) = &rpc.method {
                if let Some(m) = self.scan_rpc(method, &rpc.params) {
                    results.push(m);
                }
                return results;
            }
        }

        // Try to find embedded JSON-RPC in the text.
        // Look for patterns like {"method":"eth_sendTransaction"
        for candidate in self.extract_json_candidates(input) {
            if let Ok(rpc) = serde_json::from_str::<JsonRpcRequest>(&candidate) {
                if let Some(method) = &rpc.method {
                    if let Some(m) = self.scan_rpc(method, &rpc.params) {
                        results.push(m);
                    }
                }
            }
        }

        results
    }

    /// Scan a parsed JSON-RPC request.
    fn scan_rpc(&self, method: &str, params: &Option<serde_json::Value>) -> Option<Web3Match> {
        let params = params.as_ref()?;

        match method {
            "eth_sendTransaction" => self.scan_send_transaction(params),
            "eth_signTypedData_v4" | "eth_signTypedData_v3" | "eth_signTypedData" => {
                self.scan_typed_data(params)
            }
            "personal_sign" | "eth_sign" => self.scan_personal_sign(params),
            "eth_sendRawTransaction" => Some(Web3Match {
                detector: "web3_raw_tx".into(),
                action: Web3Action::Flag,
                reason: "Raw transaction broadcast detected — cannot inspect contents".into(),
            }),
            "wallet_addEthereumChain" => self.scan_add_chain(params),
            "wallet_watchAsset" => self.scan_watch_asset(params),
            // Read-only methods are safe.
            "eth_call" | "eth_getBalance" | "eth_getTransactionReceipt"
            | "eth_blockNumber" | "eth_chainId" | "net_version" | "eth_gasPrice"
            | "eth_estimateGas" | "eth_getCode" | "eth_getStorageAt"
            | "eth_getTransactionCount" | "eth_getLogs" => None,
            _ => None,
        }
    }

    /// Scan eth_sendTransaction params.
    fn scan_send_transaction(&self, params: &serde_json::Value) -> Option<Web3Match> {
        let tx = self.extract_tx_params(params)?;

        // Check scam address.
        if let Some(to) = &tx.to {
            if self.scam_addresses.contains(&to.to_lowercase()) {
                return Some(Web3Match {
                    detector: "web3_blocklist".into(),
                    action: Web3Action::Block,
                    reason: format!("Transaction to known scam address: {to}"),
                });
            }
        }

        // Check calldata for dangerous function selectors.
        if let Some(data) = &tx.data {
            let hex = data.strip_prefix("0x").unwrap_or(data);
            if hex.len() >= 8 {
                let selector = &hex[..8].to_lowercase();

                // Unlimited approval check.
                if selector == SELECTOR_APPROVE {
                    if hex.to_lowercase().contains(MAX_UINT256_SUFFIX) {
                        return Some(Web3Match {
                            detector: "web3_approval".into(),
                            action: Web3Action::Block,
                            reason: "Unlimited approve() — grants full token spending rights"
                                .into(),
                        });
                    }
                    // In strict mode, flag ALL approvals.
                    if self.sensitivity == Sensitivity::Strict {
                        return Some(Web3Match {
                            detector: "web3_approval".into(),
                            action: Web3Action::Flag,
                            reason: "Token approval detected (strict mode)".into(),
                        });
                    }
                }

                // setApprovalForAll — always dangerous.
                if selector == SELECTOR_SET_APPROVAL_FOR_ALL {
                    return Some(Web3Match {
                        detector: "web3_approval".into(),
                        action: Web3Action::Block,
                        reason: "setApprovalForAll() — grants full NFT collection access".into(),
                    });
                }

                // transferFrom — flag (could be legitimate delegation).
                if selector == SELECTOR_TRANSFER_FROM {
                    return Some(Web3Match {
                        detector: "web3_transfer".into(),
                        action: Web3Action::Flag,
                        reason: "transferFrom() — moves tokens on behalf of another address"
                            .into(),
                    });
                }
            }
        }

        // Check high-value transfer.
        if let Some(value) = &tx.value {
            if let Some(wei) = parse_hex_u128(value) {
                if wei >= HIGH_VALUE_THRESHOLD_WEI {
                    let eth = wei as f64 / 1e18;
                    let action = if self.sensitivity == Sensitivity::Strict {
                        Web3Action::Block
                    } else {
                        Web3Action::Flag
                    };
                    return Some(Web3Match {
                        detector: "web3_value".into(),
                        action,
                        reason: format!("High-value transfer: {eth:.2} ETH (>{} ETH threshold)", HIGH_VALUE_THRESHOLD_WEI / 1_000_000_000_000_000_000),
                    });
                }
            }
        }

        None
    }

    /// Scan eth_signTypedData_v4 params for ERC-2612 permits and marketplace orders.
    fn scan_typed_data(&self, params: &serde_json::Value) -> Option<Web3Match> {
        // params is [address, typedDataJson]
        let arr = params.as_array()?;
        if arr.len() < 2 {
            return None;
        }

        let typed_str = arr[1].as_str()?;
        let envelope: TypedDataEnvelope = serde_json::from_str(typed_str).ok()?;

        match envelope.primary_type.as_deref() {
            Some("Permit") => {
                // Check for unlimited permit value.
                if let Some(msg) = &envelope.message {
                    if let Some(val) = msg.get("value").and_then(|v| v.as_str()) {
                        let hex = val.strip_prefix("0x").unwrap_or(val);
                        if hex.to_lowercase().contains(MAX_UINT256_SUFFIX) {
                            return Some(Web3Match {
                                detector: "web3_permit".into(),
                                action: Web3Action::Block,
                                reason: "Unlimited ERC-2612 Permit — gasless approval phishing"
                                    .into(),
                            });
                        }
                    }
                }
                Some(Web3Match {
                    detector: "web3_permit".into(),
                    action: Web3Action::Flag,
                    reason: "ERC-2612 Permit signature requested".into(),
                })
            }
            Some("Order") | Some("OrderComponents") => Some(Web3Match {
                detector: "web3_marketplace".into(),
                action: Web3Action::Flag,
                reason: "Marketplace order signature — verify listing details".into(),
            }),
            _ => None,
        }
    }

    /// Scan personal_sign / eth_sign for phishing indicators.
    fn scan_personal_sign(&self, params: &serde_json::Value) -> Option<Web3Match> {
        let arr = params.as_array()?;
        if arr.is_empty() {
            return None;
        }

        // personal_sign params: [data, address] or [address, data]
        let data = arr[0].as_str().unwrap_or("");
        let decoded = hex_decode_if_prefixed(data);

        // Check for phishing keywords in the message.
        let lower = decoded.to_lowercase();
        let phishing_keywords = [
            "claim your",
            "free mint",
            "airdrop",
            "connect wallet",
            "verify ownership",
        ];
        for kw in &phishing_keywords {
            if lower.contains(kw) {
                return Some(Web3Match {
                    detector: "web3_phishing".into(),
                    action: Web3Action::Flag,
                    reason: format!("Potential phishing signature: contains '{kw}'"),
                });
            }
        }

        None
    }

    /// Scan wallet_addEthereumChain for insecure RPC URLs.
    fn scan_add_chain(&self, params: &serde_json::Value) -> Option<Web3Match> {
        let arr = params.as_array().unwrap_or(&Vec::new()).to_owned();
        let chain: ChainParams = if let Some(first) = arr.first() {
            serde_json::from_value(first.clone()).unwrap_or_default()
        } else {
            serde_json::from_value(params.clone()).unwrap_or_default()
        };

        for url in &chain.rpc_urls {
            let lower = url.to_lowercase();
            if lower.starts_with("http://")
                && !lower.starts_with("http://localhost")
                && !lower.starts_with("http://127.0.0.1")
            {
                return Some(Web3Match {
                    detector: "web3_chain".into(),
                    action: Web3Action::Block,
                    reason: format!("Insecure HTTP RPC endpoint: {url}"),
                });
            }
        }

        None
    }

    /// Scan wallet_watchAsset for scam token addresses.
    fn scan_watch_asset(&self, params: &serde_json::Value) -> Option<Web3Match> {
        let arr = params.as_array().unwrap_or(&Vec::new()).to_owned();
        let asset: WatchAssetParams = if let Some(first) = arr.first() {
            serde_json::from_value(first.clone()).unwrap_or_default()
        } else {
            serde_json::from_value(params.clone()).unwrap_or_default()
        };

        if let Some(opts) = &asset.options {
            if let Some(addr) = &opts.address {
                if self.scam_addresses.contains(&addr.to_lowercase()) {
                    return Some(Web3Match {
                        detector: "web3_blocklist".into(),
                        action: Web3Action::Block,
                        reason: format!("Token watch for known scam address: {addr}"),
                    });
                }
            }
        }

        None
    }

    /// Extract transaction params from JSON-RPC params (handles array or object).
    fn extract_tx_params(&self, params: &serde_json::Value) -> Option<TxParams> {
        if let Some(arr) = params.as_array() {
            arr.first()
                .and_then(|v| serde_json::from_value(v.clone()).ok())
        } else {
            serde_json::from_value(params.clone()).ok()
        }
    }

    /// Extract JSON object candidates from text. Finds balanced `{...}` blocks
    /// that contain `"method"`.
    fn extract_json_candidates(&self, input: &str) -> Vec<String> {
        let mut candidates = Vec::new();
        let bytes = input.as_bytes();
        let len = bytes.len();
        let mut i = 0;

        while i < len {
            if bytes[i] == b'{' {
                let start = i;
                let mut depth = 1;
                i += 1;
                while i < len && depth > 0 {
                    match bytes[i] {
                        b'{' => depth += 1,
                        b'}' => depth -= 1,
                        b'"' => {
                            // Skip string contents to avoid false brace matches.
                            i += 1;
                            while i < len && bytes[i] != b'"' {
                                if bytes[i] == b'\\' {
                                    i += 1; // skip escaped char
                                }
                                i += 1;
                            }
                        }
                        _ => {}
                    }
                    i += 1;
                }
                if depth == 0 {
                    let candidate = &input[start..i];
                    if candidate.contains("\"method\"") {
                        candidates.push(candidate.to_string());
                    }
                }
            } else {
                i += 1;
            }
        }

        candidates
    }
}

/// Parse a hex string (with or without 0x prefix) as u128.
fn parse_hex_u128(s: &str) -> Option<u128> {
    let hex = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    if hex.is_empty() {
        return None;
    }
    u128::from_str_radix(hex, 16).ok()
}

/// If the string starts with "0x", try to decode it as hex bytes into UTF-8.
/// Falls back to the original string on any decode failure.
fn hex_decode_if_prefixed(s: &str) -> String {
    let hex = match s.strip_prefix("0x") {
        Some(h) => h,
        None => return s.to_string(),
    };

    let bytes: Result<Vec<u8>, _> = (0..hex.len())
        .step_by(2)
        .map(|i| {
            let end = (i + 2).min(hex.len());
            u8::from_str_radix(&hex[i..end], 16)
        })
        .collect();

    match bytes {
        Ok(b) => String::from_utf8(b).unwrap_or_else(|_| s.to_string()),
        Err(_) => s.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scanner() -> Web3Scanner {
        Web3Scanner::new(Sensitivity::Normal)
    }

    fn strict_scanner() -> Web3Scanner {
        Web3Scanner::new(Sensitivity::Strict)
    }

    // --- eth_sendTransaction ---

    #[test]
    fn passes_clean_transaction() {
        let s = scanner();
        let input = r#"{"method":"eth_sendTransaction","params":[{"to":"0x1234567890abcdef1234567890abcdef12345678","value":"0x1000"}]}"#;
        let matches = s.scan(input);
        assert!(matches.is_empty());
    }

    #[test]
    fn blocks_scam_address() {
        let s = scanner();
        let input = r#"{"method":"eth_sendTransaction","params":[{"to":"0x0000000000000000000000000000000000000000","value":"0x1000"}]}"#;
        let matches = s.scan(input);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].action, Web3Action::Block);
        assert_eq!(matches[0].detector, "web3_blocklist");
    }

    #[test]
    fn blocks_unlimited_approve() {
        let s = scanner();
        let data = format!(
            "0x095ea7b3000000000000000000000000spenderaddr{}",
            "f".repeat(64)
        );
        let input = format!(
            r#"{{"method":"eth_sendTransaction","params":[{{"to":"0xtoken","data":"{data}"}}]}}"#
        );
        let matches = s.scan(&input);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].action, Web3Action::Block);
        assert_eq!(matches[0].detector, "web3_approval");
        assert!(matches[0].reason.to_lowercase().contains("unlimited"));
    }

    #[test]
    fn blocks_set_approval_for_all() {
        let s = scanner();
        let input = r#"{"method":"eth_sendTransaction","params":[{"to":"0xnft","data":"0xa22cb46500000000000000000000000000000001"}]}"#;
        let matches = s.scan(input);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].action, Web3Action::Block);
        assert!(matches[0].reason.contains("setApprovalForAll"));
    }

    #[test]
    fn flags_transfer_from() {
        let s = scanner();
        let input = r#"{"method":"eth_sendTransaction","params":[{"to":"0xtoken","data":"0x23b872dd0000000000000000000000001234567890abcdef"}]}"#;
        let matches = s.scan(input);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].action, Web3Action::Flag);
        assert_eq!(matches[0].detector, "web3_transfer");
    }

    #[test]
    fn flags_high_value_transfer() {
        let s = scanner();
        let value = format!("0x{:x}", 15_000_000_000_000_000_000u128);
        let input = format!(
            r#"{{"method":"eth_sendTransaction","params":[{{"to":"0x1234567890abcdef1234567890abcdef12345678","value":"{value}"}}]}}"#
        );
        let matches = s.scan(&input);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].action, Web3Action::Flag);
        assert_eq!(matches[0].detector, "web3_value");
        assert!(matches[0].reason.contains("ETH"));
    }

    #[test]
    fn blocks_high_value_in_strict_mode() {
        let s = strict_scanner();
        let value = format!("0x{:x}", 15_000_000_000_000_000_000u128);
        let input = format!(
            r#"{{"method":"eth_sendTransaction","params":[{{"to":"0x1234567890abcdef1234567890abcdef12345678","value":"{value}"}}]}}"#
        );
        let matches = s.scan(&input);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].action, Web3Action::Block);
    }

    #[test]
    fn passes_small_value_transfer() {
        let s = scanner();
        let value = format!("0x{:x}", 100_000_000_000_000_000u128); // 0.1 ETH
        let input = format!(
            r#"{{"method":"eth_sendTransaction","params":[{{"to":"0x1234567890abcdef1234567890abcdef12345678","value":"{value}"}}]}}"#
        );
        let matches = s.scan(&input);
        assert!(matches.is_empty());
    }

    #[test]
    fn flags_all_approvals_in_strict_mode() {
        let s = strict_scanner();
        let input = r#"{"method":"eth_sendTransaction","params":[{"to":"0xtoken","data":"0x095ea7b300000000000000000000000012345678000000000000000000000000000003e8"}]}"#;
        let matches = s.scan(&input);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].action, Web3Action::Flag);
        assert_eq!(matches[0].detector, "web3_approval");
    }

    // --- eth_signTypedData_v4 ---

    #[test]
    fn blocks_unlimited_permit() {
        let s = scanner();
        let typed_data = serde_json::json!({
            "primaryType": "Permit",
            "message": {
                "owner": "0xowner",
                "spender": "0xspender",
                "value": format!("0x{}", "f".repeat(64)),
            }
        });
        let input = format!(
            r#"{{"method":"eth_signTypedData_v4","params":["0xowner",{}]}}"#,
            serde_json::to_string(&typed_data.to_string()).unwrap()
        );
        let matches = s.scan(&input);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].action, Web3Action::Block);
        assert_eq!(matches[0].detector, "web3_permit");
    }

    #[test]
    fn flags_marketplace_order() {
        let s = scanner();
        let typed_data = serde_json::json!({
            "primaryType": "Order",
            "message": { "offerer": "0x123" }
        });
        let input = format!(
            r#"{{"method":"eth_signTypedData_v4","params":["0xowner",{}]}}"#,
            serde_json::to_string(&typed_data.to_string()).unwrap()
        );
        let matches = s.scan(&input);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].action, Web3Action::Flag);
        assert_eq!(matches[0].detector, "web3_marketplace");
    }

    #[test]
    fn passes_normal_typed_data() {
        let s = scanner();
        let typed_data = serde_json::json!({
            "primaryType": "Mail",
            "message": { "from": "Alice", "to": "Bob" }
        });
        let input = format!(
            r#"{{"method":"eth_signTypedData_v4","params":["0xowner",{}]}}"#,
            serde_json::to_string(&typed_data.to_string()).unwrap()
        );
        let matches = s.scan(&input);
        assert!(matches.is_empty());
    }

    // --- wallet_addEthereumChain ---

    #[test]
    fn blocks_insecure_http_rpc() {
        let s = scanner();
        let input = r#"{"method":"wallet_addEthereumChain","params":[{"chainId":"0x1","rpcUrls":["http://evil.com/rpc"]}]}"#;
        let matches = s.scan(input);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].action, Web3Action::Block);
        assert_eq!(matches[0].detector, "web3_chain");
    }

    #[test]
    fn allows_https_rpc() {
        let s = scanner();
        let input = r#"{"method":"wallet_addEthereumChain","params":[{"chainId":"0x1","rpcUrls":["https://mainnet.infura.io/v3/key"]}]}"#;
        let matches = s.scan(input);
        assert!(matches.is_empty());
    }

    #[test]
    fn allows_localhost_http() {
        let s = scanner();
        let input = r#"{"method":"wallet_addEthereumChain","params":[{"chainId":"0x539","rpcUrls":["http://localhost:8545"]}]}"#;
        let matches = s.scan(input);
        assert!(matches.is_empty());
    }

    // --- wallet_watchAsset ---

    #[test]
    fn blocks_scam_token_watch() {
        let s = scanner();
        let input = r#"{"method":"wallet_watchAsset","params":[{"type":"ERC20","options":{"address":"0x0000000000000000000000000000000000000000"}}]}"#;
        let matches = s.scan(input);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].action, Web3Action::Block);
        assert_eq!(matches[0].detector, "web3_blocklist");
    }

    #[test]
    fn passes_legitimate_token_watch() {
        let s = scanner();
        let input = r#"{"method":"wallet_watchAsset","params":[{"type":"ERC20","options":{"address":"0xdac17f958d2ee523a2206206994597c13d831ec7"}}]}"#;
        let matches = s.scan(input);
        assert!(matches.is_empty());
    }

    // --- Read-only methods ---

    #[test]
    fn passes_eth_call() {
        let s = scanner();
        let input = r#"{"method":"eth_call","params":[{"to":"0x123","data":"0x"}]}"#;
        let matches = s.scan(input);
        assert!(matches.is_empty());
    }

    #[test]
    fn passes_eth_get_balance() {
        let s = scanner();
        let input = r#"{"method":"eth_getBalance","params":["0x123","latest"]}"#;
        let matches = s.scan(input);
        assert!(matches.is_empty());
    }

    // --- Raw transaction ---

    #[test]
    fn flags_raw_transaction() {
        let s = scanner();
        let input = r#"{"method":"eth_sendRawTransaction","params":["0xf86c"]}"#;
        let matches = s.scan(input);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].action, Web3Action::Flag);
        assert_eq!(matches[0].detector, "web3_raw_tx");
    }

    // --- Embedded JSON-RPC detection ---

    #[test]
    fn detects_embedded_json_rpc() {
        let s = scanner();
        let input = r#"The user wants to execute this transaction: {"method":"eth_sendTransaction","params":[{"to":"0x0000000000000000000000000000000000000000","value":"0x1"}]} can you help?"#;
        let matches = s.scan(input);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].action, Web3Action::Block);
        assert_eq!(matches[0].detector, "web3_blocklist");
    }

    #[test]
    fn no_match_on_clean_text() {
        let s = scanner();
        let input = "What is the capital of France? I like Ethereum but this is just a question.";
        let matches = s.scan(input);
        assert!(matches.is_empty());
    }

    // --- Custom scam address ---

    #[test]
    fn custom_scam_address_blocked() {
        let mut s = scanner();
        s.add_scam_address("0xbadactor1234567890abcdef1234567890abcdef");
        let input = r#"{"method":"eth_sendTransaction","params":[{"to":"0xbadactor1234567890abcdef1234567890abcdef","value":"0x1"}]}"#;
        let matches = s.scan(input);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].action, Web3Action::Block);
    }

    // --- personal_sign phishing ---

    #[test]
    fn flags_phishing_personal_sign() {
        let s = scanner();
        let input = r#"{"method":"personal_sign","params":["0x636c61696d20796f757220616972646f70","0xowner"]}"#;
        // "claim your airdrop" in hex
        let matches = s.scan(input);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].action, Web3Action::Flag);
        assert_eq!(matches[0].detector, "web3_phishing");
    }

    #[test]
    fn passes_normal_personal_sign() {
        let s = scanner();
        let input = r#"{"method":"personal_sign","params":["0x48656c6c6f","0xowner"]}"#;
        // "Hello" in hex
        let matches = s.scan(input);
        assert!(matches.is_empty());
    }

    // --- Utility tests ---

    #[test]
    fn parse_hex_u128_works() {
        assert_eq!(parse_hex_u128("0x0"), Some(0));
        assert_eq!(parse_hex_u128("0x1000"), Some(4096));
        assert_eq!(parse_hex_u128("0xde0b6b3a7640000"), Some(1_000_000_000_000_000_000));
        assert_eq!(parse_hex_u128(""), None);
    }

    #[test]
    fn hex_decode_works() {
        assert_eq!(hex_decode_if_prefixed("0x48656c6c6f"), "Hello");
        assert_eq!(hex_decode_if_prefixed("not hex"), "not hex");
    }

    // --- Dead address variant ---

    #[test]
    fn blocks_dead_address() {
        let s = scanner();
        let input = r#"{"method":"eth_sendTransaction","params":[{"to":"0x000000000000000000000000000000000000dEaD","value":"0x1"}]}"#;
        let matches = s.scan(input);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].action, Web3Action::Block);
        assert_eq!(matches[0].detector, "web3_blocklist");
    }
}
