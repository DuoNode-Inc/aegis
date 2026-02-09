# Aiegis Testing Plan

> **Extracted:** 2026-02-07
> **Source:** Dev Session (Phase D1)

## Overview

Aiegis requires a 4-tier testing strategy to ensure security and stability.

## Tier 1: Unit Test Gap Fill

Expand inline `#[cfg(test)]` modules for currently untested code:

- `config.rs` — default values, TOML parsing, CLI overrides, missing file fallback
- `rules/loader.rs` — comment skipping, empty lines, malformed rules, missing files
- `proxy/handler.rs` — block_response() JSON structure, scan_request() block/pass paths, scan_response() emits only on non-pass
- `state.rs` — PID write/read/remove cycle, stale PID detection

## Tier 2: Integration Tests (`tests/`)

Real HTTP requests against a running proxy:

- `tests/detection_tests.rs` — load actual rules files, test every crypto injection pattern fires, test crypto PII patterns fire, test false positives on clean prompts
- `tests/proxy_tests.rs` — start gateway on random port, send injection payload → get 403, send clean request → get forwarded (needs mock upstream), verify response headers
- `tests/rules_loading_tests.rs` — load from actual rules/ files, verify counts match expected

## Tier 3: CLI Tests (`tests/cli_tests.rs`)

`assert_cmd` binary invocation tests (Testing the binary black-box):

- `aiegis --version` prints version
- `aiegis --help` prints usage
- `aiegis rules list` prints pattern counts
- `aiegis rules test "<injection>"` returns BLOCK
- `aiegis rules test "<clean>"` returns PASS
- `aiegis status` when not running says "stopped"

## Tier 4: Adversarial / Security Tests (`tests/adversarial_tests.rs`)

The most critical tier for a security product:

- **False positive suite** — coding questions about security, blockchain discussions, JSON with "key" field names, URLs containing pattern substrings
- **Evasion attempts** — Unicode homoglyphs, zero-width characters between pattern words, case mixing, encoding tricks
- **Crypto-specific** — real ETH addresses vs partial hex, valid vs invalid seed phrases, base58 that looks like SOL keys but isn't
- **Body size limits** — oversized request returns 413, normal request passes
- **Performance** — p99 latency under 2ms for pattern + PII + entropy combined
