# AIEGIS MODULE — AI RULES

> **Persona:** VALIDITUS (Security Critic)
> **Runtime:** Rust
> **Scope:** v0.1 Shield Preview — rules engine + gateway proxy. Scope is locked.

## Non-Negotiable Rules

1. **V0.1 SCOPE IS LOCKED.** Do not build: TLS MITM, LLM integration, licensing, fleet management, web UI, user accounts, telemetry, or phone-home.
2. **NO UNWRAP ON USER INPUT.** Never `unwrap()` or `expect()` on code paths handling user input or network I/O. `unwrap()` is acceptable ONLY in tests and static init.
3. **NO PRINTLN IN LIB CODE.** All logging through `tracing` macros. `println!` acceptable only in CLI output commands.
4. **CLIPPY CLEAN.** `cargo clippy -- -D warnings` must pass at all times.
5. **PERFORMANCE.** Detection pipeline target: < 2ms p99. Aho-Corasick automaton built once at startup, reused.

## Build & Test

```bash
cd aiegis-module/
cargo check
cargo test
cargo clippy -- -D warnings
cargo build --release    # Target: < 15MB binary
```

## Error Handling

- `thiserror` for typed errors in library code (detection, rules, config).
- `anyhow` for application-level error propagation (main, CLI, proxy).

## Architecture Rules

- **Detection Pipeline:** injection (Aho-Corasick) → PII (regex) → entropy (Shannon) → Verdict (PASS/BLOCK/FLAG).
- **Gateway Mode:** Reverse proxy, route by path prefix (`/openai/*`, `/anthropic/*`, etc.).
- **Proxy Mode:** Traditional HTTP proxy via `HTTP_PROXY` env var.
- **Block Response:** HTTP 403 with JSON `{ error: { type, detector, reason, confidence } }`.

## Testing Rules

- Every injection pattern has a test that confirms it triggers.
- Every PII pattern has a test with a realistic example.
- False positive tests: normal coding questions, security discussions must NOT trigger.
- Integration tests spin up the actual proxy on a random port.
