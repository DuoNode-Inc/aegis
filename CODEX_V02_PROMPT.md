You are a senior Rust systems engineer planning the next version of Aiegis, a local AI security firewall. You will use a closed-loop iteration cycle with circuit breaker logic to plan every feature of V0.2.

## V0.1 BASELINE (what exists, shipped)

- Rust binary, 3,780 LOC across 18 source files
- 60 passing tests (30 adversarial, 18 CLI, 12 detection)
- 8MB ARM64 binary, 0 clippy warnings
- Gateway reverse proxy (hyper v1, port 8080) + traditional forward proxy mode
- Detection pipeline: Aho-Corasick injection (147 patterns, <1ms) → Regex PII (27 patterns) → Shannon entropy
- Rules engine: injection.rules, pii.rules, endpoints.rules, web3_addresses.rules
- CLI: start, stop, status, logs, rules list, rules test
- TOML config with defaults
- Structured JSON logging (tracing)
- Verdict: PASS / BLOCK / FLAG with confidence score + latency_us
- Dependencies: hyper 1, tokio 1, rustls 0.23, tokio-rustls 0.26, aho-corasick 1, regex 1, clap 4, serde 1, tracing 0.1, anyhow 1, thiserror 2
- GitHub: DuoNode-Inc/aiegis, tag v0.1.0
- No TLS MITM, no LLM, no licensing, no dashboard, no telemetry

## V0.2 TARGET: "Neural Shield"

V0.2 adds two major capabilities:

### Feature Group A: TLS Transparent Proxy (D3)
MITM transparent proxy using rustls + rcgen so Aiegis can inspect HTTPS request/response bodies (not just log endpoints).
- Generate CA cert at first boot (rcgen)
- On CONNECT, generate leaf cert per SNI hostname
- Client must trust the Aiegis CA
- Developer tier and above only. Shield (free) tier stays explicit proxy only.
- New file: src/tls.rs
- Modified: src/proxy/forward.rs
- New crates: rcgen
- Test: Proxy HTTPS request to httpbin.org, verify request body was scanned

### Feature Group B: Neural Classifier
Add an ONNX-based ML classifier that fires on AMBIGUOUS verdicts from the rules engine (when rules can't decide).
- ONNX Runtime for Rust inference
- Tokenizer (tiktoken or sentencepiece compatible)
- Model: small text classifier (~50MB ONNX, quantized INT8)
- Only fires when rules engine returns AMBIGUOUS (new verdict state)
- First 512 tokens of input
- Returns: { verdict: safe|injection|jailbreak|pii|malicious, confidence: 0.0-1.0 }
- New files: src/detection/classifier.rs, src/detection/tokenizer.rs
- Modified: src/detection/pipeline.rs (add AMBIGUOUS state, wire classifier)
- New crates: ort (ONNX Runtime), tokenizers
- ~800 new LOC

### Feature Group C: Enhanced Detection
- AMBIGUOUS verdict state in pipeline (between PASS and BLOCK)
- Per-detector action overrides in config (block, flag, log per detector)
- Response scanning (scan AI responses for data exfil, not just requests)
- Configurable classifier confidence threshold

### Feature Group D: Pricing & Tier Gating (prep for V0.3 licensing)
- detect_mode() function: check for /etc/realm/aiegis.toml → Realm OS mode (no license needed), else standalone
- TierGate trait: Shield (free) vs Developer ($25 one-time) vs Sentinel ($10/mo/node)
- Shield tier: rules-only, explicit proxy, no TLS MITM, no classifier
- Developer tier: TLS MITM + classifier + custom patterns
- Sentinel tier: everything + rate limiting + metrics + dashboard (V0.3)
- No actual license validation yet — just the gate structure and config

## CLOSED-LOOP ITERATION CYCLE

Execute this 8-step cycle for each feature group (A, B, C, D). The cycle has circuit breaker logic — if a step fails 3 times, STOP and escalate.

### Step 1: GAP ANALYSIS
For the feature group, enumerate:
- What V0.1 HAS that this builds on
- What V0.2 NEEDS (exact capabilities)
- The DELTA = new files, modified files, new deps, new tests

### Step 2: DEPENDENCY AUDIT
For each new crate:
- Latest stable version on crates.io
- Breaking changes vs current Cargo.toml
- Conflicts with existing deps (especially rustls/tokio versions)
- Binary size impact estimate
- CIRCUIT BREAKER: If a dependency conflict is unresolvable, flag it and skip to next feature group

### Step 3: FILE MANIFEST
For each new/modified file:
- Path, estimated LOC, purpose
- Integration point (which existing file it connects to)
- Test companion file
- Output as a table

### Step 4: IMPLEMENTATION MILESTONES
Group into 2-4 milestones per feature group:
- Each milestone has: name, steps, files touched, gate criteria
- Each step has: action verb, file, verification command
- Milestones are ordered — M1 must pass before M2 starts
- CIRCUIT BREAKER: If a milestone has >5 hard dependencies on unfinished work, defer it

### Step 5: RISK REGISTER
For each feature group:
- Build risks (compile failures, dep conflicts)
- Runtime risks (performance regression, memory bloat from ONNX)
- Security risks (CA key storage, MITM cert validation)
- Mitigation for each
- Severity: LOW / MEDIUM / HIGH / CRITICAL

### Step 6: ACCEPTANCE CRITERIA
When is this feature group DONE:
- Test count target (V0.2 total should be 80+ tests)
- Benchmark targets (rules path stays <2ms, classifier path <50ms, TLS handshake <100ms)
- Binary size target (<25MB with ONNX, <12MB without)
- Feature verification checklist (specific curl commands that prove it works)

### Step 7: MARKETING ALIGNMENT
For each feature group, confirm it supports the go-to-market:
- Which pricing tier does it unlock?
- What's the user-facing benefit? (not the technical spec)
- Does it strengthen "local-first" positioning?
- Does it differentiate from cloud alternatives?
- One-line value prop for the feature

### Step 8: RECYCLE OR RELEASE
- If more feature groups remain → recycle to Step 1 for the next group
- If all groups done → produce the FINAL V0.2 RELEASE PLAN (consolidated)

## CIRCUIT BREAKER RULES

- If any step fails 3 times (unresolvable conflict, missing info, circular dependency) → OPEN the breaker
- When breaker is OPEN: stop iteration, document the blocker, skip to next feature group
- After all groups: list all open breakers as "V0.2 BLOCKERS" requiring human decision
- Breaker states: CLOSED (normal), OPEN (blocked), HALF-OPEN (retrying after fix)

## OUTPUT FORMAT

For each feature group, produce:

```
=============================================
  AIEGIS V0.2 FEATURE PLAN: {GROUP_NAME}
  Codename: Neural Shield
  Breaker: CLOSED | OPEN | HALF-OPEN
=============================================

GAP SUMMARY
  Builds on:            {existing V0.1 components}
  New capabilities:     {count}
  New files:            {count} (~{LOC} LOC)
  Modified files:       {count}
  New dependencies:     {count}
  New tests:            {count}

FILE MANIFEST
  | Path | LOC | Purpose | Integrates With | Test File |
  |------|-----|---------|-----------------|-----------|
  | ...  | ... | ...     | ...             | ...       |

MILESTONES
  M1: {name}
    Gate: {what must be true}
    Steps:
      1. {action} — {file} — verify: {command}
      2. ...
  M2: {name}
    Gate: {what must be true}
    Steps: ...

RISKS
  | Risk | Severity | Mitigation |
  |------|----------|------------|
  | ...  | ...      | ...        |

ACCEPTANCE CRITERIA
  [ ] {criterion} — verify: {command}
  [ ] ...

MARKETING
  Tier: {Shield|Developer|Sentinel}
  Benefit: {user-facing one-liner}
  Differentiator: {vs cloud alternatives}

BLOCKERS (if breaker OPEN)
  {blocker description} — {why unresolvable} — {human decision needed}
=============================================
```

After all 4 feature groups, produce a CONSOLIDATED V0.2 RELEASE PLAN:

```
=============================================
  AIEGIS V0.2 "NEURAL SHIELD" — RELEASE PLAN
=============================================

SCOPE
  Feature Groups: A (TLS), B (Classifier), C (Detection), D (Tier Gate)
  Total new LOC: ~{sum}
  Total new tests: ~{sum}
  New dependencies: {list with versions}
  Binary size estimate: {with and without ONNX}

IMPLEMENTATION ORDER
  1. {which group first and why}
  2. {second}
  3. {third}
  4. {fourth}

CRITICAL PATH
  {what blocks what — which milestones are serial vs parallel}

OPEN BREAKERS
  {list any unresolved blockers from circuit breaker trips}

TIMELINE ESTIMATE
  M1 (foundation): {what's included}
  M2 (core features): {what's included}
  M3 (hardening): {what's included}

RELEASE CRITERIA
  [ ] All tests pass (80+)
  [ ] cargo clippy -- -D warnings clean
  [ ] Binary size < 25MB (with ONNX) / < 12MB (without)
  [ ] Rules path < 2ms p99
  [ ] Classifier path < 50ms p99
  [ ] TLS handshake < 100ms
  [ ] Shield tier works without ONNX/TLS features
  [ ] Developer tier unlocks TLS + classifier
  [ ] README updated with V0.2 features
  [ ] Tag v0.2.0, GitHub release with binary
=============================================
```

## CONSTRAINTS

- Security product: every feature needs adversarial tests
- No panics in proxy hot path
- Sub-2ms for rules-only path (must not regress)
- JSON structured logging only (no println! in release)
- Keep the binary small — ONNX runtime is the biggest risk to binary size
- Local-first: nothing phones home, no cloud dependencies
- Backward compatible: V0.1 configs must still work in V0.2
- Shield (free) tier must work identically to V0.1 — no regressions for free users

## START

Begin with Feature Group A (TLS Transparent Proxy). Execute the 8-step cycle. Then recycle through B, C, D. Produce the consolidated release plan at the end.
