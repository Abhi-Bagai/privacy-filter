# Privacy Filter / Obfuscation Engine — MVP-First Implementation Plan

A local PII-sanitization service that runs entirely on a Jetson Orin Nano and stands between an agent application and any cloud LLM endpoint. No raw user data ever leaves the device.

**This plan is organized around shippable versions.** Each version is independently useful and small in scope. Don't build features that aren't needed by the version in front of you. Decisions that can be deferred are flagged in the version where they actually need to be made.

---

## Guiding Principles

1. **Each version is shippable.** Not "half-built and waiting for the next phase to make sense" — actually usable in production, even if narrow.
2. **Add features when there's evidence you need them.** Don't preemptively build session management, ML layers, or a Rust rewrite. They're listed here so you know where they fit, not so you build them now.
3. **Defer state.** The MVP is stateless — the caller (agent) holds the token map. Session management only enters if/when there's a concrete reason it can't.
4. **Defer hardening, but never compromise the one property that matters: PII does not leak.** A stripped-down MVP with strong logging hygiene is fine. A feature-rich MVP that logs raw input is not.

---

## Minimal Threat Model (lives across all versions)

You need this upfront because it disciplines the MVP. Keep it short:

- **What we're defending against:** accidental exfiltration of PII to a cloud LLM in normal operation. An honest-but-curious cloud provider that logs/trains on what we send.
- **What we're not defending against (yet):** code execution on the Jetson, a malicious agent bypassing the engine, side-channels in the cloud response.
- **The one rule that must hold from v0.1:** no raw user input or PII value ever appears in logs, crash output, metrics, or any persisted file.

Everything else — vault zeroization, peer-cred checks, egress firewall — is a hardening step that comes later. That one rule is non-negotiable from day one because violating it is silent and forever.

## Architecture Sketch (target end-state, not v0.1)

```
┌───────────────┐    raw text     ┌─────────────────────────┐
│  Agent App    │ ──────────────► │  Privacy Engine (local) │
│               │ ◄────sanitized──│   detection → tokenize  │
└──────┬────────┘                 └─────────────────────────┘
       │ sanitized
       ▼
┌───────────────┐
│  Cloud LLM    │
└───────────────┘
```

The engine is a local service. The agent owns the cloud-API call — the engine never makes outbound network requests itself. That keeps the trust boundary small and the engine auditable.

---

## v0.1 — Regex MVP

**Goal:** the agent can route text through the engine, get back a sanitized version, send it to a cloud LLM, and trust that obvious structured PII has been redacted.

**Stack:** Python 3.11+, FastAPI, uvicorn, `phonenumbers` (libphonenumber bindings), `regex`. Nothing else.

**In scope:**
- One endpoint: `POST /v1/sanitize` → `{sanitized_text, replacements}`. Stateless.
- Regex detection for: email, phone (libphonenumber), credit card (with Luhn validation to cut false positives), US SSN, IPv4/IPv6, MAC address, common API-key prefixes (`sk-`, `ghp_`, `xoxb-`, `AKIA…`, JWTs starting `eyJ`), URLs.
- Placeholder format: `«TYPE_N»` (e.g. `«EMAIL_1»`). ASCII fallback `[[TYPE_N]]` behind a config flag. **Not** `<TYPE_N>` — angle brackets get eaten by markdown/HTML renderers, which is exactly what happened in your original spec.
- Consistency within a single request: same value → same token.
- The response includes a `replacements` array so the caller can reconstruct later if they want. The engine holds nothing.
- Listen on a Unix domain socket at `/run/privacy-engine.sock` (not TCP). Reasons: no accidental network exposure, faster, supports peer-credential checks later.
- Logging: structured JSON, counts and types only, never values. Build with `structlog`. Add a CI check (a grep over the source tree) that fails the build if a logger ever receives a variable named `text`, `original`, `value`, or similar.
- systemd unit, `/healthz` endpoint.

**Explicitly out of scope:**
- Name detection (no NER). Yes, this means names leak. That's the v0.3 problem. Tell the agent's users until then.
- Reconstruction endpoint. Caller holds the map; if they need to reverse, they do it themselves with a one-liner.
- Sessions or any cross-request state.
- Custom domain rules.
- Hardening beyond the logging rule.
- Performance work.
- Tests beyond a smoke suite.

**Definition of done:**
- Engine starts cleanly under systemd on JetPack.
- Agent can sanitize a paragraph containing each supported PII type and get correct redactions.
- Round-trip latency p99 under 20 ms for a 500-character input.
- Logging-hygiene CI check is green.
- A two-page README explains the API and what's not yet detected.

**Decisions you need to make for this version:**
- Which regional ID formats matter (US SSN only? UK NINO? Both?). Pick the smallest set that covers actual usage.
- URL policy: redact whole URL, or just path/query? Recommend: replace entire URL with `«URL_N»` initially; revisit if it degrades cloud-LLM responses.

---

## v0.2 — Reconstruction

**Goal:** the agent can pass a cloud LLM's response back through the engine and get tokens swapped back to originals.

Trigger to build: the first time the agent shows a cloud response to a user and the user is confused by `«PERSON_1»` (which won't happen yet because names aren't detected — but credit-card or email placeholders may appear in responses).

**In scope:**
- `POST /v1/reconstruct` → `{text, replacements}` from a prior sanitize call, returns reconstructed text.
- Still stateless. The caller passes the map back.
- Exact-token matching only; ignore partial tokens (`«PERSON_` without closer).
- If response contains a token not in the provided map, leave it as-is and increment a metric counter.
- Prepend a recommended system-prompt addendum to the README:
  > "The user message may contain placeholder tokens like `«PERSON_1»`, `«EMAIL_1»`, `«PHONE_1»`. Treat these as opaque identifiers. Preserve them exactly in your response — do not paraphrase, translate, or expand them."

**Out of scope:**
- Engine-side storage of maps (still stateless).
- Reconstruction inside code blocks (decide later based on observed behavior).

**Definition of done:**
- Round-trip property test: for any input `x`, `reconstruct(sanitize(x))` equals `x`.
- Agent integration shows tokens reversed correctly in real LLM responses.

---

## v0.3 — Names and Unstructured PII via NER

**Goal:** redact person names, organizations, and locations — the most common unstructured PII that regex can't catch.

Trigger to build: you have v0.1 + v0.2 running on real traffic and want to start catching names. This is the version that turns the engine from "useful" into "actually trustworthy."

**In scope:**
- Add spaCy with `en_core_web_lg` (CPU). Entities: PERSON, ORG, GPE, LOC.
- Optional Presidio integration if you want its context-enhancers and ready-made recognizers. Worth evaluating — Presidio bundles spaCy + a lot of curated rules, so you may save effort by adopting it now.
- Confidence threshold in config; default 0.4 with a "default-redact when uncertain" policy.
- Golden corpus of 50–200 hand-annotated examples to track precision/recall per entity type. Fail CI if recall drops.
- Span-merge logic when regex and NER overlap: highest-confidence wins, ties broken by specificity (`CREDIT_CARD` beats `NUMBER`).

**Out of scope:**
- GPU/ONNX optimization. Default to CPU spaCy until measurements show it's a problem.
- Transformer NER. Tempting, but adds a lot of complexity. Save for v0.6 if needed.
- Multilingual support.

**Definition of done:**
- Golden corpus passes baseline (target ~85% F1 on PERSON; spaCy `lg` realistically delivers this; measure don't trust).
- p99 latency under 100 ms on a 500-character input on Orin Nano.
- README updated with the list of entity types now supported.

**Decisions you need to make for this version:**
- Allowlist policy. Should the user's own name be sent through unredacted so the LLM can address them? If yes, how does the agent communicate the allowlist (per-request option, or service-level config)? Recommend per-request `allow_list: [strings]` in the sanitize call.
- Confidence threshold default. Start at 0.4, measure, tune.

---

## v0.4 — Custom Domain Rules

**Goal:** non-engineers can add project-specific patterns without a code change.

Trigger to build: your team identifies internal patterns (customer IDs, ticket numbers, internal product codes) that need redaction.

**In scope:**
- YAML config loaded at startup, hot-reloadable on SIGHUP.
- Each custom rule has: name, regex (or keyword list), entity type, confidence, optional context words that boost confidence.
- Config integrity: log the file hash at startup. Refuse to start if the file is missing required fields.

**Out of scope:**
- Per-tenant configs.
- A web UI for editing rules. (YAML in git is fine.)

**Definition of done:**
- A new rule can be added by editing YAML and reloading; tests prove it triggers.

---

## v0.5 — Hardening

**Goal:** raise the engine from "doesn't leak through logs" to "doesn't leak through anything an attacker is likely to try."

Trigger to build: before you handle anything beyond test data, or when a compliance/security review is upcoming — whichever is sooner.

**In scope:**
- Crash safety: install a panic/exception hook that scrubs local variables before any traceback is logged. Verify by deliberately raising exceptions in detection code and checking that no PII appears in output.
- Disable core dumps in the systemd unit (`LimitCORE=0`) and via `prctl(PR_SET_DUMPABLE, 0)` on Linux.
- Drop network egress capability. Add a firewall rule (or systemd `IPAddressDeny=any`) so the engine literally cannot reach the internet. The agent is the only thing that talks to the cloud.
- Peer-credential check on the UDS: only accept connections from configured UIDs.
- Memory hygiene: in Python, route detected PII values through a `Secret` wrapper that overwrites the underlying buffer on `__del__`. Acknowledge upfront that CPython doesn't give you Rust-grade guarantees — this is best-effort.
- Unicode normalization (NFKC) and zero-width-character stripping before detection runs, with index-mapping back to the original string so redaction lands in the right place. Defeats trivial evasion like "john@example.com" with zero-width spaces.
- Adversarial test corpus: known evasion patterns (spaced text, homoglyphs, base64 chunks, leetspeak names). Track regression direction; not all need to pass.
- Fuzz testing with `hypothesis` for the critical property: "no substring of any original PII value appears in the sanitized output."
- Short red-team session: have someone unfamiliar with the rules spend an hour trying to leak PII through the engine. Fix whatever they find.

**Out of scope:**
- Signed config bundles (overkill until you have a real distribution problem).
- Audit logging (add it when there's a compliance requirement).

**Definition of done:**
- Panic-hook scrub verified.
- Outbound network blocked at the OS level — confirmed by trying to `curl` from inside the engine's process and watching it fail.
- Adversarial corpus passes at agreed-on threshold.
- Fuzz tests run clean for 1M+ iterations.

---

## v0.6 — Performance / Optional NER Upgrade (build only if needed)

**Goal:** address measured performance problems or measured detection quality gaps.

Trigger to build: profiling shows the engine missing its latency budget, OR golden-corpus quality plateaus below acceptable.

**Possible work (pick what the measurements indicate):**
- Pre-compile and cache Aho-Corasick automatons at startup.
- Skip NER when the regex layer already covered the text and the input is short.
- Move NER from spaCy CPU to a transformer model exported to ONNX, running with CUDA Execution Provider on the Jetson's GPU. Candidate model: `dslim/bert-base-NER` quantized to INT8.
- Batch concurrent requests.

**Out of scope:**
- Rust rewrite. Don't even consider it until ONNX-on-GPU isn't enough. NER inference dominates latency, and that's GPU-bound regardless of the host language. Python overhead is noise.

**Definition of done:** the measurement that triggered this work is now in spec.

---

## v0.7+ — Future Work (don't plan, just know it exists)

Things to be aware of but not to scope yet:

- **Engine-managed sessions.** If the agent keeps asking for cross-request token consistency and is finding it annoying to manage maps itself, add session state. Comes with vault TTL, zeroize-on-expiry, and session authentication. Significant complexity — defer until the agent's pain is real.
- **Streaming sanitization.** Token-by-token sanitization for live transcription or streaming LLM responses. Genuinely hard (partial-token detection across chunks) — its own design doc when needed.
- **Multilingual NER.** Different model, larger memory footprint.
- **Egress proxy / attestation enforcement.** The biggest real-world leak risk isn't the engine — it's a developer adding a new cloud call somewhere that bypasses it. A network-level egress proxy that allowlists outbound traffic and requires a sanitization-attestation header is the strongest mitigation. Independent project; mention to whoever owns infra.
- **Rust rewrite.** Only after exhausting Python optimizations and measuring that Python remains the bottleneck.

---

## Cross-Cutting Concerns

These evolve across versions. Don't build them all in v0.1 — but know where each grows.

**Testing:**
- v0.1: smoke tests, manual integration with the agent.
- v0.2: round-trip property tests.
- v0.3: golden corpus with precision/recall per entity, CI fails on recall regression.
- v0.5: adversarial corpus + hypothesis fuzzing.
- v0.6: load/latency benchmarks in CI.

**Observability:**
- v0.1: structured logs (counts only), `/healthz`.
- v0.3: per-entity-type detection counters, latency histograms via Prometheus `/metrics`.
- v0.5: panic-hook scrub.

**Security:**
- v0.1: logging hygiene CI check. Non-negotiable.
- v0.3: confidence-threshold-driven default-redact.
- v0.5: everything in the hardening section.

**Documentation:**
- v0.1: two-page README — API, supported entities, what's not yet detected, recommended system-prompt addendum.
- Every version: update README's "what's detected" section. Agent developers will check this constantly.

---

## Jetson-Specific Notes (read once, refer back)

- **Architecture:** ARM64. Verify every wheel. `onnxruntime-gpu` for Jetson needs the JetPack-specific build from NVIDIA's index, not PyPI's.
- **RAM:** 4 GB Orin Nano is tight if you're also running Whisper + the agent. Plan for 8 GB Orin Nano Super or skip the v0.6 transformer NER.
- **GPU:** route NER to CUDA via ONNX Runtime when you get there. Don't use spaCy's GPU support — cupy on Jetson is a pain. CPU spaCy is fine through v0.5.
- **Model files:** quantize to INT8 when moving to ONNX. Store on NVMe, not SD card — much better load times.
- **Power profile:** `nvpmodel -m 0` during development; consider 15 W mode in production if thermals are an issue in your enclosure.

---

## Risks and What Catches Them

Listed by which version is supposed to handle each:

| Risk | Caught by |
|---|---|
| PII value leaked into logs | v0.1 logging-hygiene CI |
| Email/phone/CC leaked to cloud | v0.1 regex layer |
| Name leaked to cloud | v0.3 NER |
| Domain-specific ID leaked | v0.4 custom rules |
| Adversarial encoding bypass | v0.5 Unicode normalization + adversarial corpus |
| PII leaked via crash/traceback | v0.5 panic-hook scrub |
| PII leaked via core dump | v0.5 core-dump disabled |
| Engine sends data anywhere | v0.5 egress blocked at OS level |
| Developer adds a new cloud call that bypasses the engine | v0.7+ egress proxy with attestation header; meanwhile, code review |
| Latency degrades UX | v0.6, if measurements demand |
| NER quality plateaus | v0.6 transformer NER, if measurements demand |

---

## Appendix A — v0.1 API Schema

```jsonc
// POST /v1/sanitize
{
  "text": "Hi, I'm John. My email is john@acme.com.",
  "options": {
    "entity_types": ["EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD"], // optional filter; default = all
    "allow_list": ["Acme"]                                            // optional; strings never to redact
  }
}

// Response
{
  "sanitized_text": "Hi, I'm John. My email is «EMAIL_1».",
  "replacements": [
    {"token": "«EMAIL_1»", "type": "EMAIL_ADDRESS", "original": "john@acme.com"}
  ],
  "latency_ms": 4
}
```

Note that the response includes `original` values — the engine is stateless, and the caller is trusted (it's local, on the same box). If you later decide the caller shouldn't see originals (e.g., the engine is shared across less-trusted clients), that's when sessions enter the picture.

```jsonc
// POST /v1/reconstruct (added in v0.2)
{
  "text": "Your message was sent to «EMAIL_1» successfully.",
  "replacements": [
    {"token": "«EMAIL_1»", "type": "EMAIL_ADDRESS", "original": "john@acme.com"}
  ]
}

// Response
{
  "text": "Your message was sent to john@acme.com successfully.",
  "replacements_made": 1,
  "unknown_tokens": []
}
```

## Appendix B — Recommended System-Prompt Addendum (ship with v0.2)

> The user-facing message you are about to receive contains placeholder tokens of the form `«TYPE_N»`, where TYPE is one of PERSON, EMAIL, PHONE, CREDIT_CARD, ADDRESS, ORGANIZATION, LOCATION, IP_ADDRESS, DATE_OF_BIRTH, US_SSN, IBAN, API_KEY, URL, or CUSTOM. These tokens are opaque identifiers that replace personally identifiable information that has been redacted before reaching you. You must:
> 1. Treat each token as an opaque variable. Do not guess or speculate about its value.
> 2. Preserve every token exactly — same characters, same delimiters — in your response.
> 3. Do not invent new tokens or modify existing ones.
> 4. If the user's intent requires the actual value, ask the user a clarifying question rather than attempting to fill it in.
