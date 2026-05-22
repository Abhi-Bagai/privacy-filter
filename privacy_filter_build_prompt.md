# Privacy Filter / Obfuscation Engine — Build Prompt for Claude Agent

**Context:** You are building a local PII-sanitization service for WatchTower (NVIDIA Jetson Orin Nano, JetPack 6.2). This service sits between an agent application and cloud LLM endpoints (OpenAI, Anthropic, Grok). No raw user data ever leaves the device.

**Scope:** v0.1 (Regex MVP) only. Build a stateless FastAPI service that detects and redacts structured PII using regex patterns and the `phonenumbers` library. The agent application holds the token map and can reconstruct responses later (v0.2).

---

## Step 1: Project Setup & Scaffolding

**Objective:** Create a minimal Python FastAPI project with the correct dependencies and file structure.

### Tasks:
1. Create a new directory: `/home/claude/privacy-engine-v0.1`
2. Create `pyproject.toml` with dependencies:
   - `fastapi==0.104.1`
   - `uvicorn[standard]==0.24.0`
   - `phonenumbers==8.13.0`
   - `regex==2023.11.8`
   - `structlog==23.2.0`
   - `pytest==7.4.3` (for smoke tests only)
   - `pydantic==2.5.0`

3. Create directory structure:
   ```
   privacy-engine-v0.1/
   ├── pyproject.toml
   ├── main.py                    (FastAPI app entry point)
   ├── sanitizer.py               (PII detection logic)
   ├── models.py                  (Pydantic schemas)
   ├── logging_config.py           (structlog setup)
   ├── tests/
   │   └── test_sanitizer.py      (smoke tests only)
   ├── systemd/
   │   └── privacy-engine.service (systemd unit)
   └── README.md                  (API docs + what's not detected)
   ```

4. Do not write code yet — confirm the structure and list any ambiguities about directory placement or naming.

---

## Step 2: Logging & Safety Infrastructure

**Objective:** Set up structured logging that never logs raw text, PII values, or any original data. Build a CI check that fails the build if a logger ever receives a variable named `text`, `original`, `value`, `pii`, `password`, `secret`, or similar.

### Tasks:
1. Create `logging_config.py`:
   - Configure `structlog` for JSON output.
   - Every log entry includes: `timestamp`, `level`, `event`, `counts` (e.g., `{"email_count": 1, "phone_count": 2}`), `type` (entity type), and `request_id`.
   - Never include the actual PII value, the raw input text, or any original data.
   - Example safe log: `{"timestamp": "...", "event": "sanitize_complete", "entities_found": 3, "types": ["EMAIL_ADDRESS", "PHONE_NUMBER"]}`
   - Example unsafe log: `{"event": "found email", "value": "john@example.com"}` — never do this.

2. Create a CI check script (`scripts/check_logging_hygiene.sh`):
   - Grep the entire source tree for any logger call that includes a variable named: `text`, `original`, `value`, `pii`, `password`, `secret`, `raw`, `input`, `data`, `payload`, `content`.
   - Fail the build (exit 1) if any are found.
   - Log a clear message: "Logging hygiene check failed: logger receives PII-like variable names at [line]."
   - Add this check to the README under "Running the Build."

3. Create a test that verifies no log output ever contains raw email addresses or phone numbers.

4. Confirm the logging structure and what counts as "safe" to log before implementation.

---

## Step 3: Pydantic Models & API Schema

**Objective:** Define the request/response schemas based on the v0.1 API spec.

### Tasks:
1. Create `models.py` with:
   - `SanitizeRequest`: 
     - `text: str` — the input to sanitize.
     - `options: Optional[dict]` with:
       - `entity_types: Optional[List[str]]` — filter which types to detect (default: all).
       - `allow_list: Optional[List[str]]` — strings never to redact.
   - `Replacement`:
     - `token: str` — the placeholder (e.g., `«EMAIL_1»`).
     - `type: str` — entity type.
     - `original: str` — the original value (safe to include in response; caller is trusted, local-only).
   - `SanitizeResponse`:
     - `sanitized_text: str` — the redacted text.
     - `replacements: List[Replacement]` — the token map.
     - `latency_ms: float` — request latency in milliseconds.

2. Add validation: `text` must not be empty, max 50,000 characters. `allow_list` max 100 items.

3. Confirm the schema matches the spec before moving to the sanitizer logic.

---

## Step 4: PII Detection Patterns

**Objective:** Implement the regex and library-based detectors for structured PII.

### Tasks:
1. Create `sanitizer.py` with a `PIIDetector` class.
2. Implement detectors for:
   - **Email:** `r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'`
   - **Phone:** Use `phonenumbers` library; parse with `phonenumbers.parse(text, 'US')` and `phonenumbers.is_valid_number()`. Support US format for v0.1 only.
   - **Credit Card:** `r'(?:\d{4}[\s-]?){3}\d{4}'` + Luhn validation (implement or use `luhnok` library).
   - **US SSN:** `r'\b\d{3}-\d{2}-\d{4}\b'`
   - **IPv4:** `r'\b(?:\d{1,3}\.){3}\d{1,3}\b'` (basic; refine if needed).
   - **IPv6:** `r'(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}'` (basic).
   - **MAC Address:** `r'(?:[0-9a-fA-F]{2}[:-]){5}(?:[0-9a-fA-F]{2})'`
   - **API Keys:** patterns for `sk-` (OpenAI), `ghp_` (GitHub), `xoxb-` (Slack), `AKIA` (AWS), `eyJ` (JWT).
   - **URLs:** `r'https?://[^\s]+'` (redact entire URL).

3. Each detector returns a list of tuples: `(start_pos, end_pos, entity_type, value)`.

4. Implement `consolidate_spans()`: when spans overlap (e.g., regex finds a phone inside an API key), keep the highest-confidence match. For v0.1, assume regex confidence is uniform (no NER yet).

5. Implement consistency: same PII value within a single request always gets the same token.

6. Implement `allow_list` logic: skip redacting strings in the allow_list.

7. Do not write the endpoint handler yet — confirm the detection logic is clear.

---

## Step 5: Tokenization & Redaction

**Objective:** Replace detected PII spans with consistent, readable placeholders.

### Tasks:
1. In `sanitizer.py`, add a `Tokenizer` class:
   - Generates tokens in format `«TYPE_N»` where N is a counter per type per request.
   - Maintains a map: `{"«EMAIL_1»": "john@example.com", ...}`.
   - Ensures the same value always maps to the same token within a request.

2. Implement `sanitize(text: str, replacements_map: dict) -> Tuple[str, List[Replacement]]`:
   - Takes the raw text and the consolidated spans.
   - Replaces spans with tokens (highest-position-first to avoid offset drift).
   - Returns the sanitized text and the replacement list.

3. Confirm the placeholder format and edge cases (what if text itself contains `«` or `»`?) before proceeding.

---

## Step 6: FastAPI Endpoint & Health Check

**Objective:** Wire the sanitizer into a FastAPI service listening on a Unix domain socket.

### Tasks:
1. Create `main.py`:
   - Initialize FastAPI app.
   - Import `PIIDetector`, `Tokenizer`, logging setup.
   - Implement `POST /v1/sanitize`:
     - Accept `SanitizeRequest`.
     - Call `detector.detect(text)` → spans.
     - Call `tokenizer.tokenize_and_redact(text, spans)` → (sanitized_text, replacements).
     - Return `SanitizeResponse` with latency measured.
     - Log: counts and types only, no values.
   - Implement `GET /healthz`:
     - Return `{"status": "ok"}` (200).
     - Add a startup hook that logs "Privacy engine started" (no values).

2. Run the app on a Unix domain socket at `/run/privacy-engine.sock` using `uvicorn`:
   - Use `uvicorn.run(app, uds='/run/privacy-engine.sock', log_config=...)` or equivalent.
   - Confirm this is the correct way to bind on ARM64 (Jetson).

3. Confirm the endpoint structure and Unix socket binding method.

---

## Step 7: Systemd Unit & Startup

**Objective:** Make the service startable and restartable via systemd.

### Tasks:
1. Create `systemd/privacy-engine.service`:
   - `Type=simple`
   - `ExecStart=/usr/bin/python3 -m uvicorn main:app --uds /run/privacy-engine.sock`
   - `WorkingDirectory=/opt/privacy-engine` (or wherever you install it)
   - `Restart=on-failure`
   - `RestartSec=5`
   - `StandardOutput=journal`
   - `StandardError=journal`
   - Requires: `/run` directory exists and is writable by the service user.

2. Add post-install instructions to the README:
   ```
   sudo cp systemd/privacy-engine.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable privacy-engine
   sudo systemctl start privacy-engine
   ```

3. Add a healthcheck script or instructions for testing:
   ```
   curl --unix-socket /run/privacy-engine.sock http://localhost/healthz
   ```

4. Confirm the systemd unit and install process before writing the README.

---

## Step 8: Smoke Tests

**Objective:** Build minimal tests that verify the service works end-to-end.

### Tasks:
1. Create `tests/test_sanitizer.py`:
   - Test 1: Detect and redact an email. Verify token format and consistency.
   - Test 2: Detect and redact a phone number (valid US format). Verify phonenumbers library works.
   - Test 3: Detect and redact a credit card. Verify Luhn validation filters invalid cards.
   - Test 4: Detect and redact a US SSN.
   - Test 5: Detect and redact a URL (entire URL redacted).
   - Test 6: Allow-list test: string in allow_list is not redacted.
   - Test 7: Consistency test: same email appears twice in text, gets same token both times.
   - Test 8: Latency test: 500-character input completes in < 20 ms.
   - Test 9: Logging hygiene: run the CI check script and verify it passes.

2. Do not build a full integration test suite yet — these are smoke tests only.

3. Add `pytest` command to README: `pytest tests/`.

---

## Step 9: README & Documentation

**Objective:** Document the API, what's detected, what's not, and deployment instructions.

### Tasks:
1. Create `README.md` (two pages, roughly 40–50 lines):
   - **Overview:** What this service does, why, and what it doesn't yet do.
   - **API:**
     - `POST /v1/sanitize` request/response schema with example.
     - `GET /healthz` for liveness.
   - **Supported Entity Types:** List (EMAIL, PHONE, CREDIT_CARD, SSN, IP_ADDRESS, MAC_ADDRESS, API_KEYS, URL).
   - **What's Not Yet Detected:** Names, organizations, locations, custom domain IDs, Unicode normalization attacks, adversarial encoding.
   - **Installation & Systemd:**
     - Dependencies (Python 3.11+, pip install from pyproject.toml).
     - systemd setup.
     - Health check.
   - **Logging:** "This service logs counts and entity types only. No raw text, emails, or PII values are logged."
   - **System-Prompt Addendum (optional, for future v0.2):**
     - Document the placeholder token format so cloud LLMs know how to handle them.

2. Add a "Running the Build" section:
   - `pip install -e .`
   - `scripts/check_logging_hygiene.sh` (must pass before you can run the service).
   - `pytest tests/`

---

## Step 10: Integration with Agent & First Test Run

**Objective:** Verify the service works end-to-end with the agent.

### Tasks:
1. Deploy the service to the Jetson:
   - Clone/copy to `/opt/privacy-engine`.
   - Install dependencies: `pip install -e /opt/privacy-engine`.
   - Install systemd unit and start the service.
   - Verify `/healthz` is reachable: `curl --unix-socket /run/privacy-engine.sock http://localhost/healthz`.

2. From the agent (Rook/Hermes), before sending to a cloud LLM:
   - Make a POST request to `/v1/sanitize` with sample user input.
   - Verify you get back sanitized text and replacements.
   - Send the sanitized text to the cloud LLM.
   - (Optional, v0.2 later:) Pass the cloud response back through `/v1/reconstruct` to restore original values.

3. Test with real agent traffic:
   - A paragraph containing an email, a phone number, and a URL.
   - Verify all three are redacted.
   - Verify latency is < 20 ms.

4. Run the logging hygiene check one more time: `scripts/check_logging_hygiene.sh`.

---

## Implementation Decisions You Need to Make (for v0.1)

1. **Regional ID formats:** US SSN only, or should you also support UK NINO, Canadian SIN, etc.? (Recommend: US SSN only for v0.1; expand in v0.4.)

2. **URL redaction policy:** Redact the entire URL with a single token, or try to preserve the domain and redact only the path/query? (Recommend: entire URL → `«URL_N»` initially.)

3. **Credit-card false positives:** Luhn validation will catch most, but should you add an additional check (e.g., "only redact if it looks like a Visa/Mastercard/Amex BIN")? (Recommend: Luhn is enough for v0.1.)

4. **Phone number regions:** For v0.1, support US-formatted numbers only. When do you want to add support for international numbers (v0.3, v0.4, or later)? (Recommend: defer; document this in the README.)

5. **Unix socket vs. TCP:** Should the service also listen on TCP (e.g., `:8000`) for flexibility, or stick to Unix socket only? (Recommend: Unix socket only for now; add TCP in a config flag later if needed.)

---

## Build Order (Do Steps In This Order)

1. Project setup & scaffolding (Step 1).
2. Logging & CI check (Step 2).
3. Pydantic models (Step 3).
4. PII detection patterns (Step 4).
5. Tokenization (Step 5).
6. FastAPI endpoint (Step 6).
7. Systemd unit (Step 7).
8. Smoke tests (Step 8).
9. README (Step 9).
10. Integration test with agent (Step 10).

---

## Success Criteria (for v0.1 "Definition of Done")

- [ ] Engine starts cleanly under systemd on JetPack 6.2.
- [ ] `GET /healthz` returns 200 OK.
- [ ] Agent can sanitize a paragraph with each supported PII type (email, phone, CC, SSN, IP, MAC, API key, URL) and get correct redactions and consistent tokens.
- [ ] Round-trip latency p99 < 20 ms for a 500-character input.
- [ ] Logging hygiene CI check passes (no raw text, no PII values in logs).
- [ ] README explains the API, what's detected, what's not, and deployment instructions.
- [ ] Smoke tests pass: `pytest tests/` is green.

---

## Notes

- **No code yet:** Confirm the structure, decisions, and approach before you write anything.
- **Leverage the schema in Appendix A:** The v0.1 API spec is frozen; don't redesign the request/response format.
- **Logging is non-negotiable:** If you find yourself tempted to log a raw value for debugging, stop and ask how to log safely instead.
- **Unix socket is deliberate:** It's safer than TCP and supports peer-credential checks in v0.5. Stick with it.
- **Reconstruction is v0.2:** Don't build the `/v1/reconstruct` endpoint in v0.1. The agent holds the map; they can implement reversal themselves if needed.

---

## Questions for You Before You Start

Answer these three before moving to Step 1:

1. **Regional ID formats:** SSN only, or add others (UK NINO, Canadian SIN) from day one?
2. **URL redaction:** Entire URL → `«URL_N»`, or preserve domain?
3. **Where should the code live?** Confirm `/home/claude/privacy-engine-v0.1` is the right location, or provide a preferred path.
