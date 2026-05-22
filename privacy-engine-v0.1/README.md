# Privacy Engine v0.1

Local PII-sanitization service for WatchTower (NVIDIA Jetson Orin Nano, JetPack 6.2). Runs between an agent application and cloud LLM endpoints. **No raw user data ever leaves the device.**

## Overview

Privacy Engine detects and redacts structured PII (emails, phone numbers, credit cards, SSNs, IP addresses, MAC addresses, API keys, URLs) using regex patterns and the `phonenumbers` library. The agent application holds the token map and can reconstruct responses later (v0.2).

v0.1 is a **stateless Regex MVP**. Name detection via NER is planned for v0.3.

## API

### POST /v1/sanitize

Sanitizes input text by detecting and replacing PII with placeholder tokens.

**Request:**
```json
{
  "text": "Contact me at john@example.com or call 555-123-4567",
  "options": {
    "entity_types": ["EMAIL_ADDRESS", "PHONE_NUMBER"],
    "allow_list": ["trusted@example.com"]
  }
}
```

**Response:**
```json
{
  "sanitized_text": "Contact me at «EMAIL_1» or call «PHONE_1»",
  "replacements": [
    {"token": "«EMAIL_1»", "type": "EMAIL_ADDRESS", "original": "john@example.com"},
    {"token": "«PHONE_1»", "type": "PHONE_NUMBER", "original": "555-123-4567"}
  ],
  "latency_ms": 1.23
}
```

### GET /healthz

Health check endpoint. Returns `{"status": "ok"}`.

```bash
curl --unix-socket /run/privacy-engine.sock http://localhost/healthz
```

## Supported Entity Types

| Type | Detection Method | Token Format |
|------|------------------|--------------|
| EMAIL_ADDRESS | Regex | `«EMAIL_1»` |
| PHONE_NUMBER | phonenumbers (US only) | `«PHONE_1»` |
| CREDIT_CARD | Regex + Luhn validation | `«CREDIT_CARD_1»` |
| US_SSN | Regex (`XXX-XX-XXXX`) | `«US_SSN_1»` |
| IPV4_ADDRESS | Regex + octet validation | `«IPV4_ADDRESS_1»` |
| IPV6_ADDRESS | Regex | `«IPV6_ADDRESS_1»` |
| MAC_ADDRESS | Regex | `«MAC_ADDRESS_1»` |
| API_KEY | Patterns for `sk-`, `ghp_`, `xoxb-`, `AKIA`, `eyJ` | `«API_KEY_1»` |
| URL | Regex (entire URL redacted) | `«URL_1»` |

## What's Not Yet Detected

- **Names, organizations, locations** — requires NER (planned for v0.3)
- Custom domain rules (planned for v0.4)
- Unicode normalization attacks, zero-width characters (planned for v0.5)
- International phone numbers beyond US format
- Adversarial encoding attempts

## Installation & Systemd

1. Install dependencies:
```bash
pip install -e .
```

2. Install and start the systemd unit:
```bash
sudo cp systemd/privacy-engine.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable privacy-engine
sudo systemctl start privacy-engine
```

3. Verify health:
```bash
curl --unix-socket /run/privacy-engine.sock http://localhost/healthz
```

## Logging

This service logs **counts and entity types only**. No raw text, PII values, emails, or original data is ever logged. Logging hygiene is enforced via CI check.

Example safe log:
```json
{"timestamp": "...", "event": "sanitize_complete", "entities_found": 3, "types": ["EMAIL_ADDRESS", "PHONE_NUMBER"], "counts": {"email_address_count": 1, "phone_number_count": 1}}
```

## Running the Build

```bash
# Install dependencies
pip install -e .

# Run logging hygiene check (must pass before running service)
./scripts/check_logging_hygiene.sh

# Run smoke tests
pytest tests/

# Start the service (Unix socket)
python -m uvicorn main:app --uds /run/privacy-engine.sock
```

## System-Prompt Addendum (for v0.2+)

When Privacy Engine is active, user messages may contain placeholder tokens like `«EMAIL_1»`, `«PHONE_1»`, `«PERSON_1»`. Treat these as opaque identifiers. Preserve them exactly in your response — do not paraphrase, translate, or expand them.

---

For deployment details, see [systemd/privacy-engine.service](systemd/privacy-engine.service).