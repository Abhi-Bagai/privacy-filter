# How it works

## What gets sanitized

Every message you send to your Discord bot passes through the privacy engine before reaching the LLM. PII is replaced with opaque tokens:

┌────────────────────────────────────────┬───────────────────────────────┐
│                You type                │           LLM sees            │
├────────────────────────────────────────┼───────────────────────────────┤
│ email me at john@acme.com              │ email me at «EMAIL_1»         │
├────────────────────────────────────────┼───────────────────────────────┤
│ call (415) 867-5309                    │ call «PHONE_NUMBER_1»         │
├────────────────────────────────────────┼───────────────────────────────┤
│ check https://internal.corp.com/report │ check «URL_1»                 │
├────────────────────────────────────────┼───────────────────────────────┤
│ card 4111 1111 1111 1111               │ card «CREDIT_CARD_1»          │
├────────────────────────────────────────┼───────────────────────────────┤
│ SSN 123-45-6789                        │ SSN «US_SSN_1»                │
├────────────────────────────────────────┼───────────────────────────────┤
│ server at 192.168.1.50                 │ server at «IPV4_ADDRESS_1»    │
├────────────────────────────────────────┼───────────────────────────────┤
│ mac aa:bb:cc:dd:ee:ff                  │ mac «MAC_ADDRESS_1»           │
├────────────────────────────────────────┼───────────────────────────────┤
│ key sk-1234567890abcdefghij            │ key «API_KEY_1»               │
└────────────────────────────────────────┴───────────────────────────────┘

The LLM never sees the raw values — it works on the sanitized text. The original values stay only in the local
replacement map on the Jetson. The agent application can use the replacement map to reconstruct original values
later (v0.2 reconstruction endpoint).

## What doesn't get sanitized

- The API server path (POST :8642/v1/chat/completions) — that's the local tool API, not the Discord path. If you use it
for agent-to-agent calls, those bypass the filter.
- The agent's responses back to you — outbound is not sanitized (sentinel handles credential leak detection separately).
- Messages to the LLM from tool results — the filter is on the initial user message only.
- Names, organizations, locations — requires NER (planned for v0.3)

## How to verify it's running

```bash
# On the Jetson:
systemctl is-active privacy-engine          # should say: active

# Health check:
curl --unix-socket /run/privacy-engine.sock http://localhost/healthz
# Returns: {"status":"ok"}

# Check logs (journald):
journalctl -u privacy-engine -f

# Smoke tests:
cd /opt/privacy-engine && pytest tests/
```

When PII is detected, logs show counts and types only (no raw values):
```
{"timestamp":"...","event":"sanitize_complete","request_id":"a1b2c3d4","entities_found":2,"types":["EMAIL_ADDRESS","PHONE_NUMBER"],"counts":{"email_address_count":1,"phone_number_count":1},"latency_ms":4.5}
```

If the privacy engine is down, messages pass through unchanged (fail-open) — your bot stays up.

## How to stop/start the filter

```bash
sudo systemctl stop privacy-engine    # disable — messages pass through unfiltered
sudo systemctl start privacy-engine   # re-enable
sudo systemctl restart privacy-engine  # restart after config changes
```

## Running the build

```bash
cd /opt/privacy-engine

# Install dependencies
pip install -e .

# Run logging hygiene check (must pass)
./scripts/check_logging_hygiene.sh

# Run smoke tests
pytest tests/

# Start manually (for debugging)
python -m uvicorn main:app --uds /run/privacy-engine.sock
```

## On Jetson reboot

Both services come back automatically:
- `privacy-engine.service` — enabled at boot via systemd
- `rook-sandbox` — `restart: unless-stopped` in docker-compose

## Architecture

```
┌─────────────┐     raw      ┌──────────────────┐   sanitized   ┌─────────────┐
│  Discord    │ ──────────►  │  Privacy Engine  │ ────────────► │  Cloud LLM  │
│  user       │ ◄──────────  │  (Jetson local)  │ ◄──reconstruct│  (OpenAI,   │
│             │   tokens    │                  │               │  Anthropic) │
└─────────────┘              └──────────────────┘               └─────────────┘
                                 │
                                 │ Token map
                                 ▼
                          ┌─────────────┐
                          │ Agent App   │  (holds the map)
                          └─────────────┘
```

The engine is stateless — it holds no session state. The agent owns the token map and can reconstruct
original values after the LLM response (v0.2).
