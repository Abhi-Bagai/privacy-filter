"""PII Detection Logic and Tokenization for Privacy Engine v0.1.

Plugin Architecture: Add new PII types via config/detectors.yaml
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Optional

import phonenumbers
import yaml

ENTITY_EMAIL = "EMAIL_ADDRESS"
ENTITY_PHONE = "PHONE_NUMBER"
ENTITY_CREDIT_CARD = "CREDIT_CARD"
ENTITY_SSN = "US_SSN"
ENTITY_IPV4 = "IPV4_ADDRESS"
ENTITY_IPV6 = "IPV6_ADDRESS"
ENTITY_MAC = "MAC_ADDRESS"
ENTITY_API_KEY = "API_KEY"
ENTITY_URL = "URL"

# Token placeholder format
TOKEN_PREFIX = "«"
TOKEN_SUFFIX = "»"
TOKEN_ASCII_PREFIX = "[["
TOKEN_ASCII_SUFFIX = "]]"

# Config path
CONFIG_DIR = os.path.join(os.path.dirname(__file__), "..", "config")
DETECTORS_CONFIG = os.path.join(CONFIG_DIR, "detectors.yaml")


@dataclass(frozen=True)
class Span:
    start: int
    end: int
    entity_type: str
    value: str


# ============================================================
# Validators
# ============================================================


class LuhnValidator:
    """Luhn algorithm validator for credit card numbers."""

    @staticmethod
    def is_valid(card_number: str) -> bool:
        digits = re.sub(r"\D", "", card_number)
        if len(digits) < 13 or len(digits) > 19:
            return False
        total = 0
        reverse_digits = digits[::-1]
        for i, digit in enumerate(reverse_digits):
            n = int(digit)
            if i % 2 == 1:
                n *= 2
                if n > 9:
                    n -= 9
            total += n
        return total % 10 == 0


class CanadianSINValidator:
    """Canadian SIN validator using mod-10 algorithm."""

    @staticmethod
    def is_valid(sin: str) -> bool:
        # Remove dashes
        digits = re.sub(r"\D", "", sin)
        if len(digits) != 9:
            return False

        # Mod-10 validation
        total = 0
        for i, digit in enumerate(digits):
            n = int(digit)
            if i % 2 == 0:  # Even positions (0-indexed)
                n *= 2
                if n > 9:
                    n -= 9
            total += n

        return total % 10 == 0


class AustralianTFNValidator:
    """Australian Tax File Number validator."""

    @staticmethod
    def is_valid(tfn: str) -> bool:
        digits = re.sub(r"\D", "", tfn)
        if len(digits) != 9:
            return False

        # AUSTRALIAN CHECK DIGIT ALGORITHM
        weights = [1, 2, 3, 4, 5, 6, 7, 8, 10]
        total = sum(int(d) * w for d, w in zip(digits, weights))
        return total % 11 == 0


# Validator registry
VALIDATORS = {
    "luhn": LuhnValidator.is_valid,
    "canadian_sin": CanadianSINValidator.is_valid,
    "australian_tfn": AustralianTFNValidator.is_valid,
    "none": lambda x: True,
    "ipv4": lambda x: all(0 <= int(o) <= 255 for o in x.split(".")),
}


# ============================================================
# Config Loader
# ============================================================


def load_detectors_config() -> dict:
    """Load detector config from YAML file."""
    try:
        with open(DETECTORS_CONFIG, "r") as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        return {"detectors": []}


def get_enabled_detectors() -> list[dict]:
    """Get list of enabled detectors from config."""
    config = load_detectors_config()
    return [d for d in config.get("detectors", []) if d.get("enabled", False)]


def get_all_detectors() -> list[dict]:
    """Get all detectors (enabled and disabled) from config."""
    config = load_detectors_config()
    return config.get("detectors", [])


def add_detector(
    name: str, pattern: str, validator: str = "none", description: str = ""
) -> tuple[bool, str]:
    """Add a new detector to the config file.

    Returns:
        (success, message)
    """
    # Validate pattern compiles
    try:
        re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        return False, f"Invalid regex pattern: {e}"

    # Validate validator exists
    if validator not in VALIDATORS:
        return (
            False,
            f"Unknown validator: {validator}. Valid: {list(VALIDATORS.keys())}",
        )

    # Load existing config
    config = load_detectors_config()
    detectors = config.get("detectors", [])

    # Check for duplicate
    existing_names = [d.get("name") for d in detectors]
    status = "updated"
    if name not in existing_names:
        status = "added"

    # Remove existing if present, then add new
    detectors = [d for d in detectors if d.get("name") != name]
    detectors.append(
        {
            "name": name,
            "pattern": pattern,
            "validator": validator,
            "description": description,
            "enabled": True,
        }
    )

    config["detectors"] = detectors

    # Save
    try:
        with open(DETECTORS_CONFIG, "w") as f:
            yaml.dump(config, f, default_flow_style=False)
    except IOError as e:
        return False, f"Failed to write config: {e}"

    return True, status


def delete_detector(name: str) -> tuple[bool, str]:
    """Delete a detector from config.

    Returns:
        (success, message)
    """
    config = load_detectors_config()
    detectors = config.get("detectors", [])

    original_count = len(detectors)
    detectors = [d for d in detectors if d.get("name") != name]

    if len(detectors) == original_count:
        return False, f"Detector not found: {name}"

    config["detectors"] = detectors

    try:
        with open(DETECTORS_CONFIG, "w") as f:
            yaml.dump(config, f, default_flow_style=False)
    except IOError as e:
        return False, f"Failed to write config: {e}"

    return True, f"Detector '{name}' deleted"


# ============================================================
# Tokenizer
# ============================================================


class Tokenizer:
    """Generates consistent tokens for PII values within a request."""

    def __init__(self, use_ascii_fallback: bool = False):
        self._use_ascii_fallback = use_ascii_fallback
        self._counters: dict[str, int] = {}
        self._value_to_token: dict[str, tuple[str, str]] = {}

    def _make_token(self, entity_type: str) -> str:
        normalized = entity_type.upper().replace(" ", "_")
        count = self._counters.get(normalized, 0) + 1
        self._counters[normalized] = count

        prefix = TOKEN_ASCII_PREFIX if self._use_ascii_fallback else TOKEN_PREFIX
        suffix = TOKEN_ASCII_SUFFIX if self._use_ascii_fallback else TOKEN_SUFFIX

        return f"{prefix}{normalized}_{count}{suffix}"

    def _get_type_key(self, value: str, entity_type: str) -> str:
        return f"{entity_type}:{value}"

    def tokenize(self, value: str, entity_type: str) -> str:
        key = self._get_type_key(value, entity_type)
        if key not in self._value_to_token:
            token = self._make_token(entity_type)
            self._value_to_token[key] = (token, value)
        return self._value_to_token[key][0]

    def get_replacements(self) -> list[tuple[str, str, str]]:
        result = []
        for key, (token, original) in self._value_to_token.items():
            entity_type, _ = key.split(":", 1)
            result.append((token, entity_type, original))
        return result


# ============================================================
# PIIDetector with Plugin Support
# ============================================================


class PIIDetector:
    """Detects PII entities using built-in + YAML-configured detectors."""

    # Built-in patterns (always available)
    BUILTIN_PATTERNS = {
        ENTITY_EMAIL: re.compile(
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", re.IGNORECASE
        ),
        ENTITY_CREDIT_CARD: re.compile(r"(?:\d{4}[\s-]?){3}\d{4}"),
        ENTITY_SSN: re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        ENTITY_IPV4: re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        ENTITY_IPV6: re.compile(r"(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}"),
        ENTITY_MAC: re.compile(
            r"(?:[0-9a-fA-F]{2}[:-]){5}(?:[0-9a-fA-F]{2})", re.IGNORECASE
        ),
        ENTITY_URL: re.compile(r"https?://[^\s]+", re.IGNORECASE),
    }

    API_KEY_PATTERNS = [
        (re.compile(r"\bsk-[a-zA-Z0-9]{20,}\b"), "sk- (OpenAI)"),
        (re.compile(r"\bghp_[a-zA-Z0-9]{36,}\b"), "ghp_ (GitHub)"),
        (re.compile(r"\bxoxb-[a-zA-Z0-9]{22,}-[a-zA-Z0-9]{22,}\b"), "xoxb- (Slack)"),
        (re.compile(r"\bAKIA[a-zA-Z0-9]{16,}\b"), "AKIA (AWS)"),
        (
            re.compile(r"\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b"),
            "eyJ (JWT)",
        ),
    ]

    def __init__(self, allow_list: Optional[list[str]] = None):
        self._allow_list = allow_list or []
        self._luhn = LuhnValidator()
        self._config_detectors = self._load_config_detectors()

    def _load_config_detectors(self) -> list[dict]:
        """Load enabled detectors from YAML config."""
        detectors = []
        for config in get_enabled_detectors():
            name = config.get("name")
            pattern = config.get("pattern")
            validator_name = config.get("validator", "none")

            if not pattern:  # Skip phone numbers (handled separately)
                continue

            validator = VALIDATORS.get(validator_name, lambda x: True)

            try:
                regex = re.compile(pattern, re.IGNORECASE)
                detectors.append(
                    {
                        "name": name,
                        "pattern": regex,
                        "validator": validator,
                    }
                )
            except re.error:
                pass  # Skip invalid patterns

        return detectors

    def detect(self, text: str) -> list[Span]:
        spans: list[Span] = []

        # Run built-in detectors
        spans.extend(self._detect_email(text))
        spans.extend(self._detect_phone(text))
        spans.extend(self._detect_credit_card(text))
        spans.extend(self._detect_ssn(text))
        spans.extend(self._detect_ipv4(text))
        spans.extend(self._detect_ipv6(text))
        spans.extend(self._detect_mac(text))
        spans.extend(self._detect_api_keys(text))
        spans.extend(self._detect_urls(text))

        # Run config-based detectors (Canadian SIN, Driver's Licenses, etc.)
        spans.extend(self._detect_config_based(text))

        spans.sort(key=lambda s: s.start)
        spans = self._consolidate_spans(spans)
        spans = self._filter_allow_list(text, spans)
        return spans

    def _detect_config_based(self, text: str) -> list[Span]:
        """Detect using YAML-configured patterns."""
        spans = []
        for detector in self._config_detectors:
            name = detector["name"]
            pattern = detector["pattern"]
            validator = detector["validator"]

            for match in pattern.finditer(text):
                value = match.group()
                if validator(value):
                    spans.append(
                        Span(
                            start=match.start(),
                            end=match.end(),
                            entity_type=name,
                            value=value,
                        )
                    )
        return spans

    def _detect_email(self, text: str) -> list[Span]:
        spans = []
        for match in self.BUILTIN_PATTERNS[ENTITY_EMAIL].finditer(text):
            spans.append(
                Span(
                    start=match.start(),
                    end=match.end(),
                    entity_type=ENTITY_EMAIL,
                    value=match.group(),
                )
            )
        return spans

    def _detect_phone(self, text: str) -> list[Span]:
        spans = []
        for match in phonenumbers.PhoneNumberMatcher(text, "US"):
            if phonenumbers.is_valid_number(match.number):
                spans.append(
                    Span(
                        start=match.start,
                        end=match.end,
                        entity_type=ENTITY_PHONE,
                        value=match.raw_string,
                    )
                )
        return spans

    def _detect_credit_card(self, text: str) -> list[Span]:
        spans = []
        for match in self.BUILTIN_PATTERNS[ENTITY_CREDIT_CARD].finditer(text):
            if self._luhn.is_valid(match.group()):
                spans.append(
                    Span(
                        start=match.start(),
                        end=match.end(),
                        entity_type=ENTITY_CREDIT_CARD,
                        value=match.group(),
                    )
                )
        return spans

    def _detect_ssn(self, text: str) -> list[Span]:
        spans = []
        for match in self.BUILTIN_PATTERNS[ENTITY_SSN].finditer(text):
            spans.append(
                Span(
                    start=match.start(),
                    end=match.end(),
                    entity_type=ENTITY_SSN,
                    value=match.group(),
                )
            )
        return spans

    def _detect_ipv4(self, text: str) -> list[Span]:
        spans = []
        for match in self.BUILTIN_PATTERNS[ENTITY_IPV4].finditer(text):
            ip = match.group()
            if all(0 <= int(o) <= 255 for o in ip.split(".")):
                spans.append(
                    Span(
                        start=match.start(),
                        end=match.end(),
                        entity_type=ENTITY_IPV4,
                        value=ip,
                    )
                )
        return spans

    def _detect_ipv6(self, text: str) -> list[Span]:
        spans = []
        for match in self.BUILTIN_PATTERNS[ENTITY_IPV6].finditer(text):
            spans.append(
                Span(
                    start=match.start(),
                    end=match.end(),
                    entity_type=ENTITY_IPV6,
                    value=match.group(),
                )
            )
        return spans

    def _detect_mac(self, text: str) -> list[Span]:
        spans = []
        for match in self.BUILTIN_PATTERNS[ENTITY_MAC].finditer(text):
            spans.append(
                Span(
                    start=match.start(),
                    end=match.end(),
                    entity_type=ENTITY_MAC,
                    value=match.group(),
                )
            )
        return spans

    def _detect_api_keys(self, text: str) -> list[Span]:
        spans = []
        for pattern, _ in self.API_KEY_PATTERNS:
            for match in pattern.finditer(text):
                spans.append(
                    Span(
                        start=match.start(),
                        end=match.end(),
                        entity_type=ENTITY_API_KEY,
                        value=match.group(),
                    )
                )
        return spans

    def _detect_urls(self, text: str) -> list[Span]:
        spans = []
        for match in self.BUILTIN_PATTERNS[ENTITY_URL].finditer(text):
            spans.append(
                Span(
                    start=match.start(),
                    end=match.end(),
                    entity_type=ENTITY_URL,
                    value=match.group(),
                )
            )
        return spans

    def _consolidate_spans(self, spans: list[Span]) -> list[Span]:
        if not spans:
            return []
        consolidated = [spans[0]]
        for current in spans[1:]:
            last = consolidated[-1]
            if current.start < last.end:
                continue
            else:
                consolidated.append(current)
        return consolidated

    def _filter_allow_list(self, text: str, spans: list[Span]) -> list[Span]:
        if not self._allow_list:
            return spans
        return [s for s in spans if s.value not in self._allow_list]


def tokenize_and_redact(
    text: str,
    spans: list[Span],
    use_ascii_fallback: bool = False,
) -> tuple[str, list[tuple[str, str, str]]]:
    """Replace detected PII spans with tokens."""
    if not spans:
        return text, []

    tokenizer = Tokenizer(use_ascii_fallback=use_ascii_fallback)
    sorted_spans = sorted(spans, key=lambda s: s.start, reverse=True)

    result = text
    for span in sorted_spans:
        token = tokenizer.tokenize(span.value, span.entity_type)
        result = result[: span.start] + token + result[span.end :]

    replacements = tokenizer.get_replacements()
    return result, replacements
