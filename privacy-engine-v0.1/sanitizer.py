"""PII Detection Logic and Tokenization for Privacy Engine v0.1."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

import phonenumbers

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


@dataclass(frozen=True)
class Span:
    start: int
    end: int
    entity_type: str
    value: str


class LuhnValidator:
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


class Tokenizer:
    """Generates consistent tokens for PII values within a request.

    Token format: «TYPE_N» where N is a counter per type per request.
    Same value within a request always gets the same token.
    """

    def __init__(self, use_ascii_fallback: bool = False):
        """Initialize the tokenizer.

        Args:
            use_ascii_fallback: If True, use [[TYPE_N]] instead of «TYPE_N».
        """
        self._use_ascii_fallback = use_ascii_fallback
        self._counters: dict[str, int] = {}
        self._value_to_token: dict[str, tuple[str, str]] = {}

    def _make_token(self, entity_type: str) -> str:
        """Generate a new token for the given entity type."""
        normalized = entity_type.upper().replace(" ", "_")
        count = self._counters.get(normalized, 0) + 1
        self._counters[normalized] = count

        prefix = TOKEN_ASCII_PREFIX if self._use_ascii_fallback else TOKEN_PREFIX
        suffix = TOKEN_ASCII_SUFFIX if self._use_ascii_fallback else TOKEN_SUFFIX

        return f"{prefix}{normalized}_{count}{suffix}"

    def _get_type_key(self, value: str, entity_type: str) -> str:
        """Get a key for value-to-token mapping."""
        return f"{entity_type}:{value}"

    def tokenize(self, value: str, entity_type: str) -> str:
        """Get or create a token for a PII value.

        Same value + same type always returns the same token within a request.
        """
        key = self._get_type_key(value, entity_type)

        if key not in self._value_to_token:
            token = self._make_token(entity_type)
            self._value_to_token[key] = (token, value)

        return self._value_to_token[key][0]

    def get_replacements(self) -> list[tuple[str, str, str]]:
        """Get list of (token, type, original_value) tuples."""
        result = []
        for key, (token, original) in self._value_to_token.items():
            entity_type, _ = key.split(":", 1)
            result.append((token, entity_type, original))
        return result


class PIIDetector:
    PATTERNS = {
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

    def detect(self, text: str) -> list[Span]:
        spans: list[Span] = []
        spans.extend(self._detect_email(text))
        spans.extend(self._detect_phone(text))
        spans.extend(self._detect_credit_card(text))
        spans.extend(self._detect_ssn(text))
        spans.extend(self._detect_ipv4(text))
        spans.extend(self._detect_mac(text))
        spans.extend(self._detect_ipv6(text))
        spans.extend(self._detect_api_keys(text))
        spans.extend(self._detect_urls(text))
        spans.sort(key=lambda s: s.start)
        spans = self._consolidate_spans(spans)
        spans = self._filter_allow_list(text, spans)
        return spans

    def _detect_email(self, text: str) -> list[Span]:
        spans = []
        for match in self.PATTERNS[ENTITY_EMAIL].finditer(text):
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
        for match in self.PATTERNS[ENTITY_CREDIT_CARD].finditer(text):
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
        for match in self.PATTERNS[ENTITY_SSN].finditer(text):
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
        for match in self.PATTERNS[ENTITY_IPV4].finditer(text):
            ip = match.group()
            octets = ip.split(".")
            if all(0 <= int(o) <= 255 for o in octets):
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
        for match in self.PATTERNS[ENTITY_IPV6].finditer(text):
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
        for match in self.PATTERNS[ENTITY_MAC].finditer(text):
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
        for match in self.PATTERNS[ENTITY_URL].finditer(text):
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
        filtered = []
        for span in spans:
            if span.value not in self._allow_list:
                filtered.append(span)
        return filtered


def tokenize_and_redact(
    text: str,
    spans: list[Span],
    use_ascii_fallback: bool = False,
) -> tuple[str, list[tuple[str, str, str]]]:
    """Replace detected PII spans with tokens.

    Args:
        text: The original text.
        spans: Detected PII spans, sorted by start position (descending for replacement).
        use_ascii_fallback: If True, use [[TYPE_N]] instead of «TYPE_N».

    Returns:
        Tuple of (sanitized_text, replacements) where replacements is
        list of (token, entity_type, original_value).
    """
    if not spans:
        return text, []

    tokenizer = Tokenizer(use_ascii_fallback=use_ascii_fallback)

    # Sort spans by start position descending (replace from end to start to preserve positions)
    sorted_spans = sorted(spans, key=lambda s: s.start, reverse=True)

    result = text
    for span in sorted_spans:
        token = tokenizer.tokenize(span.value, span.entity_type)
        result = result[: span.start] + token + result[span.end :]

    replacements = tokenizer.get_replacements()

    return result, replacements
