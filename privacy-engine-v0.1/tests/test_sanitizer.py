"""Smoke Tests for Privacy Engine v0.1."""

from __future__ import annotations

import os
import subprocess
import time

import pytest

from sanitizer import (
    ENTITY_CREDIT_CARD,
    ENTITY_EMAIL,
    ENTITY_IPV4,
    ENTITY_MAC,
    ENTITY_PHONE,
    ENTITY_SSN,
    ENTITY_URL,
    PIIDetector,
    tokenize_and_redact,
)


class TestEmailDetection:
    """Test 1: Detect and redact an email."""

    def test_email_detected_and_redacted(self):
        """Email should be detected and replaced with token format «EMAIL_N»."""
        text = "Contact me at john.doe@example.com for more info."
        detector = PIIDetector()
        spans = detector.detect(text)

        sanitized, replacements = tokenize_and_redact(text, spans)

        # Should have one replacement
        assert len(replacements) == 1
        token, entity_type, original = replacements[0]

        # Check token format
        assert token.startswith("«EMAIL_")
        assert token.endswith("»")
        assert entity_type == ENTITY_EMAIL
        assert original == "john.doe@example.com"

        # Check sanitized text doesn't contain email
        assert "john.doe@example.com" not in sanitized
        assert "john.doe" not in sanitized  # Should be fully redacted


class TestPhoneDetection:
    """Test 2: Detect and redact a US phone number."""

    def test_us_phone_detected(self):
        """Valid US phone numbers should be detected."""
        text = "Call me at (415) 867-5309 or (202) 456-1111."
        detector = PIIDetector()
        spans = detector.detect(text)

        # Should detect valid US phone numbers
        phone_spans = [s for s in spans if s.entity_type == ENTITY_PHONE]
        assert len(phone_spans) >= 1  # At least one valid format


class TestCreditCardDetection:
    """Test 3: Detect and redact credit card with Luhn validation."""

    def test_valid_credit_card_detected(self):
        """Valid credit card numbers should be detected."""
        # This is a valid Luhn number (4111111111111111 - Visa test number)
        text = "My card is 4111111111111111."
        detector = PIIDetector()
        spans = detector.detect(text)

        cc_spans = [s for s in spans if s.entity_type == ENTITY_CREDIT_CARD]
        assert len(cc_spans) == 1
        assert cc_spans[0].value == "4111111111111111"

    def test_invalid_credit_card_not_detected(self):
        """Invalid credit card numbers (failing Luhn) should NOT be detected."""
        text = "Card number is 1234567890123456 (invalid)."
        detector = PIIDetector()
        spans = detector.detect(text)

        cc_spans = [s for s in spans if s.entity_type == ENTITY_CREDIT_CARD]
        assert len(cc_spans) == 0


class TestSSNDetection:
    """Test 4: Detect and redact US SSN."""

    def test_ssn_detected(self):
        """US SSN in XXX-XX-XXXX format should be detected."""
        text = "My SSN is 123-45-6789."
        detector = PIIDetector()
        spans = detector.detect(text)

        ssn_spans = [s for s in spans if s.entity_type == ENTITY_SSN]
        assert len(ssn_spans) == 1
        assert ssn_spans[0].value == "123-45-6789"


class TestURLDetection:
    """Test 5: Detect and redact URL (entire URL redacted)."""

    def test_url_detected(self):
        """Full URL should be detected and redacted."""
        text = "Check out https://example.com/path?query=value#fragment"
        detector = PIIDetector()
        spans = detector.detect(text)

        url_spans = [s for s in spans if s.entity_type == ENTITY_URL]
        assert len(url_spans) == 1

        sanitized, replacements = tokenize_and_redact(text, spans)
        assert "https://" not in sanitized
        assert "example.com" not in sanitized


class TestAllowList:
    """Test 6: Allow-list test."""

    def test_allow_list_item_not_redacted(self):
        """Strings in allow_list should not be redacted."""
        text = "My email is user@example.com and my name is John."
        allow_list = ["user@example.com"]

        detector = PIIDetector(allow_list=allow_list)
        spans = detector.detect(text)

        sanitized, replacements = tokenize_and_redact(text, spans)

        # Email should NOT be redacted (it's in allow_list)
        assert "user@example.com" in sanitized

        # But name if it were detectable would be... (not in v0.1 scope)
        email_spans = [s for s in spans if s.entity_type == ENTITY_EMAIL]
        assert len(email_spans) == 0  # Because it's in allow_list


class TestConsistency:
    """Test 7: Consistency test - same value gets same token."""

    def test_same_email_twice_same_token(self):
        """Same email appearing twice should get the same token."""
        text = "Email me at john@example.com or at john@example.com again."
        detector = PIIDetector()
        spans = detector.detect(text)

        sanitized, replacements = tokenize_and_redact(text, spans)

        # Should have only one replacement (same email, same token)
        assert len(replacements) == 1
        token = replacements[0][0]

        # Both occurrences should be replaced with same token
        assert sanitized.count(token) == 2
        assert "john@example.com" not in sanitized


class TestLatency:
    """Test 8: Latency test."""

    def test_500_char_input_under_20ms(self):
        """500-character input should complete in under 20 ms."""
        text = "A" * 500 + " email: test@example.com and phone: 555-123-4567"
        detector = PIIDetector()

        start = time.perf_counter()
        spans = detector.detect(text)
        sanitized, replacements = tokenize_and_redact(text, spans)
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert elapsed_ms < 20, f"Took {elapsed_ms:.2f} ms, expected < 20 ms"


class TestLoggingHygiene:
    """Test 9: Logging hygiene check."""

    def test_logging_hygiene_passes(self):
        """The logging hygiene CI check should pass."""
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        result = subprocess.run(
            ["./scripts/check_logging_hygiene.sh"],
            cwd=project_root,
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, f"Logging hygiene check failed:\n{result.stderr}"


class TestIPv4Detection:
    """Additional test: IPv4 detection."""

    def test_ipv4_detected(self):
        """IPv4 addresses should be detected."""
        text = "Server at 192.168.1.1 and 10.0.0.1"
        detector = PIIDetector()
        spans = detector.detect(text)

        ipv4_spans = [s for s in spans if s.entity_type == ENTITY_IPV4]
        assert len(ipv4_spans) == 2


class TestMACDetection:
    """Additional test: MAC address detection."""

    def test_mac_detected(self):
        """MAC addresses should be detected."""
        text = "MAC address is aa:bb:cc:dd:ee:ff or 00:11:22:33:44:55"
        detector = PIIDetector()
        spans = detector.detect(text)

        mac_spans = [s for s in spans if s.entity_type == ENTITY_MAC]
        assert len(mac_spans) == 2
