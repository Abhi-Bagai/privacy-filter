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
    add_detector,
    delete_detector,
    get_all_detectors,
    load_detectors_config,
    tokenize_and_redact,
)

# Get config path for tests
CONFIG_DIR = os.path.join(os.path.dirname(__file__), "..", "config")
DETECTORS_CONFIG = os.path.join(CONFIG_DIR, "detectors.yaml")


class TestEmailDetection:
    """Test 1: Detect and redact an email."""

    def test_email_detected_and_redacted(self):
        """Email should be detected and replaced with token format «EMAIL_N»."""
        text = "Contact me at john.doe@example.com for more info."
        detector = PIIDetector()
        spans = detector.detect(text)

        sanitized, replacements = tokenize_and_redact(text, spans)

        assert len(replacements) == 1
        token, entity_type, original = replacements[0]

        assert token.startswith("«EMAIL_")
        assert token.endswith("»")
        assert entity_type == ENTITY_EMAIL
        assert original == "john.doe@example.com"

        assert "john.doe@example.com" not in sanitized
        assert "john.doe" not in sanitized


class TestPhoneDetection:
    """Test 2: Detect and redact a US phone number."""

    def test_us_phone_detected(self):
        """Valid US phone numbers should be detected."""
        text = "Call me at (555) 123-4567 or 555.987.6543."
        detector = PIIDetector()
        spans = detector.detect(text)

        phone_spans = [s for s in spans if s.entity_type == ENTITY_PHONE]
        assert len(phone_spans) >= 1


class TestCreditCardDetection:
    """Test 3: Detect and redact credit card with Luhn validation."""

    def test_valid_credit_card_detected(self):
        """Valid credit card numbers should be detected."""
        text = "My card is 4111111111111111."
        detector = PIIDetector()
        spans = detector.detect(text)

        cc_spans = [s for s in spans if s.entity_type == ENTITY_CREDIT_CARD]
        assert len(cc_spans) == 1

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


class TestAllowList:
    """Test 6: Allow-list test."""

    def test_allow_list_item_not_redacted(self):
        """Strings in allow_list should not be redacted."""
        text = "My email is user@example.com and my name is John."
        allow_list = ["user@example.com"]

        detector = PIIDetector(allow_list=allow_list)
        spans = detector.detect(text)

        sanitized, replacements = tokenize_and_redact(text, spans)

        assert "user@example.com" in sanitized

        email_spans = [s for s in spans if s.entity_type == ENTITY_EMAIL]
        assert len(email_spans) == 0


class TestConsistency:
    """Test 7: Consistency test - same value gets same token."""

    def test_same_email_twice_same_token(self):
        """Same email appearing twice should get the same token."""
        text = "Email me at john@example.com or at john@example.com again."
        detector = PIIDetector()
        spans = detector.detect(text)

        sanitized, replacements = tokenize_and_redact(text, spans)

        assert len(replacements) == 1
        token = replacements[0][0]

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
        result = subprocess.run(
            ["./scripts/check_logging_hygiene.sh"],
            cwd="privacy-engine-v0.1",
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


# ============================================================
# Config Endpoint Tests
# ============================================================


class TestDetectorConfig:
    """Tests for dynamic detector configuration."""

    def test_get_all_detectors(self):
        """Should return list of all detectors."""
        detectors = get_all_detectors()
        assert isinstance(detectors, list)
        assert len(detectors) > 0

        # Check structure
        for d in detectors:
            assert "name" in d
            assert "enabled" in d

    def test_add_detector_valid(self):
        """Should add a valid detector."""
        # Add test detector
        success, status = add_detector(
            name="TEST_INVOICE_ID",
            pattern=r"INV-\d{6}",
            validator="none",
            description="Test invoice detector",
        )

        assert success is True
        assert status in ["added", "updated"]

        # Verify it was added
        detectors = get_all_detectors()
        test_detectors = [d for d in detectors if d.get("name") == "TEST_INVOICE_ID"]
        assert len(test_detectors) == 1
        assert test_detectors[0].get("enabled") is True

    def test_add_detector_invalid_pattern(self):
        """Should fail with invalid regex pattern."""
        success, message = add_detector(
            name="INVALID_TEST",
            pattern=r"[invalid(",  # Invalid regex
            validator="none",
        )

        assert success is False
        assert "Invalid regex" in message

    def test_add_detector_invalid_validator(self):
        """Should fail with unknown validator."""
        success, message = add_detector(
            name="INVALID_VALIDATOR_TEST",
            pattern=r"\d+",
            validator="unknown_validator",
        )

        assert success is False
        assert "Unknown validator" in message

    def test_add_detector_updates_existing(self):
        """Should update existing detector if same name."""
        # Add first time
        success1, status1 = add_detector(
            name="DUPLICATE_TEST",
            pattern=r"ABC\d{3}",
            validator="none",
        )
        assert success1 is True
        assert status1 == "added"

        # Add again with different pattern
        success2, status2 = add_detector(
            name="DUPLICATE_TEST",
            pattern=r"XYZ\d{5}",
            validator="none",
        )
        assert success2 is True
        assert status2 == "updated"

        # Verify it was updated
        detectors = get_all_detectors()
        dup = [d for d in detectors if d.get("name") == "DUPLICATE_TEST"]
        assert len(dup) == 1
        assert dup[0].get("pattern") == r"XYZ\d{5}"

    def test_delete_detector(self):
        """Should delete a detector."""
        # Add first
        add_detector(
            name="DELETE_ME_TEST",
            pattern=r"DELETE-\d+",
            validator="none",
        )

        # Delete it
        success, message = delete_detector("DELETE_ME_TEST")
        assert success is True
        assert "DELETE_ME_TEST" in message

        # Verify it's gone
        detectors = get_all_detectors()
        remaining = [d for d in detectors if d.get("name") == "DELETE_ME_TEST"]
        assert len(remaining) == 0

    def test_delete_detector_not_found(self):
        """Should fail when deleting non-existent detector."""
        success, message = delete_detector("NON_EXISTENT_DETECTOR_12345")

        assert success is False
        assert "not found" in message.lower()

    def test_new_detector_detects_pii(self):
        """Newly added detector should actually detect PII."""
        # Add detector for specific pattern
        add_detector(
            name="TEST_CUSTOM_PII",
            pattern=r"CUSTOM-\d{4}",
            validator="none",
        )

        # Test detection
        text = "My ID is CUSTOM-1234 and email is test@example.com"
        detector = PIIDetector()
        spans = detector.detect(text)

        custom_spans = [s for s in spans if s.entity_type == "TEST_CUSTOM_PII"]
        assert len(custom_spans) == 1
        assert custom_spans[0].value == "CUSTOM-1234"

        # Verify sanitization
        sanitized, replacements = tokenize_and_redact(text, spans)
        assert "CUSTOM-1234" not in sanitized
        assert "«TEST_CUSTOM_PII_1»" in sanitized

        # Cleanup
        delete_detector("TEST_CUSTOM_PII")


class TestCanadianSIN:
    """Test Canadian SIN detection."""

    def test_canadian_sin_detected(self):
        """Canadian SIN should be detected."""
        text = "My SIN is 123-456-789."
        detector = PIIDetector()
        spans = detector.detect(text)

        sin_spans = [s for s in spans if s.entity_type == "CANADIAN_SIN"]
        assert len(sin_spans) >= 1


class TestUKNINO:
    """Test UK NINO detection."""

    def test_uk_nino_detected(self):
        """UK NINO should be detected."""
        text = "My NINO is AB 123456C"
        detector = PIIDetector()
        spans = detector.detect(text)

        nino_spans = [s for s in spans if s.entity_type == "UK_NINO"]
        assert len(nino_spans) >= 1
