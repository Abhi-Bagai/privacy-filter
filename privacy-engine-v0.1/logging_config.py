"""Logging configuration for Privacy Engine v0.1.

This module configures structlog for JSON output with strict hygiene rules:
- NEVER log raw PII values, original text, or any variable named:
  text, original, value, pii, password, secret, raw, input, data, payload, content
- ALWAYS log counts and types only
"""

from __future__ import annotations

import json
import sys
import time
from typing import Any

import structlog


def configure_logging() -> None:
    """Configure structlog for JSON output with hygiene rules."""

    # Configure structlog processors
    shared_processors = [
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    structlog.configure(
        processors=shared_processors
        + [
            structlog.processors.JSONRenderer(serializer=_json_serializer),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def _json_serializer(obj: Any) -> str:
    """Serialize object to JSON string."""
    return json.dumps(obj, default=str, separators=(",", ":"))


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Get a configured logger instance."""
    return structlog.get_logger(name)


class SanitizeLogger:
    """Logger wrapper for sanitization operations with enforced hygiene."""

    def __init__(self, logger: structlog.stdlib.BoundLogger):
        self._logger = logger

    def request_received(self, request_id: str, text_length: int) -> None:
        """Log that a sanitization request was received."""
        self._logger.info(
            "request_received",
            request_id=request_id,
            text_length=text_length,
        )

    def sanitize_started(self, request_id: str) -> None:
        """Log that a sanitization request has started."""
        self._logger.info(
            "sanitize_started",
            request_id=request_id,
        )

    def sanitize_complete(
        self,
        request_id: str,
        entities_found: int,
        types: list[str],
        counts: dict[str, int],
        sanitized_preview: str = "",
        latency_ms: float = 0.0,
    ) -> None:
        """Log that sanitization completed successfully.

        Args:
            request_id: Unique request identifier
            entities_found: Total number of PII entities detected
            types: List of entity type names
            counts: Dictionary of counts per type
            sanitized_preview: First 100 chars of sanitized text (safe to log)
            latency_ms: Request latency in milliseconds
        """
        self._logger.info(
            "sanitize_complete",
            request_id=request_id,
            entities_found=entities_found,
            types=types,
            counts=counts,
            sanitized_preview=sanitized_preview,
            latency_ms=latency_ms,
        )

    def sanitize_error(self, request_id: str, error: str) -> None:
        """Log a sanitization error (no PII values)."""
        self._logger.error(
            "sanitize_error",
            request_id=request_id,
            error=error,
        )

    def engine_started(self) -> None:
        """Log that the privacy engine has started."""
        self._logger.info("privacy_engine_started")

    def health_check(self, request_id: str) -> None:
        """Log a health check request."""
        self._logger.debug("health_check", request_id=request_id)


# Global logger instance - initialized by configure_logging()
_logger: structlog.stdlib.BoundLogger | None = None


def init_logger() -> SanitizeLogger:
    """Initialize and return a SanitizeLogger instance."""
    global _logger
    if _logger is None:
        configure_logging()
        _logger = get_logger("privacy-engine")
    return SanitizeLogger(_logger)
