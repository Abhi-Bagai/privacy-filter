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
        processors=shared_processors + [
            structlog.processors.JSONRenderer(serializer=_json_serializer),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def _json_serializer(obj: Any, **kwargs: Any) -> str:
    """Serialize object to JSON string."""
    return json.dumps(obj, default=str, separators=(",", ":"))


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Get a configured logger instance.
    
    Args:
        name: Logger name (typically __name__)
        
    Returns:
        Configured structlog logger
    """
    return structlog.get_logger(name)


class SanitizeLogger:
    """Logger wrapper for sanitization operations with enforced hygiene.
    
    This class provides safe logging methods that never expose PII values.
    All logging goes through sanitized methods that only log counts and types.
    """
    
    def __init__(self, logger: structlog.stdlib.BoundLogger):
        self._logger = logger
    
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
    ) -> None:
        """Log that sanitization completed successfully.
        
        Args:
            request_id: Unique request identifier
            entities_found: Total number of PII entities detected
            types: List of entity type names (e.g., ["EMAIL_ADDRESS", "PHONE_NUMBER"])
            counts: Dictionary of counts per type (e.g., {"email_count": 2, "phone_count": 1})
        """
        self._logger.info(
            "sanitize_complete",
            request_id=request_id,
            entities_found=entities_found,
            types=types,
            counts=counts,
        )
    
    def sanitize_error(self, request_id: str, error: str) -> None:
        """Log a sanitization error (no PII values).
        
        Args:
            request_id: Unique request identifier
            error: Error message (no PII values)
        """
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
    """Initialize and return a SanitizeLogger instance.
    
    Returns:
        SanitizeLogger configured for safe PII logging
    """
    global _logger
    if _logger is None:
        configure_logging()
        _logger = get_logger("privacy-engine")
    return SanitizeLogger(_logger)
