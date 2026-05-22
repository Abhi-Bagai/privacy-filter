"""Privacy Engine v0.1 - FastAPI Entry Point."""

from __future__ import annotations

import time
import uuid
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from logging_config import SanitizeLogger, init_logger
from models import HealthResponse, Replacement, SanitizeRequest, SanitizeResponse
from sanitizer import PIIDetector, tokenize_and_redact

# Global logger instance
_log: SanitizeLogger | None = None


def get_log() -> SanitizeLogger:
    """Get or initialize the global logger."""
    global _log
    if _log is None:
        _log = init_logger()
    return _log


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup/shutdown events."""
    log = get_log()
    log.engine_started()
    yield


app = FastAPI(
    title="Privacy Engine v0.1",
    description="Local PII-sanitization service for WatchTower",
    version="0.1.0",
    lifespan=lifespan,
)


@app.post("/v1/sanitize", response_model=SanitizeResponse)
async def sanitize(request: SanitizeRequest) -> SanitizeResponse:
    """Sanitize text by detecting and redacting PII.

    Detects: email, phone (US), credit card, US SSN, IPv4/IPv6, MAC address,
    API keys (sk-, ghp_, xoxb-, AKIA, eyJ), and URLs.

    Returns sanitized text with placeholders and a map for reconstruction.
    """
    log = get_log()
    request_id = str(uuid.uuid4())[:8]

    log.sanitize_started(request_id)

    start_time = time.perf_counter()

    try:
        # Build detector with allow_list from options
        allow_list = None
        if request.options and request.options.allow_list:
            allow_list = request.options.allow_list

        detector = PIIDetector(allow_list=allow_list)
        spans = detector.detect(request.text)

        # Tokenize and redact
        sanitized_text, replacements_tuple = tokenize_and_redact(
            request.text,
            spans,
        )

        # Convert replacements to model objects
        replacements = [
            Replacement(token=t, type=entity_type, original=original)
            for t, entity_type, original in replacements_tuple
        ]

        # Calculate counts for logging
        counts: dict[str, int] = {}
        types: list[str] = []
        for replacement in replacements:
            type_key = f"{replacement.type.lower()}_count"
            counts[type_key] = counts.get(type_key, 0) + 1
            if replacement.type not in types:
                types.append(replacement.type)

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        log.sanitize_complete(
            request_id=request_id,
            entities_found=len(replacements),
            types=types,
            counts=counts,
        )

        return SanitizeResponse(
            sanitized_text=sanitized_text,
            replacements=replacements,
            latency_ms=round(elapsed_ms, 2),
        )

    except Exception as e:
        log.sanitize_error(request_id=request_id, error=str(e))
        return JSONResponse(
            status_code=500,
            content={"error": "Internal sanitization error"},
        )


@app.get("/healthz", response_model=HealthResponse)
async def healthz() -> HealthResponse:
    """Health check endpoint.

    Returns {"status": "ok"} if the service is running.
    """
    return HealthResponse(status="ok")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, uds="/run/privacy-engine.sock")
