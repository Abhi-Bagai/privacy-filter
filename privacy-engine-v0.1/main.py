"""Privacy Engine v0.1 - FastAPI Entry Point."""

from __future__ import annotations

import time
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from logging_config import SanitizeLogger, init_logger
from models import (
    DetectorAddResponse,
    DetectorConfig,
    DetectorInfo,
    DetectorListResponse,
    HealthResponse,
    ReloadResponse,
    Replacement,
    SanitizeRequest,
    SanitizeResponse,
)
from sanitizer import (
    PIIDetector,
    add_detector,
    delete_detector,
    get_all_detectors,
    load_detectors_config,
    tokenize_and_redact,
)

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


# ============================================================
# Sanitization Endpoints
# ============================================================


@app.post("/v1/sanitize", response_model=SanitizeResponse)
async def sanitize(request: SanitizeRequest) -> SanitizeResponse:
    """Sanitize text by detecting and redacting PII."""
    log = get_log()
    request_id = str(uuid.uuid4())[:8]

    # Log: Request received
    log.request_received(
        request_id=request_id,
        text_length=len(request.text),
    )

    start_time = time.perf_counter()

    try:
        allow_list = None
        if request.options and request.options.allow_list:
            allow_list = request.options.allow_list

        detector = PIIDetector(allow_list=allow_list)
        spans = detector.detect(request.text)

        sanitized_text, replacements_tuple = tokenize_and_redact(
            request.text,
            spans,
        )

        replacements = [
            Replacement(token=t, type=entity_type, original=original)
            for t, entity_type, original in replacements_tuple
        ]

        counts: dict[str, int] = {}
        types: list[str] = []
        for replacement in replacements:
            type_key = f"{replacement.type.lower()}_count"
            counts[type_key] = counts.get(type_key, 0) + 1
            if replacement.type not in types:
                types.append(replacement.type)

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        sanitized_preview = (
            sanitized_text[:100] + "..."
            if len(sanitized_text) > 100
            else sanitized_text
        )
        log.sanitize_complete(
            request_id=request_id,
            entities_found=len(replacements),
            types=types,
            counts=counts,
            sanitized_preview=sanitized_preview,
            latency_ms=round(elapsed_ms, 2),
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
    """Health check endpoint."""
    return HealthResponse(status="ok")


# ============================================================
# Detector Config Endpoints
# ============================================================


@app.get("/v1/config/detectors", response_model=DetectorListResponse)
async def list_detectors():
    """List all configured detectors."""
    detectors = get_all_detectors()
    detector_list = [
        DetectorInfo(
            name=d.get("name", ""),
            pattern=d.get("pattern", ""),
            validator=d.get("validator", "none"),
            description=d.get("description", ""),
            enabled=d.get("enabled", False),
        )
        for d in detectors
    ]
    return DetectorListResponse(detectors=detector_list, count=len(detector_list))


@app.post("/v1/config/detectors", response_model=DetectorAddResponse)
async def add_new_detector(config: DetectorConfig):
    """Add a new detector pattern."""
    success, status = add_detector(
        name=config.name,
        pattern=config.pattern,
        validator=config.validator or "none",
        description=config.description or "",
    )

    if not success:
        raise HTTPException(status_code=400, detail=status)

    return DetectorAddResponse(
        status=status,
        name=config.name,
        message=f"Detector '{config.name}' {status}. Call /v1/config/reload to activate.",
    )


@app.delete("/v1/config/detectors/{name}")
async def remove_detector(name: str):
    """Remove a detector by name."""
    success, message = delete_detector(name)

    if not success:
        raise HTTPException(status_code=404, detail=message)

    return {"status": "deleted", "name": name, "message": message}


@app.post("/v1/config/reload", response_model=ReloadResponse)
async def reload_config():
    """Reload detector config from disk."""
    config = load_detectors_config()
    enabled = [d for d in config.get("detectors", []) if d.get("enabled", False)]

    return ReloadResponse(
        status="reloaded",
        message="Configuration reloaded successfully",
        detectors_loaded=len(enabled),
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, uds="/run/privacy-engine.sock")
