"""Pydantic models for Privacy Engine v0.1 API."""

from typing import Optional

from pydantic import BaseModel, Field, field_validator


class SanitizeOptions(BaseModel):
    """Optional configuration for sanitization requests."""

    entity_types: Optional[list[str]] = Field(
        default=None,
        description="List of entity types to detect (default: all)",
    )
    allow_list: Optional[list[str]] = Field(
        default=None,
        max_length=100,
        description="Strings that should never be redacted",
    )

    @field_validator("allow_list")
    @classmethod
    def allow_list_max_length(cls, v: Optional[list[str]]) -> Optional[list[str]]:
        if v is not None and len(v) > 100:
            raise ValueError("allow_list must have at most 100 items")
        return v


class SanitizeRequest(BaseModel):
    """Request schema for /v1/sanitize endpoint."""

    text: str = Field(
        ...,
        min_length=1,
        max_length=50_000,
        description="The input text to sanitize",
    )
    options: Optional[SanitizeOptions] = Field(
        default=None,
        description="Optional configuration for sanitization",
    )

    @field_validator("text")
    @classmethod
    def text_must_not_be_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("text must not be empty or whitespace only")
        return v


class Replacement(BaseModel):
    """A single PII replacement mapping."""

    token: str = Field(..., description="The placeholder token (e.g., «EMAIL_1»)")
    type: str = Field(..., description="The entity type (e.g., EMAIL_ADDRESS)")
    original: str = Field(..., description="The original PII value")


class SanitizeResponse(BaseModel):
    """Response schema for /v1/sanitize endpoint."""

    sanitized_text: str = Field(
        ..., description="The sanitized text with PII replaced by tokens"
    )
    replacements: list[Replacement] = Field(
        default_factory=list,
        description="List of replacement mappings for reconstruction",
    )
    latency_ms: float = Field(
        ..., ge=0.0, description="Request latency in milliseconds"
    )


class HealthResponse(BaseModel):
    """Response schema for /healthz endpoint."""

    status: str = Field(default="ok", description="Health status")


# ============================================================
# Detector Config Models
# ============================================================


class DetectorConfig(BaseModel):
    """Request schema for adding a new detector."""

    name: str = Field(..., description="Detector name (e.g., INVOICE_ID)")
    pattern: str = Field(..., description="Regex pattern for detection")
    validator: Optional[str] = Field(
        default="none",
        description="Validator name: luhn, canadian_sin, australian_tfn, ipv4, none",
    )
    description: Optional[str] = Field(
        default="",
        description="Human-readable description",
    )


class DetectorInfo(BaseModel):
    """Response schema for detector info."""

    name: str
    pattern: str
    validator: str
    description: str
    enabled: bool


class DetectorAddResponse(BaseModel):
    """Response after adding a detector."""

    status: str  # "added", "updated"
    name: str
    message: str


class DetectorListResponse(BaseModel):
    """Response for listing detectors."""

    detectors: list[DetectorInfo]
    count: int


class ReloadResponse(BaseModel):
    """Response after config reload."""

    status: str
    message: str
    detectors_loaded: int
