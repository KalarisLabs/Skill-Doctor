"""
Pydantic models for Skill Doctor.
"""

from datetime import datetime, timezone
from typing import Optional, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class Finding(BaseModel):
    """A security finding from a scan layer."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    category: str = Field(description="e.g., 'SD-02 · Command Injection'")
    file: str = Field(description="Relative path within bundle")
    line: Optional[int] = None
    description: str = Field(description="Plain English, 1-2 sentences")
    remediation: str = Field(description="Specific fix suggestion")
    engine: str = Field(description="yara, ast, llm, sandbox, threat_db")
    confidence: float = Field(ge=0.0, le=1.0, description="0.0 – 1.0")


class ScanResult(BaseModel):
    """Complete scan result from all layers."""

    scan_id: str = Field(default_factory=lambda: str(uuid4()))
    bundle_hash: str
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    duration_ms: int
    findings: list[Finding]
    risk_level: Literal["SAFE", "CAUTION", "DANGEROUS"]
    risk_score: float = Field(ge=0.0, le=10.0, description="0.0–10.0")
    layers_run: list[str] = Field(description="Which layers executed")


class ScanProgress(BaseModel):
    """Progress update during scanning."""

    scan_id: str
    status: Literal["queued", "running", "done", "error"]
    progress: Optional[dict] = Field(
        default=None,
        description="e.g., {'layer': 1, 'stage': 'YARA rules'}",
    )
    result: Optional[ScanResult] = None
    error: Optional[str] = None


class ScanRequest(BaseModel):
    """Request to start a scan."""

    url: Optional[str] = None
    file: Optional[str] = None
