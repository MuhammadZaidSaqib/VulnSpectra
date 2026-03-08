"""Pydantic schemas for VulnSpectra API."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    target: str = Field(..., description="Target IP, domain, or CIDR")
    ports: str = Field("1-1000", description="Port range/list")
    timeout: int = Field(2, ge=1, le=30, description="Connection timeout seconds")


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str


class ScanStatus(BaseModel):
    scan_id: str
    status: str
    progress: float
    started_at: datetime
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None


class DashboardOverview(BaseModel):
    totals: Dict[str, Any]
    severity_distribution: Dict[str, int]
    risk_timeline: List[Dict[str, Any]]
    recent_scans: List[Dict[str, Any]]
    recent_vulnerabilities: List[Dict[str, Any]]

