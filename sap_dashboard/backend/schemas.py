"""
sap_dashboard/backend/schemas.py — DTO models for the dashboard API.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class EngagementSummary(BaseModel):
    id: str
    name: str
    client: str
    status: str
    current_phase: str
    created_at: datetime


class EngagementCreateBody(BaseModel):
    name: str
    client: str
    tester: str = ""
    authorization_ref: str = ""
    scope_cidrs: list[str] = Field(default_factory=list)
    scope_domains: list[str] = Field(default_factory=list)
    scope_urls: list[str] = Field(default_factory=list)
    rules_of_engagement: str = ""


class EngagementPatch(BaseModel):
    status: Optional[str] = None
    current_phase: Optional[str] = None


class RunStartBody(BaseModel):
    objective: str
    mode: str = "execution"
    max_iterations: int = 12
    model: Optional[str] = None
    provider: Optional[str] = None


class RunStatus(BaseModel):
    run_id: str
    engagement_id: str
    objective: str
    mode: str
    state: str  # running | paused | done | error | killed
    started_at: datetime
    finished_at: Optional[datetime] = None
    iterations: int = 0
    error: Optional[str] = None
    final_text: Optional[str] = None


class RunControl(BaseModel):
    action: str  # pause | resume | kill


class ApprovalDecisionBody(BaseModel):
    gate_id: str
    decision: str  # allow | deny
    reason: str = ""


class SudoUnlockBody(BaseModel):
    password: str
    ttl_seconds: int = 600


class SudoStatus(BaseModel):
    locked: bool
    expires_at_monotonic: float = 0.0
    ttl_remaining_seconds: float = 0.0
    last_use_monotonic: float = 0.0
    failures: int = 0
    unlock_count: int = 0


class SettingsView(BaseModel):
    llm: dict[str, Any]
    agent: dict[str, Any]
    executor: dict[str, Any]
    sudo: dict[str, Any]
    mcp_servers: list[str]


class SettingsPatch(BaseModel):
    section: str
    key: str
    value: Any
