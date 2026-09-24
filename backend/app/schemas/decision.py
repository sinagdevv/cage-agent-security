"""Security decision model representing authoritative evaluation outcomes."""

from datetime import UTC, datetime
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from app.schemas.enums import PolicyDecision


class SecurityDecision(BaseModel):
    """Authoritative security decision returned by CAGE for an agent action."""

    decision_id: UUID = Field(
        default_factory=uuid4, description="Unique authorization decision identifier"
    )
    action_id: UUID = Field(..., description="Action UUID that was evaluated")
    session_id: str = Field(..., description="Execution session identifier")
    decision: PolicyDecision = Field(
        ..., description="Resolved policy decision (DENY, ALLOW, etc.)"
    )
    reason: str = Field(..., description="Explainable justification for the decision")
    matched_rules: list[str] = Field(
        default_factory=list, description="Identifiers of rules triggered"
    )
    risk_score: float = Field(
        default=0.0, ge=0.0, le=1.0, description="Evaluated action risk score"
    )
    requires_human_approval: bool = Field(
        default=False, description="Whether human approval is required"
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="Decision timestamp"
    )
