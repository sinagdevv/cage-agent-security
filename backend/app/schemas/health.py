"""Health check response schemas."""

from pydantic import BaseModel, Field

from app.schemas.policy import PolicyEngineHealth


class HealthResponse(BaseModel):
    """Schema for service health status."""

    status: str = Field(default="ok", description="Current service health status")
    version: str = Field(description="Application version")
    environment: str = Field(description="Current deployment environment")
    engine: str = Field(default="CAGE", description="Governance engine identifier")
    policy_engine: "PolicyEngineHealth | None" = Field(
        default=None, description="Policy engine operational and health status"
    )
