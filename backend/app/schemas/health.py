"""Health check response schemas."""

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Schema for service health status."""

    status: str = Field(default="ok", description="Current service health status")
    version: str = Field(description="Application version")
    environment: str = Field(description="Current deployment environment")
    engine: str = Field(default="CAGE", description="Governance engine identifier")
