"""Health check endpoint."""

from fastapi import APIRouter

from app.core.config import settings
from app.schemas.health import HealthResponse

router = APIRouter(tags=["Health"])


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Return system health and environment status."""
    return HealthResponse(
        status="ok",
        version=settings.version,
        environment=settings.environment,
        engine="CAGE",
    )
