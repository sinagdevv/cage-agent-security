from fastapi import APIRouter

from app.core.config import settings
from app.policies.opa_client import default_opa_client
from app.schemas.enums import PolicyBackend
from app.schemas.health import HealthResponse
from app.schemas.policy import PolicyEngineHealth

router = APIRouter(tags=["Health"])


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Return system health and environment status, reflecting configured policy backend."""
    backend_mode = PolicyBackend(settings.policy_backend)
    opa_reachable = default_opa_client.check_health()
    opa_required = backend_mode in (PolicyBackend.SHADOW, PolicyBackend.OPA)

    if backend_mode == PolicyBackend.PYTHON:
        engine_status = "healthy"
        overall_status = "ok"
    elif backend_mode == PolicyBackend.SHADOW:
        if opa_reachable:
            engine_status = "healthy"
            overall_status = "ok"
        else:
            engine_status = "degraded"
            overall_status = "degraded"
    else:  # PolicyBackend.OPA
        if opa_reachable:
            engine_status = "healthy"
            overall_status = "ok"
        else:
            engine_status = "unhealthy"
            overall_status = "unhealthy"

    policy_engine_health = PolicyEngineHealth(
        backend=backend_mode,
        status=engine_status,
        opa_reachable=opa_reachable,
        opa_required=opa_required,
        policy_version=settings.policy_version,
        schema_version=settings.policy_input_schema_version,
        error="OPA unreachable" if not opa_reachable and opa_required else None,
    )

    return HealthResponse(
        status=overall_status,
        version=settings.version,
        environment=settings.environment,
        engine="CAGE",
        policy_engine=policy_engine_health,
    )
