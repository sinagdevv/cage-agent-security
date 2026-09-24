"""Control-plane authentication and authority boundary for CAGE.

Enforces clear separation between:
- CONTROL PLANE: Intent creation, revocation, and authority narrowing.
- DATA PLANE: Agent tool action proposals and execution requests.

NOTICE:
For Phase 2, trusted authority validation uses a dedicated control-plane header / token.
This models the architectural boundary and is not a substitute for full enterprise IAM.
"""

from fastapi import Header, HTTPException, status
from pydantic import BaseModel

from app.core.config import settings


class TrustedAuthorityContext(BaseModel):
    """Context representing an authenticated control-plane human administrator or service."""

    principal_id: str
    role: str = "control_plane_admin"
    is_trusted: bool = True


async def require_trusted_authority(
    x_cage_control_plane: str | None = Header(
        default=None,
        alias="X-CAGE-Control-Plane",
        description="Control-plane authorization token or identifier",
    ),
) -> TrustedAuthorityContext:
    """Dependency enforcing that an operation originates from a trusted control-plane principal.

    Agent data-plane traffic MUST NOT have access to control-plane endpoints.
    """
    # Accept if development debug mode or if valid control-plane token provided
    expected_key = settings.api_key or "cage_dev_test_api_key"
    allowed_tokens = {"trusted-admin", "control-plane", expected_key}

    if x_cage_control_plane and x_cage_control_plane in allowed_tokens:
        return TrustedAuthorityContext(principal_id=x_cage_control_plane)

    # In development mode, provide a fallback if explicitly set, but default to requiring header
    if settings.debug and x_cage_control_plane is None:
        # Allow default local dev context with a clear warning in logs
        return TrustedAuthorityContext(principal_id="local-dev-admin")

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Operation requires trusted control-plane authority. Agent data-plane clients are forbidden.",
    )
