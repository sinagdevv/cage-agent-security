"""FastAPI REST router for multi-agent delegation management."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response, status

from app.api.deps import get_agent_principal, get_delegation_service
from app.delegation.models import (
    DelegationCloseRequest,
    DelegationCreateResponse,
    DelegationProposal,
    DelegationRevokeRequest,
    DelegationSnapshot,
)
from app.delegation.service import DelegationService
from app.identity.principal import AgentPrincipal
from app.schemas.enums import PolicyDecision

router = APIRouter(prefix="/delegations", tags=["delegations"])


@router.post(
    "",
    response_model=DelegationCreateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Propose and create a multi-agent delegation grant",
)
async def create_delegation(
    proposal: DelegationProposal,
    response: Response,
    principal: Annotated[AgentPrincipal, Depends(get_agent_principal)],
    service: Annotated[DelegationService, Depends(get_delegation_service)],
) -> DelegationCreateResponse:
    """Evaluate a candidate delegation proposal and create an active grant or register pending approval."""
    result = service.propose_delegation(proposal=proposal, principal=principal)

    if result.decision == PolicyDecision.REQUIRE_APPROVAL:
        response.status_code = status.HTTP_202_ACCEPTED
    elif result.decision == PolicyDecision.DENY:
        response.status_code = status.HTTP_403_FORBIDDEN

    return result


@router.get(
    "/{delegation_id}",
    response_model=DelegationSnapshot,
    summary="Retrieve immutable delegation grant and live effective status",
)
async def get_delegation(
    delegation_id: UUID,
    service: Annotated[DelegationService, Depends(get_delegation_service)],
) -> DelegationSnapshot:
    """Retrieve metadata and live effective authority snapshot for a delegation grant."""
    snapshot = service.get_delegation_snapshot(delegation_id)
    if snapshot is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Delegation grant '{delegation_id}' not found.",
        )
    return snapshot


@router.post(
    "/{delegation_id}/revoke",
    status_code=status.HTTP_200_OK,
    summary="Revoke an active delegation grant",
)
async def revoke_delegation(
    delegation_id: UUID,
    req: DelegationRevokeRequest,
    principal: Annotated[AgentPrincipal, Depends(get_agent_principal)],
    service: Annotated[DelegationService, Depends(get_delegation_service)],
) -> dict[str, str]:
    """Revoke a delegation grant and invalidate all descendant authority."""
    success = service.revoke_delegation(
        delegation_id=delegation_id,
        principal=principal,
        reason=req.reason,
    )
    if not success:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Not authorized to revoke delegation grant '{delegation_id}', or grant not found.",
        )
    return {"status": "REVOKED", "delegation_id": str(delegation_id)}


@router.post(
    "/{delegation_id}/close",
    status_code=status.HTTP_200_OK,
    summary="Close an active delegation grant upon task completion",
)
async def close_delegation(
    delegation_id: UUID,
    req: DelegationCloseRequest,
    principal: Annotated[AgentPrincipal, Depends(get_agent_principal)],
    service: Annotated[DelegationService, Depends(get_delegation_service)],
) -> dict[str, str]:
    """Close an active delegation grant by the delegatee upon task completion."""
    success = service.close_delegation(
        delegation_id=delegation_id,
        principal=principal,
        reason=req.reason,
    )
    if not success:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Not authorized to close delegation grant '{delegation_id}', or grant not found.",
        )
    return {"status": "CLOSED", "delegation_id": str(delegation_id)}
