"""Control-plane API endpoints for Intent Contract creation, inspection, revocation, and narrowing."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.core.auth import TrustedAuthorityContext, require_trusted_authority
from app.intent.service import (
    ActiveIntentCollisionError,
    AuthorityExpansionError,
    IntentNotFoundError,
    default_intent_service,
)
from app.schemas.intent import (
    IntentContract,
    IntentContractCreate,
    IntentContractNarrow,
)

router = APIRouter(prefix="/intents", tags=["Intent Contracts (Control Plane)"])


class RevokeIntentRequest(BaseModel):
    """Optional payload for revoking an Intent Contract."""

    reason: str = Field(default="Revoked by trusted authority", description="Reason for revocation")


@router.post(
    "",
    response_model=IntentContract,
    status_code=status.HTTP_201_CREATED,
    summary="Create an authoritative Intent Contract (Control Plane)",
    description="Establish task-scoped authority granted by a human or trusted authority to an AI agent. "
    "Enforces that only one active Intent Contract may exist per session.",
)
async def create_intent(
    req: IntentContractCreate,
    _auth: Annotated[TrustedAuthorityContext, Depends(require_trusted_authority)],
) -> IntentContract:
    """Create a new Intent Contract under control-plane authorization."""
    try:
        return default_intent_service.create_intent(req)
    except ActiveIntentCollisionError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc


@router.get(
    "/{intent_id}",
    response_model=IntentContract,
    summary="Get Intent Contract by UUID",
    description="Retrieve authoritative Intent Contract details, status, and consumed execution quota.",
)
async def get_intent(intent_id: UUID) -> IntentContract:
    """Retrieve an Intent Contract record by UUID."""
    contract = default_intent_service.get_intent(intent_id)
    if contract is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Intent Contract '{intent_id}' not found.",
        )
    return contract


@router.post(
    "/{intent_id}/revoke",
    response_model=IntentContract,
    summary="Revoke an Intent Contract (Control Plane)",
    description="Immediately terminate an Intent Contract's authority. "
    "Subsequent actions under this contract will be DENIED.",
)
async def revoke_intent(
    intent_id: UUID,
    _auth: Annotated[TrustedAuthorityContext, Depends(require_trusted_authority)],
    req: RevokeIntentRequest | None = None,
) -> IntentContract:
    """Revoke an Intent Contract."""
    reason = req.reason if req else "Revoked by trusted authority"
    try:
        return default_intent_service.revoke_intent(intent_id, reason=reason)
    except IntentNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc


@router.post(
    "/{intent_id}/narrow",
    response_model=IntentContract,
    summary="Narrow Intent Contract authority (Control Plane)",
    description="Strictly reduce an active contract's authority adhering to: authority_next <= authority_original. "
    "Attempts to expand permissions, add tools, or extend deadlines are rejected.",
)
async def narrow_intent(
    intent_id: UUID,
    narrow: IntentContractNarrow,
    _auth: Annotated[TrustedAuthorityContext, Depends(require_trusted_authority)],
) -> IntentContract:
    """Narrow an Intent Contract's authorized scope."""
    try:
        return default_intent_service.narrow_intent(intent_id, narrow)
    except IntentNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except (AuthorityExpansionError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
