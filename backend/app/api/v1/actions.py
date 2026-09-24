"""API v1 endpoints for agent action evaluation, inspection, and session graph retrieval."""

from uuid import UUID

from fastapi import APIRouter, HTTPException, status

from app.gateway.service import default_agent_gateway
from app.graph.causal_graph import (
    ActionCollisionError,
    CrossSessionParentError,
    ParentActionNotFoundError,
)
from app.schemas.action import AgentAction, AgentActionProposal
from app.schemas.decision import SecurityDecision

router = APIRouter(tags=["Actions & Governance"])


@router.post(
    "/actions/evaluate",
    response_model=SecurityDecision,
    status_code=status.HTTP_200_OK,
    summary="Evaluate an agent action proposal",
    description="Intercepts and normalizes an untrusted action proposal, validates causal parentage, "
    "records the proposed action into the causal execution graph, evaluates deterministic policies, "
    "and returns an authoritative SecurityDecision.",
)
async def evaluate_action_proposal(proposal: AgentActionProposal) -> SecurityDecision:
    """Evaluate a proposed tool action and return authoritative security decision."""
    try:
        _, decision = default_agent_gateway.evaluate_proposal(proposal)
        return decision
    except (ParentActionNotFoundError, CrossSessionParentError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except ActionCollisionError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc


@router.get(
    "/actions/{action_id}",
    response_model=AgentAction,
    summary="Get authoritative action details",
    description="Retrieve the full authoritative AgentAction record, including evaluation verdict, "
    "risk score, and execution status.",
)
async def get_action(action_id: UUID) -> AgentAction:
    """Retrieve authoritative action record by UUID."""
    action = default_agent_gateway.graph_manager.get_action_globally(str(action_id))
    if action is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Action '{action_id}' not found.",
        )
    return action


@router.get(
    "/sessions/{session_id}/graph",
    summary="Get session causal execution graph",
    description="Returns the Directed Acyclic Graph (DAG) of all actions and causal relationships "
    "recorded for the specified session.",
)
async def get_session_graph(session_id: str) -> dict:
    """Retrieve serialized causal graph for a session."""
    graph = default_agent_gateway.graph_manager.get(session_id)
    if graph is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session '{session_id}' not found.",
        )
    return graph.get_session_graph()
