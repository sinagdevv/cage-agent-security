from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status

from app.core.auth import TrustedAuthorityContext, require_trusted_authority
from app.gateway.service import default_agent_gateway
from app.graph.causal_graph import (
    ActionCollisionError,
    CrossSessionParentError,
    GraphCycleError,
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
    except (ParentActionNotFoundError, CrossSessionParentError, GraphCycleError) as exc:
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


@router.get(
    "/actions/{action_id}/ancestry",
    summary="Get action causal ancestry (Control-Plane Diagnostic)",
    description="Diagnostic control-plane endpoint to retrieve the causal ancestry trajectory, "
    "including ancestor actions, causal edges, and trajectory depth.",
)
async def get_action_ancestry(
    action_id: UUID,
    _authority: Annotated[TrustedAuthorityContext, Depends(require_trusted_authority)],
) -> dict:
    """Retrieve causal ancestry details for an action under control-plane authorization."""
    action_key = str(action_id)
    action = default_agent_gateway.graph_manager.get_action_globally(action_key)
    if action is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Action '{action_id}' not found.",
        )

    session_id = action.session_id
    graph = default_agent_gateway.graph_manager.get(session_id)
    if graph is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session '{session_id}' not found for action '{action_id}'.",
        )

    ancestors = graph.get_action_ancestors(action_key)
    ancestor_ids = [str(a.action_id) for a in ancestors]

    # Collect edges along the ancestry path
    edges = []
    nodes_in_path = set(ancestor_ids) | {action_key}
    for u, v, data in graph.graph.edges(data=True):
        if u in nodes_in_path and v in nodes_in_path:
            edges.append(
                {
                    "source": u,
                    "target": v,
                    "relation": data.get("relation", "causes"),
                }
            )

    return {
        "action_id": action_key,
        "session_id": session_id,
        "causal_depth": len(ancestors),
        "action": action,
        "ancestors": ancestors,
        "edges": edges,
    }
