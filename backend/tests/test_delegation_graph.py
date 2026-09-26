"""Tests for Phase 8 Causal Execution Graph delegation nodes, typed edges, and DAG invariants."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from app.delegation.models import DelegationGrant
from app.graph.causal_graph import CausalExecutionGraph, DelegationCycleError
from app.schemas.enums import (
    AuthorityScopeMode,
    DataClassification,
    GraphNodeType,
    GraphRelation,
    TargetEnvironment,
)
from app.trajectory.models import AuthorityEnvelope, ResourceAuthorityScope


def _create_grant(delegator="agent-a", delegatee="agent-b", session_id="session-1"):
    return DelegationGrant(
        delegation_id=uuid4(),
        root_intent_id=uuid4(),
        session_id=uuid4(),
        issued_from_action_id=uuid4(),
        delegator_agent_id=delegator,
        delegatee_agent_id=delegatee,
        delegated_task_id="task-1",
        authority_envelope=AuthorityEnvelope(
            allowed_tools=frozenset(["web.search"]),
            resource_scope=ResourceAuthorityScope(mode=AuthorityScopeMode.UNCONSTRAINED),
            allowed_environments=frozenset([TargetEnvironment.DEVELOPMENT]),
            allowed_data_classifications=frozenset([DataClassification.PUBLIC]),
        ),
        depth=1,
        remaining_subdelegation_depth=1,
        allow_subdelegation=True,
        max_actions=10,
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )


def test_agent_and_delegation_graph_nodes_and_edges():
    graph = CausalExecutionGraph("session-1")
    grant = _create_grant()

    graph.add_agent_node(grant.delegator_agent_id)
    graph.add_agent_node(grant.delegatee_agent_id)
    graph.add_delegation_node(grant)

    del_id_str = str(grant.delegation_id)
    graph.add_issues_delegation_edge(grant.delegator_agent_id, del_id_str)
    graph.add_grants_to_edge(del_id_str, grant.delegatee_agent_id)

    raw = graph.graph
    assert raw.has_node(grant.delegator_agent_id)
    assert raw.has_node(del_id_str)
    assert raw.has_edge(grant.delegator_agent_id, del_id_str)
    assert (
        raw[grant.delegator_agent_id][del_id_str]["relation"]
        == GraphRelation.ISSUES_DELEGATION.value
    )
    assert raw.has_edge(del_id_str, grant.delegatee_agent_id)
    assert raw[del_id_str][grant.delegatee_agent_id]["relation"] == GraphRelation.GRANTS_TO.value


def test_subdelegates_dag_and_cycle_rejection():
    """SUBDELEGATES relation must independently satisfy DAG invariant and reject cycles."""
    graph = CausalExecutionGraph("session-1")
    g1 = _create_grant(delegator="agent-a", delegatee="agent-b")
    g2 = _create_grant(delegator="agent-b", delegatee="agent-c")
    g3 = _create_grant(delegator="agent-c", delegatee="agent-a")

    id1, id2, id3 = str(g1.delegation_id), str(g2.delegation_id), str(g3.delegation_id)

    graph.add_delegation_node(g1)
    graph.add_delegation_node(g2)
    graph.add_delegation_node(g3)

    # g1 -> g2 -> g3 is a valid DAG
    graph.add_subdelegates_edge(id1, id2)
    graph.add_subdelegates_edge(id2, id3)
    assert graph.is_subdelegation_dag() is True

    # Attempting g3 -> g1 must be rejected as DelegationCycleError
    with pytest.raises(DelegationCycleError):
        graph.add_subdelegates_edge(id3, id1)


def test_mixed_heterogeneous_cycles_allowed():
    """Graph permits valid mixed cycles across different relation types without global DAG failure."""
    graph = CausalExecutionGraph("session-1")

    # Add Action A, Artifact B, Action C
    graph.add_node("action-1", GraphNodeType.ACTION.value)
    graph.add_node("artifact-1", GraphNodeType.ARTIFACT.value)
    graph.add_node("action-2", GraphNodeType.ACTION.value)

    # action-1 PRODUCES artifact-1
    graph.add_causal_edge("action-1", "artifact-1", relation=GraphRelation.PRODUCES)
    # artifact-1 CONSUMES action-2
    graph.add_causal_edge("artifact-1", "action-2", relation=GraphRelation.CONSUMES)
    # action-2 CAUSES action-1
    graph.add_causal_edge("action-2", "action-1", relation=GraphRelation.CAUSES)

    # Valid typed DAGs must pass
    assert graph.has_valid_typed_dags() is True
