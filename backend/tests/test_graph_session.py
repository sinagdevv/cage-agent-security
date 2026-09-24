"""Tests for CausalExecutionGraph and SessionGraphManager."""

from uuid import uuid4

import pytest

from app.graph.causal_graph import (
    ActionCollisionError,
    CausalExecutionGraph,
    ParentActionNotFoundError,
    SessionGraphManager,
)
from app.schemas.action import AgentAction, AgentActionProposal
from app.schemas.enums import ActionType, PolicyDecision, ToolExecutionStatus


def make_action(session_id: str, tool_name: str = "web.search") -> AgentAction:
    proposal = AgentActionProposal(
        agent_id="agent-graph-test",
        session_id=session_id,
        tool_name=tool_name,
        action_type=ActionType.TOOL_CALL,
    )
    return AgentAction.from_proposal(proposal)


def test_add_action_and_retrieval() -> None:
    """Verify adding action stores node and enables retrieval."""
    graph = CausalExecutionGraph("session-01")
    action = make_action("session-01")

    graph.add_action(action)
    retrieved = graph.get_action(str(action.action_id))

    assert retrieved is not None
    assert retrieved.action_id == action.action_id
    assert graph.node_count() == 1


def test_duplicate_action_id_cannot_mutate_history() -> None:
    """Verify that adding an action with an existing ID raises ActionCollisionError."""
    graph = CausalExecutionGraph("session-01")
    action = make_action("session-01")

    graph.add_action(action)
    with pytest.raises(ActionCollisionError):
        graph.add_action(action)


def test_parent_child_causal_relationships() -> None:
    """Verify linking parent to child creates valid DAG edge."""
    graph = CausalExecutionGraph("session-01")
    action_1 = make_action("session-01", "file.read")
    action_2 = make_action("session-01", "file.write")

    graph.add_action(action_1)
    graph.add_action(action_2)
    graph.add_relationship(str(action_1.action_id), str(action_2.action_id), relation="causes")

    assert graph.edge_count() == 1
    assert graph.is_dag() is True
    assert graph.get_ancestors(str(action_2.action_id)) == [str(action_1.action_id)]
    assert graph.get_descendants(str(action_1.action_id)) == [str(action_2.action_id)]


def test_missing_parent_action_raises_error() -> None:
    """Verify attempting to link a non-existent parent action raises ParentActionNotFoundError."""
    graph = CausalExecutionGraph("session-01")
    action = make_action("session-01")
    graph.add_action(action)

    with pytest.raises(ParentActionNotFoundError):
        graph.add_relationship("non-existent-parent-id", str(action.action_id))


def test_session_graph_serialization() -> None:
    """Verify serialization output matches expected schema for API consumption."""
    graph = CausalExecutionGraph("session-serial")
    action = make_action("session-serial", "database.read")
    graph.add_action(action)
    graph.update_action_state(
        str(action.action_id),
        execution_status=ToolExecutionStatus.AUTHORIZED,
        policy_result=PolicyDecision.ALLOW,
        risk_score=0.1,
    )

    data = graph.get_session_graph()
    assert data["session_id"] == "session-serial"
    assert data["node_count"] == 1
    assert data["nodes"][0]["tool_name"] == "database.read"
    assert data["nodes"][0]["execution_status"] == "AUTHORIZED"
    assert data["nodes"][0]["policy_result"] == "ALLOW"


def test_session_graph_manager_isolation() -> None:
    """Verify multiple sessions remain isolated in the SessionGraphManager."""
    mgr = SessionGraphManager()
    g1 = mgr.get_or_create("sess-1")
    g2 = mgr.get_or_create("sess-2")

    a1 = make_action("sess-1")
    a2 = make_action("sess-2")

    g1.add_action(a1)
    g2.add_action(a2)
    mgr.register_action_session(str(a1.action_id), "sess-1")
    mgr.register_action_session(str(a2.action_id), "sess-2")

    assert g1.node_count() == 1
    assert g2.node_count() == 1
    assert mgr.get_action_globally(str(a1.action_id)) is not None
    assert mgr.get_action_globally(str(a2.action_id)) is not None
    assert mgr.get_action_globally(str(uuid4())) is None
