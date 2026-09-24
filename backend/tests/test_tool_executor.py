"""Tests for ToolExecutor safe simulation and authorization validation."""

from uuid import uuid4

import pytest

from app.gateway.tools import ToolExecutor, ToolRequest, UnauthorizedExecutionError
from app.schemas.decision import SecurityDecision
from app.schemas.enums import PolicyDecision


def make_decision(decision: PolicyDecision) -> SecurityDecision:
    return SecurityDecision(
        action_id=uuid4(),
        session_id="test-exec-session",
        decision=decision,
        reason=f"Test verdict: {decision.value}",
    )


def test_executor_allows_execution_on_allow_decision() -> None:
    """Verify tool executes when decision is ALLOW."""
    executor = ToolExecutor()
    req = ToolRequest(
        tool_name="web.search",
        arguments={"query": "test query"},
        action_id=uuid4(),
        session_id="test-exec-session",
    )
    decision = make_decision(PolicyDecision.ALLOW)
    result = executor.execute(req, decision)
    assert result.success is True
    assert result.simulated is True
    assert "query" in result.output


def test_executor_blocks_execution_on_require_approval() -> None:
    """Verify tool execution is blocked when decision is REQUIRE_APPROVAL."""
    executor = ToolExecutor()
    req = ToolRequest(
        tool_name="system.delete_resource",
        arguments={"resource_id": "test-res"},
        action_id=uuid4(),
        session_id="test-exec-session",
    )
    decision = make_decision(PolicyDecision.REQUIRE_APPROVAL)
    with pytest.raises(UnauthorizedExecutionError):
        executor.execute(req, decision)


def test_executor_blocks_execution_on_deny() -> None:
    """Verify tool execution is blocked when decision is DENY."""
    executor = ToolExecutor()
    req = ToolRequest(
        tool_name="external.http_post",
        arguments={"url": "https://malicious.sink"},
        action_id=uuid4(),
        session_id="test-exec-session",
    )
    decision = make_decision(PolicyDecision.DENY)
    with pytest.raises(UnauthorizedExecutionError):
        executor.execute(req, decision)


def test_simulated_tools_behavior() -> None:
    """Verify standard tool implementations produce expected simulated payloads."""
    executor = ToolExecutor()
    decision = make_decision(PolicyDecision.ALLOW)

    tools_to_test = [
        ("file.read", {"path": "config.yaml"}),
        ("file.write", {"path": "out.txt", "content": "hello"}),
        ("database.read", {"table": "logs"}),
        ("external.http_post", {"url": "https://api.test"}),
        ("system.delete_resource", {"resource_id": "res-1"}),
    ]

    for tool_name, args in tools_to_test:
        req = ToolRequest(
            tool_name=tool_name,
            arguments=args,
            action_id=uuid4(),
            session_id="test-exec-session",
        )
        res = executor.execute(req, decision)
        assert res.success is True
        assert res.simulated is True
