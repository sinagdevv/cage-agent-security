"""Unit tests for OpaClient transport, schema validation, and fail-closed handling."""

from unittest.mock import MagicMock
from uuid import uuid4

import httpx
import pytest

from app.gateway.registry import default_tool_registry
from app.policies.opa_client import OpaClient
from app.policies.policy_input import build_cage_policy_input
from app.schemas.action import AgentAction
from app.schemas.enums import (
    ActionType,
    OpaStatus,
    PolicyDecision,
    TargetEnvironment,
    TrustLevel,
)


@pytest.fixture
def sample_policy_input():
    action = AgentAction(
        action_id=uuid4(),
        agent_id="test-agent",
        session_id="test-session",
        tool_name="web.search",
        action_type=ActionType.TOOL_CALL,
        target_environment=TargetEnvironment.DEVELOPMENT,
        input_trust_level=TrustLevel.MEDIUM,
    )
    return build_cage_policy_input(
        action=action,
        contract=None,
        tool_registry=default_tool_registry,
        require_intent=False,
    )


def test_opa_client_valid_response(sample_policy_input) -> None:
    """Verify OpaClient correctly parses valid structured OPA findings."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "result": {
            "findings": [
                {
                    "rule_id": "RULE_INTENT_ALLOW",
                    "decision": "ALLOW",
                    "reason": "Permitted by intent contract.",
                    "risk_score": 0.1,
                }
            ]
        }
    }

    mock_http = MagicMock()
    mock_http.post.return_value = mock_resp

    client = OpaClient(client=mock_http)
    result = client.evaluate(sample_policy_input)

    assert result.status == OpaStatus.SUCCESS
    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "RULE_INTENT_ALLOW"
    assert result.findings[0].decision == PolicyDecision.ALLOW
    assert result.findings[0].risk_score == 0.1
    assert result.error_reason is None


def test_opa_client_timeout(sample_policy_input) -> None:
    """Verify timeout produces TIMEOUT status without synthesizing fake findings."""
    mock_http = MagicMock()
    mock_http.post.side_effect = httpx.TimeoutException("Timed out")

    client = OpaClient(client=mock_http)
    result = client.evaluate(sample_policy_input)

    assert result.status == OpaStatus.TIMEOUT
    assert result.findings == []
    assert "timed out" in (result.error_reason or "").lower()


def test_opa_client_connection_error(sample_policy_input) -> None:
    """Verify connection refusal produces UNAVAILABLE status."""
    mock_http = MagicMock()
    mock_http.post.side_effect = httpx.ConnectError("Connection refused")

    client = OpaClient(client=mock_http)
    result = client.evaluate(sample_policy_input)

    assert result.status == OpaStatus.UNAVAILABLE
    assert result.findings == []
    assert "refused" in (result.error_reason or "").lower()


def test_opa_client_http_500(sample_policy_input) -> None:
    """Verify HTTP 500 produces EVALUATION_ERROR."""
    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_resp.text = "Internal Server Error"

    mock_http = MagicMock()
    mock_http.post.return_value = mock_resp

    client = OpaClient(client=mock_http)
    result = client.evaluate(sample_policy_input)

    assert result.status == OpaStatus.EVALUATION_ERROR
    assert result.findings == []
    assert "500" in (result.error_reason or "")


def test_opa_client_malformed_json(sample_policy_input) -> None:
    """Verify non-JSON response produces INVALID_RESPONSE status."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.side_effect = ValueError("Invalid JSON")

    mock_http = MagicMock()
    mock_http.post.return_value = mock_resp

    client = OpaClient(client=mock_http)
    result = client.evaluate(sample_policy_input)

    assert result.status == OpaStatus.INVALID_RESPONSE
    assert result.findings == []


def test_opa_client_empty_findings_treated_as_invalid(sample_policy_input) -> None:
    """Verify empty findings list is treated as INVALID_RESPONSE per Requirement 9."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"result": {"findings": []}}

    mock_http = MagicMock()
    mock_http.post.return_value = mock_resp

    client = OpaClient(client=mock_http)
    result = client.evaluate(sample_policy_input)

    assert result.status == OpaStatus.INVALID_RESPONSE
    assert result.findings == []
    assert "empty findings" in (result.error_reason or "").lower()


def test_opa_client_unknown_decision_rejected(sample_policy_input) -> None:
    """Verify unknown PolicyDecision in finding causes INVALID_RESPONSE."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "result": {
            "findings": [
                {
                    "rule_id": "RULE_TEST",
                    "decision": "UNRECOGNIZED_VERDICT",
                    "reason": "Test",
                    "risk_score": 0.5,
                }
            ]
        }
    }

    mock_http = MagicMock()
    mock_http.post.return_value = mock_resp

    client = OpaClient(client=mock_http)
    result = client.evaluate(sample_policy_input)

    assert result.status == OpaStatus.INVALID_RESPONSE
    assert result.findings == []


def test_opa_client_risk_score_bounds_rejected(sample_policy_input) -> None:
    """Verify out-of-bounds risk score causes INVALID_RESPONSE."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "result": {
            "findings": [
                {
                    "rule_id": "RULE_TEST",
                    "decision": "DENY",
                    "reason": "Test",
                    "risk_score": 1.5,  # Exceeds 1.0
                }
            ]
        }
    }

    mock_http = MagicMock()
    mock_http.post.return_value = mock_resp

    client = OpaClient(client=mock_http)
    result = client.evaluate(sample_policy_input)

    assert result.status == OpaStatus.INVALID_RESPONSE
    assert result.findings == []


def test_opa_client_check_health() -> None:
    """Verify check_health queries OPA health endpoint."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200

    mock_http = MagicMock()
    mock_http.get.return_value = mock_resp

    client = OpaClient(client=mock_http)
    assert client.check_health() is True

    mock_http.get.side_effect = httpx.ConnectError("down")
    assert client.check_health() is False
