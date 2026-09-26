"""Security and functional tests for FastAPI delegations API router."""

from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.api.deps import get_agent_principal, get_delegation_service
from app.delegation.service import DelegationService
from app.identity.principal import AgentPrincipal, PrincipalAuthenticationSource
from app.intent.service import IntentService
from app.main import app
from app.schemas.enums import DataClassification, TargetEnvironment
from app.schemas.intent import IntentContractCreate


@pytest.fixture
def api_test_env():
    intent_service = IntentService()
    delegation_service = DelegationService(intent_service=intent_service)
    session_id = uuid4()
    session_str = str(session_id)

    # Create root Intent
    intent_service.create_intent(
        IntentContractCreate(
            session_id=session_str,
            agent_id="root-agent",
            user_id="user-1",
            goal="API test goal",
            allowed_tools=["web.search", "db.read"],
            allowed_environments=[TargetEnvironment.DEVELOPMENT],
            allowed_resources=["res://1"],
            allowed_data_classifications=[DataClassification.PUBLIC],
            maximum_tool_calls=50,
        )
    )

    trusted_root = AgentPrincipal(
        agent_id="root-agent",
        session_id=session_id,
        authentication_source=PrincipalAuthenticationSource.TEST_FIXTURE,
        is_control_plane=False,
    )

    app.dependency_overrides[get_agent_principal] = lambda: trusted_root
    app.dependency_overrides[get_delegation_service] = lambda: delegation_service

    client = TestClient(app)
    yield {
        "client": client,
        "session_id": session_id,
        "delegation_service": delegation_service,
        "trusted_root": trusted_root,
    }
    app.dependency_overrides.clear()


def test_api_create_delegation_success(api_test_env):
    client = api_test_env["client"]
    session_id = str(api_test_env["session_id"])

    payload = {
        "session_id": session_id,
        "delegator_agent_id": "root-agent",
        "delegatee_agent_id": "worker-1",
        "delegated_task_id": "task-api-1",
        "requested_tools": ["web.search"],
        "requested_environments": ["DEVELOPMENT"],
        "requested_classifications": ["PUBLIC"],
        "requested_resource_scope": {
            "mode": "ALLOWLIST",
            "allowed_resources": ["res://1"],
        },
        "requested_max_actions": 5,
        "allow_subdelegation": True,
    }

    res = client.post("/api/v1/delegations", json=payload)
    assert res.status_code == 201
    data = res.json()
    assert data["decision"] == "ALLOW"
    assert data["delegation_id"] is not None
    assert data["status"] == "ACTIVE"


def test_api_body_cannot_spoof_control_plane(api_test_env):
    """Sending is_control_plane in proposal body is rejected by Pydantic extra=forbid."""
    client = api_test_env["client"]
    session_id = str(api_test_env["session_id"])

    payload = {
        "session_id": session_id,
        "delegator_agent_id": "root-agent",
        "delegatee_agent_id": "worker-1",
        "delegated_task_id": "task-api-1",
        "requested_tools": ["web.search"],
        "requested_environments": ["DEVELOPMENT"],
        "requested_classifications": ["PUBLIC"],
        "is_control_plane": True,  # Extra field attempt
    }

    res = client.post("/api/v1/delegations", json=payload)
    assert res.status_code == 422  # Validation error


def test_api_delegator_mismatch_denied(api_test_env):
    """Claiming delegator_agent_id != authenticated principal returns 403."""
    client = api_test_env["client"]
    session_id = str(api_test_env["session_id"])

    payload = {
        "session_id": session_id,
        "delegator_agent_id": "different-agent",  # Mismatch with root-agent
        "delegatee_agent_id": "worker-1",
        "delegated_task_id": "task-api-1",
        "requested_tools": ["web.search"],
        "requested_environments": ["DEVELOPMENT"],
        "requested_classifications": ["PUBLIC"],
    }

    res = client.post("/api/v1/delegations", json=payload)
    assert res.status_code == 403
    data = res.json()
    assert data["decision"] == "DENY"
    assert "RULE_DELEGATION_CALLER_NOT_AUTHORIZED" in data["matched_rules"]
