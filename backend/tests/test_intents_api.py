"""API tests for Intent Contract control-plane endpoints."""

from uuid import uuid4

from fastapi.testclient import TestClient


def test_api_create_and_get_intent(client: TestClient) -> None:
    """Verify POST /api/v1/intents creates contract and GET retrieves it."""
    session_id = f"api-sess-{uuid4().hex[:6]}"
    payload = {
        "agent_id": "api-agent",
        "session_id": session_id,
        "goal": "Test API intent creation",
        "allowed_tools": ["web.search", "file.read"],
        "maximum_tool_calls": 10,
    }
    headers = {"X-CAGE-Control-Plane": "trusted-admin"}
    create_resp = client.post("/api/v1/intents", json=payload, headers=headers)
    assert create_resp.status_code == 201
    contract = create_resp.json()
    intent_id = contract["intent_id"]
    assert contract["agent_id"] == "api-agent"
    assert contract["status"] == "ACTIVE"

    # GET /intents/{id}
    get_resp = client.get(f"/api/v1/intents/{intent_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["intent_id"] == intent_id


def test_api_second_active_intent_for_session_returns_409(client: TestClient) -> None:
    """Verify attempting to create a second active intent for the same session returns 409 Conflict."""
    session_id = f"api-sess-{uuid4().hex[:6]}"
    payload = {
        "agent_id": "api-agent",
        "session_id": session_id,
        "goal": "First intent",
        "allowed_tools": ["web.search"],
    }
    headers = {"X-CAGE-Control-Plane": "trusted-admin"}
    res1 = client.post("/api/v1/intents", json=payload, headers=headers)
    assert res1.status_code == 201

    # Second attempt
    res2 = client.post("/api/v1/intents", json=payload, headers=headers)
    assert res2.status_code == 409


def test_api_revoke_intent(client: TestClient) -> None:
    """Verify POST /api/v1/intents/{id}/revoke revokes contract."""
    session_id = f"api-sess-{uuid4().hex[:6]}"
    headers = {"X-CAGE-Control-Plane": "trusted-admin"}
    create_resp = client.post(
        "/api/v1/intents",
        json={
            "agent_id": "api-agent",
            "session_id": session_id,
            "goal": "Revoke target",
            "allowed_tools": ["web.search"],
        },
        headers=headers,
    )
    intent_id = create_resp.json()["intent_id"]

    revoke_resp = client.post(
        f"/api/v1/intents/{intent_id}/revoke",
        json={"reason": "Security review cancellation"},
        headers=headers,
    )
    assert revoke_resp.status_code == 200
    assert revoke_resp.json()["status"] == "REVOKED"


def test_api_narrow_intent_success_and_expansion_rejected(client: TestClient) -> None:
    """Verify POST /api/v1/intents/{id}/narrow accepts reduction and rejects expansion."""
    session_id = f"api-sess-{uuid4().hex[:6]}"
    headers = {"X-CAGE-Control-Plane": "trusted-admin"}
    create_resp = client.post(
        "/api/v1/intents",
        json={
            "agent_id": "api-agent",
            "session_id": session_id,
            "goal": "Narrow target",
            "allowed_tools": ["web.search", "file.read"],
            "maximum_tool_calls": 10,
        },
        headers=headers,
    )
    intent_id = create_resp.json()["intent_id"]

    # Valid narrowing: reduce tools to ["web.search"]
    narrow_resp = client.post(
        f"/api/v1/intents/{intent_id}/narrow",
        json={"allowed_tools": ["web.search"]},
        headers=headers,
    )
    assert narrow_resp.status_code == 200
    assert narrow_resp.json()["allowed_tools"] == ["web.search"]

    # Invalid expansion: attempt to add "system.delete_resource"
    expand_resp = client.post(
        f"/api/v1/intents/{intent_id}/narrow",
        json={"allowed_tools": ["web.search", "system.delete_resource"]},
        headers=headers,
    )
    assert expand_resp.status_code == 400
    assert "Cannot expand" in expand_resp.json()["detail"]
