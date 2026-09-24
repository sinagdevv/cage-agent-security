"""API integration tests for CAGE action evaluation and session graph endpoints."""

from uuid import uuid4

from fastapi.testclient import TestClient


def test_api_evaluate_action_allow(client: TestClient) -> None:
    """Verify POST /api/v1/actions/evaluate returns 200 and ALLOW for benign action."""
    session_id = f"api-sess-{uuid4().hex[:6]}"
    payload = {
        "agent_id": "test-agent",
        "session_id": session_id,
        "tool_name": "web.search",
        "tool_arguments": {"query": "CAGE architecture"},
        "target_environment": "LOCAL",
        "data_classifications": ["PUBLIC"],
    }

    response = client.post("/api/v1/actions/evaluate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "ALLOW"
    assert data["session_id"] == session_id
    assert "action_id" in data
    assert "matched_rules" in data


def test_api_evaluate_action_rejects_extra_fields(client: TestClient) -> None:
    """Verify that clients attempting to inject authoritative fields receive 422 Unprocessable Entity."""
    session_id = f"api-sess-{uuid4().hex[:6]}"
    payload = {
        "agent_id": "malicious-agent",
        "session_id": session_id,
        "tool_name": "system.delete_resource",
        "policy_result": "ALLOW",  # Injected field
    }

    response = client.post("/api/v1/actions/evaluate", json=payload)
    assert response.status_code == 422


def test_api_evaluate_action_rejects_missing_parent(client: TestClient) -> None:
    """Verify that referencing an unrecorded parent returns 400 Bad Request."""
    session_id = f"api-sess-{uuid4().hex[:6]}"
    payload = {
        "agent_id": "child-agent",
        "session_id": session_id,
        "tool_name": "file.read",
        "parent_action_id": str(uuid4()),
    }

    response = client.post("/api/v1/actions/evaluate", json=payload)
    assert response.status_code == 400
    assert "not found in session" in response.json()["detail"]


def test_api_get_action_and_session_graph(client: TestClient) -> None:
    """Verify GET /actions/{action_id} and GET /sessions/{session_id}/graph."""
    session_id = f"api-sess-{uuid4().hex[:6]}"
    # 1. Post action
    payload = {
        "agent_id": "explorer",
        "session_id": session_id,
        "tool_name": "database.read",
        "tool_arguments": {"table": "customers"},
        "target_environment": "DEVELOPMENT",
    }
    eval_resp = client.post("/api/v1/actions/evaluate", json=payload)
    assert eval_resp.status_code == 200
    action_id = eval_resp.json()["action_id"]

    # 2. Get action by ID
    action_resp = client.get(f"/api/v1/actions/{action_id}")
    assert action_resp.status_code == 200
    action_data = action_resp.json()
    assert action_data["action_id"] == action_id
    assert action_data["tool_name"] == "database.read"
    assert action_data["policy_result"] == "ALLOW"

    # 3. Get session graph
    graph_resp = client.get(f"/api/v1/sessions/{session_id}/graph")
    assert graph_resp.status_code == 200
    graph_data = graph_resp.json()
    assert graph_data["session_id"] == session_id
    assert graph_data["node_count"] == 1
    assert graph_data["is_dag"] is True


def test_api_get_nonexistent_action_returns_404(client: TestClient) -> None:
    """Verify GET /actions/{action_id} returns 404 for unknown action."""
    random_id = str(uuid4())
    response = client.get(f"/api/v1/actions/{random_id}")
    assert response.status_code == 404


def test_api_get_nonexistent_session_graph_returns_404(client: TestClient) -> None:
    """Verify GET /sessions/{session_id}/graph returns 404 for unknown session."""
    response = client.get("/api/v1/sessions/non-existent-session/graph")
    assert response.status_code == 404
