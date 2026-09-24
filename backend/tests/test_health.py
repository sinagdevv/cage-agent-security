"""Tests for health and root endpoints."""

from fastapi.testclient import TestClient


def test_root_endpoint(client: TestClient) -> None:
    """Verify that root endpoint returns engine info and links."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["engine"] == "CAGE"
    assert "version" in data
    assert data["health"] == "/api/v1/health"


def test_health_check_endpoint(client: TestClient) -> None:
    """Verify that health check returns ok status and engine identifier."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["engine"] == "CAGE"
    assert "version" in data
    assert "environment" in data
