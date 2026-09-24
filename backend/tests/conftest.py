"""Pytest configuration and fixtures for CAGE tests."""

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture
def client() -> TestClient:
    """Fixture providing a test client for FastAPI application."""
    return TestClient(app)
