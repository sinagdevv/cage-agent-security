"""Tests for AgentPrincipal models and principal provider boundaries."""

from uuid import uuid4

import pytest
from fastapi import Request

from app.api.deps import DefaultProductionPrincipalProvider
from app.identity.principal import (
    AgentPrincipal,
    DevelopmentHeaderPrincipalProvider,
    PrincipalAuthenticationSource,
    TrustedTestPrincipalProvider,
)


def _make_dummy_request(
    headers: dict[str, str], state_principal: AgentPrincipal | None = None
) -> Request:
    """Create a dummy Starlette Request with specific headers and optional state principal."""
    header_list = [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in headers.items()]
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/v1/delegations",
        "headers": header_list,
    }
    request = Request(scope)
    if state_principal:
        request.state.agent_principal = state_principal
    return request


def test_agent_principal_immutability():
    """AgentPrincipal must be deeply frozen and reject direct attribute mutation."""
    p = AgentPrincipal(
        agent_id="agent-alice",
        session_id=uuid4(),
        authentication_source=PrincipalAuthenticationSource.TEST_FIXTURE,
        is_control_plane=False,
    )
    with pytest.raises((TypeError, AttributeError, ValueError)):
        p.agent_id = "agent-bob"  # type: ignore[misc]

    with pytest.raises((TypeError, AttributeError, ValueError)):
        p.is_control_plane = True  # type: ignore[misc]


def test_production_provider_rejects_unauthenticated_headers():
    """Default production provider must reject raw client spoofing headers with 401 Unauthorized."""
    provider = DefaultProductionPrincipalProvider()
    req = _make_dummy_request(
        {
            "X-CAGE-Control-Plane": "true",
            "X-CAGE-Agent-ID": "admin-spoofed",
            "X-CAGE-Session-ID": str(uuid4()),
        }
    )

    with pytest.raises(Exception) as exc_info:
        provider.get_principal(req)
    assert "401" in str(exc_info.value) or "No trusted agent principal context" in str(
        exc_info.value
    )


def test_production_provider_accepts_runtime_injected_state():
    """Production provider retrieves principal if supplied by trusted hosting runtime state."""
    session_id = uuid4()
    trusted = AgentPrincipal(
        agent_id="agent-alice",
        session_id=session_id,
        authentication_source=PrincipalAuthenticationSource.HOSTING_RUNTIME,
        is_control_plane=False,
    )
    req = _make_dummy_request({}, state_principal=trusted)
    provider = DefaultProductionPrincipalProvider()
    p = provider.get_principal(req)
    assert p.agent_id == "agent-alice"
    assert p.session_id == session_id
    assert not p.is_control_plane


def test_trusted_test_provider():
    """TrustedTestPrincipalProvider returns the injected principal deterministically."""
    session_id = uuid4()
    principal = AgentPrincipal(
        agent_id="test-control-plane",
        session_id=session_id,
        authentication_source=PrincipalAuthenticationSource.TEST_FIXTURE,
        is_control_plane=True,
    )
    provider = TrustedTestPrincipalProvider(principal)
    req = _make_dummy_request({})
    resolved = provider.get_principal(req)
    assert resolved == principal
    assert resolved.is_control_plane is True


def test_dev_header_provider_disabled_by_default():
    """DevelopmentHeaderPrincipalProvider must fail closed if allow_dev_mode is False."""
    with pytest.raises(RuntimeError) as exc_info:
        DevelopmentHeaderPrincipalProvider(allow_dev_mode=False, environment="development")
    assert "prohibited" in str(exc_info.value).lower()


def test_dev_header_provider_rejected_in_production():
    """DevelopmentHeaderPrincipalProvider must fail closed if environment is production."""
    with pytest.raises(RuntimeError) as exc_info:
        DevelopmentHeaderPrincipalProvider(allow_dev_mode=True, environment="production")
    assert "prohibited" in str(exc_info.value).lower()


def test_dev_header_provider_simulation_in_dev_mode():
    """In allowed non-production mode, development simulation parses dev-prefixed headers."""
    session_id = uuid4()
    provider = DevelopmentHeaderPrincipalProvider(allow_dev_mode=True, environment="development")
    req = _make_dummy_request(
        {
            "X-CAGE-Dev-Agent-ID": "dev-agent-1",
            "X-CAGE-Dev-Session-ID": str(session_id),
            "X-CAGE-Dev-Control-Plane": "true",
        }
    )
    p = provider.get_principal(req)
    assert p.agent_id == "dev-agent-1"
    assert p.session_id == session_id
    assert p.is_control_plane is True
    assert p.authentication_source == PrincipalAuthenticationSource.DEV_SIMULATED
