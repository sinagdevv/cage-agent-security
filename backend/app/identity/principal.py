"""Authoritative AgentPrincipal models and provider boundaries for CAGE Phase 8.

CAGE Phase 8 consumes a trusted AgentPrincipal supplied by the hosting runtime.
Phase 8 does not itself authenticate external callers or provide an identity provider.
Development principal simulation is not production authentication.
"""

from enum import StrEnum
from typing import Protocol
from uuid import UUID

from fastapi import Request
from pydantic import BaseModel, ConfigDict


class PrincipalAuthenticationSource(StrEnum):
    """Source of principal authentication context."""

    HOSTING_RUNTIME = "HOSTING_RUNTIME"
    TEST_FIXTURE = "TEST_FIXTURE"
    INTERNAL_GATEWAY = "INTERNAL_GATEWAY"
    DEV_SIMULATED = "DEV_SIMULATED"


class AgentPrincipal(BaseModel):
    """Server-authoritative authenticated principal identity.

    Immutable. Never constructed from unvalidated request bodies.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    agent_id: str
    session_id: UUID
    authentication_source: PrincipalAuthenticationSource
    is_control_plane: bool = False


class AgentPrincipalProvider(Protocol):
    """Protocol for extracting trusted principal context from hosting runtime."""

    def get_principal(self, request: Request) -> AgentPrincipal:
        """Resolve authoritative principal for the request context."""
        ...


class TrustedTestPrincipalProvider:
    """Explicit test fixture provider for deterministic test suites."""

    def __init__(self, principal: AgentPrincipal):
        self._principal = principal

    def get_principal(self, request: Request) -> AgentPrincipal:
        return self._principal


class DevelopmentHeaderPrincipalProvider:
    """Simulated principal provider for local development only.

    Strictly disabled by default and forbidden in production mode.
    """

    def __init__(
        self,
        allow_dev_mode: bool = False,
        environment: str = "production",
    ):
        if not allow_dev_mode or environment.lower() == "production":
            raise RuntimeError(
                "DevelopmentHeaderPrincipalProvider is strictly prohibited in production mode "
                "or when development simulation is disabled."
            )
        self._allow_dev_mode = allow_dev_mode
        self._environment = environment

    def get_principal(self, request: Request) -> AgentPrincipal:
        # Development simulation only - raw headers are never trusted in production
        agent_id = request.headers.get("X-CAGE-Dev-Agent-ID", "dev-agent")
        session_id_str = request.headers.get("X-CAGE-Dev-Session-ID")
        is_control_plane = (
            request.headers.get("X-CAGE-Dev-Control-Plane", "false").lower() == "true"
        )

        session_id = (
            UUID(session_id_str) if session_id_str else UUID("00000000-0000-0000-0000-000000000000")
        )

        return AgentPrincipal(
            agent_id=agent_id,
            session_id=session_id,
            authentication_source=PrincipalAuthenticationSource.DEV_SIMULATED,
            is_control_plane=is_control_plane,
        )
