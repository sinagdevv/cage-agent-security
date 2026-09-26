"""FastAPI dependency providers for authentication, delegation, and governance services."""

from typing import Annotated

from fastapi import Depends, HTTPException, Request, status

from app.core.config import settings
from app.delegation.service import DelegationService, default_delegation_service
from app.identity.principal import (
    AgentPrincipal,
    AgentPrincipalProvider,
    DevelopmentHeaderPrincipalProvider,
)


class DefaultProductionPrincipalProvider:
    """Production principal provider expecting pre-authenticated gateway context.

    Rejects unauthenticated callers and does NOT trust raw spoofable headers.
    """

    def get_principal(self, request: Request) -> AgentPrincipal:
        # In a real hosting runtime, the gateway or reverse proxy injects authenticated context
        # into request.state. Raw headers are NOT trusted.
        principal = getattr(request.state, "agent_principal", None)
        if principal is not None and isinstance(principal, AgentPrincipal):
            return principal

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No trusted agent principal context found in hosting runtime.",
        )


def get_principal_provider() -> AgentPrincipalProvider:
    """Resolve active principal provider based on environment configuration."""
    if settings.debug and settings.environment.lower() != "production":
        return DevelopmentHeaderPrincipalProvider(
            allow_dev_mode=True,
            environment=settings.environment,
        )
    return DefaultProductionPrincipalProvider()


def get_agent_principal(
    request: Request,
    provider: Annotated[AgentPrincipalProvider, Depends(get_principal_provider)],
) -> AgentPrincipal:
    """FastAPI dependency extracting trusted AgentPrincipal from runtime provider."""
    return provider.get_principal(request)


def get_delegation_service() -> DelegationService:
    """FastAPI dependency for DelegationService singleton."""
    return default_delegation_service
