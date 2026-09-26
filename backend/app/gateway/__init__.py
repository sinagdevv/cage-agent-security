"""Gateway module for intercepting, mediating, and proxying agent tool calls."""

from typing import Any

from app.gateway.registry import ToolRegistry, ToolSpec, default_tool_registry
from app.gateway.tools import (
    ToolExecutor,
    ToolRequest,
    ToolResult,
    UnauthorizedExecutionError,
    default_tool_executor,
)

__all__ = [
    "AgentGateway",
    "ToolExecutor",
    "ToolRegistry",
    "ToolRequest",
    "ToolResult",
    "ToolSpec",
    "UnauthorizedExecutionError",
    "default_agent_gateway",
    "default_tool_executor",
    "default_tool_registry",
]


def __getattr__(name: str) -> Any:
    if name in ("AgentGateway", "default_agent_gateway"):
        from app.gateway import service

        if name == "AgentGateway":
            return service.AgentGateway
        return service.default_agent_gateway
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
