"""Gateway module for intercepting, mediating, and proxying agent tool calls."""

from app.gateway.registry import ToolRegistry, ToolSpec, default_tool_registry
from app.gateway.service import AgentGateway, default_agent_gateway
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
