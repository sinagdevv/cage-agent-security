"""Safe simulated tool execution abstraction for Phase 1 demonstration.

Never connects to real external or destructive infrastructure.
Enforces that tools can only execute if the authorization decision is explicitly ALLOW.
"""

from dataclasses import dataclass
from typing import Any
from uuid import UUID

from app.schemas.decision import SecurityDecision
from app.schemas.enums import PolicyDecision


class UnauthorizedExecutionError(PermissionError):
    """Raised when an attempt is made to execute a tool without explicit ALLOW authorization."""


@dataclass(frozen=True)
class ToolRequest:
    """Request payload for tool execution."""

    tool_name: str
    arguments: dict[str, Any]
    action_id: UUID
    session_id: str


@dataclass(frozen=True)
class ToolResult:
    """Outcome of a tool execution."""

    tool_name: str
    success: bool
    output: Any
    error: str | None = None
    simulated: bool = True


class ToolExecutor:
    """Simulated safe tool execution engine."""

    def execute(self, request: ToolRequest, decision: SecurityDecision) -> ToolResult:
        """Execute a tool request strictly after validating the security decision."""
        if decision.decision != PolicyDecision.ALLOW:
            raise UnauthorizedExecutionError(
                f"Tool '{request.tool_name}' execution prohibited. "
                f"Decision was {decision.decision.value} ({decision.reason})."
            )

        handler = getattr(self, f"_execute_{request.tool_name.replace('.', '_')}", None)
        if handler is None:
            return ToolResult(
                tool_name=request.tool_name,
                success=True,
                output={"status": "simulated_success", "args": request.arguments},
            )

        return handler(request.arguments)

    def _execute_web_search(self, args: dict[str, Any]) -> ToolResult:
        query = args.get("query", "")
        return ToolResult(
            tool_name="web.search",
            success=True,
            output={
                "query": query,
                "results": [
                    {
                        "title": f"Public research on {query}",
                        "snippet": f"Verified public overview of {query}.",
                    }
                ],
            },
        )

    def _execute_file_read(self, args: dict[str, Any]) -> ToolResult:
        path = args.get("path", "sample.txt")
        return ToolResult(
            tool_name="file.read",
            success=True,
            output={"path": path, "content": f"[Simulated Content of {path}]"},
        )

    def _execute_file_write(self, args: dict[str, Any]) -> ToolResult:
        path = args.get("path", "sample.txt")
        return ToolResult(
            tool_name="file.write",
            success=True,
            output={"path": path, "bytes_written": len(str(args.get("content", "")))},
        )

    def _execute_database_read(self, args: dict[str, Any]) -> ToolResult:
        table = args.get("table", "users")
        return ToolResult(
            tool_name="database.read",
            success=True,
            output={"table": table, "rows": [{"id": 1, "status": "active"}]},
        )

    def _execute_external_http_post(self, args: dict[str, Any]) -> ToolResult:
        url = args.get("url", "https://api.example.com")
        return ToolResult(
            tool_name="external.http_post",
            success=True,
            output={"url": url, "status_code": 200, "response": "ok"},
        )

    def _execute_system_delete_resource(self, args: dict[str, Any]) -> ToolResult:
        res_id = args.get("resource_id", "default")
        return ToolResult(
            tool_name="system.delete_resource",
            success=True,
            output={"resource_id": res_id, "deleted": True},
        )


# Global default executor
default_tool_executor = ToolExecutor()
