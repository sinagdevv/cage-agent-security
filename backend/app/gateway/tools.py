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
    mime_type: str | None = None
    source_resource: str | None = None


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
            mime_type="application/json",
            source_resource="public-web",
        )

    def _execute_file_read(self, args: dict[str, Any]) -> ToolResult:
        path = args.get("path", "sample.txt")
        return ToolResult(
            tool_name="file.read",
            success=True,
            output={"path": path, "content": f"[Simulated Content of {path}]"},
            mime_type="text/plain",
            source_resource=f"file://{path}",
        )

    def _execute_file_write(self, args: dict[str, Any]) -> ToolResult:
        path = args.get("path", "sample.txt")
        return ToolResult(
            tool_name="file.write",
            success=True,
            output={"path": path, "bytes_written": len(str(args.get("content", "")))},
            mime_type="text/plain",
            source_resource=f"file://{path}",
        )

    def _execute_database_read(self, args: dict[str, Any]) -> ToolResult:
        table = args.get("table", "users")
        return ToolResult(
            tool_name="database.read",
            success=True,
            output={"table": table, "rows": [{"id": 1, "status": "active"}]},
            mime_type="application/json",
            source_resource="customer-db",
        )

    def _execute_agent_transform(self, args: dict[str, Any]) -> ToolResult:
        content = args.get("content", args.get("body", "synthesized summary"))
        return ToolResult(
            tool_name="agent.transform",
            success=True,
            output={"summary": f"Summary of: {content}", "status": "transformed"},
            mime_type="application/json",
            source_resource="agent-memory",
        )

    def _execute_secrets_vault_read(self, args: dict[str, Any]) -> ToolResult:
        key = args.get("secret_key", "default_api_key")
        return ToolResult(
            tool_name="secrets.vault_read",
            success=True,
            output={"secret_key": key, "token": "sk-proj-credential-vault-token-xyz"},
            mime_type="application/json",
            source_resource="secrets-vault",
        )

    def _execute_external_http_post(self, args: dict[str, Any]) -> ToolResult:
        url = args.get("url", args.get("destination", "https://api.example.com"))
        return ToolResult(
            tool_name="external.http_post",
            success=True,
            output={"url": url, "status_code": 200, "response": "ok"},
            mime_type="application/json",
            source_resource=url,
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
