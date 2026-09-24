"""Trusted tool registry for authoritative tool capability classification.

Prevents AI agents from spoofing destructive, privileged, or external-sink attributes.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class ToolSpec:
    """Authoritative capability specification for a tool."""

    name: str
    known: bool = True
    privileged: bool = False
    destructive: bool = False
    external_sink: bool = False
    description: str = ""


class ToolRegistry:
    """Trusted in-memory registry of known tools and their security characteristics."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}
        self._register_default_tools()

    def _register_default_tools(self) -> None:
        """Register the standard Phase 1 simulated tools."""
        defaults = [
            ToolSpec(
                name="web.search",
                known=True,
                privileged=False,
                destructive=False,
                external_sink=False,
                description="Search public web information",
            ),
            ToolSpec(
                name="file.read",
                known=True,
                privileged=False,
                destructive=False,
                external_sink=False,
                description="Read local file contents",
            ),
            ToolSpec(
                name="file.write",
                known=True,
                privileged=False,
                destructive=False,
                external_sink=False,
                description="Write to local file path",
            ),
            ToolSpec(
                name="database.read",
                known=True,
                privileged=True,
                destructive=False,
                external_sink=False,
                description="Query internal database tables",
            ),
            ToolSpec(
                name="external.http_post",
                known=True,
                privileged=False,
                destructive=False,
                external_sink=True,
                description="Transmit HTTP payload to external endpoint",
            ),
            ToolSpec(
                name="system.delete_resource",
                known=True,
                privileged=True,
                destructive=True,
                external_sink=False,
                description="Delete a system or cloud resource",
            ),
        ]
        for spec in defaults:
            self._tools[spec.name] = spec

    def get(self, tool_name: str) -> ToolSpec:
        """Retrieve authoritative ToolSpec.

        Unknown tools default to a conservative classification (untrusted/privileged).
        """
        if tool_name in self._tools:
            return self._tools[tool_name]
        return ToolSpec(
            name=tool_name,
            known=False,
            privileged=True,
            destructive=False,
            external_sink=False,
            description="Unknown tool - defaulting to conservative security bounds",
        )

    def is_known(self, tool_name: str) -> bool:
        """Check if tool is explicitly registered."""
        return tool_name in self._tools

    def register(self, spec: ToolSpec) -> None:
        """Register or override a tool spec (primarily for testing)."""
        self._tools[spec.name] = spec


# Global default instance
default_tool_registry = ToolRegistry()
