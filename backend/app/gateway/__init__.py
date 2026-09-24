"""Gateway module for intercepting, mediating, and proxying agent tool calls.

This layer acts as the primary reverse proxy between autonomous agents
and external tools/services (e.g., Model Context Protocol servers).
Tool invocations are paused here pending causal graph evaluation and policy decisions.
"""
