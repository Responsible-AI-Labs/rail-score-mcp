"""Per-request context for the stateless MCP gateway.

The auth middleware validates the incoming RAIL key once per HTTP request and
stashes the credential plus the resolved tenant here. Tool functions read the
tenant from this context, never from tool parameters (Section 5, item 5:
tenant isolation by construction). ContextVars propagate into the threadpool
that runs synchronous tool callables, so this is safe for both async and sync
tools.
"""
from __future__ import annotations

from contextvars import ContextVar
from typing import Any

# The validated `rail_*` API key for the current request. Phase 1 forwards this
# same credential upstream so per-tenant credits and isolation are preserved by
# the existing REST auth. Phase 2 (OAuth) replaces this with a validated token
# plus a service credential and on-behalf-of header.
current_key: ContextVar[str | None] = ContextVar("current_key", default=None)

# Resolved identity from POST /verify: {org_id, plan, email, ...}. Never
# trusted from tool input.
current_tenant: ContextVar[dict[str, Any] | None] = ContextVar(
    "current_tenant", default=None
)

# Correlation id propagated to every upstream call (X-Request-ID).
current_request_id: ContextVar[str | None] = ContextVar(
    "current_request_id", default=None
)


class AuthRequired(Exception):
    """Raised inside a tool when no validated tenant is bound to the request."""
