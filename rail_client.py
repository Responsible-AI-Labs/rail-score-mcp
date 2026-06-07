"""Thin HTTP client for the RAIL Score REST API.

This is the gateway's only path to scoring logic. It forwards the validated
per-request `rail_*` key upstream (phase 1) and propagates the correlation id
on every call. It never logs request bodies or detected PII (Section 5,
item 10 / hard constraint 4).
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

import config
from request_context import (
    AuthRequired,
    current_key,
    current_request_id,
)

logger = logging.getLogger("rail-mcp.client")

# Reused connection pool. The per-request credential is injected per call, so a
# single shared client is safe across tenants.
_client = httpx.Client(
    base_url=config.RAIL_API_BASE,
    timeout=config.UPSTREAM_TIMEOUT,
    headers={"User-Agent": "rail-mcp-server/1.0"},
)


class UpstreamError(Exception):
    """A non-2xx response from the REST API, surfaced as a structured error."""

    def __init__(self, status: int, code: str, message: str):
        self.status = status
        self.code = code
        self.message = message
        super().__init__(f"{status} {code}: {message}")


def _auth_headers() -> dict[str, str]:
    key = current_key.get()
    if not key:
        # Should be unreachable: middleware rejects unauthenticated /mcp calls.
        raise AuthRequired("no validated RAIL key bound to this request")
    headers = {"Authorization": f"Bearer {key}"}
    rid = current_request_id.get()
    if rid:
        headers["X-Request-ID"] = rid
    return headers


def _handle(
    resp: httpx.Response, allow_statuses: frozenset[int] = frozenset()
) -> dict[str, Any]:
    try:
        body = resp.json()
    except ValueError:
        body = {}
    # Some endpoints encode a valid verdict in a non-2xx status (tool-call BLOCK
    # -> 403, safe-regenerate critical-content -> 422). Callers opt in to treat
    # those as data, not errors.
    if resp.is_success or resp.status_code in allow_statuses:
        return body
    # Surface the upstream error code/message without leaking internals.
    code = body.get("code") or f"HTTP_{resp.status_code}"
    message = body.get("error") or resp.reason_phrase or "upstream error"
    logger.warning("upstream %s on %s -> %s", resp.status_code, resp.url.path, code)
    raise UpstreamError(resp.status_code, code, message)


def verify(key: str, request_id: str | None = None) -> dict[str, Any] | None:
    """Validate a key against POST /verify. Returns identity or None if rejected.

    Used by the auth middleware. Does not consume credits.
    """
    headers = {"Authorization": f"Bearer {key}"}
    if request_id:
        headers["X-Request-ID"] = request_id
    try:
        resp = _client.post("/verify", headers=headers, json={})
    except httpx.HTTPError as e:
        logger.error("verify call failed: %s", e)
        # Fail closed: a verification outage must not grant access.
        return None
    if resp.status_code in (401, 403):
        return None
    if not resp.is_success:
        logger.error("verify returned %s", resp.status_code)
        return None
    body = resp.json()
    return body if body.get("valid") else None


def post(
    path: str,
    payload: dict[str, Any],
    allow_statuses: frozenset[int] = frozenset(),
) -> dict[str, Any]:
    """POST to a REST endpoint with the request's RAIL credential."""
    resp = _client.post(path, headers=_auth_headers(), json=payload)
    return _handle(resp, allow_statuses)


def get(path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    """GET a REST endpoint with the request's RAIL credential."""
    clean = {k: v for k, v in (params or {}).items() if v is not None}
    resp = _client.get(path, headers=_auth_headers(), params=clean)
    return _handle(resp)
