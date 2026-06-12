"""Phase 1 authentication: bearer `rail_*` API keys.

Every request to the MCP endpoint must carry `Authorization: Bearer rail_...`.
The key is validated once against the REST API's POST /verify (result cached
for KEY_CACHE_TTL) and the resolved tenant is bound to the request context.

The validated key is forwarded upstream by rail_client so per-tenant credits
and isolation are enforced by the existing REST auth. Phase 2 swaps this for
the SDK's OAuth TokenVerifier (RFC 9728 metadata, RFC 8707 audience binding)
plus a service credential and on-behalf-of header.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import time
import uuid
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

import config
import rail_client
from request_context import current_key, current_request_id, current_tenant

logger = logging.getLogger("rail-mcp.auth")

# Paths that never require a key: health probe and OAuth discovery metadata.
# (The landing page "/" is handled as an exact match below, not a prefix —
# matching "/" as a prefix would make every path public.)
_PUBLIC_PREFIXES = ("/health", "/.well-known/")

# token-hash -> (expires_at, tenant)
_cache: dict[str, tuple[float, dict[str, Any]]] = {}


def _cache_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def _cache_get(key: str) -> dict[str, Any] | None:
    entry = _cache.get(_cache_key(key))
    if not entry:
        return None
    expires_at, tenant = entry
    if time.monotonic() >= expires_at:
        _cache.pop(_cache_key(key), None)
        return None
    return tenant


def _cache_set(key: str, tenant: dict[str, Any]) -> None:
    _cache[_cache_key(key)] = (time.monotonic() + config.KEY_CACHE_TTL, tenant)


def extract_api_key(authorization: str, x_api_key: str) -> str | None:
    """Pull a `rail_` key from either auth header.

    Two accepted forms so gateways (e.g. Smithery) that forward a raw value
    work without a Bearer prefix:
      - `Authorization: Bearer rail_...`  (standard)
      - `X-API-Key: rail_...`             (raw key, gateway-friendly)
    """
    if authorization.startswith("Bearer rail_"):
        return authorization.removeprefix("Bearer ").strip()
    if x_api_key.startswith("rail_"):
        return x_api_key.strip()
    return None


# Query-param keys gateways use when they cannot set custom headers. Smithery's
# toolbox passes server config in the URL: either flat params (?apiKey=rail_...)
# or a base64-encoded JSON blob (?config=<base64>). Headers stay the preferred,
# more secure path (query strings can land in access logs); these are a
# compatibility fallback only.
_QUERY_KEY_NAMES = ("api_key", "apiKey", "rail_api_key", "railApiKey", "key")


def extract_api_key_from_query(params: Any) -> str | None:
    """Pull a `rail_` key from Smithery-style query parameters.

    Accepts both flat params and a base64-encoded JSON `config` blob. Returns
    only values that look like RAIL keys so a stray param never spoofs auth.
    """
    for name in _QUERY_KEY_NAMES:
        value = params.get(name)
        if value and value.startswith("rail_"):
            return value.strip()

    raw = params.get("config")
    if raw:
        try:
            # base64 may arrive URL-safe and unpadded; normalise before decode.
            padded = raw.replace("-", "+").replace("_", "/")
            padded += "=" * (-len(padded) % 4)
            decoded = base64.b64decode(padded)
            cfg = json.loads(decoded)
        except (binascii.Error, ValueError, TypeError):
            return None
        if isinstance(cfg, dict):
            for name in _QUERY_KEY_NAMES:
                value = cfg.get(name)
                if isinstance(value, str) and value.startswith("rail_"):
                    return value.strip()
    return None


class RailKeyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path == "/" or any(path.startswith(p) for p in _PUBLIC_PREFIXES):
            return await call_next(request)

        # Correlation id: honour an inbound one, else mint a new one.
        request_id = request.headers.get("x-request-id") or f"mcp_{uuid.uuid4().hex[:12]}"

        key = extract_api_key(
            request.headers.get("authorization", ""),
            request.headers.get("x-api-key", ""),
        )
        # Fall back to Smithery-style query-param config when no header is set.
        if key is None:
            key = extract_api_key_from_query(request.query_params)
        if key is None:
            return JSONResponse(
                {"error": "missing or invalid RAIL API key", "code": "UNAUTHENTICATED"},
                status_code=401,
            )

        tenant = _cache_get(key)
        if tenant is None:
            # verify() is a blocking httpx call; run it off the event loop.
            from starlette.concurrency import run_in_threadpool

            tenant = await run_in_threadpool(rail_client.verify, key, request_id)
            if tenant is None:
                return JSONResponse(
                    {"error": "key rejected", "code": "FORBIDDEN"}, status_code=403
                )
            _cache_set(key, tenant)

        # Bind request scope. Tools read tenant from here, never from params.
        key_token = current_key.set(key)
        tenant_token = current_tenant.set(tenant)
        rid_token = current_request_id.set(request_id)
        try:
            response = await call_next(request)
        finally:
            current_key.reset(key_token)
            current_tenant.reset(tenant_token)
            current_request_id.reset(rid_token)
        response.headers["X-Request-ID"] = request_id
        return response
