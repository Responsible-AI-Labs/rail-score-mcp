"""Runtime configuration for the RAIL Score MCP gateway.

All values are environment-driven so the same image runs in staging and prod.
No secrets live here; the per-request RAIL API key arrives on the wire and the
upstream base URL is the only deployment knob.
"""
from __future__ import annotations

import os


# Upstream REST API the gateway proxies to. The MCP server is a thin, hardened
# front door for these endpoints; it never reimplements scoring logic.
RAIL_API_BASE: str = os.environ.get(
    "RAIL_API_BASE", "https://api.responsibleailabs.ai"
).rstrip("/")

# Bind address. 8080 matches the rest of the platform's Cloud Run services.
MCP_HOST: str = os.environ.get("MCP_HOST", "0.0.0.0")
MCP_PORT: int = int(os.environ.get("MCP_PORT", "8080"))

# Upstream call timeout (seconds). safe-regenerate is the slow path; keep a
# generous ceiling but always bounded so a hung upstream never wedges a worker.
UPSTREAM_TIMEOUT: float = float(os.environ.get("RAIL_UPSTREAM_TIMEOUT", "60"))

# Hard input cap enforced at the gateway, independent of upstream limits
# (Section 5, item 9). eval/dpdp-scan cap content at 10k upstream.
MAX_CONTENT_CHARS: int = int(os.environ.get("RAIL_MAX_CONTENT_CHARS", "10000"))
# tool-result accepts larger payloads upstream (50k).
MAX_RESULT_CHARS: int = int(os.environ.get("RAIL_MAX_RESULT_CHARS", "50000"))

# How long a validated key's identity is cached (seconds), mirroring the
# engine's 5-minute auth cache.
KEY_CACHE_TTL: float = float(os.environ.get("RAIL_KEY_CACHE_TTL", "300"))
