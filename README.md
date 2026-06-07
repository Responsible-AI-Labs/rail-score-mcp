# RAIL Score MCP Server

Add a responsible-AI safety layer to any agent in one URL.

A remote, hosted [Model Context Protocol](https://modelcontextprotocol.io) server
that exposes RAIL Score's evaluation, agent-guardrail, and India DPDP compliance
capabilities to any MCP client — Claude, ChatGPT, Cursor, Copilot, Replit Agent,
LangGraph, CrewAI, or a custom stack — with zero SDK integration.

```
https://mcp.responsibleailabs.ai/mcp
```

The server is a thin, hardened gateway in front of the existing REST API at
`api.responsibleailabs.ai/railscore/v1/`. It reimplements no scoring logic: it
validates the caller, shapes requests and responses for agent ergonomics, and
forwards to the engine. Credits, tenancy, and rate limits are identical via MCP
and REST.

## Quickstart

You need a RAIL API key (`rail_...`) from the [dashboard](https://responsibleailabs.ai/dashboard).

**Claude Code**

```bash
claude mcp add --transport http rail https://mcp.responsibleailabs.ai/mcp \
  --header "Authorization: Bearer ${RAIL_API_KEY}"
```

**Cursor / Windsurf** (`.cursor/mcp.json`)

```json
{
  "mcpServers": {
    "rail": {
      "url": "https://mcp.responsibleailabs.ai/mcp",
      "headers": { "Authorization": "Bearer rail_YOUR_KEY" }
    }
  }
}
```

**Claude.ai / Desktop** — Settings → Connectors → Add custom connector → URL
`https://mcp.responsibleailabs.ai/mcp`, then paste your `rail_` key.

More clients (OpenAI Responses API, LangGraph, Replit) are documented at
[docs.responsibleailabs.ai/mcp](https://docs.responsibleailabs.ai/mcp/connect).

## Tools

Nine tools, all `rail_`-prefixed. Descriptions state cost, latency, and when not
to use a tool, because agents select tools from descriptions alone.

| Tool | Purpose | Credits |
|---|---|---|
| `rail_evaluate` | Score content across the 8 RAIL dimensions | 1.0 basic / 3.0 deep |
| `rail_check_compliance` | Check against gdpr, ccpa, hipaa, eu_ai_act, india_dpdp, india_ai_gov | 5–10 |
| `rail_detect_injection` | Detect prompt injection in untrusted text | 0.5 |
| `rail_evaluate_tool_call` | Allow/warn/block a tool call before it runs | 1.5–3.0 |
| `rail_scan_tool_result` | Scan a tool's output for PII + injection, return redacted text | 0.5–1.0 |
| `rail_safe_regenerate` | Iteratively regenerate content until it passes (slow) | 1–9 |
| `rail_dpdp_scan` | Scan for Indian personal data under the DPDP Act 2023 | 0.5 |
| `rail_dpdp_gate` | Real-time DPDP processing gate (allow/block/require_action) | 0.3 |
| `rail_dpdp_compliance` | DPDP workflow: emit, require, evidence, session, timers | varies |

Two read-only **resources** (free, zero credits): `rail://framework/dimensions`
and `rail://account/capabilities`.

## The guarded agent loop

The canonical use is to wrap an agent's reasoning end to end:

1. `rail_detect_injection` on untrusted input before acting on it
2. `rail_evaluate_tool_call` before executing any tool call (block = hard stop)
3. `rail_scan_tool_result` on the tool's output (prefer the redacted text)
4. `rail_evaluate` (deep) on the draft answer, or `rail_safe_regenerate` to fix it
5. `rail_dpdp_scan` (mask) on anything leaving the boundary in India deployments

## Security model

A safety product that is itself unsafe is a credibility failure. The launch
blockers (enforced and regression-tested):

- **Verdicts are structured data, never advisory prose** an agent can ignore.
- **No reflection of analyzed content.** Tools return verdicts, scores, spans,
  and masked excerpts — never the raw analyzed text (second-order injection).
- **No raw PII.** Detection returns masked values and offsets only.
- **Tenant isolation by construction.** Identity comes from the validated key in
  the auth middleware, never from a tool parameter.
- **No token passthrough** in phase 2: client tokens are validated and dropped;
  downstream calls use the gateway's service credential. In phase 1 the bearer
  `rail_` key *is* the customer's RAIL credential, so it is forwarded upstream to
  preserve per-tenant credits and isolation.
- **Input caps, timeouts, rate limits, and audit logging** (no content bodies).

See `tests/test_no_reflection.py` and `tests/test_pii_masking.py` — these run as
a hard CI gate.

## Architecture

- **Transport:** Streamable HTTP only, single `/mcp` endpoint (SSE is sunset).
- **State:** `stateless_http=True`, `json_response=True` — scales horizontally
  behind a normal load balancer; aligns with the MCP 2026-07-28 stateless core.
- **Auth (phase 1):** `rail_` key via `Authorization: Bearer rail_...` **or**
  `X-API-Key: rail_...` (the latter is gateway-friendly — no Bearer prefix),
  validated once against `POST /verify` (cached 5 min) by
  `auth.RailKeyMiddleware`, then bound to the request context.
- **Discovery:** `GET /.well-known/mcp/server-card.json` (public) lets registries
  that scan behind an auth wall (e.g. Smithery) enumerate the tools without a key.
- **Auth (phase 2):** OAuth 2.1 resource server (RFC 9728 metadata, RFC 8707
  audience binding) via the SDK's `TokenVerifier`.

```
rail_client.py   thin httpx client to api.responsibleailabs.ai (forwards key, propagates X-Request-ID)
auth.py          RailKeyMiddleware: validate rail_ keys, bind tenant
request_context.py  per-request ContextVars (key, tenant, request id)
server.py        FastMCP app: 9 tools + 2 resources + landing (/) + /health + server-card
server.json      official MCP registry manifest (ai.responsibleailabs/rail-score)
```

## Local development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
ruff check . && pytest          # unit + safety regression tests
RAIL_API_BASE=https://api.responsibleailabs.ai python server.py   # serves on :8080
```

Protocol smoke test against a running server (needs a real key):

```bash
npx @modelcontextprotocol/inspector --cli \
  http://localhost:8080/mcp --method tools/list \
  --header "Authorization: Bearer ${RAIL_API_KEY}"
```

### Configuration

| Env var | Default | Purpose |
|---|---|---|
| `RAIL_API_BASE` | `https://api.responsibleailabs.ai` | Upstream REST API |
| `MCP_PORT` | `8080` | Bind port |
| `RAIL_UPSTREAM_TIMEOUT` | `60` | Upstream call timeout (s) |
| `RAIL_KEY_CACHE_TTL` | `300` | Validated-key cache TTL (s) |

## Hosting

Responsible AI Labs operates the hosted server at
`https://mcp.responsibleailabs.ai/mcp` — for almost everyone, just connect to
that URL; you do not need to run anything.

To self-host, build the image and run it anywhere that serves HTTP; point it at
the public REST API with `RAIL_API_BASE` (its default). No secrets are required:
the customer's RAIL key arrives on each request.

```bash
docker build -t rail-score-mcp .
docker run -p 8080:8080 -e RAIL_API_BASE=https://api.responsibleailabs.ai rail-score-mcp
```

## Registry

Published to the official registry as `ai.responsibleailabs/rail-score` via
`server.json` and the `mcp-publisher` CLI (DNS-authenticated `responsibleailabs.ai`
namespace). Downstream registries (Smithery, Glama, PulseMCP) sync from it.
