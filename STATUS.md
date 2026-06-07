# RAIL Score MCP Server — Status

**Status:** 🟢 **Live** · **Version:** 1.0.0 · **Last updated:** 7 June 2026

Add a responsible-AI safety layer to any agent in one URL. A remote, hosted
[Model Context Protocol](https://modelcontextprotocol.io) server that exposes
RAIL Score's evaluation, agent-guardrail, and India DPDP compliance to any MCP
client — Claude, ChatGPT, Cursor, Copilot, Replit, v0, LangGraph, CrewAI, or a
custom stack — with zero SDK integration.

```
https://mcp.responsibleailabs.ai/mcp
```

---

## Status at a glance

| Item | Status |
|---|---|
| Production endpoint | 🟢 Live — `https://mcp.responsibleailabs.ai/mcp` |
| Official MCP Registry | 🟢 Published — `ai.responsibleailabs/rail-score` v1.0.0 |
| Smithery | 🟢 Listed — [responsibleailabs/rail-score](https://smithery.ai/servers/responsibleailabs/rail-score) |
| Glama / PulseMCP / mcp.directory | 🟡 Syncing from the official registry |
| Auth | 🟢 API key (`Authorization: Bearer` or `X-API-Key`) |
| OAuth 2.1 | 🔜 Roadmap |

**Landing:** <https://mcp.responsibleailabs.ai/> · **Health:** `/health` ·
**Server card:** `/.well-known/mcp/server-card.json`

---

## What it is

A thin, hardened gateway in front of the RAIL Score REST API. It reimplements no
scoring logic — it validates the caller, shapes requests/responses for agent
ergonomics, and forwards to the engine. Credits, tenancy, and rate limits are
identical whether you call RAIL via MCP or the REST API / SDKs.

- **Transport:** Streamable HTTP only, single `/mcp` endpoint.
- **State:** stateless — scales horizontally.
- **Framework:** FastMCP (official `mcp` Python SDK).

---

## Tools (9) and resources (2)

All tools are `rail_`-prefixed. Descriptions state cost, latency, and when not to
use them, because agents select tools from descriptions alone.

| Tool | Purpose | Credits |
|---|---|---|
| `rail_evaluate` | Score content across the 8 RAIL dimensions | 1.0 basic / 3.0 deep |
| `rail_check_compliance` | gdpr, ccpa, hipaa, eu_ai_act, india_dpdp, india_ai_gov (1–5 per call) | 5–10 |
| `rail_detect_injection` | Detect prompt injection in untrusted text | 0.5 |
| `rail_evaluate_tool_call` | Allow / warn / block a tool call before it runs | 1.5–3.0 |
| `rail_scan_tool_result` | Scan a tool's output for PII + injection; return redacted text | 0.5–1.0 |
| `rail_safe_regenerate` | Iteratively regenerate until content passes (slow) | 1–9 |
| `rail_dpdp_scan` | Scan for Indian personal data (DPDP Act 2023) | 0.5 |
| `rail_dpdp_gate` | Real-time DPDP processing gate (allow/block/require_action) | 0.3 |
| `rail_dpdp_compliance` | DPDP workflow ops (emit, require, evidence, session, timers) | varies |

**Resources** (free, read-only): `rail://framework/dimensions`,
`rail://account/capabilities`.

**The 8 RAIL dimensions:** Fairness · Safety · Reliability · Transparency ·
Privacy · Accountability · Inclusivity · User Impact.

---

## The guarded agent loop

1. `rail_detect_injection` on untrusted input before acting on it
2. `rail_evaluate_tool_call` before executing any tool call (`block` = hard stop)
3. `rail_scan_tool_result` on the tool's output (prefer the redacted text)
4. `rail_evaluate` (deep) on the draft answer, or `rail_safe_regenerate` to fix it
5. `rail_dpdp_scan` (mask) on anything leaving the boundary, for India deployments

---

## Authentication

Use your RAIL API key (`rail_…` from the
[dashboard](https://responsibleailabs.ai/dashboard)) as a header — either form:

```
Authorization: Bearer rail_your_key
```
```
X-API-Key: rail_your_key
```

`/`, `/health`, and `/.well-known/*` are public; everything else requires a key.
OAuth 2.1 is on the roadmap.

---

## How to connect

**Claude Code**
```bash
claude mcp add --transport http rail https://mcp.responsibleailabs.ai/mcp \
  --header "Authorization: Bearer ${RAIL_API_KEY}"
```

**Cursor / Windsurf** (`.cursor/mcp.json`)
```json
{ "mcpServers": { "rail": {
  "url": "https://mcp.responsibleailabs.ai/mcp",
  "headers": { "Authorization": "Bearer rail_YOUR_KEY" } } } }
```

**Claude.ai / Desktop** — Settings → Connectors → Add custom connector → URL
`https://mcp.responsibleailabs.ai/mcp`, paste your key.

**Vercel v0** — Settings → Integrations → Add Custom MCP Connection → URL
`https://mcp.responsibleailabs.ai/mcp` → Auth **Bearer** (paste key) or
**Headers** (`X-API-Key` = `rail_YOUR_KEY`).

**Smithery** — [smithery.ai/servers/responsibleailabs/rail-score](https://smithery.ai/servers/responsibleailabs/rail-score).

**OpenAI Responses API / LangGraph / Replit** — see the
[connection guide](https://docs.responsibleailabs.ai/mcp/connect).

**Quick test**
```bash
curl -s -X POST https://mcp.responsibleailabs.ai/mcp \
  -H "Authorization: Bearer rail_YOUR_KEY" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

---

## Security model

- **Verdicts are structured data**, never advisory prose an agent can ignore.
- **No reflection of analyzed content** — never echoes raw analyzed text.
- **No raw PII** — masked values + offsets only; a locally redacted copy is provided.
- **Tenant isolation by construction** — identity comes from the validated key, not tool parameters.
- **Input caps, timeouts, per-key rate limits, audit logging** (no content bodies).

Regression-tested (`tests/test_no_reflection.py`, `tests/test_pii_masking.py`).

---

## Self-hosting

Most users should just connect to the hosted URL above. To self-host, build the
image and run it anywhere that serves HTTP; point it at the public REST API with
`RAIL_API_BASE` (its default). No secrets required — the customer's RAIL key
arrives on each request.

```bash
docker build -t rail-score-mcp .
docker run -p 8080:8080 -e RAIL_API_BASE=https://api.responsibleailabs.ai rail-score-mcp
```

---

## Distribution

- **Official MCP Registry** — published as `ai.responsibleailabs/rail-score`
  (DNS-verified `responsibleailabs.ai` namespace). The canonical upstream.
- **Smithery** — listed; the gateway forwards your key as `X-API-Key`. A
  `/.well-known/mcp/server-card.json` lets registries enumerate tools.
- **Downstream** — Glama, PulseMCP, mcp.directory sync from the official registry.

---

## Roadmap

- [ ] OAuth 2.1 — curated Claude / ChatGPT / Replit connector directories
- [ ] Verify and claim downstream registry listings
- [ ] `rail_evaluate_plan`, server-enforced policy profiles, webhook events for blocked calls

---

## References

- **Live:** <https://mcp.responsibleailabs.ai/mcp>
- **Docs:** <https://docs.responsibleailabs.ai/mcp/overview>
- **Registry:** `ai.responsibleailabs/rail-score`
- **Smithery:** <https://smithery.ai/servers/responsibleailabs/rail-score>
- **SDKs:** [`rail-score-sdk`](https://pypi.org/project/rail-score-sdk/) (PyPI) ·
  [`@responsible-ai-labs/rail-score`](https://www.npmjs.com/package/@responsible-ai-labs/rail-score) (npm)
