"""Tool registration, input validation, and upstream routing."""
import pytest

import server


# ── registration / schema ──────────────────────────────────────────────────────

EXPECTED_TOOLS = {
    "rail_evaluate",
    "rail_check_compliance",
    "rail_detect_injection",
    "rail_evaluate_tool_call",
    "rail_scan_tool_result",
    "rail_safe_regenerate",
    "rail_dpdp_scan",
    "rail_dpdp_gate",
    "rail_dpdp_compliance",
}


async def test_all_nine_tools_registered():
    tools = await server.mcp.list_tools()
    names = {t.name for t in tools}
    assert EXPECTED_TOOLS <= names
    # Every tool is rail_-prefixed (namespacing best practice).
    assert all(n.startswith("rail_") for n in names)


async def test_tool_schemas_have_typed_params():
    tools = {t.name: t for t in await server.mcp.list_tools()}
    props = tools["rail_evaluate"].inputSchema["properties"]
    assert "content" in props and "mode" in props and "domain" in props
    # functools.wraps must preserve the signature, not leak *args/**kwargs.
    assert "args" not in props and "kwargs" not in props


async def test_resources_registered():
    resources = await server.mcp.list_resources()
    uris = {str(r.uri) for r in resources}
    assert "rail://framework/dimensions" in uris
    assert "rail://account/capabilities" in uris


# ── input validation ────────────────────────────────────────────────────────────

def test_evaluate_rejects_short_content(bound_request, stub_upstream):
    with pytest.raises(ValueError, match="10 to"):
        server.rail_evaluate("too short")


def test_check_compliance_rejects_too_many_frameworks(bound_request, stub_upstream):
    with pytest.raises(ValueError, match="1 to 5"):
        server.rail_check_compliance("x" * 50, ["gdpr", "ccpa", "hipaa", "eu_ai_act", "india_dpdp", "india_ai_gov"])


def test_dpdp_gate_requires_purpose(bound_request, stub_upstream):
    with pytest.raises(ValueError, match="purpose"):
        server.rail_dpdp_gate(activity="process_data", purpose="")


# ── upstream routing ─────────────────────────────────────────────────────────────

def test_evaluate_deep_sets_explanation_flags(bound_request, stub_upstream):
    stub_upstream.post_returns = {"result": {}, "credits_consumed": 3.0}
    server.rail_evaluate("a valid piece of content to score", mode="deep")
    path, payload, _ = stub_upstream.last_post
    assert path == "/railscore/v1/eval"
    assert payload["include_explanations"] is True
    assert payload["mode"] == "deep"


def test_tool_call_allows_403_block(bound_request, stub_upstream):
    stub_upstream.post_returns = {"decision": "BLOCK", "decision_reason": "policy"}
    out = server.rail_evaluate_tool_call("delete_user", {"id": 1})
    _, payload, allow = stub_upstream.last_post
    assert 403 in allow
    assert payload["tool_params"] == {"id": 1}
    assert out["decision"] == "BLOCK"


def test_safe_regenerate_allows_422_critical(bound_request, stub_upstream):
    stub_upstream.post_returns = {"requires_human_review": True}
    server.rail_safe_regenerate("a valid piece of content to regenerate", threshold=8.0)
    path, payload, allow = stub_upstream.last_post
    assert 422 in allow
    assert payload["thresholds"]["overall"]["score"] == 8.0


def test_dpdp_compliance_timers_uses_get(bound_request, stub_upstream):
    stub_upstream.get_returns = {"result": {"timers": []}}
    out = server.rail_dpdp_compliance("timers", {"status": "active"})
    assert stub_upstream.last_get[0] == "/railscore/v1/compliance/dpdp/timers"
    assert out == {"timers": []}


def test_dpdp_compliance_emit_uses_post(bound_request, stub_upstream):
    stub_upstream.post_returns = {"result": {"accepted": 1, "rejected": 0}}
    server.rail_dpdp_compliance("emit", {"events": [{"type": "consent_granted", "data": {}}]})
    assert stub_upstream.last_post[0] == "/railscore/v1/compliance/dpdp/emit"
