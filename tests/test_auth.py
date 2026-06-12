"""Auth header parsing + public endpoints (server card, health) and the
X-API-Key gateway path."""
import base64
import json

import pytest
from starlette.datastructures import QueryParams
from starlette.testclient import TestClient

import auth
import rail_client
import server


@pytest.fixture(scope="module")
def client():
    # One client for the module: the StreamableHTTP session manager can only
    # run once per server instance, so the app lifespan must start just once.
    with TestClient(server.app) as c:
        yield c


# ── pure key extraction ─────────────────────────────────────────────────────────

def test_extract_key_from_bearer():
    assert auth.extract_api_key("Bearer rail_abc", "") == "rail_abc"


def test_extract_key_from_x_api_key():
    assert auth.extract_api_key("", "rail_xyz") == "rail_xyz"


def test_extract_key_bearer_takes_precedence():
    assert auth.extract_api_key("Bearer rail_first", "rail_second") == "rail_first"


def test_extract_key_rejects_garbage():
    assert auth.extract_api_key("Bearer notakey", "") is None
    assert auth.extract_api_key("", "notakey") is None
    assert auth.extract_api_key("", "") is None


# ── query-param key extraction (Smithery gateway fallback) ──────────────────────

def test_extract_key_from_flat_query_param():
    assert auth.extract_api_key_from_query(QueryParams("apiKey=rail_q1")) == "rail_q1"
    assert auth.extract_api_key_from_query(QueryParams("api_key=rail_q2")) == "rail_q2"


def test_extract_key_from_base64_config():
    blob = base64.b64encode(json.dumps({"apiKey": "rail_cfg"}).encode()).decode()
    assert auth.extract_api_key_from_query(QueryParams(f"config={blob}")) == "rail_cfg"


def test_extract_key_from_urlsafe_unpadded_config():
    # URL-safe base64 without padding, as some gateways send it.
    raw = base64.urlsafe_b64encode(json.dumps({"apiKey": "rail_url"}).encode())
    blob = raw.decode().rstrip("=")
    assert auth.extract_api_key_from_query(QueryParams(f"config={blob}")) == "rail_url"


def test_query_extraction_rejects_non_rail_and_garbage():
    assert auth.extract_api_key_from_query(QueryParams("apiKey=notakey")) is None
    assert auth.extract_api_key_from_query(QueryParams("config=not-base64!!")) is None
    assert auth.extract_api_key_from_query(QueryParams("")) is None


def test_mcp_accepts_query_param_key(client, monkeypatch):
    # Smithery sends config in the URL, not headers. Mock /verify and assert
    # the keyless-header request still clears the middleware via ?apiKey=.
    monkeypatch.setattr(
        rail_client, "verify", lambda key, request_id=None: {"valid": True, "org_id": "o"}
    )
    r = client.post(
        "/mcp?apiKey=rail_test",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        },
    )
    assert r.status_code not in (401, 403)


# ── public endpoints (no auth) ───────────────────────────────────────────────────

def test_landing_is_public_html(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "RAIL Score" in r.text and "/mcp" in r.text


def test_health_is_public(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["service"] == "rail-mcp-server"


def test_server_card_is_public_and_lists_tools(client):
    r = client.get("/.well-known/mcp/server-card.json")
    assert r.status_code == 200
    card = r.json()
    assert card["serverInfo"]["name"] == "rail-score"
    assert card["authentication"]["required"] is True
    names = {t["name"] for t in card["tools"]}
    assert {"rail_evaluate", "rail_dpdp_scan"} <= names
    assert len(card["tools"]) >= 9


# ── auth gate on /mcp ─────────────────────────────────────────────────────────────

def test_mcp_rejects_no_key(client):
    r = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Accept": "application/json, text/event-stream"},
    )
    assert r.status_code == 401


def test_mcp_accepts_x_api_key(client, monkeypatch):
    # Mock /verify so the key is accepted; assert the request clears the
    # middleware (anything but 401/403 proves auth passed).
    monkeypatch.setattr(
        rail_client, "verify", lambda key, request_id=None: {"valid": True, "org_id": "o"}
    )
    r = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={
            "X-API-Key": "rail_test",
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        },
    )
    assert r.status_code not in (401, 403)
