"""Upstream error → SDK taxonomy mapping (rail_client.map_error)."""
import httpx

import rail_client

_REQ = httpx.Request("POST", "https://api.responsibleailabs.ai/railscore/v1/eval")


def _resp(status, body=None, headers=None):
    return httpx.Response(status, json=body or {}, headers=headers or {}, request=_REQ)


def test_401_unauthenticated():
    err = rail_client.map_error(_resp(401, {"error": "no key"}), {"error": "no key"})
    assert err.code == "UNAUTHENTICATED" and err.extra == {}


def test_402_insufficient_credits_with_fields():
    body = {"error": "no credits", "required": 3.0, "balance": 0.5}
    err = rail_client.map_error(_resp(402, body), body)
    assert err.code == "INSUFFICIENT_CREDITS"
    assert err.extra == {"required": 3.0, "balance": 0.5}


def test_credit_failure_by_body_code():
    body = {"error": "x", "code": "INSUFFICIENT_BALANCE", "required": 1, "balance": 0}
    err = rail_client.map_error(_resp(400, body), body)
    assert err.code == "INSUFFICIENT_CREDITS" and err.extra["required"] == 1


def test_429_rate_limited_with_retry_after():
    err = rail_client.map_error(
        _resp(429, {"error": "slow down"}, {"retry-after": "60"}), {"error": "slow down"})
    assert err.code == "RATE_LIMITED" and err.extra["retry_after"] == 60


def test_content_too_harmful_no_echo():
    body = {"error": "Content flagged as critically unsafe: <the bad text>",
            "code": "RAIL_CRITICAL_CONTENT"}
    err = rail_client.map_error(_resp(422, body), body)
    assert err.code == "CONTENT_TOO_HARMFUL"
    assert "bad text" not in err.message  # never echo analyzed content


def test_unknown_error_falls_back():
    err = rail_client.map_error(_resp(500, {"error": "boom"}), {"error": "boom"})
    assert err.code == "HTTP_500"
