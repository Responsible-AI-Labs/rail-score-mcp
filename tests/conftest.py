"""Shared fixtures: bind a fake request context and stub the upstream client.

Tests never hit the network. They monkeypatch rail_client.post/get with canned
REST responses and assert the gateway's input validation, output shaping, and
safety guarantees.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def bound_request():
    """Bind a validated key + tenant for the duration of a test."""
    import request_context as rc

    k = rc.current_key.set("rail_test_key")
    t = rc.current_tenant.set({"org_id": "org_test", "plan": "pro", "valid": True})
    r = rc.current_request_id.set("mcp_test_rid")
    try:
        yield
    finally:
        rc.current_key.reset(k)
        rc.current_tenant.reset(t)
        rc.current_request_id.reset(r)


@pytest.fixture
def stub_upstream(monkeypatch):
    """Return a recorder that lets a test set the next upstream response.

    Usage:
        stub_upstream.post_returns = {...}
        stub_upstream.get_returns = {...}
        ... call tool ...
        assert stub_upstream.last_post == ("/path", {...})
    """
    import rail_client

    class Recorder:
        post_returns: dict = {}
        get_returns: dict = {}
        last_post = None
        last_get = None

    rec = Recorder()

    def fake_post(path, payload, allow_statuses=frozenset()):
        rec.last_post = (path, payload, allow_statuses)
        return rec.post_returns

    def fake_get(path, params=None):
        rec.last_get = (path, params)
        return rec.get_returns

    monkeypatch.setattr(rail_client, "post", fake_post)
    monkeypatch.setattr(rail_client, "get", fake_get)
    return rec
