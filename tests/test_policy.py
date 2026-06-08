"""Policy engine: validation, in-gateway outcome computation, and the
app-policy-wins / request-policy-fallback precedence on rail_evaluate."""
import pytest

import server


# ── validation ───────────────────────────────────────────────────────────────

def test_validate_policy_ok():
    rules = server.validate_policy({"rules": [
        {"dimension": "safety", "threshold": 7.0, "action": "block"},
        {"dimension": "fairness", "threshold": 6, "action": "flag"},
    ]})
    assert len(rules) == 2


@pytest.mark.parametrize("bad,match", [
    ({"rules": []}, "non-empty"),
    ({"rules": [{"dimension": "safety", "threshold": 7, "action": "block"}], "x": 1}, "unknown policy keys"),
    ({"rules": [{"dimension": "nope", "threshold": 7, "action": "block"}]}, "dimension must be"),
    ({"rules": [{"dimension": "safety", "threshold": 11, "action": "block"}]}, "threshold"),
    ({"rules": [{"dimension": "safety", "threshold": 7, "action": "nuke"}]}, "action must be"),
    ({"rules": [{"dimension": "safety", "threshold": 7, "action": "block", "z": 1}]}, "unknown keys"),
    ("notdict", "must be an object"),
])
def test_validate_policy_rejects(bad, match):
    with pytest.raises(ValueError, match=match):
        server.validate_policy(bad)


# ── outcome computation (rule fires when score < threshold) ──────────────────

def test_outcome_most_severe_action_wins():
    out = server.compute_policy_outcome(
        {"safety": 3.0, "fairness": 5.0, "reliability": 9.0},
        [{"dimension": "safety", "threshold": 7, "action": "warn"},
         {"dimension": "fairness", "threshold": 6, "action": "block"},
         {"dimension": "reliability", "threshold": 5, "action": "flag"}],
    )
    assert out["action"] == "block" and out["blocked"] is True
    assert {t["dimension"] for t in out["triggered_rules"]} == {"safety", "fairness"}
    assert out["source"] == "request"


def test_outcome_allow_when_all_pass():
    out = server.compute_policy_outcome(
        {"safety": 9.0}, [{"dimension": "safety", "threshold": 7, "action": "block"}])
    assert out["action"] == "allow" and out["blocked"] is False and out["triggered_rules"] == []


def test_outcome_threshold_is_strict_below():
    # score == threshold does NOT fire (only strictly below)
    out = server.compute_policy_outcome(
        {"safety": 7.0}, [{"dimension": "safety", "threshold": 7.0, "action": "block"}])
    assert out["action"] == "allow"


def test_outcome_handles_nested_scores_and_missing_dims():
    out = server.compute_policy_outcome(
        {"safety": {"score": 4.0}},  # nested shape; "privacy" missing entirely
        [{"dimension": "safety", "threshold": 7, "action": "flag"},
         {"dimension": "privacy", "threshold": 8, "action": "block"}])
    assert out["action"] == "flag"  # privacy skipped (no score)


def test_normalize_app_outcome():
    assert server._normalize_app_outcome({"passed": True})["action"] == "allow"
    blk = server._normalize_app_outcome({"passed": False, "enforcement": "block"})
    assert blk["action"] == "block" and blk["blocked"] and blk["source"] == "application"
    warn = server._normalize_app_outcome({"passed": False, "enforcement": "log_only"})
    assert warn["action"] == "warn"


# ── precedence on rail_evaluate ──────────────────────────────────────────────

CONTENT = "a sufficiently long piece of content to evaluate."


def test_request_policy_applied_when_no_enforced_app_policy(bound_request, stub_upstream):
    stub_upstream.post_returns = {"result": {"dimension_scores": {"safety": 3.0}}}
    out = server.rail_evaluate(CONTENT, policy={"rules": [
        {"dimension": "safety", "threshold": 7, "action": "block"}]})
    po = out["result"]["policy_outcome"]
    assert po["source"] == "request" and po["action"] == "block"


def test_enforced_app_policy_wins_over_request(bound_request, stub_upstream):
    stub_upstream.post_returns = {"result": {
        "dimension_scores": {"safety": 3.0},
        "policy_outcome": {"enforced": True, "passed": False, "enforcement": "block",
                           "score": 3.0, "threshold": 7.0},
    }}
    out = server.rail_evaluate(CONTENT, policy={"rules": [
        {"dimension": "safety", "threshold": 1, "action": "warn"}]})  # request says warn
    po = out["result"]["policy_outcome"]
    assert po["source"] == "application" and po["action"] == "block"  # app wins


def test_no_policy_outcome_when_none_requested_and_not_enforced(bound_request, stub_upstream):
    stub_upstream.post_returns = {"result": {"dimension_scores": {"safety": 3.0}}}
    out = server.rail_evaluate(CONTENT)
    assert "policy_outcome" not in out["result"]


def test_invalid_policy_rejected_before_upstream(bound_request, stub_upstream):
    with pytest.raises(ValueError, match="action must be"):
        server.rail_evaluate(CONTENT, policy={"rules": [
            {"dimension": "safety", "threshold": 7, "action": "explode"}]})
