"""Regression guard (design doc Section 5, item 4 / hard constraint 4): tools
must never return raw detected PII values — masked values and offsets only.
"""
import server

AADHAAR = "1234 5678 9012"
PAN = "ABCDE1234F"


def test_dpdp_scan_detect_strips_raw_values(bound_request, stub_upstream):
    stub_upstream.post_returns = {
        "result": {
            "pii_found": [
                {"type": "aadhaar", "original": AADHAAR, "masked": "XXXX XXXX 9012",
                 "position": {"start": 10, "end": 24}},
                {"type": "pan", "original": PAN, "masked": "XXXXX1234X",
                 "position": {"start": 40, "end": 50}},
            ],
            "child_session": False,
            "purpose_drift": False,
        },
        "credits_consumed": 0.5,
    }
    out = server.rail_dpdp_scan(f"Aadhaar {AADHAAR} and PAN {PAN} on file.", mode="detect")
    blob = repr(out)
    assert AADHAAR not in blob
    assert PAN not in blob
    for finding in out["pii_found"]:
        assert "original" not in finding
        assert "masked" in finding and "type" in finding


def test_scan_tool_result_redacts_and_hides_values(bound_request, stub_upstream):
    raw = f"Customer Aadhaar is {AADHAAR}, please confirm."
    stub_upstream.post_returns = {
        "recommended_action": "REDACT_AND_PASS",
        "risk_level": "high",
        "pii_detected": {
            "found": True,
            "entities": [
                {"type": "aadhaar", "value": AADHAAR, "offset": 20, "should_redact": True},
            ],
        },
        "credits_consumed": 0.5,
    }
    out = server.rail_scan_tool_result("crm_lookup", raw)
    assert AADHAAR not in repr({k: v for k, v in out.items()})
    assert out["pii_types"] == ["aadhaar"]
    assert "[REDACTED:AADHAAR]" in out["redacted_text"]
    assert AADHAAR not in out["redacted_text"]
