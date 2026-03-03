from types import SimpleNamespace

from app.triage import TriageEngine


def test_aggregate_prefers_highest_non_info():
    decisions = [
        SimpleNamespace(fingerprint="a", severity="info", reason="i", matched_rules=[]),
        SimpleNamespace(fingerprint="b", severity="warning", reason="w", matched_rules=["r1"]),
        SimpleNamespace(fingerprint="c", severity="high", reason="h", matched_rules=["r2"]),
    ]
    response = TriageEngine._aggregate_alert_decisions("inc-1", decisions)
    assert response.recommended_severity == "high"
    assert response.reason == "h"
    assert response.validated_fingerprints == ["a", "b", "c"]
    assert set(response.matched_rules) == {"r1", "r2"}


def test_aggregate_returns_info_only_when_all_info():
    decisions = [
        SimpleNamespace(fingerprint="a", severity="info", reason="i1", matched_rules=[]),
        SimpleNamespace(fingerprint="b", severity="info", reason="i2", matched_rules=[]),
    ]
    response = TriageEngine._aggregate_alert_decisions("inc-2", decisions)
    assert response.recommended_severity == "info"


def test_normalize_decision_falls_back_when_no_matches():
    severity, reason, matched = TriageEngine._normalize_decision(
        {
            "recommended_severity": "critical",
            "reason": "critical signal",
            "matched_rule_ids": [],
        },
        candidate_ids={"x"},
    )
    assert severity == "warning"
    assert "fallback" in reason.lower()
    assert matched == []
