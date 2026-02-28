"""Tests for explainability/explainer.py."""

import pytest
from explainability.explainer import (
    explain_incident,
    _map_mitre_techniques,
    _generate_investigation_steps,
    _explain_risk_score,
)
from conftest import make_alert, make_incident


# ---------------------------------------------------------------------------
# _map_mitre_techniques — critical classification correctness
# ---------------------------------------------------------------------------

def test_ssh_brute_force_maps_to_t1110_001():
    alerts = [make_alert("InsightOps \u2013 SSH Brute Force (Linux)")]
    techs = _map_mitre_techniques(alerts)
    ids = [t["technique_id"] for t in techs]
    assert "T1110.001" in ids


def test_ssh_brute_force_not_misclassified_as_password_spraying():
    alerts = [make_alert("InsightOps \u2013 SSH Brute Force (Linux)")]
    techs = _map_mitre_techniques(alerts)
    ids = [t["technique_id"] for t in techs]
    assert "T1110.003" not in ids


def test_password_spraying_maps_to_t1110_003():
    alerts = [make_alert("InsightOps \u2013 Password Spraying (Windows)")]
    techs = _map_mitre_techniques(alerts)
    ids = [t["technique_id"] for t in techs]
    assert "T1110.003" in ids


def test_linux_lateral_movement_maps_to_t1021_004():
    alerts = [make_alert("InsightOps \u2013 Lateral Movement (Linux)")]
    techs = _map_mitre_techniques(alerts)
    ids = [t["technique_id"] for t in techs]
    assert "T1021.004" in ids


def test_windows_lateral_movement_maps_to_t1021():
    alerts = [make_alert("InsightOps \u2013 Lateral Movement (Windows)")]
    techs = _map_mitre_techniques(alerts)
    ids = [t["technique_id"] for t in techs]
    assert "T1021" in ids
    assert "T1021.004" not in ids


def test_kerberoasting_maps_to_t1558_003():
    alerts = [make_alert("InsightOps \u2013 Kerberoasting (Windows)")]
    ids = [t["technique_id"] for t in _map_mitre_techniques(alerts)]
    assert "T1558.003" in ids


def test_credential_dumping_maps_to_t1003():
    for name in [
        "InsightOps \u2013 Credential Dumping (Windows)",
        "InsightOps \u2013 Credential Dumping (Linux)",
    ]:
        ids = [t["technique_id"] for t in _map_mitre_techniques([make_alert(name)])]
        assert "T1003" in ids


def test_linux_priv_esc_maps_to_t1548_003():
    ids = [t["technique_id"] for t in _map_mitre_techniques(
        [make_alert("InsightOps \u2013 Privilege Escalation (Linux)")]
    )]
    assert "T1548.003" in ids


def test_empty_alerts_returns_default_t1078():
    techs = _map_mitre_techniques([])
    assert techs[0]["technique_id"] == "T1078"


def test_multiple_alerts_return_deduplicated_techniques():
    alerts = [
        make_alert("InsightOps \u2013 Password Spraying (Windows)"),
        make_alert("InsightOps \u2013 Password Spraying (Linux)"),
    ]
    techs = _map_mitre_techniques(alerts)
    ids = [t["technique_id"] for t in techs]
    assert ids.count("T1110.003") == 1  # deduplicated


# ---------------------------------------------------------------------------
# _generate_investigation_steps
# ---------------------------------------------------------------------------

def test_ssh_brute_force_steps_mention_auth_log():
    alerts = [make_alert("InsightOps \u2013 SSH Brute Force (Linux)")]
    steps = _generate_investigation_steps(alerts, "alice", "dc01", 1)
    combined = " ".join(steps).lower()
    assert "auth.log" in combined


def test_ransomware_step_recommends_containment():
    alerts = [make_alert("InsightOps \u2013 Ransomware Pre-Impact (Linux)")]
    steps = _generate_investigation_steps(alerts, "alice", "dc01", 1)
    combined = " ".join(steps).lower()
    assert "containment" in combined or "isolation" in combined


def test_steps_always_end_with_document_findings():
    alerts = [make_alert("InsightOps \u2013 Password Spraying (Windows)")]
    steps = _generate_investigation_steps(alerts, "alice", "dc01", 1)
    assert "document" in steps[-1].lower()


# ---------------------------------------------------------------------------
# explain_incident — output schema
# ---------------------------------------------------------------------------

def test_explain_incident_returns_required_keys():
    inc = make_incident(["InsightOps \u2013 Password Spraying (Windows)"])
    result = explain_incident(inc, risk_score=60.0)
    for key in ("plain_english_summary", "mitre_techniques",
                "risk_score_explanation", "investigation_steps"):
        assert key in result


def test_explain_incident_summary_is_string():
    inc = make_incident(["InsightOps \u2013 Lateral Movement (Linux)"])
    result = explain_incident(inc, risk_score=75.0)
    assert isinstance(result["plain_english_summary"], str)
    assert len(result["plain_english_summary"]) > 0


def test_explain_incident_chain_summary_mentions_length():
    inc = make_incident([
        "InsightOps \u2013 Password Spraying (Windows)",
        "InsightOps \u2013 Kerberoasting (Windows)",
    ])
    result = explain_incident(inc, risk_score=80.0)
    assert "2" in result["plain_english_summary"]
