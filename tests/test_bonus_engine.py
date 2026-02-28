"""Tests for correlation/bonus_engine.py."""

import pytest
from correlation.bonus_engine import apply_correlation_bonuses, load_correlation_bonus
from conftest import make_incident

BONUS = 10.0  # fixed bonus for all tests


# ---------------------------------------------------------------------------
# load_correlation_bonus
# ---------------------------------------------------------------------------

def test_load_correlation_bonus_reads_yaml(weights_yaml):
    bonus = load_correlation_bonus(config_path=weights_yaml)
    assert bonus == 10.0


def test_load_correlation_bonus_falls_back_on_missing_file(tmp_path):
    bonus = load_correlation_bonus(config_path=tmp_path / "nonexistent.yaml")
    assert bonus == 15.0


def test_load_correlation_bonus_falls_back_on_invalid_value(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("correlation_bonus: not_a_number\n")
    assert load_correlation_bonus(config_path=p) == 15.0


# ---------------------------------------------------------------------------
# apply_correlation_bonuses — no bonus cases
# ---------------------------------------------------------------------------

def test_empty_incidents_returns_empty():
    result = apply_correlation_bonuses([], BONUS)
    assert result == []


def test_zero_bonus_no_mutation():
    inc = make_incident(["InsightOps \u2013 Password Spraying (Windows)"], base_risk=50.0)
    apply_correlation_bonuses([inc], correlation_bonus=0.0)
    assert inc["incident_risk_score"] == 50.0
    assert "correlation_bonus_component" not in (inc.get("_scoring_breakdown") or {})


def test_single_unmatched_alert_no_bonus():
    inc = make_incident(["InsightOps \u2013 SSH Brute Force (Linux)"], base_risk=30.0)
    apply_correlation_bonuses([inc], BONUS)
    assert inc["incident_risk_score"] == 30.0


# ---------------------------------------------------------------------------
# apply_correlation_bonuses — bonus cases
# ---------------------------------------------------------------------------

def test_password_spraying_solo_gets_medium_bonus():
    inc = make_incident(["InsightOps \u2013 Password Spraying (Windows)"], base_risk=40.0)
    apply_correlation_bonuses([inc], BONUS)
    # 0.5 × BONUS = 5.0
    assert inc["incident_risk_score"] == pytest.approx(45.0)
    assert inc["_scoring_breakdown"]["correlation_bonus_component"] == pytest.approx(5.0)


def test_ps_linux_also_gets_medium_bonus():
    inc = make_incident(["InsightOps \u2013 Password Spraying (Linux)"], base_risk=40.0)
    apply_correlation_bonuses([inc], BONUS)
    assert inc["incident_risk_score"] == pytest.approx(45.0)


def test_ps_plus_kerberoasting_stacks_bonus():
    inc = make_incident([
        "InsightOps \u2013 Password Spraying (Windows)",
        "InsightOps \u2013 Kerberoasting (Windows)",
    ], base_risk=40.0)
    apply_correlation_bonuses([inc], BONUS)
    # 0.5×10 (PS) + 10 (PS+KB) = 15
    assert inc["_scoring_breakdown"]["correlation_bonus_component"] == pytest.approx(15.0)


def test_privilege_escalation_chain_bonus():
    inc = make_incident([
        "InsightOps \u2013 Password Spraying (Windows)",
        "InsightOps \u2013 Privilege Escalation (Windows)",
    ], base_risk=40.0)
    apply_correlation_bonuses([inc], BONUS)
    bonus = inc["_scoring_breakdown"]["correlation_bonus_component"]
    # At minimum: PS medium (5) + PE chain (10) = 15
    assert bonus >= 15.0


def test_ransomware_caps_score_at_100():
    inc = make_incident([
        "InsightOps \u2013 Lateral Movement (Linux)",
        "InsightOps \u2013 Ransomware Pre-Impact (Linux)",
    ], base_risk=90.0)
    apply_correlation_bonuses([inc], BONUS)
    assert inc["incident_risk_score"] == 100.0


def test_credential_dumping_any_gets_bonus():
    for cd_name in [
        "InsightOps \u2013 Credential Dumping (Windows)",
        "InsightOps \u2013 Credential Dumping (Linux)",
    ]:
        inc = make_incident([cd_name], base_risk=50.0)
        apply_correlation_bonuses([inc], BONUS)
        assert inc["incident_risk_score"] > 50.0


def test_linux_lateral_movement_bonus():
    inc = make_incident(["InsightOps \u2013 Lateral Movement (Linux)"], base_risk=50.0)
    apply_correlation_bonuses([inc], BONUS)
    assert inc["incident_risk_score"] == pytest.approx(60.0)


def test_bonus_component_written_to_breakdown():
    inc = make_incident(["InsightOps \u2013 Credential Dumping (Windows)"], base_risk=50.0)
    apply_correlation_bonuses([inc], BONUS)
    assert "correlation_bonus_component" in inc["_scoring_breakdown"]


def test_multiple_incidents_processed_independently():
    inc_a = make_incident(["InsightOps \u2013 Password Spraying (Windows)"], base_risk=40.0)
    inc_b = make_incident(["InsightOps \u2013 Kerberoasting (Windows)"], base_risk=60.0)
    apply_correlation_bonuses([inc_a, inc_b], BONUS)
    # PS gets 0.5 bonus, KB alone gets nothing
    assert inc_a["incident_risk_score"] == pytest.approx(45.0)
    assert inc_b["incident_risk_score"] == pytest.approx(60.0)
