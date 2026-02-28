"""Tests for scoring/risk_scorer.py — calculate_risk_score()."""

import pytest
from scoring.risk_scorer import calculate_risk_score


def test_all_zero_inputs_score_zero():
    result = calculate_risk_score(0, 0, 0, 0)
    assert result["risk_score"] == 0.0


def test_all_max_inputs_score_100():
    result = calculate_risk_score(100, 100, 100, 100)
    assert result["risk_score"] == 100.0


def test_mid_inputs_score_50(weights_yaml):
    result = calculate_risk_score(50, 50, 50, 50, config_path=weights_yaml)
    assert result["risk_score"] == 50.0


def test_score_capped_at_100():
    result = calculate_risk_score(200, 200, 200, 200)
    assert result["risk_score"] <= 100.0


def test_score_never_negative():
    result = calculate_risk_score(-100, -100, -100, -100)
    assert result["risk_score"] >= 0.0


def test_breakdown_keys_always_present():
    result = calculate_risk_score(75, 50, 50, 25)
    bd = result["scoring_breakdown"]
    for key in (
        "severity_component",
        "host_criticality_component",
        "user_privilege_component",
        "event_frequency_component",
        "raw_score",
        "max_possible",
        "weights",
    ):
        assert key in bd, f"Missing breakdown key: {key}"


def test_higher_severity_produces_higher_score():
    low = calculate_risk_score(25, 50, 50, 50)["risk_score"]
    high = calculate_risk_score(75, 50, 50, 50)["risk_score"]
    assert high > low


def test_result_is_rounded_to_two_decimals():
    result = calculate_risk_score(33, 33, 33, 33)
    score = result["risk_score"]
    assert round(score, 2) == score
