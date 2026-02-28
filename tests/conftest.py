"""
Shared pytest fixtures for InsightOps test suite.
"""

import pytest
from pathlib import Path


# ---------------------------------------------------------------------------
# Weights file fixture — provides a real (temp) weights.yaml so tests that
# call load_correlation_bonus() or calculate_risk_score() don't need mocking.
# ---------------------------------------------------------------------------

@pytest.fixture()
def weights_yaml(tmp_path: Path) -> Path:
    """Minimal weights.yaml with known static values."""
    p = tmp_path / "weights.yaml"
    p.write_text(
        "base_severity: 1.0\n"
        "host_criticality: 1.0\n"
        "user_privilege: 1.0\n"
        "behavioral_frequency: 1.0\n"
        "correlation_bonus: 10.0\n"
    )
    return p


# ---------------------------------------------------------------------------
# Alert / incident factory helpers
# ---------------------------------------------------------------------------

def make_alert(
    name: str,
    severity: str = "high",
    risk_score: float = 50.0,
    user: str | None = "alice",
    host: str | None = "dc01",
    timestamp: str = "2024-01-01T10:00:00",
) -> dict:
    return {
        "alert_id": "test-id",
        "alert_name": name,
        "severity": severity,
        "user": user,
        "host": host,
        "timestamp": timestamp,
        "risk_score": risk_score,
        "scoring_breakdown": {
            "severity_component": risk_score * 0.25,
            "host_criticality_component": risk_score * 0.25,
            "user_privilege_component": risk_score * 0.25,
            "event_frequency_component": risk_score * 0.25,
        },
    }


def make_incident(alert_names: list[str], base_risk: float = 50.0) -> dict:
    """Build a minimal incident dict as produced by correlate_incidents()."""
    alerts = [make_alert(n, risk_score=base_risk) for n in alert_names]
    return {
        "incident_id": "inc-test",
        "alerts": alerts,
        "chain_length": len(alerts),
        "user": alerts[0]["user"],
        "host": alerts[0]["host"],
        "time_range": {"start": alerts[0]["timestamp"], "end": alerts[-1]["timestamp"]},
    }
