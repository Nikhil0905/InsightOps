"""Tests for correlation/incident_builder.py — correlate_incidents()."""

import pytest
from correlation.incident_builder import correlate_incidents, _parse_timestamp
from conftest import make_alert


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

def test_empty_input_returns_empty():
    assert correlate_incidents([]) == []


def test_single_alert_becomes_single_incident():
    alerts = [make_alert("InsightOps \u2013 Password Spraying (Windows)")]
    incidents = correlate_incidents(alerts)
    assert len(incidents) == 1
    assert incidents[0]["chain_length"] == 1


# ---------------------------------------------------------------------------
# Grouping by (user, host)
# ---------------------------------------------------------------------------

def test_same_user_host_within_window_merged():
    alerts = [
        make_alert("InsightOps \u2013 Password Spraying (Windows)",
                   timestamp="2024-01-01T10:00:00"),
        make_alert("InsightOps \u2013 Kerberoasting (Windows)",
                   timestamp="2024-01-01T10:15:00"),
    ]
    incidents = correlate_incidents(alerts)
    assert len(incidents) == 1
    assert incidents[0]["chain_length"] == 2


def test_different_hosts_become_separate_incidents():
    a1 = make_alert("InsightOps \u2013 Password Spraying (Windows)",
                    host="dc01", timestamp="2024-01-01T10:00:00")
    a2 = make_alert("InsightOps \u2013 Password Spraying (Windows)",
                    host="ws02", timestamp="2024-01-01T10:00:00")
    incidents = correlate_incidents([a1, a2])
    assert len(incidents) == 2


def test_different_users_same_host_separate_incidents():
    a1 = make_alert("InsightOps \u2013 Lateral Movement (Windows)",
                    user="alice", host="dc01", timestamp="2024-01-01T10:00:00")
    a2 = make_alert("InsightOps \u2013 Lateral Movement (Windows)",
                    user="bob", host="dc01", timestamp="2024-01-01T10:00:00")
    incidents = correlate_incidents([a1, a2])
    assert len(incidents) == 2


# ---------------------------------------------------------------------------
# Time window clustering
# ---------------------------------------------------------------------------

def test_alerts_outside_window_split_into_two_incidents():
    alerts = [
        make_alert("InsightOps \u2013 Password Spraying (Windows)",
                   timestamp="2024-01-01T08:00:00"),
        make_alert("InsightOps \u2013 Kerberoasting (Windows)",
                   timestamp="2024-01-01T10:00:00"),  # 2 hours later
    ]
    incidents = correlate_incidents(alerts, time_window_minutes=30)
    assert len(incidents) == 2


def test_alerts_at_exact_window_boundary_merged():
    alerts = [
        make_alert("InsightOps \u2013 Password Spraying (Windows)",
                   timestamp="2024-01-01T10:00:00"),
        make_alert("InsightOps \u2013 Kerberoasting (Windows)",
                   timestamp="2024-01-01T10:30:00"),  # exactly 30 min
    ]
    incidents = correlate_incidents(alerts, time_window_minutes=30)
    assert len(incidents) == 1


# ---------------------------------------------------------------------------
# Incident schema
# ---------------------------------------------------------------------------

def test_incident_has_required_keys():
    alerts = [make_alert("InsightOps \u2013 Password Spraying (Windows)")]
    inc = correlate_incidents(alerts)[0]
    for key in ("incident_id", "alerts", "chain_length", "user", "host", "time_range"):
        assert key in inc


def test_incident_id_is_unique():
    a1 = make_alert("InsightOps \u2013 Password Spraying (Windows)", host="h1")
    a2 = make_alert("InsightOps \u2013 Password Spraying (Windows)", host="h2")
    incidents = correlate_incidents([a1, a2])
    ids = [i["incident_id"] for i in incidents]
    assert len(set(ids)) == len(ids)


# ---------------------------------------------------------------------------
# Timestamp parsing
# ---------------------------------------------------------------------------

def test_parse_timestamp_none_returns_epoch():
    from datetime import datetime
    result = _parse_timestamp(None)
    assert result == datetime.fromtimestamp(0)


def test_parse_timestamp_iso_string():
    result = _parse_timestamp("2024-01-01T10:00:00")
    assert result.year == 2024
    assert result.hour == 10
