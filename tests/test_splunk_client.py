"""Tests for ingestion/splunk_client.py — pure classification functions."""

import pytest
from ingestion.splunk_client import _alert_type_from_source, _normalize_results


# ---------------------------------------------------------------------------
# _alert_type_from_source — classification correctness
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("source, expected_name, expected_sev", [
    ("alert:InsightOps \u2013 SSH Brute Force (Linux)",
     "InsightOps \u2013 SSH Brute Force (Linux)", "low"),
    ("alert:InsightOps \u2013 Password Spraying (Windows)",
     "InsightOps \u2013 Password Spraying (Windows)", "high"),
    ("alert:InsightOps \u2013 Password Spraying (Linux)",
     "InsightOps \u2013 Password Spraying (Linux)", "high"),
    ("alert:InsightOps \u2013 Kerberoasting (Windows)",
     "InsightOps \u2013 Kerberoasting (Windows)", "critical"),
    ("alert:InsightOps \u2013 Lateral Movement (Windows)",
     "InsightOps \u2013 Lateral Movement (Windows)", "high"),
    ("alert:InsightOps \u2013 Lateral Movement (Linux)",
     "InsightOps \u2013 Lateral Movement (Linux)", "high"),
    ("alert:InsightOps \u2013 Privilege Escalation (Windows)",
     "InsightOps \u2013 Privilege Escalation (Windows)", "critical"),
    ("alert:InsightOps \u2013 Privilege Escalation (Linux)",
     "InsightOps \u2013 Privilege Escalation (Linux)", "critical"),
    ("alert:InsightOps \u2013 Persistence (Windows)",
     "InsightOps \u2013 Persistence (Windows)", "critical"),
    ("alert:InsightOps \u2013 Persistence (Linux)",
     "InsightOps \u2013 Persistence (Linux)", "critical"),
    ("alert:InsightOps \u2013 Ransomware Pre-Impact (Windows)",
     "InsightOps \u2013 Ransomware Pre-Impact (Windows)", "critical"),
    ("alert:InsightOps \u2013 Ransomware Pre-Impact (Linux)",
     "InsightOps \u2013 Ransomware Pre-Impact (Linux)", "critical"),
    ("alert:InsightOps \u2013 Credential Dumping (Windows)",
     "InsightOps \u2013 Credential Dumping (Windows)", "critical"),
    ("alert:InsightOps \u2013 Credential Dumping (Linux)",
     "InsightOps \u2013 Credential Dumping (Linux)", "critical"),
])
def test_classification_all_alert_types(source, expected_name, expected_sev):
    name, sev = _alert_type_from_source(source)
    assert name == expected_name
    assert sev == expected_sev


def test_ssh_brute_force_not_classified_as_password_spraying():
    name, sev = _alert_type_from_source("alert:InsightOps \u2013 SSH Brute Force (Linux)")
    assert "Password Spraying" not in name
    assert sev == "low"


def test_linux_lateral_not_classified_as_windows():
    name, _ = _alert_type_from_source("alert:InsightOps \u2013 Lateral Movement (Linux)")
    assert "(Linux)" in name
    assert "(Windows)" not in name


def test_linux_priv_esc_not_classified_as_windows():
    name, _ = _alert_type_from_source("alert:InsightOps \u2013 Privilege Escalation (Linux)")
    assert "(Linux)" in name


def test_none_source_returns_fallback():
    name, sev = _alert_type_from_source(None)
    assert isinstance(name, str)
    assert isinstance(sev, str)


def test_empty_source_returns_fallback():
    name, sev = _alert_type_from_source("")
    assert isinstance(name, str)


# ---------------------------------------------------------------------------
# _normalize_results — user field extraction
# ---------------------------------------------------------------------------

def _raw(results: list[dict]) -> dict:
    return {"results": results}


def test_normalize_extracts_user_field():
    raw = _raw([{"source": "alert:InsightOps \u2013 Password Spraying (Windows)",
                 "user": "alice", "host": "dc01", "_time": "2024-01-01T10:00:00"}])
    alerts = _normalize_results(raw)
    assert alerts[0]["user"] == "alice"


def test_normalize_falls_back_to_src_user():
    raw = _raw([{"source": "alert:InsightOps \u2013 Password Spraying (Windows)",
                 "src_user": "bob", "host": "dc01", "_time": "2024-01-01T10:00:00"}])
    alerts = _normalize_results(raw)
    assert alerts[0]["user"] == "bob"


def test_normalize_falls_back_to_account_name():
    raw = _raw([{"source": "alert:InsightOps \u2013 Password Spraying (Windows)",
                 "Account_Name": "carol", "host": "dc01", "_time": "2024-01-01T10:00:00"}])
    alerts = _normalize_results(raw)
    assert alerts[0]["user"] == "carol"


def test_normalize_user_none_when_no_user_field():
    raw = _raw([{"source": "alert:InsightOps \u2013 Password Spraying (Windows)",
                 "host": "dc01", "_time": "2024-01-01T10:00:00"}])
    alerts = _normalize_results(raw)
    assert alerts[0]["user"] is None


def test_normalize_extracts_source_ip():
    raw = _raw([{"source": "alert:InsightOps \u2013 Password Spraying (Windows)",
                 "src": "192.168.1.1", "host": "dc01", "_time": "2024-01-01T10:00:00"}])
    alerts = _normalize_results(raw)
    assert alerts[0]["source_ip"] == "192.168.1.1"


def test_normalize_empty_results_returns_empty():
    assert _normalize_results({"results": []}) == []


def test_normalize_skips_non_dict_rows():
    raw = _raw(["not_a_dict", 42, None])
    alerts = _normalize_results(raw)
    assert alerts == []


def test_normalize_alert_has_required_keys():
    raw = _raw([{"source": "alert:InsightOps \u2013 Kerberoasting (Windows)",
                 "host": "dc01", "_time": "2024-01-01T10:00:00"}])
    alert = _normalize_results(raw)[0]
    for key in ("alert_id", "alert_name", "severity", "host", "user", "timestamp", "source_ip"):
        assert key in alert
