from app.detector import score_event


def sample(**overrides):
    data = {
        "event_type": "login_success",
        "source_ip": "192.0.2.10",
        "username": "demo-user",
        "country": "US",
        "failed_attempts": 0,
        "bytes_out": 10000,
        "unusual_hour": False,
        "process_name": "browser",
        "details": "synthetic test event",
    }
    data.update(overrides)
    return data


def test_routine_event_has_low_risk():
    result = score_event(sample())
    assert 0 <= result["risk_score"] <= 100
    assert result["risk_level"] in {"low", "medium", "high", "critical"}


def test_repeated_failures_and_suspicious_process_raise_risk():
    result = score_event(sample(failed_attempts=20, unusual_hour=True, country="ZZ", process_name="credential-dumper"))
    assert result["risk_score"] >= 85
    assert result["risk_level"] == "critical"
    assert "Repeated authentication failures" in result["detection_reasons"]
