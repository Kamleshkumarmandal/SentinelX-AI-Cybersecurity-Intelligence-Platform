from sentinelx_engine import analyze_event


def sample(**updates):
    event = {
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
    event.update(updates)
    return event


def test_score_is_bounded_and_explainable():
    result = analyze_event(sample())
    assert 0 <= result["risk_score"] <= 100
    assert result["risk_level"] in {"low", "medium", "high", "critical"}
    assert isinstance(result["detection_reasons"], list)


def test_obvious_demo_indicators_raise_critical_risk():
    result = analyze_event(sample(failed_attempts=20, unusual_hour=True, country="ZZ", process_name="credential-dumper"))
    assert result["risk_score"] >= 85
    assert result["risk_level"] == "critical"
    assert "Repeated authentication failures" in result["detection_reasons"]


def test_boolean_strings_are_handled():
    result = analyze_event(sample(unusual_hour="false"))
    assert "Activity during an unusual local hour" not in result["detection_reasons"]
