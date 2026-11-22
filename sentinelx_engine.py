"""Explainable event scoring for the SentinelX Streamlit demo.

The model is trained on deterministic synthetic baseline data. It is intended
for education and portfolio demonstration, not production security decisions.
"""
from __future__ import annotations

import json
from functools import lru_cache
from typing import Any, Mapping

import numpy as np
from sklearn.ensemble import IsolationForest

SUSPICIOUS_PROCESSES = {
    "encoded-powershell",
    "unknown-binary",
    "credential-dumper",
    "unsigned-script",
}
KNOWN_COUNTRIES = {"US", "IN", "GB", "DE", "CA", "AU", "FR", "SG"}
FEATURE_COLUMNS = (
    "failed_attempts",
    "bytes_out",
    "unusual_hour",
    "foreign_login",
    "suspicious_process",
)


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


@lru_cache(maxsize=1)
def _model() -> IsolationForest:
    rng = np.random.default_rng(41)
    baseline = np.column_stack(
        [
            rng.poisson(0.15, 600),
            rng.lognormal(8.0, 0.7, 600),
            rng.binomial(1, 0.08, 600),
            rng.binomial(1, 0.04, 600),
            rng.binomial(1, 0.01, 600),
        ]
    )
    detector = IsolationForest(
        n_estimators=120,
        contamination=0.04,
        random_state=41,
    )
    detector.fit(baseline)
    return detector


def analyze_event(event: Mapping[str, Any]) -> dict[str, Any]:
    """Return a bounded risk score, severity and human-readable reasons."""
    try:
        failed = max(0, int(float(event.get("failed_attempts", 0) or 0)))
    except (TypeError, ValueError):
        failed = 0
    try:
        bytes_out = max(0, int(float(event.get("bytes_out", 0) or 0)))
    except (TypeError, ValueError):
        bytes_out = 0

    unusual = _as_bool(event.get("unusual_hour", False))
    country = str(event.get("country", "unknown") or "unknown").strip().upper()
    process = str(event.get("process_name", "unknown") or "unknown").strip().lower()
    foreign_login = int(country not in KNOWN_COUNTRIES)
    suspicious_process = int(process in SUSPICIOUS_PROCESSES)

    reasons: list[str] = []
    if failed >= 8:
        reasons.append("Repeated authentication failures")
    elif failed >= 4:
        reasons.append("Elevated authentication failures")
    if bytes_out >= 50_000_000:
        reasons.append("Unusually large outbound data volume")
    if unusual:
        reasons.append("Activity during an unusual local hour")
    if foreign_login:
        reasons.append("Login country is outside the demo baseline")
    if suspicious_process:
        reasons.append("Process name matches a high-risk demo indicator")

    vector = np.array(
        [[failed, bytes_out, int(unusual), foreign_login, suspicious_process]],
        dtype=float,
    )
    anomaly = int(_model().predict(vector)[0] == -1)
    raw_score = (
        12
        + min(failed * 5, 40)
        + min(bytes_out / 2_000_000, 25)
        + (12 if unusual else 0)
        + (12 if foreign_login else 0)
        + (25 if suspicious_process else 0)
    )
    if anomaly:
        raw_score += 12
        reasons.append("Isolation Forest marked the event as statistically unusual")

    score = float(min(100, round(raw_score, 1)))
    level = (
        "critical" if score >= 85
        else "high" if score >= 65
        else "medium" if score >= 40
        else "low"
    )
    return {
        "risk_score": score,
        "risk_level": level,
        "detection_reasons": reasons,
        "anomaly_flag": bool(anomaly),
    }


def analyze_events(records: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Analyze a collection while preserving each event's original fields."""
    analyzed = []
    for record in records:
        item = dict(record)
        item.update(analyze_event(item))
        analyzed.append(item)
    return analyzed


def reasons_as_json(reasons: list[str]) -> str:
    """Stable JSON representation useful when exporting alert records."""
    return json.dumps(reasons, ensure_ascii=False)
