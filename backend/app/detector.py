import json
import numpy as np
from sklearn.ensemble import IsolationForest

FEATURES = ["failed_attempts", "bytes_out", "unusual_hour", "foreign_login", "suspicious_process"]


def _build_model() -> IsolationForest:
    rng = np.random.default_rng(41)
    baseline = np.column_stack([
        rng.poisson(0.15, 600),
        rng.lognormal(8.0, 0.7, 600),
        rng.binomial(1, 0.08, 600),
        rng.binomial(1, 0.04, 600),
        rng.binomial(1, 0.01, 600),
    ])
    model = IsolationForest(n_estimators=120, contamination=0.04, random_state=41)
    model.fit(baseline)
    return model


_MODEL = _build_model()
SUSPICIOUS_PROCESSES = {"encoded-powershell", "unknown-binary", "credential-dumper", "unsigned-script"}
KNOWN_COUNTRIES = {"US", "IN", "GB", "DE", "CA", "AU", "FR", "SG"}


def score_event(data: dict) -> dict:
    reasons: list[str] = []
    failed = int(data.get("failed_attempts", 0))
    bytes_out = int(data.get("bytes_out", 0))
    unusual = bool(data.get("unusual_hour", False))
    country = str(data.get("country", "unknown")).upper()
    process = str(data.get("process_name", "unknown")).lower()

    if failed >= 8:
        reasons.append("Repeated authentication failures")
    elif failed >= 4:
        reasons.append("Elevated authentication failures")
    if bytes_out >= 50_000_000:
        reasons.append("Unusually large outbound data volume")
    if unusual:
        reasons.append("Activity during an unusual local hour")
    if country not in KNOWN_COUNTRIES:
        reasons.append("Login country is outside the demo baseline")
    if process in SUSPICIOUS_PROCESSES:
        reasons.append("Process name matches a high-risk demo indicator")

    vector = np.array([[failed, bytes_out, int(unusual), int(country not in KNOWN_COUNTRIES), int(process in SUSPICIOUS_PROCESSES)]], dtype=float)
    anomaly = int(_MODEL.predict(vector)[0] == -1)
    raw_score = 12 + min(failed * 5, 40) + min(bytes_out / 2_000_000, 25) + (12 if unusual else 0) + (12 if country not in KNOWN_COUNTRIES else 0) + (25 if process in SUSPICIOUS_PROCESSES else 0)
    if anomaly:
        raw_score += 12
        reasons.append("Isolation Forest marked the event as statistically unusual")
    score = float(min(100, round(raw_score, 1)))
    level = "critical" if score >= 85 else "high" if score >= 65 else "medium" if score >= 40 else "low"
    return {"risk_score": score, "risk_level": level, "detection_reasons": json.dumps(reasons)}
