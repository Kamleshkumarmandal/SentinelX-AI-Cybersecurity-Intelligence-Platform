from pathlib import Path

import pandas as pd

REQUIRED = {
    "event_type", "source_ip", "username", "country", "failed_attempts",
    "bytes_out", "unusual_hour", "process_name", "details",
}


def test_demo_dataset_has_required_fields_and_records():
    path = Path(__file__).parents[1] / "sample_data" / "security_events.csv"
    frame = pd.read_csv(path)
    assert REQUIRED.issubset(frame.columns)
    assert len(frame) >= 10
