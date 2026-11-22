# SentinelX — AI Cybersecurity Intelligence Platform

SentinelX is a browser-based security operations dashboard for exploring security events, detecting suspicious activity, prioritizing alerts, and reviewing explainable risk scores. It combines machine-learning anomaly detection with transparent security rules in a Streamlit application.

Project Live:
https://sentinelx-ai-cybersecurity-intelligence-platform-mys6tea6erq8d.streamlit.app/

**Repository:** [Kamleshkumarmandal/SentinelX-AI-Cybersecurity-Intelligence-Platform](https://github.com/Kamleshkumarmandal/SentinelX-AI-Cybersecurity-Intelligence-Platform)

## Features

- Load the included synthetic security-event dataset or import your own CSV.
- Explore event types, source IP addresses, user identities, countries, processes, and timestamps.
- Score events with an Isolation Forest anomaly model and explainable detection rules.
- Prioritize critical, high, and medium-risk events in an analyst alert queue.
- Review risk distribution and event activity with interactive charts.
- Analyze a test event manually with configurable authentication, transfer, process, and time indicators.
- Update alert dispositions during the current Streamlit session.
- Export analyzed events and risk explanations to CSV.
- Run automated tests with GitHub Actions CI.

## Run locally

Python 3.10 or newer is recommended.

### Windows PowerShell

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
streamlit run app.py
```

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
streamlit run app.py
```

Streamlit will print a local URL, usually http://localhost:8501.

## Explore the sample dataset

The app opens with the synthetic events in `sample_data/security_events.csv`.

The dataset includes examples of:

- `login_success`: routine sign-in activity.
- `login_failure`: failed authentication attempts, including a repeated-failure pattern.
- `data_transfer`: ordinary and unusually large outbound transfers.
- `process_alert`: demo process indicators for analyst review.
- `api_access`: synthetic service and integration activity.

All sample IP addresses use documentation-only ranges, and the records do not represent real people, devices, or incidents.

## Analyze a security event

Open **Analyze event** in the sidebar and provide an event type, source IP, username, country code, failed-attempt count, outbound byte count, unusual-hour flag, and process name. SentinelX returns a risk score, severity level, anomaly flag, and readable detection reasons.

Use **Alert queue** to review findings with risk scores of 40 or higher. The demo lets you change an alert's disposition to `new`, `investigating`, or `resolved`. These dispositions are stored in the current Streamlit session and are not persisted to a user account or database.

## Import your own events

Open **Import data** and upload a CSV file. The CSV must contain these columns:

```text
event_type, source_ip, username, country, failed_attempts,
bytes_out, unusual_hour, process_name, details
```

The importer accepts CSV files with up to 50,000 rows. Imported records are processed in the active Streamlit session. Use synthetic, sanitized, or explicitly authorized telemetry only; do not upload confidential records to a public demo.

## Detection method

SentinelX combines two types of signal:

1. **Explainable rules** identify repeated authentication failures, unusually large outbound data volume, activity during an unusual hour, country codes outside the demo baseline, and selected high-risk process names.
2. **Isolation Forest** scores statistical outliers. The demo model is trained at startup on deterministic synthetic baseline data so results are reproducible.

The resulting score is bounded from 0 to 100 and mapped to low, medium, high, or critical severity. Reasons are shown alongside the score so analysts can understand which indicators contributed to the finding.

This is a portfolio demonstration, not a calibrated production detection model. A high score is not proof of compromise. Evaluate model quality against representative, labelled data before considering operational use.

## Tests

Install development dependencies and run:

```bash
pip install -r requirements-dev.txt
pytest -q
```

GitHub Actions runs the test suite when changes are pushed to `main` or a pull request targets `main`.

## Deploy on Streamlit Community Cloud

1. Sign in to [Streamlit Community Cloud](https://share.streamlit.io/).
2. Choose **New app** and select this repository.
3. Select the `main` branch.
4. Set the main file path to `app.py`.
5. Deploy the app. Streamlit Community Cloud will install the dependencies from `requirements.txt`.

The repository includes theme settings in `.streamlit/config.toml`.

## Security and privacy notes

- SentinelX does not scan networks, exploit systems, execute malware, or run uploaded files.
- The included dataset is synthetic and uses documentation-only IP ranges.
- Imported data and analyst dispositions are held in the active Streamlit session; this demo does not save them to a persistent database.
- Do not upload sensitive or confidential information to a public hosted demo.
- The model is a demonstration and must not be used as the sole basis for security decisions.

## Project structure

```text
.
├── .github/
│   └── workflows/
│       └── ci.yml
├── .streamlit/
│   └── config.toml
├── sample_data/
│   └── security_events.csv
├── tests/
│   ├── conftest.py
│   ├── test_detector.py
│   └── test_sample_data.py
├── app.py
├── sentinelx_engine.py
├── requirements.txt
├── requirements-dev.txt
├── .gitignore
├── LICENSE
└── README.md
```

## Data and license

The sample security events are synthetic demonstration data. SentinelX is released under the MIT License; see [LICENSE](LICENSE).
