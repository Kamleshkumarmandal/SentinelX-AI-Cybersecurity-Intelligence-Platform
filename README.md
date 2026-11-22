# SentinelX — AI Cybersecurity Intelligence Platform

SentinelX is a defensive security-operations portfolio MVP combining a full-stack dashboard, Python API, explainable detection rules, anomaly scoring, alert triage, and audit history.

> **Current implementation:** runnable local MVP with a React/Vite dashboard and FastAPI backend. The detector combines transparent rule-based indicators with an Isolation Forest trained on generated baseline data. It is not a production SIEM and it does not connect to live threat feeds.

## Preview

- **Dashboard:** security overview, 7-day event trend, alert severity distribution
- **Alert queue:** search, severity filter, and new / investigating / resolved workflow
- **Event stream:** normalized telemetry with risk scores and detection reasons
- **Audit trail:** records event ingestion and alert status changes
- **Demo data:** safe synthetic telemetry using documentation-only IP ranges

## Technology

| Layer | Tools |
| --- | --- |
| Frontend | React, Vite, Lucide icons, responsive CSS |
| API | Python, FastAPI, Pydantic |
| Data | SQLAlchemy, SQLite |
| Detection | scikit-learn Isolation Forest + explainable rules |
| Authentication | JWT bearer tokens, PBKDF2 password hashing, role checks |
| Delivery | Docker, Docker Compose, pytest |

## Quick start with Docker

1. Install Docker Desktop or Docker Engine with the Compose plugin.
2. Clone this repository and switch to the development branch:

   ```bash
   git clone https://github.com/Kamleshkumarmandal/SentinelX-AI-Cybersecurity-Intelligence-Platform.git
   cd SentinelX-AI-Cybersecurity-Intelligence-Platform
   git checkout sentinelx-development
   ```

3. Copy the environment template and change the local admin password and secret:

   ```bash
   cp .env.example .env
   ```

4. Start the services:

   ```bash
   docker compose up --build
   ```

5. Open the dashboard at http://localhost:5173. The API and interactive docs are at http://localhost:8000 and http://localhost:8000/docs.

The initial admin account is created from ADMIN_EMAIL and ADMIN_PASSWORD on first startup. The values in the template are for local demonstration only. Replace them before use, and never expose the demo credentials or local secret on a public deployment.

## Run without Docker

### Backend

Use Python 3.11 or newer.

```bash
cd backend
python -m venv .venv
# macOS/Linux:
source .venv/bin/activate
# Windows PowerShell:
# .venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Set environment variables before first startup as needed:

- ADMIN_EMAIL
- ADMIN_PASSWORD
- SECRET_KEY
- DATABASE_URL (defaults to a local SQLite file)

### Frontend

In a second terminal:

```bash
cd frontend
npm install
npm run dev
```

The Vite app expects the API at http://localhost:8000/api by default. Set VITE_API_URL to override it.

## First-run workflow

1. Sign in using the admin email and password configured in the backend environment.
2. Select **Load demo telemetry** to insert a safe synthetic dataset. The seed endpoint skips insertion when events already exist.
3. Review alert scores and reasons in **Alert queue**.
4. Change an alert to **Investigating** or **Resolved**. Changes are recorded in **Audit trail**.
5. Use **Generate test event** to send one additional synthetic event through the detector.

The seeded event dataset is illustrative, not a real incident feed. It deliberately includes a mixture of ordinary and suspicious-looking records for demonstration.

## API overview

All application endpoints are under /api.

| Method | Endpoint | Access | Purpose |
| --- | --- | --- | --- |
| GET | /health | Public | Service health |
| POST | /auth/login | Public | Issue a JWT bearer token |
| GET | /auth/me | Authenticated | Current user and role |
| GET | /summary | Authenticated | Dashboard KPIs and 7-day trend |
| GET | /events | Authenticated | Recent analyzed events |
| POST | /events | Analyst / admin | Validate and score an event |
| GET | /alerts | Authenticated | List alerts with optional filters |
| PATCH | /alerts/{id} | Analyst / admin | Change alert status |
| GET | /audit | Authenticated | Recent audit entries |
| POST | /demo/seed | Analyst / admin | Load synthetic starter telemetry |

OpenAPI documentation is generated at /docs when the backend is running.

## Detection model

SentinelX creates a 0–100 risk score from bounded event fields, including authentication failures, outbound byte volume, unusual-hour activity, country baseline deviation, and a small set of demo process indicators. It adds an anomaly signal from an Isolation Forest trained at startup on synthetic baseline vectors. Reasons are stored with each event and displayed in the event stream and associated alert.

This is a demonstration detector, not a calibrated production model. Evaluate it on representative labelled data before relying on it. Do not interpret its output as proof of compromise.

## Tests

```bash
cd backend
pytest
```

Tests cover password hashing and core risk scoring. Add integration tests and model evaluation as the API evolves.

## Security notes and limitations

- Use only authorized, synthetic, or properly approved telemetry.
- No network scanning, exploitation, malware execution, uploaded-file execution, or third-party threat feed ingestion is implemented.
- The local demo uses a bearer token in browser storage for convenience. Production deployments should use secure HttpOnly cookies or an equivalent hardened session design, TLS, CSRF protection, rate limits, MFA/SSO, and a managed secret store.
- The sample admin credentials must be changed. Rotate SECRET_KEY and use a managed database for any shared environment.
- SQLite, in-process model fitting, and the current role model are intended for a single-instance portfolio demo.
- Apply dependency updates, code review, backups, monitoring, retention controls, and a documented incident-response process before operational use.

See [docs/architecture.md](docs/architecture.md) for data flow and the production-hardening checklist.

## License

MIT. See [LICENSE](LICENSE).
