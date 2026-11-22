# SentinelX Architecture

## Component map

- React + Vite dashboard: authentication, operational overview, alert queue, event stream, and audit trail.
- FastAPI service: token authentication, role checks, event ingestion, summary aggregation, and alert workflow.
- SQLite via SQLAlchemy: users, security events, alerts, and audit records. The configuration can point to another SQLAlchemy-compatible database after testing.
- Detection service: deterministic rule signals combined with a small Isolation Forest model trained on generated baseline data.

## Event lifecycle

1. An analyst sends a validated event to POST /api/events.
2. The detector calculates a 0-100 risk score, severity band, and human-readable reasons.
3. Events scoring 40 or above create an alert.
4. Analysts move alerts between new, investigating, and resolved. Changes are written to the audit table.
5. The dashboard requests summary metrics, alerts, events, and audit actions from the API.

## Trust boundaries

- All event data is treated as untrusted input and validated by Pydantic.
- JWT sessions protect non-health endpoints. Analyst and admin roles are required for ingestion and state changes; viewer role is read-only.
- No payload execution, exploit code, active scanning, or live third-party threat feed is included.
- Synthetic IP ranges and generated events are used for the demonstration dataset.

## Production hardening checklist

- Use managed PostgreSQL, TLS, secret manager, secure HttpOnly cookies, CSRF protections, rate limiting, and centralized logs.
- Enforce MFA/SSO, account provisioning, least privilege, retention controls, and backups.
- Add model evaluation against a labelled, representative dataset and monitor false-positive/false-negative rates.
- Add tenant isolation, immutable external audit storage, observability, alert delivery, and incident response runbooks.
- Pin frontend package versions and run dependency/security scanning in CI.
