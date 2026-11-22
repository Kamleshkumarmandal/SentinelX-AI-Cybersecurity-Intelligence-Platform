import json
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import func
from sqlalchemy.orm import Session, joinedload

from .config import settings
from .database import Base, engine, get_db, SessionLocal
from .detector import score_event
from .models import Alert, AuditLog, SecurityEvent, User, utcnow
from .schemas import AlertOut, AlertStatusUpdate, EventCreate, EventOut, TokenOut, UserOut
from .security import create_access_token, get_current_user, hash_password, require_analyst, verify_password


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.email == settings.admin_email).first()
        if not admin:
            db.add(User(email=settings.admin_email, password_hash=hash_password(settings.admin_password), role="admin"))
            db.commit()
    finally:
        db.close()
    yield


app = FastAPI(title=settings.app_name, version="0.1.0", description="Defensive security event scoring and alert triage API", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=[x.strip() for x in settings.cors_origins.split(",") if x.strip()], allow_credentials=True, allow_methods=["GET", "POST", "PATCH"], allow_headers=["Authorization", "Content-Type"])


def record_audit(db: Session, actor: str, action: str, target: str, details: str = "") -> None:
    db.add(AuditLog(actor_email=actor, action=action, target=target, details=details))


def event_payload(event: SecurityEvent) -> dict:
    data = {column.name: getattr(event, column.name) for column in event.__table__.columns}
    data["detection_reasons"] = json.loads(event.detection_reasons or "[]")
    return data


def alert_payload(alert: Alert) -> dict:
    return {
        "id": alert.id,
        "event_id": alert.event_id,
        "title": alert.title,
        "description": alert.description,
        "severity": alert.severity,
        "status": alert.status,
        "assigned_to": alert.assigned_to,
        "created_at": alert.created_at,
        "updated_at": alert.updated_at,
        "event": event_payload(alert.event),
    }


def create_event(db: Session, payload: dict) -> SecurityEvent:
    scored = score_event(payload)
    event = SecurityEvent(**payload, **scored)
    db.add(event)
    db.flush()
    if event.risk_score >= 40:
        severity = "critical" if event.risk_score >= 85 else "high" if event.risk_score >= 65 else "medium"
        reasons = json.loads(event.detection_reasons or "[]")
        description = "; ".join(reasons) or "An event exceeded the detection threshold"
        db.add(Alert(event_id=event.id, title=f"{event.event_type.replace('_', ' ').title()} detected", description=description, severity=severity))
    return event


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "sentinelx-api", "version": "0.1.0"}


@app.post("/api/auth/login", response_model=TokenOut)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form.username.lower()).first()
    if not user or not verify_password(form.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    return {"access_token": create_access_token(user.email), "token_type": "bearer"}


@app.get("/api/auth/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user


@app.get("/api/summary")
def summary(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    total_events = db.query(func.count(SecurityEvent.id)).scalar() or 0
    total_alerts = db.query(func.count(Alert.id)).scalar() or 0
    open_alerts = db.query(func.count(Alert.id)).filter(Alert.status != "resolved").scalar() or 0
    critical = db.query(func.count(Alert.id)).filter(Alert.severity == "critical", Alert.status != "resolved").scalar() or 0
    avg_risk = db.query(func.avg(SecurityEvent.risk_score)).scalar() or 0
    since = utcnow() - timedelta(days=6)
    rows = db.query(func.date(SecurityEvent.created_at), func.count(SecurityEvent.id)).filter(SecurityEvent.created_at >= since).group_by(func.date(SecurityEvent.created_at)).all()
    trend_map = {str(day): count for day, count in rows}
    trend = []
    for offset in range(6, -1, -1):
        day = (utcnow() - timedelta(days=offset)).date().isoformat()
        trend.append({"date": day, "events": trend_map.get(day, 0)})
    return {"total_events": total_events, "total_alerts": total_alerts, "open_alerts": open_alerts, "critical_alerts": critical, "average_risk": round(float(avg_risk), 1), "trend": trend}


@app.get("/api/events", response_model=list[EventOut])
def list_events(limit: int = Query(default=50, ge=1, le=200), db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    events = db.query(SecurityEvent).order_by(SecurityEvent.created_at.desc()).limit(limit).all()
    return [event_payload(event) for event in events]


@app.post("/api/events", response_model=EventOut, status_code=201)
def ingest_event(payload: EventCreate, db: Session = Depends(get_db), user: User = Depends(require_analyst)):
    event = create_event(db, payload.model_dump())
    record_audit(db, user.email, "event.ingest", f"event:{event.id}", f"risk_score={event.risk_score}")
    db.commit()
    db.refresh(event)
    return event_payload(event)


@app.get("/api/alerts", response_model=list[AlertOut])
def list_alerts(status_filter: str | None = Query(default=None, alias="status"), severity: str | None = None, limit: int = Query(default=100, ge=1, le=200), db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    query = db.query(Alert).options(joinedload(Alert.event)).order_by(Alert.created_at.desc())
    if status_filter:
        query = query.filter(Alert.status == status_filter)
    if severity:
        query = query.filter(Alert.severity == severity)
    return [alert_payload(alert) for alert in query.limit(limit).all()]


@app.patch("/api/alerts/{alert_id}", response_model=AlertOut)
def update_alert(alert_id: int, payload: AlertStatusUpdate, db: Session = Depends(get_db), user: User = Depends(require_analyst)):
    alert = db.query(Alert).options(joinedload(Alert.event)).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    old_status = alert.status
    alert.status = payload.status
    alert.assigned_to = user.email if payload.status != "resolved" else alert.assigned_to
    alert.updated_at = utcnow()
    record_audit(db, user.email, "alert.status_change", f"alert:{alert.id}", f"{old_status} -> {payload.status}")
    db.commit()
    db.refresh(alert)
    return alert_payload(alert)


@app.get("/api/audit")
def list_audit(limit: int = Query(default=30, ge=1, le=200), db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    rows = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit).all()
    return [{"id": r.id, "actor_email": r.actor_email, "action": r.action, "target": r.target, "details": r.details, "created_at": r.created_at} for r in rows]


@app.post("/api/demo/seed")
def seed_demo(db: Session = Depends(get_db), user: User = Depends(require_analyst)):
    if db.query(SecurityEvent).count() > 0:
        return {"created": 0, "message": "Events already exist; demo seed skipped."}
    samples = [
        {"event_type": "login_success", "source_ip": "203.0.113.10", "username": "maria", "country": "US", "failed_attempts": 0, "bytes_out": 12000, "unusual_hour": False, "process_name": "browser", "details": "Routine synthetic login"},
        {"event_type": "login_failure", "source_ip": "203.0.113.24", "username": "alex", "country": "IN", "failed_attempts": 2, "bytes_out": 0, "unusual_hour": False, "process_name": "browser", "details": "Two failed sign-in attempts"},
        {"event_type": "login_failure", "source_ip": "198.51.100.77", "username": "finance-admin", "country": "ZZ", "failed_attempts": 14, "bytes_out": 0, "unusual_hour": True, "process_name": "browser", "details": "Synthetic repeated login failures from an unfamiliar region"},
        {"event_type": "data_transfer", "source_ip": "203.0.113.45", "username": "service-account", "country": "GB", "failed_attempts": 0, "bytes_out": 98000000, "unusual_hour": True, "process_name": "unknown-binary", "details": "Synthetic unusually large outbound transfer"},
        {"event_type": "process_alert", "source_ip": "192.0.2.50", "username": "workstation-12", "country": "US", "failed_attempts": 0, "bytes_out": 4000, "unusual_hour": False, "process_name": "unsigned-script", "details": "Synthetic process indicator for analyst triage"},
        {"event_type": "login_success", "source_ip": "192.0.2.80", "username": "jules", "country": "DE", "failed_attempts": 0, "bytes_out": 20000, "unusual_hour": False, "process_name": "browser", "details": "Routine synthetic login"},
        {"event_type": "api_access", "source_ip": "203.0.113.90", "username": "integration", "country": "SG", "failed_attempts": 1, "bytes_out": 60000, "unusual_hour": False, "process_name": "python-client", "details": "Synthetic service API activity"},
        {"event_type": "login_failure", "source_ip": "198.51.100.11", "username": "root", "country": "RU", "failed_attempts": 9, "bytes_out": 0, "unusual_hour": True, "process_name": "unknown", "details": "Synthetic high-risk authentication pattern"},
        {"event_type": "data_transfer", "source_ip": "192.0.2.91", "username": "analyst", "country": "CA", "failed_attempts": 0, "bytes_out": 250000, "unusual_hour": False, "process_name": "browser", "details": "Routine synthetic download"},
        {"event_type": "login_success", "source_ip": "203.0.113.120", "username": "sam", "country": "AU", "failed_attempts": 0, "bytes_out": 18000, "unusual_hour": False, "process_name": "browser", "details": "Routine synthetic login"},
        {"event_type": "process_alert", "source_ip": "198.51.100.37", "username": "endpoint-04", "country": "FR", "failed_attempts": 1, "bytes_out": 9000, "unusual_hour": True, "process_name": "credential-dumper", "details": "Synthetic endpoint detection event"},
        {"event_type": "api_access", "source_ip": "192.0.2.17", "username": "api-user", "country": "US", "failed_attempts": 0, "bytes_out": 8000, "unusual_hour": False, "process_name": "service", "details": "Routine synthetic API activity"},
    ]
    for sample in samples:
        create_event(db, sample)
    record_audit(db, user.email, "demo.seed", "demo-dataset", f"created={len(samples)} synthetic events")
    db.commit()
    return {"created": len(samples), "message": "Synthetic demo events created."}
