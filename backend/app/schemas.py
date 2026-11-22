from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress


class EventCreate(BaseModel):
    event_type: str = Field(min_length=3, max_length=80)
    source_ip: str = Field(default="192.0.2.10", max_length=64)
    username: str = Field(default="demo-user", min_length=1, max_length=120)
    country: str = Field(default="US", min_length=2, max_length=80)
    failed_attempts: int = Field(default=0, ge=0, le=1000)
    bytes_out: int = Field(default=0, ge=0, le=2_000_000_000)
    unusual_hour: bool = False
    process_name: str = Field(default="unknown", max_length=120)
    details: str = Field(default="Synthetic demo security event", max_length=2000)


class UserOut(BaseModel):
    id: int
    email: str
    role: str
    model_config = ConfigDict(from_attributes=True)


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"


class EventOut(BaseModel):
    id: int
    event_type: str
    source_ip: str
    username: str
    country: str
    failed_attempts: int
    bytes_out: int
    unusual_hour: bool
    process_name: str
    details: str
    risk_score: float
    risk_level: str
    detection_reasons: list[str]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AlertStatusUpdate(BaseModel):
    status: str = Field(pattern="^(new|investigating|resolved)$")


class AlertOut(BaseModel):
    id: int
    event_id: int
    title: str
    description: str
    severity: str
    status: str
    assigned_to: str
    created_at: datetime
    updated_at: datetime
    event: EventOut

    model_config = ConfigDict(from_attributes=True)
