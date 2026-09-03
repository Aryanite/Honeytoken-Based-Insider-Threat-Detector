from typing import Optional, Dict, Any, Literal
from datetime import datetime, timezone
from pydantic import BaseModel, Field, IPvAnyAddress, field_validator

TriggerVector = Literal["beacon_pixel", "credential_verify", "database_proxy", "canary_pdf"]


class TelemetryPayloadSchema(BaseModel):
    """
    Standardized forensic telemetry structure shared across all honeytoken hit channels.
    Normalizes web beacon pings, mock auth submissions, and canary document opens
    into an identical analytical format.
    """
    token_id: str = Field(..., description="Target honeytoken UUID")
    source_ip: str = Field(..., description="Client IP (IPv4 or IPv6)")
    user_agent: str = Field("Unknown", description="Client user-agent string")
    headers: Dict[str, Any] = Field(default_factory=dict, description="Sanitized HTTP headers")
    trigger_vector: TriggerVector = Field(..., description="Channel through which decoy was tripped")
    triggered_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC access timestamp",
    )
    is_proxy_forwarded: bool = Field(False, description="Whether request passed through X-Forwarded-For")
    origin_country: Optional[str] = Field(None, description="Optional GeoIP origin if available")

    @field_validator("source_ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        # Strip port or whitespace if present
        cleaned = v.strip().split(":")[0] if ":" in v and not v.startswith("[") and v.count(":") == 1 else v.strip()
        return cleaned or "0.0.0.0"


class NormalizedTriggerSchema(BaseModel):
    """
    Consistent representation of a logged trigger event for internal processing and analysis.
    """
    trigger_id: str
    token_id: str
    token_name: str
    token_type: str
    criticality: int
    source_ip: str
    user_agent: Optional[str] = None
    trigger_vector: str
    triggered_at: datetime
