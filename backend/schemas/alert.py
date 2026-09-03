from typing import Optional, Dict, Any, List, Literal
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict

SeverityLevel = Literal["Low", "Medium", "High", "Critical"]


class ScoreBreakdownSchema(BaseModel):
    """
    Detailed analytical factors behind the dynamic risk score.
    Explicit breakdown for security analysts reviewing alerts on the dashboard.
    """
    asset_weight: float = Field(..., description="Base asset sensitivity weight W_asset (1 to 50)")
    context_multiplier: float = Field(..., description="Access context multiplier C_access (e.g. 1.0x to 1.8x)")
    context_reasons: List[str] = Field(default_factory=list, description="Audit rationale for context adjustments")
    frequency_multiplier: float = Field(..., description="Trigger burst multiplier F_frequency (1.0x to 1.8x)")
    frequency_reason: str = Field(..., description="Audit rationale for burst frequency")
    recent_hits_in_window: int = Field(..., description="Number of accesses in the rolling evaluation window")
    formula: str = Field(..., description="Human-readable formula string showing calculation")
    token_name: Optional[str] = Field(None, description="Name of the triggered honeytoken")
    token_type: Optional[str] = Field(None, description="Type of honeytoken (api_key, canary_doc, db_record)")
    source_ip: Optional[str] = Field(None, description="Originating client IP address")
    user_agent: Optional[str] = Field(None, description="Originating User-Agent header")
    triggered_at: Optional[str] = Field(None, description="ISO timestamp of trigger event")


class AlertPayloadSchema(BaseModel):
    """
    Outbound real-time alert event broadcasted over Server-Sent Events (SSE).
    """
    alert_id: str = Field(..., description="Unique alert identifier (UUID)")
    trigger_id: str = Field(..., description="Associated trigger event identifier")
    severity: SeverityLevel = Field(..., description="Triage classification: Low | Medium | High | Critical")
    risk_score: float = Field(..., description="Final dynamic risk score")
    token_id: str = Field(..., description="Target honeytoken UUID")
    token_name: str = Field(..., description="Target honeytoken label")
    token_type: str = Field(..., description="Category of honeytoken")
    source_ip: str = Field(..., description="Accessor IP address")
    user_agent: Optional[str] = Field(None, description="Accessor client User-Agent")
    created_at: str = Field(..., description="ISO 8601 alert generation timestamp")
    details: ScoreBreakdownSchema = Field(..., description="Complete score breakdown factors")


class AlertLogResponseSchema(BaseModel):
    """
    Historical alert log record returned by query endpoints.
    """
    alert_id: str
    trigger_id: str
    severity: SeverityLevel
    risk_score: float
    details: Optional[Dict[str, Any]] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AlertFilterQuerySchema(BaseModel):
    """
    Validation schema for filtering alerts via query parameters.
    """
    severity: Optional[SeverityLevel] = None
    token_id: Optional[str] = None
    limit: int = Field(50, ge=1, le=200)
    offset: int = Field(0, ge=0)
