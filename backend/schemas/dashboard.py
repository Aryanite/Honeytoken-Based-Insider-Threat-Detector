from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field


class MetricCardsSchema(BaseModel):
    """
    Top-level KPI metrics displayed on the administrative security dashboard.
    """
    active_decoys: int = Field(..., description="Currently active honeytokens monitoring for access")
    total_decoys: int = Field(..., description="Total deployed honeytoken count across all types")
    revoked_decoys: int = Field(..., description="Honeytokens deactivated or rotated")
    today_triggers: int = Field(..., description="Number of decoy triggers recorded today (UTC)")
    total_triggers: int = Field(..., description="Total historical trigger telemetry records")
    critical_threats: int = Field(..., description="High-priority alerts triaged as Critical")


class SeverityBreakdownSchema(BaseModel):
    """
    Categorized distribution of alerts across dynamic severity tiers.
    """
    low: int = Field(0, description="Score 0–25: Low-risk probe or benign hit")
    medium: int = Field(0, description="Score 26–50: Moderate asset or business-hour hit")
    high: int = Field(0, description="Score 51–75: High-value asset or suspicious tooling")
    critical: int = Field(0, description="Score 76+: Sensitive credential off-hours burst")


class TokenTypeBreakdownSchema(BaseModel):
    """
    Counts of deployed honeytokens categorized by format type.
    """
    api_key: int = Field(0, description="Simulated cloud/service API keys")
    canary_doc: int = Field(0, description="Tracking-pixel embedded Word/PDF documents")
    db_record: int = Field(0, description="Canary database rows and credentials")


class RecentAlertSummarySchema(BaseModel):
    """
    Alert item for the dashboard's live feed preview.
    """
    alert_id: str
    token_id: str
    token_name: str
    token_type: str
    severity: str
    risk_score: float
    source_ip: str
    triggered_at: str


class DashboardStatsSchema(BaseModel):
    """
    Complete aggregated analytical payload returned by GET /api/v1/dashboard/stats.
    Contains both root-level convenience metrics and detailed structured cards.
    """
    total_triggers: int = Field(..., description="Total count of all recorded triggers")
    total_alerts: int = Field(..., description="Total count of all triaged alerts")
    active_tokens: int = Field(..., description="Active honeytoken count")
    total_tokens: int = Field(..., description="Total honeytokens deployed")
    critical_alerts: int = Field(..., description="Critical severity count")
    metrics: MetricCardsSchema
    severity_breakdown: SeverityBreakdownSchema
    token_type_breakdown: TokenTypeBreakdownSchema
    recent_alerts: List[RecentAlertSummarySchema] = []
    generated_at: str = Field(..., description="ISO 8601 generation timestamp")
