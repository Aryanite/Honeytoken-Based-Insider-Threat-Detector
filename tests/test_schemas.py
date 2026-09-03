import pytest
from datetime import datetime, timezone
from pydantic import ValidationError

from backend.schemas.token import (
    TokenCreateSchema,
    TokenUpdateSchema,
    TokenResponseSchema,
    build_beacon_url,
)
from backend.schemas.alert import (
    ScoreBreakdownSchema,
    AlertPayloadSchema,
    AlertLogResponseSchema,
    AlertFilterQuerySchema,
)
from backend.schemas.auth_verify import (
    AuthVerifyRequestSchema,
    AuthVerifyErrorResponseSchema,
)
from backend.schemas.decoy import (
    DecoyDownloadQuerySchema,
    DecoyPreviewDataSchema,
    DecoyArtifactMetadataSchema,
)
from backend.schemas.telemetry import (
    TelemetryPayloadSchema,
    NormalizedTriggerSchema,
)
from backend.schemas.dashboard import (
    MetricCardsSchema,
    SeverityBreakdownSchema,
    TokenTypeBreakdownSchema,
    RecentAlertSummarySchema,
    DashboardStatsSchema,
)
from backend.schemas.envelope import (
    ApiResponse,
    success_response,
    error_response,
)


def test_token_create_schema_valid():
    schema = TokenCreateSchema(
        name="Prod Database Canary",
        token_type="db_record",
        criticality=45,
        placement_location="finance_db.users",
        description="Planted canary record for payroll",
    )
    assert schema.name == "Prod Database Canary"
    assert schema.token_type == "db_record"
    assert schema.criticality == 45
    assert schema.placement_location == "finance_db.users"


def test_token_create_schema_criticality_boundaries():
    # Minimum valid: 1
    s_min = TokenCreateSchema(name="Min Valid", token_type="api_key", criticality=1)
    assert s_min.criticality == 1

    # Maximum valid: 50
    s_max = TokenCreateSchema(name="Max Valid", token_type="api_key", criticality=50)
    assert s_max.criticality == 50

    # Below minimum: 0 (should fail)
    with pytest.raises(ValidationError):
        TokenCreateSchema(name="Below Min", token_type="api_key", criticality=0)

    # Above maximum: 51 (should fail)
    with pytest.raises(ValidationError):
        TokenCreateSchema(name="Above Max", token_type="api_key", criticality=51)


def test_token_create_schema_invalid_token_type():
    with pytest.raises(ValidationError):
        TokenCreateSchema(name="Invalid Type", token_type="unknown_device", criticality=25)


def test_token_create_schema_name_validation():
    # Empty string should fail min_length=1
    with pytest.raises(ValidationError):
        TokenCreateSchema(name="", token_type="api_key", criticality=25)

    # Over 100 characters should fail max_length=100
    with pytest.raises(ValidationError):
        TokenCreateSchema(name="A" * 101, token_type="api_key", criticality=25)


def test_beacon_url_builder():
    url = build_beacon_url("123e4567-e89b-12d3-a456-426614174000")
    assert "/beacon/123e4567-e89b-12d3-a456-426614174000" in url
    assert url.startswith("http")


def test_auth_verify_request_schema():
    valid = AuthVerifyRequestSchema(api_key="ak_live_test123", client_id="client_corp")
    assert valid.api_key == "ak_live_test123"
    assert valid.client_id == "client_corp"

    # Empty payload is valid (headers or query params may be used instead)
    empty = AuthVerifyRequestSchema()
    assert empty.api_key is None


def test_auth_verify_error_response_schema():
    err = AuthVerifyErrorResponseSchema()
    assert err.status == "error"
    assert err.data is None
    assert "invalid" in err.error.lower()


def test_decoy_download_query_schema():
    docx = DecoyDownloadQuerySchema(format="docx")
    assert docx.format == "docx"

    pdf = DecoyDownloadQuerySchema(format="pdf")
    assert pdf.format == "pdf"

    with pytest.raises(ValidationError):
        DecoyDownloadQuerySchema(format="exe")


def test_telemetry_payload_schema_ip_sanitization():
    # IPv4 standard
    t1 = TelemetryPayloadSchema(
        token_id="tok-1",
        source_ip="192.168.1.50",
        trigger_vector="beacon_pixel",
    )
    assert t1.source_ip == "192.168.1.50"

    # IP with port string
    t2 = TelemetryPayloadSchema(
        token_id="tok-2",
        source_ip="10.0.0.1:8080",
        trigger_vector="credential_verify",
    )
    assert t2.source_ip == "10.0.0.1"


def test_score_breakdown_schema():
    breakdown = ScoreBreakdownSchema(
        asset_weight=45.0,
        context_multiplier=1.8,
        context_reasons=["Weekend access", "curl detected"],
        frequency_multiplier=1.8,
        frequency_reason="High-frequency burst: 5 hits in 5m",
        recent_hits_in_window=5,
        formula="45.0 * 1.8 * 1.8 = 145.8",
        token_name="Critical Key",
        token_type="api_key",
        source_ip="203.0.113.1",
    )
    assert breakdown.asset_weight == 45.0
    assert breakdown.context_multiplier == 1.8
    assert len(breakdown.context_reasons) == 2


def test_dashboard_stats_schema():
    stats = DashboardStatsSchema(
        total_triggers=15,
        total_alerts=10,
        active_tokens=4,
        total_tokens=6,
        critical_alerts=2,
        metrics=MetricCardsSchema(
            active_decoys=4,
            total_decoys=6,
            revoked_decoys=2,
            today_triggers=5,
            total_triggers=15,
            critical_threats=2,
        ),
        severity_breakdown=SeverityBreakdownSchema(
            low=3,
            medium=3,
            high=2,
            critical=2,
        ),
        token_type_breakdown=TokenTypeBreakdownSchema(
            api_key=3,
            canary_doc=2,
            db_record=1,
        ),
        recent_alerts=[
            RecentAlertSummarySchema(
                alert_id="alt-1",
                token_id="tok-1",
                token_name="Canary 1",
                token_type="canary_doc",
                severity="Critical",
                risk_score=92.5,
                source_ip="198.51.100.2",
                triggered_at="2026-09-08T12:00:00Z",
            )
        ],
        generated_at="2026-09-08T12:05:00Z",
    )
    assert stats.total_triggers == 15
    assert stats.total_alerts == 10
    assert stats.metrics.active_decoys == 4
    assert stats.severity_breakdown.critical == 2
    assert stats.token_type_breakdown.api_key == 3


def test_api_response_envelope_helpers():
    succ = success_response({"message": "OK"})
    assert succ.status == "success"
    assert succ.data == {"message": "OK"}
    assert succ.error is None

    err = error_response("Something went wrong")
    assert err.status == "error"
    assert err.data is None
    assert err.error == "Something went wrong"
