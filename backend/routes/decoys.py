import re
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from backend.core.config import settings
from backend.db.session import get_db
from backend.models.token import HoneyToken
from backend.services.canary_doc import generate_canary_docx
from backend.services.canary_pdf import generate_canary_pdf
from backend.schemas.envelope import ApiResponse, success_response
from backend.schemas.decoy import DecoyPreviewDataSchema, DecoyFormat

router = APIRouter(tags=["Decoy Generation & Downloads"])


def _sanitize_filename(name: str) -> str:
    """Sanitize string for HTTP Content-Disposition headers."""
    clean = re.sub(r"[^\w\-_.]", "_", name)
    return clean or "decoy_document"


@router.get(
    "/tokens/{token_id}/download",
    summary="Download Generated Canary Decoy File",
    description=(
        "Generates and serves a live decoy artifact (Word .docx or PDF) containing "
        "the embedded tracking beacon URL for the specified honeytoken. "
        "When opened by an insider, the document triggers covert telemetry."
    ),
    responses={
        200: {
            "description": "Binary document stream with embedded tracking beacons.",
            "content": {
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document": {},
                "application/pdf": {},
            },
        },
        404: {"description": "HoneyToken not found."},
    },
)
def download_decoy_file(
    token_id: str,
    format: DecoyFormat = Query("docx", description="Decoy file format: 'docx' or 'pdf'"),
    db: Session = Depends(get_db),
):
    """
    Synthesize and stream the binary canary document for the requested honeytoken.
    """
    token = db.query(HoneyToken).filter(HoneyToken.token_id == token_id).first()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"HoneyToken '{token_id}' not found.",
        )

    safe_name = _sanitize_filename(token.name)

    if format == "pdf":
        file_stream = generate_canary_pdf(token)
        media_type = "application/pdf"
        filename = f"{safe_name}.pdf"
    else:
        file_stream = generate_canary_docx(token)
        media_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        filename = f"{safe_name}.docx"

    return StreamingResponse(
        file_stream,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-cache, no-store, must-revalidate",
        },
    )


@router.get(
    "/tokens/{token_id}/decoy-preview",
    response_model=ApiResponse[DecoyPreviewDataSchema],
    summary="Preview Decoy Text Payload",
    description="Returns text representations of the decoy credential or snippet for placement.",
)
def preview_decoy_payload(
    token_id: str,
    db: Session = Depends(get_db),
):
    token = db.query(HoneyToken).filter(HoneyToken.token_id == token_id).first()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"HoneyToken '{token_id}' not found.",
        )

    beacon_base = settings.BEACON_BASE_URL.rstrip("/")
    api_prefix = settings.API_V1_STR.rstrip("/")

    download_url = None
    if token.token_type == "api_key":
        preview = (
            f"# Production Cloud Access Keys - Planted Decoy\n"
            f"AWS_ACCESS_KEY_ID=AKIA{token.token_id[:16].upper().replace('-', '')}\n"
            f"AWS_SECRET_ACCESS_KEY=sec_{token.token_id.replace('-', '')}\n"
            f"API_AUTH_VERIFY_ENDPOINT={beacon_base}{api_prefix}/auth/verify\n"
        )
    elif token.token_type == "db_record":
        preview = (
            f"-- Decoy Database Record Injection\n"
            f"INSERT INTO confidential_payroll (emp_id, full_name, salary, ssn, access_token)\n"
            f"VALUES ('DEC-8821', 'Eleanor Vance', 245000, '992-01-4412', '{token.token_id}');\n"
        )
    else:
        download_url = f"{beacon_base}{api_prefix}/tokens/{token.token_id}/download?format=docx"
        preview = (
            f"Canary Document Decoy: {token.name}\n"
            f"Tracking Beacon: {beacon_base}/beacon/{token.token_id}\n"
            f"Download URL: {download_url}\n"
        )

    data = DecoyPreviewDataSchema(
        token_id=token.token_id,
        token_name=token.name,
        token_type=token.token_type,
        preview_snippet=preview,
        download_url=download_url,
    )
    return success_response(data)
