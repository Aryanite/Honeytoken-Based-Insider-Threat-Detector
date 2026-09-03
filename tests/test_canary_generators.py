import io
import pytest
from docx import Document
from httpx import AsyncClient
from sqlalchemy.orm import Session

from backend.models.token import HoneyToken
from backend.services.canary_doc import generate_canary_docx
from backend.services.canary_pdf import generate_canary_pdf


def test_generate_canary_docx_structure(db_session: Session):
    token = HoneyToken(
        name="Payroll Confidential Decoy",
        token_type="canary_doc",
        criticality=45,
        status="active",
        placement="Finance Shared Drive",
    )
    db_session.add(token)
    db_session.commit()

    stream = generate_canary_docx(token)
    assert isinstance(stream, io.BytesIO)
    bytes_data = stream.getvalue()
    assert len(bytes_data) > 0

    # Verify that python-docx can parse the generated file back
    stream.seek(0)
    doc = Document(stream)
    text = " ".join([p.text for p in doc.paragraphs])
    assert "CONFIDENTIAL: PAYROLL CONFIDENTIAL DECOY" in text

    # Verify external beacon relationship is present
    rels = doc.part.rels
    external_targets = [r.target_ref for r in rels.values() if r.is_external]
    assert any(f"/beacon/{token.token_id}" in t for t in external_targets)


def test_generate_canary_pdf_structure(db_session: Session):
    token = HoneyToken(
        name="Q3 Executive Audit Decoy",
        token_type="canary_doc",
        criticality=40,
        status="active",
        placement="Executive Dropbox",
    )
    db_session.add(token)
    db_session.commit()

    stream = generate_canary_pdf(token)
    assert isinstance(stream, io.BytesIO)
    pdf_bytes = stream.getvalue()

    # Valid PDF syntax checks
    assert pdf_bytes.startswith(b"%PDF-1.4")
    assert b"%%EOF" in pdf_bytes
    assert b"/OpenAction" in pdf_bytes
    assert f"/beacon/{token.token_id}".encode("ascii") in pdf_bytes


@pytest.mark.asyncio
async def test_download_decoy_endpoint(client: AsyncClient):
    # 1. Create token
    create_res = await client.post("/api/v1/tokens", json={
        "name": "Downloadable Canary Memo",
        "token_type": "canary_doc",
        "criticality": 35,
    })
    token_id = create_res.json()["data"]["token_id"]

    # 2. Download DOCX format
    docx_res = await client.get(f"/api/v1/tokens/{token_id}/download?format=docx")
    assert docx_res.status_code == 200
    assert "wordprocessingml.document" in docx_res.headers["content-type"]
    assert "attachment; filename=" in docx_res.headers["content-disposition"]
    assert len(docx_res.content) > 500

    # 3. Download PDF format
    pdf_res = await client.get(f"/api/v1/tokens/{token_id}/download?format=pdf")
    assert pdf_res.status_code == 200
    assert "application/pdf" in pdf_res.headers["content-type"]
    assert "attachment; filename=" in pdf_res.headers["content-disposition"]
    assert pdf_res.content.startswith(b"%PDF-1.4")


@pytest.mark.asyncio
async def test_download_nonexistent_token_404(client: AsyncClient):
    res = await client.get("/api/v1/tokens/00000000-0000-0000-0000-000000000000/download")
    assert res.status_code == 404
