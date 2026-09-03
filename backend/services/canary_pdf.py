import io
from datetime import datetime, timezone
from backend.core.config import settings
from backend.models.token import HoneyToken


def generate_canary_pdf(token: HoneyToken) -> io.BytesIO:
    """
    Generates a valid PDF-1.4 canary document containing realistic internal audit
    decoy content, with an embedded OpenAction URI and Link annotation pointing
    to the honeytoken beacon URL.

    When opened in Adobe Acrobat Reader, Foxit, Evince, or browser PDF engines,
    the embedded URI action triggers an outbound HTTP beacon request.
    """
    beacon_url = f"{settings.BEACON_BASE_URL.rstrip('/')}/beacon/{token.token_id}"
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Content stream text commands (PostScript-like PDF instructions)
    stream_content = (
        "BT\n"
        "/F1 18 Tf\n"
        "50 740 Td\n"
        f"(CONFIDENTIAL: {token.name.upper()}) Tj\n"
        "/F1 10 Tf\n"
        "0 -25 Td\n"
        "(Classification: Internal Restricted - Discretionary Access Only) Tj\n"
        "0 -30 Td\n"
        "/F1 12 Tf\n"
        f"(Generated: {now_str}) Tj\n"
        "0 -20 Td\n"
        f"(Asset ID: {token.token_id}) Tj\n"
        "0 -20 Td\n"
        f"(Criticality Weight: Level {token.criticality} of 50) Tj\n"
        "0 -20 Td\n"
        f"(Placement Scope: {getattr(token, 'placement_location', None) or 'Production Corporate Cluster'}) Tj\n"
        "0 -35 Td\n"
        "/F1 11 Tf\n"
        "(Operational Security Advisory:) Tj\n"
        "0 -18 Td\n"
        "(All activities regarding this asset are logged in the Central Security Auditing Pipeline.) Tj\n"
        "0 -16 Td\n"
        "(Unapproved distribution or unauthorized viewing is subject to regulatory sanctions.) Tj\n"
        "ET\n"
    ).encode("utf-8")

    stream_len = len(stream_content)

    # Construct the PDF objects
    pdf_parts = []
    offsets = []

    # Header
    header = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
    pdf_parts.append(header)

    def add_object(obj_bytes: bytes) -> int:
        nonlocal pdf_parts, offsets
        offset = sum(len(p) for p in pdf_parts)
        offsets.append(offset)
        pdf_parts.append(obj_bytes)
        return len(offsets)

    # 1 0 obj: Catalog with OpenAction
    obj1 = (
        b"1 0 obj\n"
        b"<<\n"
        b"  /Type /Catalog\n"
        b"  /Pages 2 0 R\n"
        b"  /OpenAction 5 0 R\n"
        b">>\n"
        b"endobj\n"
    )
    add_object(obj1)

    # 2 0 obj: Pages
    obj2 = (
        b"2 0 obj\n"
        b"<<\n"
        b"  /Type /Pages\n"
        b"  /Kids [3 0 R]\n"
        b"  /Count 1\n"
        b">>\n"
        b"endobj\n"
    )
    add_object(obj2)

    # 3 0 obj: Page
    obj3 = (
        b"3 0 obj\n"
        b"<<\n"
        b"  /Type /Page\n"
        b"  /Parent 2 0 R\n"
        b"  /MediaBox [0 0 612 792]\n"
        b"  /Contents 4 0 R\n"
        b"  /Resources <<\n"
        b"    /Font <<\n"
        b"      /F1 <<\n"
        b"        /Type /Font\n"
        b"        /Subtype /Type1\n"
        b"        /BaseFont /Helvetica-Bold\n"
        b"      >>\n"
        b"    >>\n"
        b"  >>\n"
        b"  /Annots [6 0 R]\n"
        b">>\n"
        b"endobj\n"
    )
    add_object(obj3)

    # 4 0 obj: Page contents stream
    obj4 = (
        f"4 0 obj\n"
        f"<< /Length {stream_len} >>\n"
        f"stream\n"
    ).encode("utf-8") + stream_content + b"\nendstream\nendobj\n"
    add_object(obj4)

    # 5 0 obj: OpenAction pointing to Honeytoken beacon URI
    safe_beacon_url = beacon_url.replace("(", "\\(").replace(")", "\\)")
    obj5 = (
        f"5 0 obj\n"
        f"<<\n"
        f"  /Type /Action\n"
        f"  /S /URI\n"
        f"  /URI ({safe_beacon_url})\n"
        f">>\n"
        f"endobj\n"
    ).encode("utf-8")
    add_object(obj5)

    # 6 0 obj: Annotation Link
    obj6 = (
        f"6 0 obj\n"
        f"<<\n"
        f"  /Type /Annot\n"
        f"  /Subtype /Link\n"
        f"  /Rect [50 710 500 760]\n"
        f"  /Border [0 0 0]\n"
        f"  /A 5 0 R\n"
        f">>\n"
        f"endobj\n"
    ).encode("utf-8")
    add_object(obj6)

    # Cross-Reference Table
    xref_offset = sum(len(p) for p in pdf_parts)
    xref = [f"xref\n0 {len(offsets) + 1}\n0000000000 65535 f \n".encode("ascii")]
    for off in offsets:
        xref.append(f"{off:010d} 00000 n \n".encode("ascii"))
    pdf_parts.extend(xref)

    # Trailer
    trailer = (
        f"trailer\n"
        f"<<\n"
        f"  /Size {len(offsets) + 1}\n"
        f"  /Root 1 0 R\n"
        f">>\n"
        f"startxref\n"
        f"{xref_offset}\n"
        f"%%EOF\n"
    ).encode("ascii")
    pdf_parts.append(trailer)

    full_pdf_bytes = b"".join(pdf_parts)
    stream = io.BytesIO(full_pdf_bytes)
    stream.seek(0)
    return stream
