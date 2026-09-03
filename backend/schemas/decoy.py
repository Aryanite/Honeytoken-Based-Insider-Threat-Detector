from typing import Literal, Optional
from pydantic import BaseModel, Field

DecoyFormat = Literal["docx", "pdf"]


class DecoyDownloadQuerySchema(BaseModel):
    """
    Validates query parameters for decoy document synthesis and download.
    """
    format: DecoyFormat = Field(
        "docx",
        description="Binary decoy format to generate: 'docx' (Word) or 'pdf' (Adobe)",
    )


class DecoyPreviewDataSchema(BaseModel):
    token_id: str = Field(..., description="Honeytoken identifier")
    token_name: str = Field(..., description="Label of the honeytoken")
    token_type: str = Field(..., description="Category: api_key, canary_doc, db_record")
    preview_snippet: str = Field(..., description="Planted credential string, SQL statement, or document summary")
    download_url: Optional[str] = Field(None, description="Direct download link if binary decoy")


class DecoyArtifactMetadataSchema(BaseModel):
    """
    Metadata representation of a generated decoy artifact ready for deployment.
    """
    token_id: str
    token_name: str
    token_type: str
    format: Optional[str] = None
    filename: str
    mime_type: str
    size_bytes: int
    beacon_url: str
    placement_location: Optional[str] = None
