from typing import Optional, List, Literal, TYPE_CHECKING
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict
from backend.core.config import settings
from backend.schemas.trigger import TriggerLogResponseSchema

if TYPE_CHECKING:
    from backend.models.token import HoneyToken

TokenType = Literal["api_key", "canary_doc", "db_record"]
TokenStatus = Literal["active", "revoked"]


def build_beacon_url(token_id: str) -> str:
    """Build the public beacon listener URL for embedding in decoy assets."""
    base = settings.BEACON_BASE_URL.rstrip("/")
    return f"{base}/beacon/{token_id}"


class TokenCreateSchema(BaseModel):
    name: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Human-readable label for the decoy asset",
    )
    token_type: TokenType = Field(
        ...,
        description="Category of honeytoken: api_key | canary_doc | db_record",
    )
    criticality: int = Field(
        25,
        ge=1,
        le=50,
        description="Asset criticality weight (1 = lowest, 50 = highest)",
    )
    description: Optional[str] = Field(None, max_length=255)
    placement_location: Optional[str] = Field(
        None,
        max_length=255,
        description="Where this decoy is or will be deployed",
    )


class TokenUpdateSchema(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    criticality: Optional[int] = Field(None, ge=1, le=50)
    status: Optional[TokenStatus] = None
    description: Optional[str] = Field(None, max_length=255)
    placement_location: Optional[str] = Field(None, max_length=255)


class TokenResponseSchema(BaseModel):
    token_id: str
    name: str
    token_type: str
    criticality: int
    status: str
    description: Optional[str] = None
    placement_location: Optional[str] = None
    beacon_url: str
    created_at: datetime
    updated_at: datetime
    recent_triggers: List[TriggerLogResponseSchema] = []

    model_config = ConfigDict(from_attributes=True)

    @classmethod
    def from_orm_model(cls, token: "HoneyToken") -> "TokenResponseSchema":
        """Build a response schema from an ORM model, injecting the computed beacon URL."""
        return cls(
            token_id=token.token_id,
            name=token.name,
            token_type=token.token_type,
            criticality=token.criticality,
            status=token.status,
            description=token.description,
            placement_location=token.placement_location,
            beacon_url=build_beacon_url(token.token_id),
            created_at=token.created_at,
            updated_at=token.updated_at,
            # Return only the 10 most recent triggers to keep response lean
            recent_triggers=[
                TriggerLogResponseSchema.model_validate(t)
                for t in (token.triggers[:10] if token.triggers else [])
            ],
        )
