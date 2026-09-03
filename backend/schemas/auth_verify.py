from typing import Optional
from pydantic import BaseModel, Field


class AuthVerifyRequestSchema(BaseModel):
    """
    Validates payload submitted to the mock credential verification gateway.
    Handles attackers testing leaked API keys via JSON payloads.
    """
    api_key: Optional[str] = Field(
        None,
        min_length=1,
        max_length=255,
        description="Candidate API key or access token being tested",
        examples=["ak_live_9b1deb4d3b7d4bad9bdd2b0d7b3dcb6d", "AKIA-9B1DEB4D-PROD-SECRET"],
    )
    client_id: Optional[str] = Field(
        None,
        max_length=100,
        description="Optional client or service identifier passed by the tester",
    )


class AuthVerifyErrorResponseSchema(BaseModel):
    """
    Simulated 401 response model convincing the adversary that the credential
    is merely expired or unauthorized, avoiding alert tip-offs.
    """
    status: str = "error"
    data: None = None
    error: str = "The provided credentials are invalid, revoked, or lack necessary IAM privileges."
