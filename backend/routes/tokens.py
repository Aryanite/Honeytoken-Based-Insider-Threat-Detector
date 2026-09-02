from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi import status as http_status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.models.token import HoneyToken
from backend.schemas.envelope import ApiResponse, success_response
from backend.schemas.token import (
    TokenCreateSchema,
    TokenUpdateSchema,
    TokenResponseSchema,
    TokenType,
    TokenStatus,
)

router = APIRouter(prefix="/tokens", tags=["Tokens"])


@router.post(
    "",
    response_model=ApiResponse[TokenResponseSchema],
    status_code=http_status.HTTP_201_CREATED,
    summary="Create a new honeytoken",
)
def create_token(
    payload: TokenCreateSchema,
    db: Session = Depends(get_db),
):
    """Register a new honeytoken decoy and return its details including the beacon URL."""
    token = HoneyToken(
        name=payload.name,
        token_type=payload.token_type,
        criticality=payload.criticality,
        description=payload.description,
        placement_location=payload.placement_location,
        status="active",
    )
    db.add(token)
    db.commit()
    db.refresh(token)
    return success_response(TokenResponseSchema.from_orm_model(token))


@router.get(
    "",
    response_model=ApiResponse[List[TokenResponseSchema]],
    summary="List all honeytokens",
)
def list_tokens(
    token_status: Optional[TokenStatus] = Query(
        None,
        alias="status",
        description="Filter by operational status: 'active' or 'revoked'",
    ),
    token_type: Optional[TokenType] = Query(
        None,
        description="Filter by token type: api_key | canary_doc | db_record",
    ),
    db: Session = Depends(get_db),
):
    """Return all registered honeytokens with optional status and type filters."""
    query = db.query(HoneyToken)
    if token_status:
        query = query.filter(HoneyToken.status == token_status)
    if token_type:
        query = query.filter(HoneyToken.token_type == token_type)

    tokens = query.order_by(HoneyToken.created_at.desc()).all()
    return success_response([TokenResponseSchema.from_orm_model(t) for t in tokens])


@router.get(
    "/{token_id}",
    response_model=ApiResponse[TokenResponseSchema],
    summary="Get a single honeytoken",
)
def get_token(
    token_id: str,
    db: Session = Depends(get_db),
):
    """Retrieve detailed information and recent triggers for a specific honeytoken."""
    token = db.query(HoneyToken).filter(HoneyToken.token_id == token_id).first()
    if not token:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"Honeytoken with ID '{token_id}' not found.",
        )
    return success_response(TokenResponseSchema.from_orm_model(token))


@router.patch(
    "/{token_id}",
    response_model=ApiResponse[TokenResponseSchema],
    summary="Update a honeytoken",
)
def update_token(
    token_id: str,
    payload: TokenUpdateSchema,
    db: Session = Depends(get_db),
):
    """Update editable fields of an existing honeytoken."""
    token = db.query(HoneyToken).filter(HoneyToken.token_id == token_id).first()
    if not token:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"Honeytoken with ID '{token_id}' not found.",
        )
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(token, field, value)
    db.commit()
    db.refresh(token)
    return success_response(TokenResponseSchema.from_orm_model(token))


@router.delete(
    "/{token_id}",
    response_model=ApiResponse[dict],
    summary="Revoke a honeytoken",
)
def revoke_token(
    token_id: str,
    db: Session = Depends(get_db),
):
    """Soft-revoke a honeytoken. Future beacon hits from revoked tokens are silently ignored."""
    token = db.query(HoneyToken).filter(HoneyToken.token_id == token_id).first()
    if not token:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail=f"Honeytoken with ID '{token_id}' not found.",
        )
    token.status = "revoked"
    db.commit()
    return success_response({
        "token_id": token_id,
        "status": "revoked",
        "message": f"Honeytoken '{token.name}' successfully revoked.",
    })
