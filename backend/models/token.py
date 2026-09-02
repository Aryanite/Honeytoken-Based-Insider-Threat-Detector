import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, DateTime, desc
from sqlalchemy.orm import relationship
from backend.db.base import Base


class HoneyToken(Base):
    __tablename__ = "honey_tokens"

    token_id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        index=True,
    )
    name = Column(String(100), nullable=False)
    # Allowed values: api_key, canary_doc, db_record
    token_type = Column(String(20), nullable=False)
    # Criticality weight 1 (low) to 50 (highest)
    criticality = Column(Integer, nullable=False, default=25)
    # Operational state: active or revoked
    status = Column(String(20), nullable=False, default="active")
    description = Column(String(255), nullable=True)
    placement_location = Column(String(255), nullable=True)
    created_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Cascade triggers deletion when parent honeytoken is deleted
    triggers = relationship(
        "TokenTrigger",
        back_populates="token",
        cascade="all, delete-orphan",
        lazy="select",
    )

    def __repr__(self) -> str:
        return (
            f"<HoneyToken("
            f"id={self.token_id}, "
            f"name={self.name}, "
            f"type={self.token_type}, "
            f"status={self.status})>"
        )
