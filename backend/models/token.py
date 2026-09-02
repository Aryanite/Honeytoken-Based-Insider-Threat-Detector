import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, DateTime
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
    token_type = Column(String(20), nullable=False)  # api_key, canary_doc, db_record
    criticality = Column(Integer, nullable=False, default=25)  # 1 to 50
    status = Column(String(20), nullable=False, default="active")  # active, revoked
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

    # Relationships
    triggers = relationship(
        "TokenTrigger",
        back_populates="token",
        cascade="all, delete-orphan",
        order_by="desc(TokenTrigger.triggered_at)",
    )

    def __repr__(self) -> str:
        return f"<HoneyToken(id={self.token_id}, name={self.name}, type={self.token_type}, status={self.status})>"
