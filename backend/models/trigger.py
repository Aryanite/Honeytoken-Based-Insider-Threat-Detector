import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from backend.db.base import Base


class TokenTrigger(Base):
    __tablename__ = "token_triggers"

    trigger_id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        index=True,
    )
    token_id = Column(
        String(36),
        ForeignKey("honey_tokens.token_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    source_ip = Column(String(45), nullable=False)
    user_agent = Column(String(500), nullable=True)
    headers = Column(JSON, nullable=True)
    triggered_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    # Relationships
    token = relationship("HoneyToken", back_populates="triggers")
    alerts = relationship(
        "AlertLog",
        back_populates="trigger",
        cascade="all, delete-orphan",
        order_by="desc(AlertLog.created_at)",
    )

    def __repr__(self) -> str:
        return f"<TokenTrigger(id={self.trigger_id}, token_id={self.token_id}, ip={self.source_ip})>"
