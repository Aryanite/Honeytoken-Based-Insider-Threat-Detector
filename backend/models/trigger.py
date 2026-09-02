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
    # Full request headers stored as a JSON key-value mapping
    headers = Column(JSON, nullable=True)
    triggered_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    # Back-reference to the parent honeytoken
    token = relationship("HoneyToken", back_populates="triggers")
    # Cascade alert deletion when trigger is deleted
    alerts = relationship(
        "AlertLog",
        back_populates="trigger",
        cascade="all, delete-orphan",
        lazy="select",
    )

    def __repr__(self) -> str:
        return (
            f"<TokenTrigger("
            f"id={self.trigger_id}, "
            f"token_id={self.token_id}, "
            f"ip={self.source_ip})>"
        )
