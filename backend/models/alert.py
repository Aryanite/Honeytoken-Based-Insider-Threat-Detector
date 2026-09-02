import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Float, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from backend.db.base import Base


class AlertLog(Base):
    __tablename__ = "alert_logs"

    alert_id = Column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        index=True,
    )
    trigger_id = Column(
        String(36),
        ForeignKey("token_triggers.trigger_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    severity = Column(String(20), nullable=False)  # Low, Medium, High, Critical
    risk_score = Column(Float, nullable=False)
    details = Column(JSON, nullable=True)
    created_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    # Relationships
    trigger = relationship("TokenTrigger", back_populates="alerts")

    def __repr__(self) -> str:
        return f"<AlertLog(id={self.alert_id}, severity={self.severity}, score={self.risk_score})>"
