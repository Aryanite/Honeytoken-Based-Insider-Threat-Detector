from typing import Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, ConfigDict


class TriggerLogResponseSchema(BaseModel):
    trigger_id: str
    token_id: str
    source_ip: str
    user_agent: Optional[str] = None
    headers: Optional[Dict[str, Any]] = None
    triggered_at: datetime

    model_config = ConfigDict(from_attributes=True)
