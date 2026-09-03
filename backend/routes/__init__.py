from backend.routes.tokens import router as tokens_router
from backend.routes.beacon import router as beacon_router
from backend.routes.decoys import router as decoys_router
from backend.routes.auth_verify import router as auth_verify_router
from backend.routes.stream import router as stream_router
from backend.routes.dashboard import router as dashboard_router
from backend.routes.alerts import router as alerts_router

__all__ = [
    "tokens_router",
    "beacon_router",
    "decoys_router",
    "auth_verify_router",
    "stream_router",
    "dashboard_router",
    "alerts_router",
]
