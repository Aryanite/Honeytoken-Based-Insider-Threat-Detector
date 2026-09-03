import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from backend.core.config import settings
from backend.db.base import Base
from backend.db.session import engine
from backend.routes import (
    tokens_router,
    beacon_router,
    auth_verify_router,
    decoys_router,
    stream_router,
    dashboard_router,
    alerts_router,
)
from backend.schemas.envelope import ApiResponse, error_response


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager to initialize database tables on startup."""
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title=settings.APP_NAME,
    description="Deception-based insider threat detection and dynamic risk triage system.",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Exception handler to format HTTP exceptions in standard envelope
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    # Pass through non-JSON responses like beacon, frontend HTML, or binary downloads
    if request.url.path.startswith("/beacon") or "download" in request.url.path or request.url.path in ["/", "/dashboard"]:
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
        )
    return JSONResponse(
        status_code=exc.status_code,
        content={"status": "error", "data": None, "error": exc.detail},
    )


# Exception handler for Pydantic schema validation errors
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = exc.errors()
    error_msg = "; ".join([f"{'.'.join(str(loc) for loc in err['loc'])}: {err['msg']}" for err in errors])
    status_422 = getattr(status, "HTTP_422_UNPROCESSABLE_CONTENT", status.HTTP_422_UNPROCESSABLE_ENTITY)
    return JSONResponse(
        status_code=status_422,
        content={"status": "error", "data": None, "error": error_msg},
    )


# Serve frontend dashboard interface
FRONTEND_INDEX = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend", "index.html"))

@app.get("/", include_in_schema=False)
@app.get("/dashboard", include_in_schema=False)
def serve_dashboard():
    if os.path.exists(FRONTEND_INDEX):
        return FileResponse(FRONTEND_INDEX, media_type="text/html")
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"status": "healthy", "message": "Honeytoken Backend API online. Access /docs for API documentation."},
    )


# Health check endpoint
@app.get("/health", tags=["System"])
def health_check():
    return {"status": "healthy", "app": settings.APP_NAME}


# Include sub-routers
app.include_router(tokens_router, prefix=settings.API_V1_STR)
app.include_router(decoys_router, prefix=settings.API_V1_STR)
app.include_router(auth_verify_router, prefix=settings.API_V1_STR)
app.include_router(stream_router, prefix=settings.API_V1_STR)
app.include_router(dashboard_router, prefix=settings.API_V1_STR)
app.include_router(alerts_router, prefix=settings.API_V1_STR)
app.include_router(beacon_router)
