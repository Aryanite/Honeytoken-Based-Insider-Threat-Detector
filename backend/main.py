from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from backend.core.config import settings
from backend.db.base import Base
from backend.db.session import engine
from backend.routes import tokens_router, beacon_router
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
    # Pass through non-JSON responses like beacon if needed, else envelope
    if request.url.path.startswith("/beacon"):
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
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"status": "error", "data": None, "error": error_msg},
    )


# Health check endpoint
@app.get("/health", tags=["System"])
def health_check():
    return {"status": "healthy", "app": settings.APP_NAME}


# Include sub-routers
app.include_router(tokens_router, prefix=settings.API_V1_STR)
app.include_router(beacon_router)
