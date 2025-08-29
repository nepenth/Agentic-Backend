from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from app.config import settings
from app.utils.logging import setup_logging
from app.api.middleware import LoggingMiddleware
from app.api.security_middleware import AgentSecurityMiddleware, RequestValidationMiddleware
from app.api.routes import api_router, ws_router
from app.utils.logging import get_logger

# Setup logging
setup_logging()
logger = get_logger("main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    logger.info(f"Starting {settings.app_name} v{settings.app_version}")
    
    # Startup
    try:
        # Initialize database, redis connections, etc.
        logger.info("Application startup complete")
        yield
    except Exception as e:
        logger.error(f"Startup failed: {e}")
        raise
    finally:
        # Shutdown
        logger.info("Shutting down application")


# Create FastAPI app
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Local AI Agent Backend with Celery and Ollama Integration",
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
    openapi_url="/openapi.json" if settings.debug else None,
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://whyland-ai.nakedsun.xyz",
        "https://whyland-ai.nakedsun.xyz:3443",  # Frontend with port
        "https://localhost:3000",
        "https://127.0.0.1:3000",
        "http://localhost:3000",  # For development
        "http://127.0.0.1:3000"   # For development
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["*"],
)

# Add custom middleware
app.add_middleware(LoggingMiddleware)

# Add security middleware (order matters - security should be early)
app.add_middleware(RequestValidationMiddleware)
app.add_middleware(AgentSecurityMiddleware)

# Include routers
app.include_router(api_router)
app.include_router(ws_router)

# Root endpoint
@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "app_name": settings.app_name,
        "version": settings.app_version,
        "status": "running",
        "docs_url": "/docs" if settings.debug else None
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.debug,
        log_level=settings.log_level.lower()
    )