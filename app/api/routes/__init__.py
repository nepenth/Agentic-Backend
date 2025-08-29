from fastapi import APIRouter
from .agents import router as agents_router
from .tasks import router as tasks_router
from .logs import router as logs_router
from .health import router as health_router
from .websocket import router as websocket_router
from .auth import router as auth_router
from .security import router as security_router
from .system_metrics import router as system_metrics_router
from .ollama import router as ollama_router

# Create main API router
api_router = APIRouter(prefix="/api/v1")

# Include sub-routers
api_router.include_router(health_router, tags=["health"])
api_router.include_router(auth_router, prefix="/auth", tags=["authentication"])
api_router.include_router(agents_router, prefix="/agents", tags=["agents"])
api_router.include_router(tasks_router, prefix="/tasks", tags=["tasks"])
api_router.include_router(logs_router, prefix="/logs", tags=["logs"])
api_router.include_router(security_router, prefix="/security", tags=["security"])
api_router.include_router(system_metrics_router, tags=["system"])
api_router.include_router(ollama_router, prefix="/ollama", tags=["ollama"])

# WebSocket routes don't use /api/v1 prefix
ws_router = APIRouter()
ws_router.include_router(websocket_router, prefix="/ws", tags=["websocket"])

__all__ = ["api_router", "ws_router"]