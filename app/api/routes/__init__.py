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
from .secrets import router as secrets_router
from .chat import router as chat_router
from .agent_builder import router as agent_builder_router
from .http_client import router as http_client_router
from .model_selection import router as model_selection_router
from .content_framework import router as content_framework_router
from .semantic_processing import router as semantic_processing_router
from .content import router as content_router
from .analytics import router as analytics_router
from .personalization import router as personalization_router
from .trends import router as trends_router
from .search_analytics import router as search_analytics_router

# Phase 5 Orchestration & Automation
from .workflow_automation import router as workflow_automation_router
from .integration_layer import router as integration_layer_router

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
api_router.include_router(secrets_router, tags=["secrets"])
api_router.include_router(chat_router, prefix="/chat", tags=["chat"])
api_router.include_router(agent_builder_router, prefix="/agent-builder", tags=["agent-builder"])

# Phase 1 New Services
api_router.include_router(http_client_router, tags=["HTTP Client"])
api_router.include_router(model_selection_router, tags=["Model Selection"])
api_router.include_router(content_framework_router, tags=["Content Framework"])
api_router.include_router(semantic_processing_router, tags=["Semantic Processing"])

# Phase 2 Content Connectors
api_router.include_router(content_router, tags=["Content Connectors"])

# Phase 4 Analytics & Intelligence
api_router.include_router(analytics_router, tags=["Analytics & Insights"])
api_router.include_router(personalization_router, tags=["Personalization"])
api_router.include_router(trends_router, tags=["Trend Detection & Analytics"])
api_router.include_router(search_analytics_router, tags=["Search Analytics"])

# Phase 5 Orchestration & Automation
api_router.include_router(workflow_automation_router, tags=["Workflow Automation"])
api_router.include_router(integration_layer_router, tags=["Integration Layer"])

# WebSocket routes don't use /api/v1 prefix
ws_router = APIRouter()
ws_router.include_router(websocket_router, prefix="/ws", tags=["websocket"])

__all__ = ["api_router", "ws_router"]