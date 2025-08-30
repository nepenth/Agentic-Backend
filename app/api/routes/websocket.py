from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, Query, HTTPException
from typing import Optional, Dict, Any
from uuid import UUID
import json
import asyncio
from app.utils.logging import get_logger
from app.utils.metrics import MetricsCollector
from app.utils.auth import verify_token
from app.api.dependencies import get_db_session
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.models.user import User
from sqlalchemy import select

logger = get_logger("websocket")
router = APIRouter()


async def validate_websocket_token(token: str, db: AsyncSession) -> User:
    """Validate JWT token for WebSocket connections."""
    if not token:
        raise HTTPException(status_code=401, detail="Token required")

    username = verify_token(token)
    if not username:
        raise HTTPException(status_code=401, detail="Invalid token")

    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")

    return user


class ConnectionManager:
    """Manages WebSocket connections."""
    
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.task_subscriptions: Dict[UUID, set] = {}
        self.log_subscriptions: Dict[str, dict] = {}
    
    async def connect(self, websocket: WebSocket, connection_id: str):
        """Accept WebSocket connection."""
        await websocket.accept()
        self.active_connections[connection_id] = websocket
        MetricsCollector.increment_websocket_connections("logs", 1)
        logger.info(f"WebSocket connected: {connection_id}")
    
    def disconnect(self, connection_id: str):
        """Remove WebSocket connection."""
        if connection_id in self.active_connections:
            del self.active_connections[connection_id]
            MetricsCollector.increment_websocket_connections("logs", -1)
            logger.info(f"WebSocket disconnected: {connection_id}")
    
    async def send_personal_message(self, message: dict, connection_id: str):
        """Send message to specific connection."""
        if connection_id in self.active_connections:
            websocket = self.active_connections[connection_id]
            try:
                await websocket.send_text(json.dumps(message))
            except Exception as e:
                logger.error(f"Failed to send message to {connection_id}: {e}")
                self.disconnect(connection_id)
    
    async def broadcast(self, message: dict, connection_ids: set):
        """Broadcast message to multiple connections."""
        if not connection_ids:
            return
        
        disconnected = set()
        for connection_id in connection_ids:
            if connection_id in self.active_connections:
                websocket = self.active_connections[connection_id]
                try:
                    await websocket.send_text(json.dumps(message))
                except Exception as e:
                    logger.error(f"Failed to broadcast to {connection_id}: {e}")
                    disconnected.add(connection_id)
        
        # Clean up disconnected clients
        for connection_id in disconnected:
            self.disconnect(connection_id)
    
    def subscribe_to_task(self, connection_id: str, task_id: UUID):
        """Subscribe connection to task updates."""
        if task_id not in self.task_subscriptions:
            self.task_subscriptions[task_id] = set()
        self.task_subscriptions[task_id].add(connection_id)
        logger.info(f"Connection {connection_id} subscribed to task {task_id}")
    
    def unsubscribe_from_task(self, connection_id: str, task_id: UUID):
        """Unsubscribe connection from task updates."""
        if task_id in self.task_subscriptions:
            self.task_subscriptions[task_id].discard(connection_id)
            if not self.task_subscriptions[task_id]:
                del self.task_subscriptions[task_id]
        logger.info(f"Connection {connection_id} unsubscribed from task {task_id}")
    
    def subscribe_to_logs(self, connection_id: str, filters: dict):
        """Subscribe connection to log updates with filters."""
        self.log_subscriptions[connection_id] = filters
        logger.info(f"Connection {connection_id} subscribed to logs with filters: {filters}")
    
    def unsubscribe_from_logs(self, connection_id: str):
        """Unsubscribe connection from log updates."""
        if connection_id in self.log_subscriptions:
            del self.log_subscriptions[connection_id]
        logger.info(f"Connection {connection_id} unsubscribed from logs")


manager = ConnectionManager()


@router.websocket("/logs")
async def websocket_logs(
    websocket: WebSocket,
    token: str = Query(..., description="JWT authentication token"),
    agent_id: Optional[str] = Query(None),
    task_id: Optional[str] = Query(None),
    level: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db_session)
):
    """WebSocket endpoint for real-time log streaming with subscription filters."""
    connection_id = f"logs_{id(websocket)}"

    # Validate JWT token
    try:
        user = await validate_websocket_token(token, db)
        logger.info(f"WebSocket authenticated for user: {user.username}")
    except HTTPException as e:
        logger.warning(f"WebSocket authentication failed: {e.detail}")
        await websocket.close(code=1008, reason="Authentication failed")
        return

    await manager.connect(websocket, connection_id)
    
    try:
        # Set up subscription filters
        filters = {}
        if agent_id:
            filters["agent_id"] = agent_id
        if task_id:
            filters["task_id"] = task_id
        if level:
            filters["level"] = level
        
        manager.subscribe_to_logs(connection_id, filters)
        
        # Send welcome message
        await manager.send_personal_message({
            "type": "connected",
            "message": "Connected to log stream",
            "filters": filters
        }, connection_id)
        
        # Keep connection alive and handle incoming messages
        while True:
            try:
                data = await websocket.receive_text()
                message = json.loads(data)
                
                # Handle different message types
                if message.get("type") == "ping":
                    await manager.send_personal_message({
                        "type": "pong",
                        "timestamp": "2024-01-01T00:00:00Z"  # Will be dynamic
                    }, connection_id)
                
                elif message.get("type") == "update_filters":
                    new_filters = message.get("filters", {})
                    manager.subscribe_to_logs(connection_id, new_filters)
                    await manager.send_personal_message({
                        "type": "filters_updated",
                        "filters": new_filters
                    }, connection_id)
                
            except WebSocketDisconnect:
                break
            except json.JSONDecodeError:
                await manager.send_personal_message({
                    "type": "error",
                    "message": "Invalid JSON format"
                }, connection_id)
            except Exception as e:
                logger.error(f"Error handling WebSocket message: {e}")
                await manager.send_personal_message({
                    "type": "error",
                    "message": str(e)
                }, connection_id)
    
    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected: {connection_id}")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        manager.unsubscribe_from_logs(connection_id)
        manager.disconnect(connection_id)


@router.websocket("/tasks/{task_id}")
async def websocket_task(
    websocket: WebSocket,
    task_id: UUID,
    token: str = Query(..., description="JWT authentication token"),
    db: AsyncSession = Depends(get_db_session)
):
    """WebSocket endpoint for real-time updates for specific task."""
    connection_id = f"task_{task_id}_{id(websocket)}"

    # Validate JWT token
    try:
        user = await validate_websocket_token(token, db)
        logger.info(f"Task WebSocket authenticated for user: {user.username}")
    except HTTPException as e:
        logger.warning(f"Task WebSocket authentication failed: {e.detail}")
        await websocket.close(code=1008, reason="Authentication failed")
        return

    await manager.connect(websocket, connection_id)
    
    try:
        manager.subscribe_to_task(connection_id, task_id)
        
        # Send welcome message
        await manager.send_personal_message({
            "type": "connected",
            "message": f"Connected to task {task_id}",
            "task_id": str(task_id)
        }, connection_id)
        
        # Keep connection alive
        while True:
            try:
                data = await websocket.receive_text()
                message = json.loads(data)
                
                if message.get("type") == "ping":
                    await manager.send_personal_message({
                        "type": "pong",
                        "timestamp": "2024-01-01T00:00:00Z"  # Will be dynamic
                    }, connection_id)
                
            except WebSocketDisconnect:
                break
            except json.JSONDecodeError:
                await manager.send_personal_message({
                    "type": "error",
                    "message": "Invalid JSON format"
                }, connection_id)
    
    except WebSocketDisconnect:
        logger.info(f"Task WebSocket disconnected: {connection_id}")
    except Exception as e:
        logger.error(f"Task WebSocket error: {e}")
    finally:
        manager.unsubscribe_from_task(connection_id, task_id)
        manager.disconnect(connection_id)


# Export manager for use by other modules
__all__ = ["manager"]