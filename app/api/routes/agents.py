from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete
from typing import List, Optional
from uuid import UUID
from pydantic import BaseModel, Field
from app.db.models.agent import Agent
from app.api.dependencies import get_db_session, verify_api_key
from app.utils.logging import get_logger

logger = get_logger("agents_api")
router = APIRouter()


class AgentCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    model_name: str = Field(default="llama2", min_length=1, max_length=255)
    config: Optional[dict] = Field(default_factory=dict)


class AgentUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    model_name: Optional[str] = Field(None, min_length=1, max_length=255)
    config: Optional[dict] = None
    is_active: Optional[bool] = None


class AgentResponse(BaseModel):
    id: str
    name: str
    description: Optional[str]
    model_name: str
    config: dict
    is_active: bool
    created_at: str
    updated_at: str


@router.post("/create", response_model=AgentResponse, dependencies=[Depends(verify_api_key)])
async def create_agent(
    agent_data: AgentCreate,
    db: AsyncSession = Depends(get_db_session)
):
    """Create a new agent."""
    try:
        agent = Agent(
            name=agent_data.name,
            description=agent_data.description,
            model_name=agent_data.model_name,
            config=agent_data.config or {}
        )
        
        db.add(agent)
        await db.commit()
        await db.refresh(agent)
        
        logger.info(f"Created agent: {agent.id} - {agent.name}")
        return AgentResponse(**agent.to_dict())
        
    except Exception as e:
        logger.error(f"Failed to create agent: {e}")
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create agent"
        )


@router.get("", response_model=List[AgentResponse])
async def list_agents(
    active_only: bool = True,
    limit: int = Query(default=50, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db_session)
):
    """List all agents with optional filtering."""
    try:
        query = select(Agent)
        
        if active_only:
            query = query.where(Agent.is_active == True)
        
        query = query.offset(offset).limit(limit).order_by(Agent.created_at.desc())
        
        result = await db.execute(query)
        agents = result.scalars().all()
        
        return [AgentResponse(**agent.to_dict()) for agent in agents]
        
    except Exception as e:
        logger.error(f"Failed to list agents: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve agents"
        )


@router.get("/{agent_id}", response_model=AgentResponse)
async def get_agent(
    agent_id: UUID,
    db: AsyncSession = Depends(get_db_session)
):
    """Get a specific agent by ID."""
    try:
        result = await db.execute(select(Agent).where(Agent.id == agent_id))
        agent = result.scalar_one_or_none()
        
        if not agent:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Agent not found"
            )
        
        return AgentResponse(**agent.to_dict())
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get agent {agent_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve agent"
        )


@router.put("/{agent_id}", response_model=AgentResponse, dependencies=[Depends(verify_api_key)])
async def update_agent(
    agent_id: UUID,
    agent_data: AgentUpdate,
    db: AsyncSession = Depends(get_db_session)
):
    """Update an existing agent."""
    try:
        # Check if agent exists
        result = await db.execute(select(Agent).where(Agent.id == agent_id))
        agent = result.scalar_one_or_none()
        
        if not agent:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Agent not found"
            )
        
        # Update fields
        update_data = agent_data.dict(exclude_unset=True)
        if update_data:
            stmt = update(Agent).where(Agent.id == agent_id).values(**update_data)
            await db.execute(stmt)
            await db.commit()
            await db.refresh(agent)
        
        logger.info(f"Updated agent: {agent_id}")
        return AgentResponse(**agent.to_dict())
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update agent {agent_id}: {e}")
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update agent"
        )


@router.delete("/{agent_id}", dependencies=[Depends(verify_api_key)])
async def delete_agent(
    agent_id: UUID,
    db: AsyncSession = Depends(get_db_session)
):
    """Delete an agent."""
    try:
        result = await db.execute(select(Agent).where(Agent.id == agent_id))
        agent = result.scalar_one_or_none()
        
        if not agent:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Agent not found"
            )
        
        await db.execute(delete(Agent).where(Agent.id == agent_id))
        await db.commit()
        
        logger.info(f"Deleted agent: {agent_id}")
        return {"message": "Agent deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete agent {agent_id}: {e}")
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete agent"
        )