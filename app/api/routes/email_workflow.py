"""
Email Workflow API Routes.

This module provides REST API endpoints for email workflow management including:
- Email analysis and processing
- Task creation from emails
- Workflow status tracking
- Email search and filtering
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query, BackgroundTasks
from starlette import status as status_codes
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, and_, or_
from typing import List, Optional, Dict, Any
from uuid import UUID, uuid4
from pydantic import BaseModel, Field
from datetime import datetime, timedelta

from app.api.dependencies import get_db_session, verify_api_key
from app.services.email_analysis_service import email_analysis_service, EmailAnalysis
from app.services.email_task_converter import email_task_converter, TaskCreationRequest, TaskCreationResult
from app.db.models.task import Task, TaskStatus
from app.db.models.content import ContentItem
from app.connectors.communication import EmailConnector
from app.services.secrets_service import secrets_service
from app.utils.logging import get_logger

logger = get_logger("email_workflow_api")
router = APIRouter()


class EmailWorkflowRequest(BaseModel):
    """Request to start an email workflow."""
    mailbox_config: Dict[str, Any] = Field(..., description="IMAP mailbox configuration")
    processing_options: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Processing options")
    user_id: str = Field(..., description="User identifier")


class EmailAnalysisRequest(BaseModel):
    """Request to analyze a single email."""
    email_content: str = Field(..., description="Email content to analyze")
    email_metadata: Dict[str, Any] = Field(..., description="Email metadata")
    attachments: Optional[List[Dict[str, Any]]] = Field(default_factory=list, description="Email attachments")


class EmailWorkflowResponse(BaseModel):
    """Response for workflow operations."""
    workflow_id: str
    status: str
    message: str
    created_at: str


class EmailAnalysisResponse(BaseModel):
    """Response for email analysis."""
    analysis: Dict[str, Any]
    processing_time_ms: float
    analyzed_at: str


class EmailTaskResponse(BaseModel):
    """Response for email-derived tasks."""
    task_id: str
    email_id: str
    status: str
    priority: str
    description: str
    created_at: str
    due_date: Optional[str]


class EmailWorkflowStatus(BaseModel):
    """Status of an email workflow."""
    workflow_id: str
    status: str
    emails_processed: int
    tasks_created: int
    started_at: str
    completed_at: Optional[str]
    processing_time_ms: Optional[float]


@router.post("/workflows/start", response_model=EmailWorkflowResponse, dependencies=[Depends(verify_api_key)])
async def start_email_workflow(
    request: EmailWorkflowRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db_session)
):
    """Start email processing workflow."""
    try:
        # Validate mailbox configuration
        if not request.mailbox_config.get("server") or not request.mailbox_config.get("username"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Mailbox configuration must include server and username"
            )

        # Generate workflow ID
        workflow_id = str(uuid4())

        # Store workflow metadata (in a real implementation, this would be in a database table)
        workflow_data = {
            "workflow_id": workflow_id,
            "user_id": request.user_id,
            "mailbox_config": request.mailbox_config,
            "processing_options": request.processing_options,
            "status": "running",
            "emails_processed": 0,
            "tasks_created": 0,
            "started_at": datetime.now().isoformat(),
            "created_at": datetime.now().isoformat()
        }

        # Add background task for processing
        background_tasks.add_task(
            process_email_workflow_background,
            workflow_id,
            request,
            db
        )

        logger.info(f"Started email workflow {workflow_id} for user {request.user_id}")
        return EmailWorkflowResponse(
            workflow_id=workflow_id,
            status="running",
            message="Email workflow started successfully",
            created_at=workflow_data["created_at"]
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to start email workflow: {e}")
        raise HTTPException(
            status_code=status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to start email workflow"
        )


@router.get("/workflows/{workflow_id}/status", response_model=EmailWorkflowStatus)
async def get_workflow_status(
    workflow_id: str,
    db: AsyncSession = Depends(get_db_session)
):
    """Get email workflow status."""
    try:
        # In a real implementation, this would query a workflow table
        # For now, return a mock status
        return EmailWorkflowStatus(
            workflow_id=workflow_id,
            status="completed",
            emails_processed=5,
            tasks_created=3,
            started_at=datetime.now().isoformat(),
            completed_at=datetime.now().isoformat(),
            processing_time_ms=1500.0
        )

    except Exception as e:
        logger.error(f"Failed to get workflow status {workflow_id}: {e}")
        raise HTTPException(
            status_code=status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve workflow status"
        )


@router.post("/workflows/{workflow_id}/cancel", dependencies=[Depends(verify_api_key)])
async def cancel_email_workflow(
    workflow_id: str,
    db: AsyncSession = Depends(get_db_session)
):
    """Cancel an email workflow."""
    try:
        # In a real implementation, this would update workflow status in database
        logger.info(f"Cancelled email workflow {workflow_id}")
        return {"message": "Workflow cancelled successfully"}

    except Exception as e:
        logger.error(f"Failed to cancel workflow {workflow_id}: {e}")
        raise HTTPException(
            status_code=status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to cancel workflow"
        )


@router.get("/workflows/history", response_model=List[EmailWorkflowStatus])
async def get_workflow_history(
    user_id: Optional[str] = Query(None, description="Filter by user ID"),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db_session)
):
    """Get email workflow history."""
    try:
        # In a real implementation, this would query workflow history from database
        # Return mock data for now
        workflows = []
        for i in range(min(limit, 5)):
            workflows.append(EmailWorkflowStatus(
                workflow_id=f"workflow-{i+1}",
                status="completed",
                emails_processed=5 + i,
                tasks_created=2 + i,
                started_at=(datetime.now() - timedelta(hours=i)).isoformat(),
                completed_at=(datetime.now() - timedelta(hours=i-1)).isoformat(),
                processing_time_ms=1000.0 + (i * 200)
            ))

        return workflows

    except Exception as e:
        logger.error(f"Failed to get workflow history: {e}")
        raise HTTPException(
            status_code=status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve workflow history"
        )


@router.post("/analyze", response_model=EmailAnalysisResponse, dependencies=[Depends(verify_api_key)])
async def analyze_single_email(
    request: EmailAnalysisRequest,
    db: AsyncSession = Depends(get_db_session)
):
    """Analyze a single email for importance and categorization."""
    try:
        # Perform email analysis
        analysis = await email_analysis_service.analyze_email(
            email_content=request.email_content,
            email_metadata=request.email_metadata,
            attachments=request.attachments
        )

        return EmailAnalysisResponse(
            analysis=analysis.to_dict(),
            processing_time_ms=analysis.processing_time_ms,
            analyzed_at=analysis.analyzed_at.isoformat()
        )

    except Exception as e:
        logger.error(f"Failed to analyze email: {e}")
        raise HTTPException(
            status_code=status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to analyze email"
        )


@router.get("/tasks", response_model=List[EmailTaskResponse])
async def get_email_tasks(
    email_id: Optional[str] = Query(None, description="Filter by email ID"),
    status: Optional[str] = Query(None, description="Filter by task status"),
    priority: Optional[str] = Query(None, description="Filter by priority"),
    limit: int = Query(default=50, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db_session)
):
    """Get tasks created from emails."""
    try:
        # Query tasks that were created from emails
        query = select(Task).where(
            Task.input.op('->>')('email_id').isnot(None)  # Tasks with email_id in input
        )

        if email_id:
            query = query.where(Task.input.op('->>')('email_id') == email_id)

        if status:
            query = query.where(Task.status == TaskStatus(status))

        if priority:
            # Priority would be stored in task input or metadata
            query = query.where(Task.input.op('->>')('priority') == priority)

        query = query.offset(offset).limit(limit).order_by(Task.created_at.desc())

        result = await db.execute(query)
        tasks = result.scalars().all()

        # Convert to response format
        task_responses = []
        for task in tasks:
            task_responses.append(EmailTaskResponse(
                task_id=str(task.id),
                email_id=task.input.get("email_id", ""),
                status=task.status.value,
                priority=task.input.get("priority", "medium"),
                description=task.input.get("description", "Email-derived task"),
                created_at=task.created_at.isoformat() if task.created_at else "",
                due_date=task.input.get("due_date")
            ))

        return task_responses

    except Exception as e:
        logger.error(f"Failed to get email tasks: {e}")
        raise HTTPException(
            status_code=status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve email tasks"
        )


@router.post("/tasks/{task_id}/complete", dependencies=[Depends(verify_api_key)])
async def complete_email_task(
    task_id: UUID,
    db: AsyncSession = Depends(get_db_session)
):
    """Mark an email-derived task as completed."""
    try:
        result = await db.execute(select(Task).where(Task.id == task_id))
        task = result.scalar_one_or_none()

        if not task:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Task not found"
            )

        if task.status == TaskStatus.COMPLETED:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Task is already completed"
            )

        # Update task status
        stmt = update(Task).where(Task.id == task_id).values(
            status=TaskStatus.COMPLETED,
            completed_at=datetime.now()
        )
        await db.execute(stmt)
        await db.commit()

        logger.info(f"Completed email task {task_id}")
        return {"message": "Task completed successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to complete task {task_id}: {e}")
        await db.rollback()
        raise HTTPException(
            status_code=status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to complete task"
        )


@router.post("/tasks/{task_id}/followup", dependencies=[Depends(verify_api_key)])
async def schedule_task_followup(
    task_id: UUID,
    followup_date: Optional[str] = Query(None, description="Follow-up date (ISO format)"),
    followup_notes: Optional[str] = Query(None, description="Follow-up notes"),
    db: AsyncSession = Depends(get_db_session)
):
    """Schedule follow-up for an email task."""
    try:
        result = await db.execute(select(Task).where(Task.id == task_id))
        task = result.scalar_one_or_none()

        if not task:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Task not found"
            )

        # Parse follow-up date
        if followup_date:
            try:
                parsed_date = datetime.fromisoformat(followup_date.replace('Z', '+00:00'))
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid date format. Use ISO format."
                )
        else:
            # Default to 3 days from now
            parsed_date = datetime.now() + timedelta(days=3)

        # Update task with follow-up information
        current_input = task.input or {}
        updated_input = dict(current_input)
        updated_input["follow_up_date"] = parsed_date.isoformat()
        if followup_notes:
            updated_input["follow_up_notes"] = followup_notes

        stmt = update(Task).where(Task.id == task_id).values(input=updated_input)
        await db.execute(stmt)
        await db.commit()

        logger.info(f"Scheduled follow-up for task {task_id} on {parsed_date}")
        return {
            "message": "Follow-up scheduled successfully",
            "follow_up_date": parsed_date.isoformat()
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to schedule follow-up for task {task_id}: {e}")
        await db.rollback()
        raise HTTPException(
            status_code=status_codes.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to schedule follow-up"
        )


async def process_email_workflow_background(
    workflow_id: str,
    request: EmailWorkflowRequest,
    db: AsyncSession
):
    """Background task to process email workflow."""
    try:
        logger.info(f"Starting background email processing for workflow {workflow_id}")

        # Get email connector configuration
        connector_config = {
            "type": "email",
            "credentials": {
                "imap_server": request.mailbox_config.get("server"),
                "imap_port": request.mailbox_config.get("port", 993),
                "username": request.mailbox_config.get("username"),
                "password": request.mailbox_config.get("password")
            }
        }

        # Create email connector
        from app.connectors.base import ConnectorConfig, ConnectorType
        config = ConnectorConfig(
            id="email_workflow_connector",
            name="Email Workflow Connector",
            type=ConnectorType.COMMUNICATION,
            credentials=connector_config["credentials"],
            config={}
        )

        email_connector = EmailConnector(config)

        # Discover emails
        processing_opts = request.processing_options or {}
        source_config = {
            "mailbox": request.mailbox_config.get("mailbox", "INBOX"),
            "limit": processing_opts.get("max_emails", 50),
            "unread_only": processing_opts.get("unread_only", False),
            "since_date": processing_opts.get("since_date")
        }

        emails = await email_connector.discover(source_config)

        logger.info(f"Discovered {len(emails)} emails for workflow {workflow_id}")

        # Process each email
        tasks_created = 0
        for email in emails:
            try:
                # Fetch full email content
                content_data = await email_connector.fetch(email.id)

                # Analyze email
                analysis = await email_analysis_service.analyze_email(
                    email_content=content_data.text_content or "",
                    email_metadata={
                        "subject": email.title,
                        "sender": email.metadata.get("sender", ""),
                        "message_id": email.id,
                        "date": email.last_modified.isoformat() if email.last_modified else None
                    },
                    attachments=content_data.metadata.get("attachments", [])
                )

                # Create tasks if analysis indicates action required
                if analysis.action_required:
                    task_request = TaskCreationRequest(
                        email_analysis=analysis,
                        user_id=request.user_id,
                        email_content=content_data.text_content or "",
                        email_metadata={
                            "subject": email.title,
                            "sender": email.metadata.get("sender", ""),
                            "message_id": email.id
                        }
                    )

                    result = await email_task_converter.convert_to_tasks(task_request, db)
                    tasks_created += len(result.tasks_created)

                logger.debug(f"Processed email {email.id} in workflow {workflow_id}")

            except Exception as e:
                logger.error(f"Failed to process email {email.id} in workflow {workflow_id}: {e}")
                continue

        logger.info(f"Completed email workflow {workflow_id}: {len(emails)} emails processed, {tasks_created} tasks created")

    except Exception as e:
        logger.error(f"Email workflow {workflow_id} failed: {e}")
        # In a real implementation, update workflow status in database