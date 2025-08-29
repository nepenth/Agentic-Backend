"""
Security and validation service for dynamic agents.
Optimized for home-lab setup: 2x Xeon E5-2683 v4, 2x Tesla P40, 158GB RAM
"""
import asyncio
import hashlib
import json
import re
import time
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum

from app.schemas.agent_schema import AgentSchema, ToolDefinition, FieldDefinition, FieldType
from app.utils.logging import get_logger
from app.services.log_service import LogService

logger = get_logger(__name__)


class SecurityViolationType(Enum):
    """Types of security violations."""
    RESOURCE_EXCEEDED = "resource_exceeded"
    PERMISSION_DENIED = "permission_denied"
    MALICIOUS_CONTENT = "malicious_content"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    SCHEMA_VIOLATION = "schema_violation"
    EXECUTION_TIMEOUT = "execution_timeout"


class SecurityLevel(Enum):
    """Security enforcement levels."""
    STRICT = "strict"
    MODERATE = "moderate"
    LENIENT = "lenient"


@dataclass
class HomeLabLimits:
    """Resource limits optimized for home-lab hardware (2x Xeon E5-2683 v4, 2x Tesla P40, 158GB RAM)."""

    # CPU limits (based on 32 cores total, 64 threads with hyperthreading)
    max_concurrent_agents: int = 8  # Conservative for stability
    max_agent_execution_time: int = 1800  # 30 minutes per agent
    max_pipeline_execution_time: int = 600  # 10 minutes per pipeline
    max_step_execution_time: int = 300  # 5 minutes per step

    # Memory limits (based on 158GB RAM, leaving headroom for system)
    max_agent_memory_mb: int = 8192  # 8GB per agent
    max_total_memory_mb: int = 131072  # 128GB total for all agents
    max_data_model_memory_mb: int = 1024  # 1GB per data model

    # Database limits
    max_table_rows: int = 1000000  # 1M rows per table
    max_concurrent_queries: int = 20
    max_query_execution_time: int = 300  # 5 minutes per query

    # Network limits
    max_external_requests_per_hour: int = 1000
    max_request_size_kb: int = 1024  # 1MB per request
    allowed_domains: Optional[Set[str]] = None  # Whitelist of allowed domains

    # GPU limits (2x Tesla P40)
    max_gpu_memory_mb: int = 24576  # 24GB per GPU
    max_concurrent_gpu_tasks: int = 4

    # Schema complexity limits
    max_data_models: int = 5
    max_fields_per_model: int = 20
    max_pipeline_steps: int = 10
    max_tools_per_agent: int = 8
    max_nested_json_depth: int = 3

    def __post_init__(self):
        if self.allowed_domains is None:
            # Default safe domains for home-lab
            self.allowed_domains = {
                "localhost",
                "127.0.0.1",
                "api.openai.com",
                "api.anthropic.com",
                "api.groq.com",
                "huggingface.co",
                "cdn.jsdelivr.net"
            }


@dataclass
class SecurityIncident:
    """Security incident record."""
    incident_id: str
    agent_id: str
    agent_type: str
    violation_type: SecurityViolationType
    severity: str
    description: str
    details: Dict[str, Any]
    timestamp: datetime
    resolved: bool = False
    resolution_notes: Optional[str] = None


class SecurityService:
    """
    Comprehensive security service for dynamic agents.
    Handles schema validation, execution sandboxing, and resource management.
    """

    def __init__(self, log_service: Optional[LogService] = None):
        self.log_service = log_service
        self.limits = HomeLabLimits()
        self.security_level = SecurityLevel.MODERATE

        # Runtime tracking
        self.active_agents: Dict[str, Dict[str, Any]] = {}
        self.agent_resource_usage: Dict[str, Dict[str, Any]] = {}
        self.rate_limiters: Dict[str, Dict[str, Any]] = {}
        self.security_incidents: List[SecurityIncident] = []

        # Malicious pattern detection
        self.malicious_patterns = self._load_malicious_patterns()

        logger.info("SecurityService initialized with home-lab optimized limits")

    def _load_malicious_patterns(self) -> List[Dict[str, Any]]:
        """Load patterns for detecting malicious content."""
        return [
            {
                "name": "sql_injection",
                "pattern": r"(?i)(union\s+select|drop\s+table|alter\s+table|exec\s+|eval\s*\()",
                "severity": "high"
            },
            {
                "name": "path_traversal",
                "pattern": r"\.\./|\.\.\\",
                "severity": "high"
            },
            {
                "name": "command_injection",
                "pattern": r"[;&|`$()<>]",
                "severity": "high"
            },
            {
                "name": "script_injection",
                "pattern": r"<script|<iframe|<object|<embed",
                "severity": "medium"
            },
            {
                "name": "suspicious_urls",
                "pattern": r"(?i)(javascript:|data:|vbscript:|file:|ftp:)",
                "severity": "medium"
            }
        ]

    # ===== SCHEMA SECURITY VALIDATION =====

    async def validate_agent_schema_security(self, schema: AgentSchema) -> Tuple[bool, List[str], List[str]]:
        """
        Comprehensive security validation for agent schemas.

        Args:
            schema: Agent schema to validate

        Returns:
            Tuple of (is_secure, security_errors, warnings)
        """
        errors = []
        warnings = []

        try:
            # Resource limit validation
            resource_errors = self._validate_resource_limits(schema)
            errors.extend(resource_errors)

            # Schema complexity validation
            complexity_errors, complexity_warnings = self._validate_schema_complexity(schema)
            errors.extend(complexity_errors)
            warnings.extend(complexity_warnings)

            # Tool security validation
            tool_errors = self._validate_tool_security(schema)
            errors.extend(tool_errors)

            # Data model security validation
            model_errors = self._validate_data_model_security(schema)
            errors.extend(model_errors)

            # Malicious content detection
            malicious_errors = self._detect_malicious_content(schema)
            errors.extend(malicious_errors)

            # Permission boundary validation
            permission_errors = self._validate_permission_boundaries(schema)
            errors.extend(permission_errors)

            is_secure = len(errors) == 0

            if not is_secure:
                await self._log_security_incident(
                    agent_id=f"schema_validation_{schema.agent_type}",
                    agent_type=schema.agent_type,
                    violation_type=SecurityViolationType.SCHEMA_VIOLATION,
                    severity="high" if len(errors) > 2 else "medium",
                    description=f"Schema security validation failed with {len(errors)} errors",
                    details={"errors": errors, "warnings": warnings}
                )

            return is_secure, errors, warnings

        except Exception as e:
            logger.error(f"Schema security validation error: {e}")
            return False, [f"Security validation error: {str(e)}"], warnings

    def _validate_resource_limits(self, schema: AgentSchema) -> List[str]:
        """Validate resource limits against home-lab constraints."""
        errors = []

        # Execution time limits
        if schema.max_execution_time and schema.max_execution_time > self.limits.max_agent_execution_time:
            errors.append(
                f"Execution time {schema.max_execution_time}s exceeds home-lab limit of {self.limits.max_agent_execution_time}s"
            )

        # Memory limits
        if schema.max_memory_usage and schema.max_memory_usage > self.limits.max_agent_memory_mb:
            errors.append(
                f"Memory usage {schema.max_memory_usage}MB exceeds home-lab limit of {self.limits.max_agent_memory_mb}MB"
            )

        # Data model count
        if len(schema.data_models) > self.limits.max_data_models:
            errors.append(
                f"Data model count {len(schema.data_models)} exceeds limit of {self.limits.max_data_models}"
            )

        # Pipeline steps
        if len(schema.processing_pipeline.steps) > self.limits.max_pipeline_steps:
            errors.append(
                f"Pipeline steps {len(schema.processing_pipeline.steps)} exceed limit of {self.limits.max_pipeline_steps}"
            )

        # Tools count
        if len(schema.tools) > self.limits.max_tools_per_agent:
            errors.append(
                f"Tools count {len(schema.tools)} exceeds limit of {self.limits.max_tools_per_agent}"
            )

        return errors

    def _validate_schema_complexity(self, schema: AgentSchema) -> Tuple[List[str], List[str]]:
        """Validate schema complexity to prevent system abuse."""
        errors = []
        warnings = []

        # Check field counts per model
        for model_name, model_def in schema.data_models.items():
            if len(model_def.fields) > self.limits.max_fields_per_model:
                errors.append(
                    f"Model '{model_name}' has {len(model_def.fields)} fields, exceeds limit of {self.limits.max_fields_per_model}"
                )

            # Check for complex field types that might cause performance issues
            for field_name, field_def in model_def.fields.items():
                if field_def.type == FieldType.JSON:
                    # Check for deeply nested JSON structures
                    if self._calculate_json_depth(field_def) > self.limits.max_nested_json_depth:
                        errors.append(
                            f"Field '{model_name}.{field_name}' exceeds max JSON nesting depth of {self.limits.max_nested_json_depth}"
                        )

                # Check for potentially problematic constraints
                if field_def.constraints:
                    if len(str(field_def.constraints)) > 1000:  # Arbitrary limit for constraint complexity
                        warnings.append(f"Complex constraints on field '{model_name}.{field_name}' may impact performance")

        # Check for circular dependencies in pipeline
        if self._has_circular_dependencies(schema):
            errors.append("Circular dependencies detected in processing pipeline")

        return errors, warnings

    def _validate_tool_security(self, schema: AgentSchema) -> List[str]:
        """Validate tool configurations for security issues."""
        errors = []

        for tool_name, tool_def in schema.tools.items():
            # Check for dangerous tool types
            dangerous_tools = ["system_command", "file_system", "network_scanner"]
            if tool_def.type in dangerous_tools:
                errors.append(f"Tool type '{tool_def.type}' is not allowed in home-lab environment")

            # Validate external API configurations
            if tool_def.type in ["external_api", "webhook"]:
                if not tool_def.auth_config:
                    errors.append(f"Tool '{tool_name}' requires authentication configuration")

                # Check allowed domains
                if tool_def.config.get("url"):
                    domain = self._extract_domain(tool_def.config["url"])
                    if self.limits.allowed_domains and domain not in self.limits.allowed_domains:
                        errors.append(f"Domain '{domain}' not in allowed list for tool '{tool_name}'")

            # Validate rate limits
            if not tool_def.rate_limit:
                errors.append(f"Tool '{tool_name}' must have rate limiting configured")

            # Check timeout configurations
            if tool_def.timeout and tool_def.timeout > self.limits.max_step_execution_time:
                errors.append(f"Tool '{tool_name}' timeout {tool_def.timeout}s exceeds limit")

        return errors

    def _validate_data_model_security(self, schema: AgentSchema) -> List[str]:
        """Validate data models for security issues."""
        errors = []

        for model_name, model_def in schema.data_models.items():
            # Check for reserved table names that might conflict with system tables
            reserved_names = ["users", "agents", "tasks", "logs", "sessions", "admin"]
            if model_def.table_name.lower() in reserved_names:
                errors.append(f"Table name '{model_def.table_name}' is reserved")

            # Validate field names for SQL injection potential
            for field_name in model_def.fields.keys():
                if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', field_name):
                    errors.append(f"Invalid field name '{field_name}' in model '{model_name}'")

                # Check for overly long field names
                if len(field_name) > 63:
                    errors.append(f"Field name '{field_name}' exceeds 63 character limit")

        return errors

    def _detect_malicious_content(self, schema: AgentSchema) -> List[str]:
        """Detect potentially malicious content in schema."""
        errors = []

        # Convert schema to string for pattern matching
        schema_str = json.dumps(schema.dict(), indent=2)

        for pattern_info in self.malicious_patterns:
            matches = re.findall(pattern_info["pattern"], schema_str, re.IGNORECASE)
            if matches:
                errors.append(
                    f"Potential {pattern_info['name']} detected: {len(matches)} occurrences"
                )

        return errors

    def _validate_permission_boundaries(self, schema: AgentSchema) -> List[str]:
        """Validate that schema doesn't exceed permission boundaries."""
        errors = []

        # Check for cross-agent data access patterns
        for tool_name, tool_def in schema.tools.items():
            if tool_def.type == "database" and tool_def.config.get("cross_agent_access"):
                errors.append(f"Tool '{tool_name}' attempts cross-agent data access")

        # Validate that pipeline steps don't access unauthorized resources
        for step in schema.processing_pipeline.steps:
            tool_def = schema.tools.get(step.tool)
            if tool_def and tool_def.type == "file_system":
                # Check if file paths are restricted to agent-specific directories
                config = step.config or {}
                if "path" in config:
                    if not config["path"].startswith(f"/agents/{schema.agent_type}/"):
                        errors.append(f"Step '{step.name}' accesses unauthorized file path")

        return errors

    # ===== EXECUTION SANDBOXING =====

    async def initialize_agent_sandbox(self, agent_id: str, agent_type: str, schema: Optional[AgentSchema] = None) -> bool:
        """
        Initialize sandbox environment for agent execution.

        Args:
            agent_id: Unique agent identifier
            agent_type: Agent type
            schema: Agent schema

        Returns:
            True if sandbox initialized successfully
        """
        try:
            # Check concurrent agent limits
            if len(self.active_agents) >= self.limits.max_concurrent_agents:
                await self._log_security_incident(
                    agent_id=agent_id,
                    agent_type=agent_type,
                    violation_type=SecurityViolationType.RESOURCE_EXCEEDED,
                    severity="medium",
                    description="Maximum concurrent agents limit reached",
                    details={"current_count": len(self.active_agents), "limit": self.limits.max_concurrent_agents}
                )
                return False

            # Initialize agent tracking
            self.active_agents[agent_id] = {
                "agent_type": agent_type,
                "start_time": datetime.utcnow(),
                "resource_usage": {
                    "memory_mb": 0,
                    "cpu_percent": 0,
                    "execution_time": 0
                },
                "rate_limits": {},
                "security_events": []
            }

            # Initialize resource tracking
            self.agent_resource_usage[agent_id] = {
                "memory_peak_mb": 0,
                "cpu_time_seconds": 0,
                "network_requests": 0,
                "database_queries": 0,
                "gpu_memory_mb": 0
            }

            logger.info(f"Agent sandbox initialized for {agent_id} ({agent_type})")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize agent sandbox: {e}")
            return False

    async def validate_execution_request(
        self,
        agent_id: str,
        tool_name: str,
        input_data: Dict[str, Any]
    ) -> Tuple[bool, Optional[str]]:
        """
        Validate an execution request against security policies.

        Args:
            agent_id: Agent identifier
            tool_name: Tool being executed
            input_data: Input data for the tool

        Returns:
            Tuple of (is_allowed, denial_reason)
        """
        if agent_id not in self.active_agents:
            return False, "Agent not properly initialized"

        agent_info = self.active_agents[agent_id]

        # Check rate limits
        rate_limit_ok, rate_limit_reason = await self._check_rate_limits(agent_id, tool_name)
        if not rate_limit_ok:
            return False, rate_limit_reason

        # Validate input data size
        input_size_kb = len(json.dumps(input_data).encode('utf-8')) / 1024
        if input_size_kb > self.limits.max_request_size_kb:
            return False, f"Input size {input_size_kb:.1f}KB exceeds limit of {self.limits.max_request_size_kb}KB"

        # Check for malicious content in input
        malicious_content = self._scan_for_malicious_content(input_data)
        if malicious_content:
            await self._log_security_incident(
                agent_id=agent_id,
                agent_type=agent_info["agent_type"],
                violation_type=SecurityViolationType.MALICIOUS_CONTENT,
                severity="high",
                description=f"Malicious content detected in execution input",
                details={"tool": tool_name, "content_flags": malicious_content}
            )
            return False, "Malicious content detected in input"

        return True, None

    async def monitor_execution(
        self,
        agent_id: str,
        execution_context: Dict[str, Any]
    ) -> None:
        """
        Monitor agent execution for security violations.

        Args:
            agent_id: Agent identifier
            execution_context: Current execution context
        """
        if agent_id not in self.active_agents:
            return

        agent_info = self.active_agents[agent_id]
        current_time = datetime.utcnow()

        # Update execution time
        execution_time = (current_time - agent_info["start_time"]).total_seconds()
        agent_info["resource_usage"]["execution_time"] = execution_time

        # Check execution time limits
        if execution_time > self.limits.max_agent_execution_time:
            await self._handle_security_violation(
                agent_id,
                SecurityViolationType.EXECUTION_TIMEOUT,
                f"Agent execution time {execution_time}s exceeded limit of {self.limits.max_agent_execution_time}s"
            )

        # Monitor resource usage (simplified for home-lab)
        # In a real implementation, this would integrate with system monitoring

    async def cleanup_agent_sandbox(self, agent_id: str) -> None:
        """
        Cleanup agent sandbox after execution.

        Args:
            agent_id: Agent identifier
        """
        if agent_id in self.active_agents:
            agent_info = self.active_agents[agent_id]

            # Log final resource usage
            logger.info(f"Agent {agent_id} cleanup - resources used: {self.agent_resource_usage.get(agent_id, {})}")

            # Remove agent from active tracking
            del self.active_agents[agent_id]

            # Clean up resource usage tracking
            if agent_id in self.agent_resource_usage:
                del self.agent_resource_usage[agent_id]

    # ===== HELPER METHODS =====

    def _calculate_json_depth(self, field_def: FieldDefinition, current_depth: int = 0) -> int:
        """Calculate nesting depth of JSON field."""
        if field_def.type != FieldType.JSON:
            return current_depth

        # This is a simplified calculation - in practice you'd need to analyze the actual JSON schema
        return current_depth + 1

    def _has_circular_dependencies(self, schema: AgentSchema) -> bool:
        """Check for circular dependencies in processing pipeline."""
        # Simplified circular dependency check
        step_names = {step.name for step in schema.processing_pipeline.steps}
        dependency_graph = {}

        for step in schema.processing_pipeline.steps:
            dependencies = set(step.depends_on) if step.depends_on else set()
            dependency_graph[step.name] = dependencies

        # Basic cycle detection (simplified)
        visited = set()
        rec_stack = set()

        def has_cycle(node):
            visited.add(node)
            rec_stack.add(node)

            for neighbor in dependency_graph.get(node, set()):
                if neighbor not in visited:
                    if has_cycle(neighbor):
                        return True
                elif neighbor in rec_stack:
                    return True

            rec_stack.remove(node)
            return False

        for node in dependency_graph:
            if node not in visited:
                if has_cycle(node):
                    return True

        return False

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.netloc
        except:
            return url

    def _scan_for_malicious_content(self, data: Any) -> List[str]:
        """Scan data for malicious content patterns."""
        content_str = json.dumps(data) if isinstance(data, (dict, list)) else str(data)
        flags = []

        for pattern_info in self.malicious_patterns:
            if re.search(pattern_info["pattern"], content_str, re.IGNORECASE):
                flags.append(pattern_info["name"])

        return flags

    async def _check_rate_limits(self, agent_id: str, tool_name: str) -> Tuple[bool, Optional[str]]:
        """Check if request exceeds rate limits."""
        # Simplified rate limiting - in production you'd use Redis or similar
        current_time = datetime.utcnow()

        if agent_id not in self.rate_limiters:
            self.rate_limiters[agent_id] = {}

        if tool_name not in self.rate_limiters[agent_id]:
            self.rate_limiters[agent_id][tool_name] = {
                "requests": [],
                "last_reset": current_time
            }

        limiter = self.rate_limiters[agent_id][tool_name]

        # Clean old requests (older than 1 hour)
        cutoff_time = current_time - timedelta(hours=1)
        limiter["requests"] = [req for req in limiter["requests"] if req > cutoff_time]

        # Check rate limit (100 requests per hour per tool)
        if len(limiter["requests"]) >= 100:
            return False, f"Rate limit exceeded for tool '{tool_name}' (100/hour)"

        # Add current request
        limiter["requests"].append(current_time)

        return True, None

    async def _log_security_incident(
        self,
        agent_id: str,
        agent_type: str,
        violation_type: SecurityViolationType,
        severity: str,
        description: str,
        details: Dict[str, Any]
    ) -> None:
        """Log a security incident."""
        incident = SecurityIncident(
            incident_id=f"sec_{int(time.time())}_{hashlib.md5(f'{agent_id}_{violation_type.value}'.encode()).hexdigest()[:8]}",
            agent_id=agent_id,
            agent_type=agent_type,
            violation_type=violation_type,
            severity=severity,
            description=description,
            details=details,
            timestamp=datetime.utcnow()
        )

        self.security_incidents.append(incident)

        # Log to system
        logger.warning(f"Security incident: {description}", extra={
            "incident_id": incident.incident_id,
            "agent_id": agent_id,
            "violation_type": violation_type.value,
            "severity": severity
        })

        # Log to service if available (simplified logging for security incidents)
        # Note: LogService requires task_id and agent_id as UUIDs, so we use standard logging
        logger.warning(f"Security incident: {description}", extra={
            "incident_id": incident.incident_id,
            "agent_id": agent_id,
            "violation_type": violation_type.value,
            "severity": severity,
            "details": details
        })

    async def _handle_security_violation(
        self,
        agent_id: str,
        violation_type: SecurityViolationType,
        description: str
    ) -> None:
        """Handle a security violation by potentially disabling the agent."""
        agent_info = self.active_agents.get(agent_id)
        if not agent_info:
            return

        # Add to agent's security events
        agent_info["security_events"].append({
            "type": violation_type.value,
            "description": description,
            "timestamp": datetime.utcnow().isoformat()
        })

        # For severe violations, disable the agent
        severe_violations = [SecurityViolationType.MALICIOUS_CONTENT, SecurityViolationType.EXECUTION_TIMEOUT]
        if violation_type in severe_violations:
            logger.error(f"Severe security violation for agent {agent_id}: {description}")
            # In a real implementation, this would disable the agent and notify administrators

    # ===== MONITORING AND REPORTING =====

    def get_security_status(self) -> Dict[str, Any]:
        """Get current security status and metrics."""
        return {
            "active_agents": len(self.active_agents),
            "total_incidents": len(self.security_incidents),
            "recent_incidents": [
                {
                    "id": incident.incident_id,
                    "agent_id": incident.agent_id,
                    "type": incident.violation_type.value,
                    "severity": incident.severity,
                    "timestamp": incident.timestamp.isoformat()
                }
                for incident in self.security_incidents[-10:]  # Last 10 incidents
            ],
            "resource_limits": {
                "max_concurrent_agents": self.limits.max_concurrent_agents,
                "max_memory_mb": self.limits.max_total_memory_mb,
                "max_execution_time": self.limits.max_agent_execution_time
            },
            "current_usage": {
                "active_agents": len(self.active_agents),
                "total_memory_mb": sum(
                    usage.get("memory_peak_mb", 0)
                    for usage in self.agent_resource_usage.values()
                )
            }
        }

    async def get_agent_security_report(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Get security report for a specific agent."""
        if agent_id not in self.active_agents:
            return None

        agent_info = self.active_agents[agent_id]
        resource_usage = self.agent_resource_usage.get(agent_id, {})

        # Get incidents for this agent
        agent_incidents = [
            incident for incident in self.security_incidents
            if incident.agent_id == agent_id
        ]

        return {
            "agent_id": agent_id,
            "agent_type": agent_info["agent_type"],
            "start_time": agent_info["start_time"].isoformat(),
            "resource_usage": resource_usage,
            "security_events": agent_info["security_events"],
            "incidents": [
                {
                    "id": incident.incident_id,
                    "type": incident.violation_type.value,
                    "severity": incident.severity,
                    "description": incident.description,
                    "timestamp": incident.timestamp.isoformat()
                }
                for incident in agent_incidents
            ],
            "is_secure": len(agent_incidents) == 0
        }