# 📚 API Documentation & Testing Guide

The Agentic Backend provides multiple ways to explore and test the API endpoints.

## 🔗 Interactive API Documentation

### Swagger UI (Recommended)
**URL**: http://localhost:8000/docs

The Swagger UI provides an interactive interface where you can:
- ✅ View all available endpoints
- ✅ See request/response schemas 
- ✅ Test endpoints directly in the browser
- ✅ Authenticate with API keys
- ✅ View example requests and responses

![Swagger UI Example](https://via.placeholder.com/800x400/2196F3/white?text=Swagger+UI+Interface)

### ReDoc Documentation  
**URL**: http://localhost:8000/redoc

Alternative documentation interface with:
- 📖 Clean, readable format
- 🔍 Better for browsing and reading
- 📋 Detailed schema information
- 🏷️ Tag-based organization

## 🚀 Quick API Testing Guide

### Step 1: Access Swagger UI
1. Start the system: `docker-compose up -d`
2. Open http://localhost:8000/docs in your browser
3. You should see the interactive API documentation

### Step 2: Authentication (If Enabled)
If you set an `API_KEY` in your .env file:

1. Click the **🔒 Authorize** button at the top
2. Enter your API key in the format: `your-api-key-here`
3. Click **Authorize**

### Step 3: Test Basic Endpoints

**Test System Health:**
1. Expand `GET /api/v1/health`
2. Click **"Try it out"**
3. Click **"Execute"**
4. You should see a 200 response with system status

## 📋 Complete API Reference

### 🔒 Security Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `GET` | `/api/v1/security/status` | Current security status and metrics | ✅ |
| `GET` | `/api/v1/security/agents/{agent_id}/report` | Agent-specific security reports | ✅ |
| `POST` | `/api/v1/security/validate-tool-execution` | Pre-validate tool executions | ❌ |
| `GET` | `/api/v1/security/incidents` | Security incident management with filtering | ✅ |
| `POST` | `/api/v1/security/incidents/{incident_id}/resolve` | Resolve security incidents | ✅ |
| `GET` | `/api/v1/security/limits` | Current security limits and constraints | ✅ |
| `GET` | `/api/v1/security/health` | Security service health check | ❌ |
## 🛡️ Security Features Overview

The Agentic Backend includes a comprehensive security framework designed specifically for dynamic agent execution in home-lab environments. The security system provides multiple layers of protection while maintaining flexibility for diverse agent workflows.

### Core Security Components

#### 1. **Schema Security Validation**
- **Comprehensive Schema Analysis**: Validates agent schemas against security policies before registration
- **Resource Limit Enforcement**: Ensures agent definitions stay within hardware constraints
- **Tool Security Validation**: Verifies tool configurations for security compliance
- **Data Model Security**: Validates database schemas for injection vulnerabilities
- **Malicious Content Detection**: Scans schemas for potentially harmful patterns

#### 2. **Execution Sandboxing**
- **Agent Isolation**: Each agent runs in a controlled execution environment
- **Resource Monitoring**: Tracks CPU, memory, and execution time usage
- **Rate Limiting**: Prevents abuse through configurable rate limits
- **Input Validation**: Validates all input data against security policies
- **Execution Monitoring**: Real-time monitoring of agent activities

#### 3. **Security Middleware**
- **Request Validation**: Validates incoming requests for malicious patterns
- **Agent Context Tracking**: Maintains security context throughout request lifecycle
- **Automatic Cleanup**: Ensures proper cleanup of security resources
- **Incident Logging**: Comprehensive logging of security events

#### 4. **Home-Lab Optimized Limits**
The security system is specifically tuned for your hardware configuration:
- **CPU**: 32 cores (64 threads) with conservative agent limits
- **Memory**: 158GB RAM with per-agent memory caps
- **GPU**: 2x Tesla P40 with resource monitoring
- **Network**: Controlled external API access with domain whitelisting

### Security Levels

The system supports three security enforcement levels:

- **STRICT**: Maximum security with minimal flexibility
- **MODERATE**: Balanced security and functionality (default)
- **LENIENT**: Reduced restrictions for development
### Security Limits and Constraints

The security system enforces specific limits optimized for your home-lab hardware configuration (2x Xeon E5-2683 v4, 2x Tesla P40, 158GB RAM). These limits prevent system abuse while allowing flexible agent development.

#### Resource Limits

| Category | Limit | Description |
|----------|-------|-------------|
| **Concurrent Agents** | 8 max | Maximum agents running simultaneously |
| **Agent Execution Time** | 30 minutes | Per-agent execution timeout |
| **Pipeline Execution Time** | 10 minutes | Maximum pipeline processing time |
| **Step Execution Time** | 5 minutes | Individual tool execution timeout |
| **Agent Memory** | 8GB | Memory per agent instance |
| **Total Memory** | 128GB | System-wide agent memory limit |
| **Data Model Memory** | 1GB | Memory per custom data model |
| **Table Rows** | 1M | Maximum rows per dynamic table |
| **Concurrent Queries** | 20 | Simultaneous database queries |
| **Query Execution Time** | 5 minutes | Database query timeout |
| **External Requests/Hour** | 1,000 | API calls to external services |
| **Request Size** | 1MB | Maximum input data size |
| **GPU Memory** | 24GB | Per-GPU memory allocation |
| **Concurrent GPU Tasks** | 4 | Simultaneous GPU operations |

#### Schema Complexity Limits

| Constraint | Limit | Purpose |
|------------|-------|---------|
| **Data Models** | 5 max | Prevent schema bloat |
| **Fields per Model** | 20 max | Maintain performance |
| **Pipeline Steps** | 10 max | Control processing complexity |
| **Tools per Agent** | 8 max | Limit external integrations |
| **JSON Nesting Depth** | 3 levels | Prevent complex structures |
| **Field Name Length** | 63 chars | Database compatibility |

#### Network Security

**Allowed Domains** (default whitelist):
- `localhost`, `127.0.0.1`
- `api.openai.com`, `api.anthropic.com`
- `api.groq.com`, `huggingface.co`
- `cdn.jsdelivr.net`

**Blocked Tool Types**:
- `system_command` - Direct system access
- `file_system` - Raw file operations
- `network_scanner` - Network reconnaissance

#### Rate Limiting

- **Tool Execution**: 100 requests per hour per tool
- **Agent Creation**: 10 agents per hour per user
- **API Calls**: 1000 external requests per hour
- **Database Queries**: 20 concurrent queries

### Security Monitoring

#### Real-time Metrics

The security service provides comprehensive monitoring:

```json
GET /api/v1/security/status

{
  "active_agents": 3,
  "total_incidents": 12,
  "recent_incidents": [
    {
      "id": "sec_1699123456_abc123",
      "agent_id": "agent-uuid",
      "type": "RESOURCE_EXCEEDED",
      "severity": "medium",
      "timestamp": "2024-01-01T12:00:00Z"
    }
  ],
  "resource_limits": {
    "max_concurrent_agents": 8,
    "max_memory_mb": 131072,
    "max_execution_time": 1800
  },
  "current_usage": {
    "active_agents": 3,
### Security Incident Management

The system provides comprehensive incident tracking and management capabilities to help administrators monitor and respond to security events.

#### Incident Types and Response

| Incident Type | Automatic Response | Manual Action Required |
|---------------|-------------------|----------------------|
| **Resource Exceeded** | Log incident, cleanup sandbox | Review agent configuration |
| **Permission Denied** | Block request, log incident | Verify agent permissions |
| **Malicious Content** | Disable agent, log critical incident | Security review required |
| **Rate Limit Exceeded** | Temporary block, log incident | Monitor for abuse patterns |
| **Schema Violation** | Reject registration, log incident | Fix schema issues |
| **Execution Timeout** | Terminate execution, log incident | Optimize agent performance |

#### Incident Management API

**List Security Incidents:**
```bash
GET /api/v1/security/incidents?limit=50&severity=high&resolved=false
```

**Response:**
```json
{
  "incidents": [
    {
      "incident_id": "sec_1699123456_abc123",
      "agent_id": "agent-uuid",
      "agent_type": "email_analyzer",
      "violation_type": "MALICIOUS_CONTENT",
      "severity": "critical",
      "description": "SQL injection pattern detected in input",
      "timestamp": "2024-01-01T12:00:00Z",
      "resolved": false,
      "resolution_notes": null
    }
  ],
  "total_count": 1,
  "limit": 50,
  "offset": 0
}
```

**Resolve Security Incident:**
```bash
POST /api/v1/security/incidents/sec_1699123456_abc123/resolve
{
  "resolution_notes": "Agent input validation updated to prevent SQL injection"
}
```

#### Incident Filtering

Query incidents with multiple filters:

```bash
# High severity incidents from last 24 hours
GET /api/v1/security/incidents?severity=high&limit=100

# Unresolved critical incidents
GET /api/v1/security/incidents?severity=critical&resolved=false

# Incidents for specific agent
GET /api/v1/security/incidents?agent_id=agent-uuid
```

#### Security Health Monitoring

**Security Service Health Check:**
```bash
GET /api/v1/security/health
```

**Response:**
```json
{
  "status": "warning",
  "message": "2 unresolved high/critical security incidents",
  "metrics": {
    "total_incidents": 15,
    "active_agents": 5,
    "unresolved_high_severity": 2
  },
  "timestamp": "2024-01-01T12:00:00Z"
}
```

### Security Best Practices

#### Agent Development

1. **Input Validation**: Always validate input data before processing
2. **Resource Awareness**: Monitor memory and CPU usage in development
3. **Error Handling**: Implement proper error handling and logging
4. **Schema Design**: Keep schemas simple and well-structured
5. **Tool Selection**: Use approved tools and verify configurations

#### Schema Security

1. **Field Validation**: Use appropriate field types and constraints
2. **Size Limits**: Set reasonable limits on data sizes
3. **Access Control**: Implement proper permission boundaries
4. **Regular Audits**: Review and update schemas regularly

#### Tool Configuration

1. **Authentication**: Always configure proper authentication for external tools
2. **Rate Limiting**: Set appropriate rate limits for API calls
3. **Timeout Settings**: Configure reasonable timeouts for operations
4. **Error Handling**: Implement retry logic and error recovery

#### Monitoring and Maintenance

1. **Regular Monitoring**: Check security status and incidents daily
2. **Log Analysis**: Review logs for unusual patterns
3. **Performance Tuning**: Optimize agents for your hardware constraints
4. **Security Updates**: Keep dependencies and configurations updated

### Security Configuration

#### Environment Variables

```bash
# Security level (strict, moderate, lenient)
SECURITY_LEVEL=moderate

# API key for authentication
API_KEY=your-secure-api-key

# Database security
DB_SSL_MODE=require
DB_CONNECTION_TIMEOUT=30

# Network security
ALLOWED_DOMAINS=localhost,api.openai.com,api.anthropic.com
BLOCK_SUSPICIOUS_REQUESTS=true
```

#### Security Middleware Configuration

The security middleware is automatically configured in `main.py`:

```python
# Add security middleware (order matters)
app.add_middleware(RequestValidationMiddleware)
app.add_middleware(AgentSecurityMiddleware)
```

This ensures all requests pass through security validation before reaching your application logic.

    "total_memory_mb": 24576
  }
}
```

#### Agent-Specific Reports

```json
GET /api/v1/security/agents/{agent_id}/report

{
  "agent_id": "agent-uuid",
  "agent_type": "email_analyzer",
  "start_time": "2024-01-01T10:00:00Z",
### Example 3: Security Testing and Validation

**Test Security Status:**
```bash
# Check current security status
curl http://localhost:8000/api/v1/security/status

# Expected response shows active agents and incidents
{
  "active_agents": 2,
  "total_incidents": 0,
  "recent_incidents": [],
  "resource_limits": {
    "max_concurrent_agents": 8,
    "max_memory_mb": 131072,
    "max_execution_time": 1800
  },
  "current_usage": {
    "active_agents": 2,
    "total_memory_mb": 4096
  }
}
```

**Validate Tool Execution:**
```bash
# Pre-validate a tool execution
curl -X POST http://localhost:8000/api/v1/security/validate-tool-execution \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "test-agent-id",
    "tool_name": "llm_processor",
    "input_data": {
      "prompt": "Analyze this email for importance",
      "max_tokens": 500
    }
  }'

# Expected response
{
  "allowed": true,
  "agent_id": "test-agent-id",
  "tool_name": "llm_processor",
  "validation_time": 1640995200.123
}
```

**Monitor Agent Security:**
```bash
# Get agent security report
curl http://localhost:8000/api/v1/security/agents/test-agent-id/report

# Response includes security events and incidents
{
  "agent_id": "test-agent-id",
  "agent_type": "email_analyzer",
  "resource_usage": {
    "memory_peak_mb": 1024,
    "cpu_time_seconds": 120
  },
  "security_events": [],
  "incidents": [],
  "is_secure": true
}
```

**Test Rate Limiting:**
```bash
# Attempt multiple rapid requests to test rate limiting
for i in {1..5}; do
  curl -X POST http://localhost:8000/api/v1/tasks/run \
    -H "Content-Type: application/json" \
    -d '{"agent_id": "test-agent", "input": {"type": "test"}}' &
done

# Check for rate limit incidents
curl http://localhost:8000/api/v1/security/incidents?severity=low
```

  "resource_usage": {
### 5. Security-Related Errors

**429 Resource Limit Exceeded:**
- **Cause**: Agent exceeded memory, CPU, or execution time limits
- **Solution**: Check `/api/v1/security/agents/{agent_id}/report` for resource usage
- **Prevention**: Optimize agent configuration and monitor resource usage

**403 Tool Execution Denied:**
- **Cause**: Tool execution blocked by security policy
- **Solution**: Verify tool configuration and permissions
- **Check**: Review security incidents: `GET /api/v1/security/incidents`

**400 Malicious Content Detected:**
- **Cause**: Input data contains suspicious patterns
- **Solution**: Sanitize input data before sending to agent
- **Prevention**: Implement client-side input validation

**Security Service Unavailable:**
- **Cause**: Security middleware or service not responding
- **Solution**: Check security health: `GET /api/v1/security/health`
- **Logs**: Review security service logs for errors

**Agent Sandbox Initialization Failed:**
- **Cause**: Unable to initialize secure execution environment
- **Solution**: Check system resources and concurrent agent limits
- **Status**: Monitor via `GET /api/v1/security/status`

### 6. Rate Limiting Issues

**Rate Limit Exceeded:**
- **Cause**: Too many requests in short time period
- **Solution**: Implement exponential backoff retry logic
- **Limits**: Check current limits via `GET /api/v1/security/limits`

**Tool-Specific Rate Limits:**
- **Cause**: Individual tool rate limits exceeded
- **Solution**: Space out tool executions or reduce frequency
- **Monitoring**: Check tool execution metrics in agent reports

    "memory_peak_mb": 2048,
6. **Monitor Security**: Check `/api/v1/security/status` and `/api/v1/security/health` regularly
7. **Review Incidents**: Monitor security incidents via `/api/v1/security/incidents`
8. **Generate Agent-Specific Docs**: Use `/api/v1/agent-types/{type}/documentation`
    "cpu_time_seconds": 450,
    "execution_time": 1200
  },
  "security_events": [
    {
      "type": "RESOURCE_EXCEEDED",
      "description": "Memory usage exceeded 2GB limit",
      "timestamp": "2024-01-01T11:30:00Z"
    }
  ],
  "incidents": [
    {
      "id": "sec_1699123456_abc123",
      "type": "RESOURCE_EXCEEDED",
      "severity": "medium",
      "description": "Agent exceeded memory limits",
      "timestamp": "2024-01-01T11:30:00Z"
    }
  ],
  "is_secure": true
}
```


### Security Violation Types

| Violation Type | Description | Severity | Action |
|----------------|-------------|----------|--------|
| `RESOURCE_EXCEEDED` | Agent exceeds resource limits | Medium | Sandbox cleanup |
| `PERMISSION_DENIED` | Unauthorized operation attempted | High | Request blocked |
| `MALICIOUS_CONTENT` | Malicious input detected | Critical | Agent disabled |
| `RATE_LIMIT_EXCEEDED` | Rate limit violations | Low | Temporary block |
| `SCHEMA_VIOLATION` | Invalid schema detected | High | Registration denied |
| `EXECUTION_TIMEOUT` | Agent execution timeout | Medium | Forced termination |


### � Documentation Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `GET` | `/api/v1/docs/agent-creation` | Comprehensive agent creation guide | ❌ |
| `GET` | `/api/v1/docs/frontend-integration` | Frontend integration guide | ❌ |
| `GET` | `/api/v1/docs/examples` | Example configurations and usage | ❌ |
| `GET` | `/api/v1/agent-types/{type}/documentation` | Agent-specific documentation | ❌ |

### 🏥 Health & Monitoring Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `GET` | `/api/v1/health` | System health check | ❌ |
| `GET` | `/api/v1/ready` | Readiness check | ❌ |
| `GET` | `/api/v1/metrics` | Prometheus metrics | ✅ |

### 🤖 Agent Management Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/api/v1/agents/create` | Create new agent | ✅ |
| `GET` | `/api/v1/agents` | List all agents | ❌ |
| `GET` | `/api/v1/agents/{agent_id}` | Get specific agent | ❌ |
| `PUT` | `/api/v1/agents/{agent_id}` | Update agent | ✅ |
| `DELETE` | `/api/v1/agents/{agent_id}` | Delete agent | ✅ |

### ⚡ Task Management Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/api/v1/tasks/run` | Execute task | ✅ |
| `GET` | `/api/v1/tasks` | List tasks | ❌ |
| `GET` | `/api/v1/tasks/{task_id}/status` | Get task status | ❌ |
| `DELETE` | `/api/v1/tasks/{task_id}` | Cancel task | ✅ |

### 📄 Logging Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `GET` | `/api/v1/logs/{task_id}` | Get task logs | ❌ |
| `GET` | `/api/v1/logs/history` | Query historical logs | ❌ |
| `GET` | `/api/v1/logs/stream/{task_id}` | Server-sent events stream | ❌ |

### 🌐 WebSocket Endpoints

| Endpoint | Description | Parameters |
|----------|-------------|------------|
| `/ws/logs` | Real-time log streaming | `agent_id`, `task_id`, `level` |
| `/ws/tasks/{task_id}` | Task-specific updates | - |

## 📖 Dynamic Agent Documentation System

The Agentic Backend includes a comprehensive auto-generated documentation system for dynamic agents. This system creates detailed documentation from agent schemas, including API references, usage examples, and integration guides.

### 🎯 Key Features

- **Auto-Generated Documentation**: Creates complete documentation from agent schemas
- **Multiple Formats**: Markdown, HTML, JSON, and OpenAPI specifications
- **TypeScript Types**: Auto-generated TypeScript interfaces for frontend integration
- **Usage Examples**: Code snippets in multiple languages (Python, JavaScript, cURL)
- **Interactive Guides**: Step-by-step tutorials and best practices

### 📚 Documentation Endpoints

#### Agent Creation Guide
```bash
GET /api/v1/docs/agent-creation
```
Returns a comprehensive guide covering:
- Dynamic agent overview and benefits
- Quick start tutorial
- AI-assisted creation workflow
- Manual schema creation
- Best practices and troubleshooting

#### Frontend Integration Guide
```bash
GET /api/v1/docs/frontend-integration
```
Provides:
- React hooks for agent management
- API client examples
- Real-time updates with WebSockets
- Error handling patterns
- TypeScript integration

#### Example Configurations
```bash
GET /api/v1/docs/examples
```
Contains:
- Email analysis agent example
- Document summarizer example
- Data analysis agent example
- Complete schemas and usage patterns

#### Agent-Specific Documentation
```bash
GET /api/v1/agent-types/{agent_type}/documentation?format=markdown
```
Parameters:
- `format`: `markdown` (default), `html`, `json`

Generates documentation specific to an agent type including:
- Agent overview and capabilities
- Data models and schemas
- Processing pipeline details
- API reference
- Usage examples
- TypeScript types

### 📝 Example Usage

**Get Agent Creation Guide:**
```bash
curl http://localhost:8000/api/v1/docs/agent-creation
```

**Get Frontend Integration Guide:**
```bash
curl http://localhost:8000/api/v1/docs/frontend-integration
```

**Get Agent-Specific Documentation:**
```bash
# Get documentation for email_analyzer agent
curl http://localhost:8000/api/v1/agent-types/email_analyzer/documentation

# Get as HTML
curl "http://localhost:8000/api/v1/agent-types/email_analyzer/documentation?format=html"
```

### 🔧 Integration with Existing Documentation

The documentation system integrates seamlessly with the existing API documentation:

1. **Swagger UI**: Access via http://localhost:8000/docs
2. **ReDoc**: Access via http://localhost:8000/redoc
3. **Agent-Specific Docs**: Access via `/api/v1/agent-types/{type}/documentation`

### 📋 Documentation Structure

Generated documentation includes:

#### 1. Overview Section
- Agent description and purpose
- Key features and capabilities
- Configuration options
- Requirements and dependencies

#### 2. Data Models Section
- Database table schemas
- Field definitions and types
- Indexes and relationships
- Validation rules

#### 3. Processing Pipeline Section
- Step-by-step workflow
- Tool integrations
- Execution order and dependencies
- Error handling and retry logic

#### 4. API Reference Section
- Endpoint specifications
- Request/response schemas
- Authentication requirements
- Rate limiting information

#### 5. Usage Examples Section
- Code snippets in multiple languages
- Complete workflow examples
- Error handling patterns
- Best practices

#### 6. TypeScript Types Section
- Interface definitions
- Type-safe API client examples
- Frontend integration patterns

#### 7. Frontend Integration Section
- React hooks and components
- WebSocket integration
- Real-time updates
- Error boundaries and recovery

## 🧪 Step-by-Step Testing Examples

### Example 1: Create and Test an Agent

**Step 1: Create Agent**
```json
POST /api/v1/agents/create
{
  "name": "Test Summarizer",
  "description": "Agent for testing text summarization",
  "model_name": "qwen3:30b-a3b-thinking-2507-q8_0",
  "config": {
    "temperature": 0.3,
    "max_tokens": 500,
    "system_prompt": "You are a helpful AI assistant that creates concise summaries."
  }
}
```

**Expected Response:**
```json
{
  "id": "123e4567-e89b-12d3-a456-426614174000",
  "name": "Test Summarizer",
  "description": "Agent for testing text summarization",
  "model_name": "qwen3:30b-a3b-thinking-2507-q8_0",
  "config": {...},
  "is_active": true,
  "created_at": "2024-01-01T12:00:00Z",
  "updated_at": "2024-01-01T12:00:00Z"
}
```

**Step 2: Run a Task**
```json
POST /api/v1/tasks/run
{
  "agent_id": "123e4567-e89b-12d3-a456-426614174000",
  "input": {
    "type": "summarize",
    "text": "Artificial intelligence (AI) is intelligence demonstrated by machines, in contrast to natural intelligence displayed by humans and animals. Leading AI textbooks define the field as the study of intelligent agents...",
    "length": "short"
  }
}
```

**Step 3: Check Task Status**
```json
GET /api/v1/tasks/{task_id}/status

Response:
{
  "id": "task-uuid",
  "agent_id": "123e4567-e89b-12d3-a456-426614174000",
  "status": "completed",
  "input": {...},
  "output": {
    "type": "summarize",
    "summary": "AI is machine intelligence used to study intelligent agents...",
    "compression_ratio": 5.2
  },
  "created_at": "2024-01-01T12:00:00Z",
  "completed_at": "2024-01-01T12:00:30Z"
}
```

### Example 2: Real-time Logging

**WebSocket Connection (JavaScript):**
```javascript
// Connect to real-time logs
const ws = new WebSocket('ws://localhost:8000/ws/logs?agent_id=your-agent-id');

ws.onmessage = function(event) {
  const logData = JSON.parse(event.data);
  console.log('Real-time log:', logData);
};

// Expected log messages:
// {
//   "type": "log",
//   "data": {
//     "level": "info",
//     "message": "Task processing started",
//     "timestamp": "2024-01-01T12:00:00Z"
//   }
// }
```

**Server-Sent Events:**
```javascript
// Alternative: Use Server-Sent Events
const eventSource = new EventSource('http://localhost:8000/api/v1/logs/stream/your-task-id');

eventSource.onmessage = function(event) {
  const logData = JSON.parse(event.data);
  console.log('Log stream:', logData);
};
```

## 🎯 Task Types and Examples

### 1. Text Generation
```json
{
  "type": "generate",
  "prompt": "Write a short story about a robot learning to paint",
  "system": "You are a creative storyteller"
}
```

### 2. Chat Completion
```json
{
  "type": "chat",
  "messages": [
    {"role": "user", "content": "What is machine learning?"},
    {"role": "assistant", "content": "Machine learning is..."},
    {"role": "user", "content": "Can you give an example?"}
  ]
}
```

### 3. Text Summarization
```json
{
  "type": "summarize", 
  "text": "Long text content here...",
  "length": "short"  // options: short, medium, long
}
```

### 4. Text Analysis
```json
{
  "type": "analyze",
  "text": "Text to analyze...",
  "analysis_type": "sentiment"  // options: sentiment, topics, entities, general
}
```

## 🔍 Advanced API Features

### Filtering and Pagination

**List Agents with Filters:**
```
GET /api/v1/agents?active_only=true&limit=20&offset=0
```

**Historical Logs with Search:**
```
GET /api/v1/logs/history?agent_id=xxx&level=error&search=failed&limit=50
```

### Response Formats

All endpoints return JSON with consistent structure:

**Success Response:**
```json
{
  "id": "resource-id",
  "field1": "value1",
  "field2": "value2",
  "created_at": "2024-01-01T12:00:00Z"
}
```

**Error Response:**
```json
{
  "detail": "Error description",
  "status_code": 400
}
```

**List Response:**
```json
[
  {"id": "1", "name": "Item 1"},
  {"id": "2", "name": "Item 2"}
]
```

## 📊 Monitoring and Metrics

### Health Check Response
```json
GET /api/v1/health

{
  "status": "healthy",
  "app_name": "Agentic Backend",
  "version": "0.1.0",
  "timestamp": "2024-01-01T12:00:00Z"
}
```

### Metrics (Prometheus Format)
```
GET /api/v1/metrics

# HELP agent_tasks_total Total number of agent tasks
# TYPE agent_tasks_total counter
agent_tasks_total{agent_id="123",status="completed"} 45
agent_tasks_total{agent_id="123",status="failed"} 2

# HELP api_requests_total Total API requests  
# TYPE api_requests_total counter
api_requests_total{method="POST",endpoint="/agents/create",status_code="200"} 12
```

## 🛠️ Testing Tools

### 1. Built-in Swagger UI ⭐ (Recommended)
- **URL**: http://localhost:8000/docs
- ✅ Interactive testing
- ✅ Authentication support
- ✅ Request/response validation

### 2. cURL Examples
```bash
# Health check
curl http://localhost:8000/api/v1/health

# Create agent (with auth)
curl -X POST http://localhost:8000/api/v1/agents/create \
  -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"name": "Test Agent", "model_name": "qwen3:30b-a3b-thinking-2507-q8_0"}'
```

### 3. Postman Collection
Import the OpenAPI spec from http://localhost:8000/openapi.json

### 4. HTTPie
```bash
# Install: pip install httpie
http GET localhost:8000/api/v1/health
http POST localhost:8000/api/v1/agents/create Authorization:"Bearer api-key" name="Test"
```

## ❓ Common Issues

### 1. 401 Unauthorized
- Ensure API key is set in Authorization header
- Format: `Authorization: Bearer your-api-key`

### 2. 422 Validation Error
- Check request body matches the expected schema
- Review the Swagger UI for required fields

### 3. 500 Internal Server Error
- Check server logs: `docker-compose logs api`
- Verify Ollama connectivity
- Ensure database is initialized

### 4. WebSocket Connection Failed
- Verify the WebSocket URL format
- Check for proxy/firewall blocking WebSocket connections
- Ensure the API server is running

## 🎉 Next Steps

1. **Explore Swagger UI**: http://localhost:8000/docs
2. **Read Agent Documentation**: http://localhost:8000/api/v1/docs/agent-creation
3. **Test basic workflows**: Create agent → Run task → Check logs
4. **Try WebSocket connections** for real-time updates
5. **Monitor with Flower**: http://localhost:5555
6. **Check database**: http://localhost:8080
7. **Generate Agent-Specific Docs**: Use `/api/v1/agent-types/{type}/documentation`

The API is now ready for integration with your applications! 🚀

### 📚 Documentation System Ready

The comprehensive documentation system is now available to help you:
- **Create agents** with step-by-step guides
- **Integrate frontends** with React hooks and examples
- **Understand agent capabilities** through auto-generated docs
- **Follow best practices** for development and deployment

**Start exploring**: http://localhost:8000/api/v1/docs/agent-creation