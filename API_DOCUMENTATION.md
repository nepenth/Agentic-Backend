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

### ✅ Current API Status (All Endpoints Working)

**Recently Fixed Issues:**
- ✅ **Security Routes**: Fixed double prefix issue (`/api/v1/security/security/...` → `/api/v1/security/...`)
- ✅ **Database Schema**: Added missing columns (`agent_type_id`, `dynamic_config`, `documentation_url`)
- ✅ **WebSocket Support**: Fully configured and documented
- ✅ **Agent Endpoints**: All CRUD operations working
- ✅ **System Metrics**: CPU, memory, GPU monitoring active
- ✅ **Ollama Integration**: Model management and health checks working

**Verified Working Endpoints:**
```bash
# Core endpoints
GET  /api/v1/health                    # ✅ System health
GET  /api/v1/agents                    # ✅ List agents
POST /api/v1/agents/create             # ✅ Create agent
GET  /api/v1/tasks                     # ✅ List tasks
POST /api/v1/tasks/run                 # ✅ Execute task

# Security endpoints
GET  /api/v1/security/status           # ✅ Security status (admin required)
POST /api/v1/security/status           # ✅ Update security config (admin required)
GET  /api/v1/security/health           # ✅ Security health (public)
POST /api/v1/security/validate-tool-execution # ✅ Pre-validate tool executions (authenticated)

# System monitoring
GET  /api/v1/system/metrics            # ✅ All system metrics
GET  /api/v1/system/metrics/cpu        # ✅ CPU metrics (with temperature)
GET  /api/v1/system/metrics/memory     # ✅ Memory metrics
GET  /api/v1/system/metrics/disk       # ✅ Disk metrics (with I/O)
GET  /api/v1/system/metrics/network    # ✅ Network metrics (with speeds)
GET  /api/v1/system/metrics/gpu        # ✅ GPU metrics (NVIDIA)
GET  /api/v1/system/metrics/load       # ✅ Load average (1m, 5m, 15m)
GET  /api/v1/system/metrics/swap       # ✅ Swap memory metrics
GET  /api/v1/system/info               # ✅ System info (uptime, processes)

# Ollama integration
GET  /api/v1/ollama/models             # ✅ Available models
GET  /api/v1/ollama/health             # ✅ Ollama health

# WebSocket endpoints
WS   /ws/logs                          # ✅ Real-time logs
WS   /ws/tasks/{task_id}               # ✅ Task monitoring
```

## 📋 Complete API Reference

### 🔒 Security Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `GET` | `/api/v1/security/status` | Current security status and metrics | ✅ |
| `POST` | `/api/v1/security/status` | Update security status and configuration | ✅ |
| `GET` | `/api/v1/security/agents/{agent_id}/report` | Agent-specific security reports | ✅ |
| `POST` | `/api/v1/security/validate-tool-execution` | Pre-validate tool executions | ✅ |
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
| `GET` | `/api/v1/system/metrics` | System utilization metrics (CPU, Memory, GPU, Disk, Network, Load, Swap, System) | ❌ |
| `GET` | `/api/v1/system/metrics/cpu` | CPU utilization metrics (with temperature) | ❌ |
| `GET` | `/api/v1/system/metrics/memory` | Memory utilization metrics | ❌ |
| `GET` | `/api/v1/system/metrics/disk` | Disk utilization and I/O metrics | ❌ |
| `GET` | `/api/v1/system/metrics/network` | Network I/O and speed metrics | ❌ |
| `GET` | `/api/v1/system/metrics/gpu` | GPU utilization metrics (NVIDIA) | ❌ |
| `GET` | `/api/v1/system/metrics/load` | System load average (1m, 5m, 15m) | ❌ |
| `GET` | `/api/v1/system/metrics/swap` | Swap memory utilization metrics | ❌ |
| `GET` | `/api/v1/system/info` | System information (uptime, processes, boot time) | ❌ |

### 🤖 Ollama Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `GET` | `/api/v1/ollama/models` | List all available Ollama models with metadata | ❌ |
| `GET` | `/api/v1/ollama/models/names` | List available model names only | ❌ |
| `GET` | `/api/v1/ollama/health` | Check Ollama server health | ❌ |
| `POST` | `/api/v1/ollama/models/pull/{model_name}` | Pull/download a new model | ❌ |

### 🤖 Agent Management Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/api/v1/agents/create` | Create new agent (static or dynamic) | ✅ |
| `GET` | `/api/v1/agents` | List all agents with filtering | ❌ |
| `GET` | `/api/v1/agents/{agent_id}` | Get specific agent | ❌ |
| `PUT` | `/api/v1/agents/{agent_id}` | Update agent | ✅ |
| `DELETE` | `/api/v1/agents/{agent_id}` | Delete agent | ✅ |

### ⚡ Task Management Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/api/v1/tasks/run` | Execute task (supports both static and dynamic agents) | ✅ |
| `GET` | `/api/v1/tasks` | List tasks with filtering | ❌ |
| `GET` | `/api/v1/tasks/{task_id}/status` | Get task status | ❌ |
| `DELETE` | `/api/v1/tasks/{task_id}` | Cancel task | ✅ |

### 📄 Logging Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `GET` | `/api/v1/logs/{task_id}` | Get task logs | ❌ |
| `GET` | `/api/v1/logs/history` | Query historical logs | ❌ |
| `GET` | `/api/v1/logs/stream/{task_id}` | Server-sent events stream | ❌ |

### 🌐 WebSocket Endpoints

WebSocket connections provide real-time communication for monitoring agent activities, task progress, and system events.

#### 📋 **CONFIRMED SPECIFICATIONS SUMMARY**

| Specification | Value | Details |
|---------------|-------|---------|
| **Heartbeat** | ✅ 30-second ping/pong | Frontend must send ping every 30s, backend responds with pong + timestamp |
| **Connection Limits** | ✅ 50 per user, 200 global | Automatic rejection when exceeded, auto-cleanup on disconnect |
| **Rate Limiting** | ✅ 100 messages/minute | Per-connection limit, includes all message types |
| **Authentication** | ✅ JWT required | Query parameter `?token=YOUR_JWT_TOKEN` |
| **Protocol** | ✅ Raw WebSocket | NOT Socket.IO - use standard WebSocket API |
| **Connection Timeout** | ✅ 90 seconds | Auto-disconnect if no ping received |

#### Connection URLs
- **Development**: `ws://localhost:8000/ws/...`
- **Production**: `wss://whyland-ai.nakedsun.xyz/ws/...`

#### ⚠️ Socket.IO vs Raw WebSockets

**IMPORTANT:** Our backend uses **raw WebSockets** (FastAPI), NOT Socket.IO!

❌ **Wrong (Socket.IO):**
```javascript
import io from 'socket.io-client';
const socket = io('wss://whyland-ai.nakedsun.xyz'); // Uses /socket.io/ path
```

✅ **Correct (Raw WebSocket):**
```javascript
const ws = new WebSocket('wss://whyland-ai.nakedsun.xyz/ws/logs?token=YOUR_JWT_TOKEN');
```

#### 🔐 WebSocket Authentication

**All WebSocket connections require JWT authentication:**

- Include your JWT token as a query parameter: `?token=YOUR_JWT_TOKEN`
- The token must be valid and not expired
- Invalid tokens will result in connection rejection with code 1008

**Example:**
```javascript
const token = 'your-jwt-token-here';
const ws = new WebSocket(`wss://whyland-ai.nakedsun.xyz/ws/logs?token=${token}`);
```

#### 💓 WebSocket Heartbeat (CONFIRMED)

**✅ CONFIRMED: 30-second ping/pong heartbeat mechanism**

- **Frontend MUST send ping messages every 30 seconds**
- **Backend responds with pong messages containing current timestamp**
- **Connection will be automatically closed if no ping received for 90 seconds**
- **Use this to detect connection drops and trigger reconnection**

**Heartbeat Message Format:**
```javascript
// Frontend sends:
ws.send(JSON.stringify({
  "type": "ping"
}));

// Backend responds:
{
  "type": "pong",
  "timestamp": "2024-01-01T12:00:00.000Z"
}
```

**Implementation Example:**
```javascript
function startHeartbeat(ws) {
  setInterval(() => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: "ping" }));
    }
  }, 30000); // 30 seconds
}
```

#### 🔢 Connection Limits (CONFIRMED)

**✅ CONFIRMED: Maximum 50 concurrent WebSocket connections per user**

- **Per-user limit**: 50 concurrent WebSocket connections
- **Global limit**: 200 total concurrent connections across all users
- **Connection rejection**: New connections are rejected when limits are exceeded
- **Automatic cleanup**: Disconnected clients are automatically removed from count

**Connection Management:**
```javascript
// Monitor connection count
ws.onopen = function(event) {
  console.log('WebSocket connected');
  // Connection count automatically tracked by backend
};

ws.onclose = function(event) {
  console.log('WebSocket disconnected');
  // Connection automatically removed from count
};
```

#### 🚦 Rate Limiting (CONFIRMED)

**✅ CONFIRMED: 100 messages per minute per WebSocket connection**

- **Per-connection limit**: 100 messages per minute
- **Message types counted**: All incoming messages (ping, update_filters, etc.)
- **Rate limit exceeded**: Connection receives error message and may be temporarily blocked
- **Automatic recovery**: Rate limiting is reset every minute

**Rate Limit Error Response:**
```javascript
{
  "type": "error",
  "message": "Rate limit exceeded. Please wait before sending more messages.",
  "retry_after": 60  // seconds until reset
}
```

**Rate Limiting Best Practices:**
```javascript
// Implement client-side rate limiting
let messageCount = 0;
let lastReset = Date.now();

function sendMessage(ws, message) {
  const now = Date.now();

  // Reset counter every minute
  if (now - lastReset > 60000) {
    messageCount = 0;
    lastReset = now;
  }

  // Check client-side limit (leave buffer for ping messages)
  if (messageCount >= 80) {
    console.warn('Approaching rate limit, slowing down...');
    return false;
  }

  ws.send(JSON.stringify(message));
  messageCount++;
  return true;
}
```

#### Available Endpoints

| Endpoint | Description | Parameters | Message Types |
|----------|-------------|------------|---------------|
| `/ws/logs` | Real-time log streaming | `agent_id`, `task_id`, `level` | `log_entry`, `task_update` |
| `/ws/tasks/{task_id}` | Task-specific updates | - | `task_status`, `task_progress`, `task_complete` |

#### WebSocket Message Format

**Log Entry Message:**
```json
{
  "type": "log_entry",
  "data": {
    "timestamp": "2024-01-01T12:00:00Z",
    "level": "info",
    "message": "Task processing started",
    "agent_id": "agent-uuid",
    "task_id": "task-uuid",
    "source": "pipeline"
  }
}
```

**Task Status Message:**
```json
{
  "type": "task_status",
  "data": {
    "task_id": "task-uuid",
    "status": "running",
    "progress": 45,
    "message": "Processing step 3 of 5",
    "timestamp": "2024-01-01T12:00:00Z"
  }
}
```

#### JavaScript Connection Examples

**⚠️ IMPORTANT: Use Raw WebSockets, NOT Socket.IO**

**Basic WebSocket Connection with Heartbeat:**
```javascript
// Connect to real-time logs with authentication
const token = 'your-jwt-token-here'; // Get from your authentication system
const wsUrl = window.location.protocol === 'https:'
  ? `wss://whyland-ai.nakedsun.xyz/ws/logs?token=${token}`
  : `ws://localhost:8000/ws/logs?token=${token}`;

const ws = new WebSocket(wsUrl);
let heartbeatInterval;

ws.onopen = function(event) {
  console.log('WebSocket connected');

  // Start heartbeat (30-second ping)
  heartbeatInterval = setInterval(() => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: "ping" }));
    }
  }, 30000);
};

ws.onmessage = function(event) {
  const message = JSON.parse(event.data);
  console.log('Received:', message);

  // Handle different message types
  switch(message.type) {
    case 'log_entry':
      updateLogDisplay(message.data);
      break;
    case 'task_status':
      updateTaskProgress(message.data);
      break;
    case 'connected':
      console.log('Connection confirmed:', message.message);
      break;
    case 'pong':
      console.log('Heartbeat received:', message.timestamp);
      break;
    case 'error':
      console.error('WebSocket error:', message.message);
      if (message.retry_after) {
        console.log(`Rate limited, retry after ${message.retry_after} seconds`);
      }
      break;
  }
};

ws.onclose = function(event) {
  console.log('WebSocket disconnected');
  // Stop heartbeat
  if (heartbeatInterval) {
    clearInterval(heartbeatInterval);
  }

  // Implement reconnection logic
  setTimeout(() => {
    console.log('Attempting to reconnect...');
    // Reconnect logic here
  }, 5000);
};

ws.onerror = function(error) {
  console.error('WebSocket error:', error);
  // Stop heartbeat on error
  if (heartbeatInterval) {
    clearInterval(heartbeatInterval);
  }
};
```

// Monitor a specific task
const taskId = 'your-task-uuid';
const taskWsUrl = `wss://whyland-ai.nakedsun.xyz/ws/tasks/${taskId}`;
const taskWs = new WebSocket(taskWsUrl);

taskWs.onmessage = function(event) {
  const message = JSON.parse(event.data);

  if (message.type === 'task_complete') {
    console.log('Task completed:', message.data);
    taskWs.close();
  }
};
```

**React Hook for WebSocket with Heartbeat:**
```javascript
import { useEffect, useRef, useState, useCallback } from 'react';

function useWebSocket(url) {
  const [messages, setMessages] = useState([]);
  const [isConnected, setIsConnected] = useState(false);
  const [error, setError] = useState(null);
  const ws = useRef(null);
  const heartbeatRef = useRef(null);
  const reconnectTimeoutRef = useRef(null);

  const connect = useCallback(() => {
    ws.current = new WebSocket(url);
    setError(null);

    ws.current.onopen = () => {
      setIsConnected(true);
      console.log('WebSocket connected');

      // Start heartbeat (30-second ping)
      heartbeatRef.current = setInterval(() => {
        if (ws.current && ws.current.readyState === WebSocket.OPEN) {
          ws.current.send(JSON.stringify({ type: "ping" }));
        }
      }, 30000);
    };

    ws.current.onmessage = (event) => {
      const message = JSON.parse(event.data);
      setMessages(prev => [...prev, message]);

      // Handle heartbeat response
      if (message.type === 'pong') {
        console.log('Heartbeat received:', message.timestamp);
      }

      // Handle rate limiting
      if (message.type === 'error' && message.retry_after) {
        console.warn(`Rate limited, retry after ${message.retry_after} seconds`);
      }
    };

    ws.current.onclose = (event) => {
      setIsConnected(false);
      console.log('WebSocket disconnected');

      // Stop heartbeat
      if (heartbeatRef.current) {
        clearInterval(heartbeatRef.current);
      }

      // Auto-reconnect after 5 seconds
      reconnectTimeoutRef.current = setTimeout(() => {
        console.log('Attempting to reconnect...');
        connect();
      }, 5000);
    };

    ws.current.onerror = (error) => {
      console.error('WebSocket error:', error);
      setError(error);
    };
  }, [url]);

  useEffect(() => {
    connect();

    return () => {
      // Cleanup on unmount
      if (heartbeatRef.current) {
        clearInterval(heartbeatRef.current);
      }
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      if (ws.current) {
        ws.current.close();
      }
    };
  }, [connect]);

  const sendMessage = useCallback((message) => {
    if (ws.current && ws.current.readyState === WebSocket.OPEN) {
      ws.current.send(JSON.stringify(message));
      return true;
    }
    return false;
  }, []);

  return { messages, isConnected, error, sendMessage };
}

// Usage in component
function TaskMonitor({ taskId, token }) {
  const wsUrl = `wss://whyland-ai.nakedsun.xyz/ws/tasks/${taskId}?token=${token}`;
  const { messages, isConnected, error, sendMessage } = useWebSocket(wsUrl);

  // Update filters example
  const updateFilters = () => {
    sendMessage({
      type: "update_filters",
      filters: { level: "info" }
    });
  };

  return (
    <div>
      <div>Status: {isConnected ? '🟢 Connected' : '🔴 Disconnected'}</div>
      {error && <div>Error: {error.message}</div>}
      <button onClick={updateFilters} disabled={!isConnected}>
        Update Filters
      </button>
      <div>
        {messages.map((msg, index) => (
          <div key={index} style={{ margin: '5px', padding: '5px', border: '1px solid #ccc' }}>
            {JSON.stringify(msg, null, 2)}
          </div>
        ))}
      </div>
    </div>
  );
}
```

#### Connection Parameters

**Log Streaming Parameters:**
- `agent_id`: Filter logs by specific agent
- `task_id`: Filter logs by specific task
- `level`: Filter by log level (`debug`, `info`, `warning`, `error`)

**Example URLs:**
```
ws://localhost:8000/ws/logs?token=YOUR_JWT_TOKEN&agent_id=123&level=info
wss://whyland-ai.nakedsun.xyz/ws/logs?token=YOUR_JWT_TOKEN&task_id=456
ws://localhost:8000/ws/tasks/task-uuid?token=YOUR_JWT_TOKEN
```

#### Error Handling

**Connection Errors:**
```javascript
ws.onerror = function(error) {
  console.error('WebSocket connection failed');

  // Implement reconnection logic
  setTimeout(() => {
    // Attempt to reconnect
    connectWebSocket();
  }, 5000);
};
```

**Message Parsing Errors:**
```javascript
ws.onmessage = function(event) {
  try {
    const message = JSON.parse(event.data);
    handleMessage(message);
  } catch (error) {
    console.error('Failed to parse WebSocket message:', error);
  }
};
```

#### Best Practices

1. **Connection Management**: Always handle connection lifecycle events
2. **Heartbeat Implementation**: Send ping messages every 30 seconds to maintain connection
3. **Connection Limits**: Monitor and respect the 50 concurrent connection limit per user
4. **Rate Limiting**: Implement client-side rate limiting (max 100 messages/minute)
5. **Reconnection Logic**: Implement automatic reconnection on disconnection with exponential backoff
6. **Message Filtering**: Use query parameters to reduce message volume
7. **Error Handling**: Gracefully handle parsing, connection, and rate limit errors
8. **Resource Cleanup**: Close connections when components unmount
9. **Security**: Use WSS in production environments with valid JWT tokens
10. **Connection Monitoring**: Track connection health and implement connection pooling if needed

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

**Step 1: Create Static Agent (Legacy)**
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

**Model Selection Workflow:**
```javascript
// 1. Get available models
const modelsResponse = await fetch('/api/v1/ollama/models/names');
const { models } = await modelsResponse.json();

// 2. User selects model from dropdown/interface
const selectedModel = models[0]; // e.g., "llama2"

// 3. Create agent with selected model
const agentResponse = await fetch('/api/v1/agents/create', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer your-api-key'
  },
  body: JSON.stringify({
    name: "My Custom Agent",
    description: "Agent using selected model",
    model_name: selectedModel,
    config: { temperature: 0.7 }
  })
});
```

**Step 1 Alternative: Create Dynamic Agent**
```json
POST /api/v1/agents/create
{
  "name": "Email Analyzer",
  "description": "Dynamic agent for analyzing emails",
  "agent_type": "email_analyzer",
  "config": {
    "importance_threshold": 0.7,
    "categories": ["urgent", "important", "normal"]
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
GET /api/v1/agents?agent_type=email_analyzer&include_dynamic=true&limit=10
GET /api/v1/agents?include_dynamic=false  # Only static agents
```

**List Tasks with Filters:**
```
GET /api/v1/tasks?agent_id=uuid&status=completed&limit=50
GET /api/v1/tasks?agent_type=email_analyzer&include_dynamic=true
GET /api/v1/tasks?status=running&limit=20&offset=0
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

### System Utilization Metrics

The system provides comprehensive hardware utilization monitoring with expanded metrics:

**Get All System Metrics:**
```bash
GET /api/v1/system/metrics
```

**Response:**
```json
{
  "timestamp": "2025-08-29T23:38:41.846029Z",
  "cpu": {
    "usage_percent": 0.3,
    "frequency_ghz": {"current": null, "min": 3.0, "max": 3.0},
    "frequency_mhz": {"current": null, "min": 3000.0, "max": 3000.0},
    "temperature_celsius": 42.0,
    "temperature_fahrenheit": 107.6,
    "times_percent": {"user": 0.2, "system": 0.6, "idle": 99.2},
    "count": {"physical": 64, "logical": 64}
  },
  "memory": {
    "total_gb": 157.24,
    "available_gb": 138.86,
    "used_gb": 16.39,
    "free_gb": 20.22,
    "usage_percent": 11.7,
    "buffers_gb": 1.54,
    "cached_gb": 119.08,
    "shared_gb": 0.01
  },
  "disk": {
    "usage": {
      "total_gb": 934.87,
      "used_gb": 722.84,
      "free_gb": 164.47,
      "usage_percent": 81.5
    },
    "io": {
      "read_count": 3269762,
      "write_count": 18995969,
      "read_bytes": 342495890432,
      "write_bytes": 858681742336,
      "read_time_ms": 18935827,
      "write_time_ms": 58649040
    }
  },
  "network": {
    "io": {
      "bytes_sent": 1730537,
      "bytes_recv": 2766789,
      "packets_sent": 12901,
      "packets_recv": 14704,
      "errin": 0,
      "errout": 0,
      "dropin": 0,
      "dropout": 0
    },
    "speeds": {
      "bytes_sent_per_sec": 1730537,
      "bytes_recv_per_sec": 2766789,
      "packets_sent_per_sec": 12901,
      "packets_recv_per_sec": 14704
    },
    "interfaces": [
      {"name": "eth0", "isup": true, "speed_mbps": 10000, "mtu": 1500}
    ]
  },
  "gpu": [
    {
      "index": 0,
      "name": "Tesla P40",
      "utilization": {"gpu_percent": 0, "memory_percent": 0},
      "memory": {"total_mb": 24576, "used_mb": 139, "free_mb": 24436},
      "temperature_fahrenheit": 78.8,
      "clocks": {"graphics_mhz": 544, "memory_mhz": 405},
      "power": {"usage_watts": 9.53, "limit_watts": 250.0}
    }
  ],
  "load_average": {
    "1m": 0.51,
    "5m": 0.66,
    "15m": 0.53
  },
  "swap": {
    "total_gb": 32.0,
    "used_gb": 0.11,
    "free_gb": 31.89,
    "usage_percent": 0.4,
    "sin": 494436352,
    "sout": 2693038080
  },
  "system": {
    "uptime": {
      "seconds": 1329890,
      "formatted": "15d 9h 24m"
    },
    "processes": {
      "total_count": 3
    },
    "boot_time": "2025-08-14T14:13:53Z"
  }
}
```

**Individual Metrics Endpoints:**
```bash
# CPU metrics (with temperature)
GET /api/v1/system/metrics/cpu

# Memory metrics
GET /api/v1/system/metrics/memory

# Disk metrics (with I/O)
GET /api/v1/system/metrics/disk

# Network metrics (with speeds)
GET /api/v1/system/metrics/network

# GPU metrics (NVIDIA GPUs)
GET /api/v1/system/metrics/gpu

# Load average metrics
GET /api/v1/system/metrics/load

# Swap memory metrics
GET /api/v1/system/metrics/swap

# System information (uptime, processes)
GET /api/v1/system/info
```

**Supported Metrics:**
- **CPU**: Usage percentage, frequency, core counts, time breakdowns, temperature (°C/°F)
- **Memory**: Total/used/free/available in GB, usage percentage, buffers/cached/shared
- **GPU**: Utilization %, memory usage, temperature (°F), clock frequencies, power (NVIDIA)
- **Disk**: Usage statistics and I/O metrics (read/write counts, bytes, time)
- **Network**: Traffic statistics, interface information, I/O speeds
- **Load Average**: 1m, 5m, 15m periods
- **Swap**: Total/used/free in GB, usage percentage, page in/out counts
- **System**: Uptime (seconds + formatted), process count, boot time

### System Monitoring Integration

The system metrics endpoints are designed for seamless frontend integration:

**Real-time Monitoring:**
```javascript
// Fetch system metrics every 5 seconds
setInterval(async () => {
  const response = await fetch('/api/v1/system/metrics');
  const metrics = await response.json();

  // Update dashboard with metrics
  updateDashboard(metrics);
}, 5000);
```

**GPU Temperature Monitoring (Tesla P40):**
```javascript
const gpuMetrics = await fetch('/api/v1/system/metrics/gpu');
const gpus = await gpuMetrics.json();

gpus.gpus.forEach((gpu, index) => {
  console.log(`GPU ${index} (${gpu.name}): ${gpu.temperature_fahrenheit}°F`);
});
```

**Resource Usage Alerts:**
```javascript
const systemMetrics = await fetch('/api/v1/system/metrics');
const { cpu, memory, gpu } = await systemMetrics.json();

// Check for high usage
if (cpu.usage_percent > 80) {
  alert('High CPU usage detected!');
}

if (memory.usage_percent > 90) {
  alert('High memory usage detected!');
}
```

### Ollama Model Management

The system provides comprehensive Ollama model management capabilities:

**Get Available Models:**
```bash
GET /api/v1/ollama/models
```

**Response:**
```json
{
  "models": [
    {
      "name": "llama2",
      "size": 3791730599,
      "modified_at": "2024-01-01T00:00:00Z",
      "digest": "sha256:123..."
    },
    {
      "name": "codellama",
      "size": 5377541952,
      "modified_at": "2024-01-01T00:00:00Z",
      "digest": "sha256:456..."
    }
  ]
}
```

**Get Model Names Only:**
```bash
GET /api/v1/ollama/models/names
```

**Response:**
```json
{
  "models": ["llama2", "codellama", "mistral"]
}
```

**Pull New Models:**
```bash
POST /api/v1/ollama/models/pull/llama2:13b
```

**Frontend Integration for Model Selection:**
```javascript
// Fetch available models for dropdown
const modelsResponse = await fetch('/api/v1/ollama/models/names');
const { models } = await modelsResponse.json();

// Populate dropdown
const modelSelect = document.getElementById('model-select');
models.forEach(model => {
  const option = document.createElement('option');
  option.value = model;
  option.textContent = model;
  modelSelect.appendChild(option);
});
```

**Check Ollama Health:**
```bash
GET /api/v1/ollama/health
```

**Response:**
```json
{
  "status": "healthy",
  "models_available": 5,
  "default_model": "llama2"
}
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

# System metrics
curl http://localhost:8000/api/v1/system/metrics
curl http://localhost:8000/api/v1/system/metrics/cpu
curl http://localhost:8000/api/v1/system/metrics/gpu

# Ollama model management
curl http://localhost:8000/api/v1/ollama/models
curl http://localhost:8000/api/v1/ollama/models/names
curl http://localhost:8000/api/v1/ollama/health

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

### ✅ All Systems Operational
1. **Explore Swagger UI**: http://localhost:8000/docs (All endpoints working)
2. **Monitor System Performance**: Check `/api/v1/system/metrics` for hardware utilization
3. **Browse Available Models**: Use `/api/v1/ollama/models` to see available Ollama models
4. **Test WebSocket connections** for real-time updates (fully documented)

### 🚀 Start Building Workflows
5. **Read Workflow Development Guide**: See `WORKFLOW_DEVELOPMENT_GUIDE.md`
6. **Try Email Processing Example**: Complete implementation with frontend dashboard
7. **Create Custom Agents**: Use the documented patterns and examples
8. **Build Frontend Dashboards**: Use React components and WebSocket integration

### 🔧 Development Tools
9. **Monitor with Flower**: http://localhost:5555 (Celery task monitoring)
10. **Check database**: http://localhost:8080 (Adminer database browser)
11. **Generate Agent-Specific Docs**: Use `/api/v1/agent-types/{type}/documentation`

### 📚 Learning Resources
12. **Agent Creation Guide**: http://localhost:8000/api/v1/docs/agent-creation
13. **Frontend Integration**: http://localhost:8000/api/v1/docs/frontend-integration
14. **Example Configurations**: http://localhost:8000/api/v1/docs/examples

The API is now ready for integration with your applications! 🚀

### 📚 Documentation System Ready

The comprehensive documentation system is now available to help you:
- **Create agents** with step-by-step guides
- **Integrate frontends** with React hooks and examples
- **Understand agent capabilities** through auto-generated docs
- **Follow best practices** for development and deployment

**Start exploring**: http://localhost:8000/api/v1/docs/agent-creation

### 🚀 Workflow Development Guide

A comprehensive **WORKFLOW_DEVELOPMENT_GUIDE.md** is now available with:

#### 📧 Email Processing Workflow Example
- **Complete implementation** of IMAP email processing agent
- **LLM integration** for email analysis and prioritization
- **Task management** system for follow-ups
- **Frontend dashboard** with React components
- **Database schema** for workflow data

#### 🛠️ Development Resources
- **Agent creation patterns** and best practices
- **Tool development** for custom integrations
- **Frontend integration** examples and hooks
- **WebSocket usage** for real-time updates
- **Security considerations** for agent workflows

#### 📁 Example Files Included
```
examples/
├── email_analyzer_agent.json      # Agent configuration
├── EmailWorkflowDashboard.jsx     # React dashboard component
├── EmailWorkflowDashboard.css     # Component styling
└── README.md                      # Implementation guide
```

**Read the guide**: See `WORKFLOW_DEVELOPMENT_GUIDE.md` for complete workflow development instructions!