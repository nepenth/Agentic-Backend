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
2. **Test basic workflows**: Create agent → Run task → Check logs
3. **Try WebSocket connections** for real-time updates
4. **Monitor with Flower**: http://localhost:5555
5. **Check database**: http://localhost:8080

The API is now ready for integration with your applications! 🚀