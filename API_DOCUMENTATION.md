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

### ReDoc Documentation
**URL**: http://localhost:8000/redoc

Alternative documentation interface with:
- 📖 Clean, readable format
- 🔍 Better for browsing and reading
- 📋 Detailed schema information
- 🏷️ Tag-based organization

## 📋 **COMPLETE API ENDPOINT REFERENCE FOR TESTING**

This comprehensive endpoint list serves as the foundation for testing all API functionality after recent backend changes. Each endpoint includes a brief description and authentication requirements.

### 🔐 **Authentication & User Management**
| Method | Endpoint | Description | Auth Required | Status |
|--------|----------|-------------|---------------|--------|
| `POST` | `/api/v1/auth/login` | User login with form data (OAuth2 compatible) | ❌ | ✅ |
| `POST` | `/api/v1/auth/login-json` | User login with JSON payload | ❌ | ✅ |
| `GET` | `/api/v1/auth/me` | Get current authenticated user information | ✅ | ✅ |
| `POST` | `/api/v1/auth/change-password` | Change current user's password | ✅ | ✅ |
| `POST` | `/api/v1/auth/admin/change-password` | Admin change any user's password | ✅ | ✅ |

### 🤖 **Agent Management**
| Method | Endpoint | Description | Auth Required | Status |
|--------|----------|-------------|---------------|--------|
| `POST` | `/api/v1/agents/create` | Create new agent (static or dynamic) with optional secrets | ✅ | ✅ |
| `GET` | `/api/v1/agents` | List all agents with filtering options | ❌ | ✅ |
| `GET` | `/api/v1/agents/{agent_id}` | Get specific agent details | ❌ | ✅ |
| `PUT` | `/api/v1/agents/{agent_id}` | Update agent configuration | ✅ | ✅ |
| `DELETE` | `/api/v1/agents/{agent_id}` | Delete agent | ✅ | ✅ |

### ⚡ **Task Management**
| Method | Endpoint | Description | Auth Required | Status |
|--------|----------|-------------|---------------|--------|
| `POST` | `/api/v1/tasks/run` | Execute task with agent (supports static/dynamic agents) | ✅ | ✅ |
| `GET` | `/api/v1/tasks` | List tasks with filtering | ❌ | ✅ |
| `GET` | `/api/v1/tasks/{task_id}/status` | Get specific task execution status | ❌ | ✅ |
| `DELETE` | `/api/v1/tasks/{task_id}` | Cancel running task | ✅ | ✅ |

### 💬 **Chat System**
| Method | Endpoint | Description | Auth Required | Status |
|--------|----------|-------------|---------------|--------|
| `POST` | `/api/v1/chat/sessions` | Create new chat session | ✅ | ✅ |
| `GET` | `/api/v1/chat/sessions` | List chat sessions | ❌ | ✅ |
| `GET` | `/api/v1/chat/sessions/{session_id}` | Get chat session details | ❌ | ✅ |
| `GET` | `/api/v1/chat/sessions/{session_id}/messages` | Get chat messages | ❌ | ✅ |
| `POST` | `/api/v1/chat/sessions/{session_id}/messages` | Send message & get AI response with performance metrics | ✅ | ✅ |
| `PUT` | `/api/v1/chat/sessions/{session_id}/status` | Update session status | ✅ | ✅ |
| `GET` | `/api/v1/chat/sessions/{session_id}/stats` | Get session statistics | ❌ | ✅ |
| `DELETE` | `/api/v1/chat/sessions/{session_id}` | Delete chat session | ✅ | ✅ |
| `GET` | `/api/v1/chat/templates` | List available chat templates | ❌ | ✅ |
| `GET` | `/api/v1/chat/models` | List available chat models | ❌ | ✅ |

### 🔐 **Secrets Management**
| Method | Endpoint | Description | Auth Required | Status |
|--------|----------|-------------|---------------|--------|
| `POST` | `/api/v1/agents/{agent_id}/secrets` | Create new secret for agent | ✅ | ✅ |
| `GET` | `/api/v1/agents/{agent_id}/secrets` | List all secrets for agent | ❌ | ✅ |
| `GET` | `/api/v1/agents/{agent_id}/secrets/{secret_id}` | Get specific secret details | ✅ | ✅ |
| `PUT` | `/api/v1/agents/{agent_id}/secrets/{secret_id}` | Update secret | ✅ | ✅ |
| `DELETE` | `/api/v1/agents/{agent_id}/secrets/{secret_id}` | Delete secret (soft delete) | ✅ | ✅ |
| `GET` | `/api/v1/agents/{agent_id}/secrets/{secret_key}/value` | Get decrypted secret value by key | ✅ | ✅ |

### 🛡️ **Security Framework**
| Method | Endpoint | Description | Auth Required | Status |
|--------|----------|-------------|---------------|--------|
| `GET` | `/api/v1/security/status` | Get current security status and metrics | ✅ | ✅ |
| `POST` | `/api/v1/security/status` | Update security configuration | ✅ | ✅ |
| `GET` | `/api/v1/security/agents/{agent_id}/report` | Get agent-specific security reports | ✅ | ✅ |
| `POST` | `/api/v1/security/validate-tool-execution` | Pre-validate tool executions | ✅ | ✅ |
| `GET` | `/api/v1/security/incidents` | List security incidents with filtering | ✅ | ✅ |
| `POST` | `/api/v1/security/incidents/{incident_id}/resolve` | Resolve security incidents | ✅ | ✅ |
| `GET` | `/api/v1/security/limits` | Get current security limits and constraints | ✅ | ✅ |
| `GET` | `/api/v1/security/health` | Security service health check | ❌ | ✅ |

### 📊 **System Monitoring**
| Method | Endpoint | Description | Auth Required | Status |
|--------|----------|-------------|---------------|--------|
| `GET` | `/api/v1/health` | System health check | ❌ | ✅ |
| `GET` | `/api/v1/ready` | Readiness check | ❌ | ✅ |
| `GET` | `/api/v1/metrics` | Prometheus metrics | ✅ | ✅ |
| `GET` | `/api/v1/system/metrics` | All system utilization metrics | ❌ | ✅ |
| `GET` | `/api/v1/system/metrics/cpu` | CPU metrics with temperature | ❌ | ✅ |
| `GET` | `/api/v1/system/metrics/memory` | Memory utilization metrics | ❌ | ✅ |
| `GET` | `/api/v1/system/metrics/disk` | Disk usage and I/O metrics | ❌ | ✅ |
| `GET` | `/api/v1/system/metrics/network` | Network I/O and speed metrics | ❌ | ✅ |
| `GET` | `/api/v1/system/metrics/gpu` | GPU utilization metrics (NVIDIA) | ❌ | ✅ |
| `GET` | `/api/v1/system/metrics/load` | System load average | ❌ | ✅ |
| `GET` | `/api/v1/system/metrics/swap` | Swap memory utilization | ❌ | ✅ |
| `GET` | `/api/v1/system/info` | System information (uptime, processes) | ❌ | ✅ |

### 🤖 **Ollama Integration**
| Method | Endpoint | Description | Auth Required | Status |
|--------|----------|-------------|---------------|--------|
| `GET` | `/api/v1/ollama/models` | List all available Ollama models with metadata | ❌ | ✅ |
| `GET` | `/api/v1/ollama/models/names` | List available model names only | ❌ | ✅ |
| `GET` | `/api/v1/ollama/health` | Check Ollama server health | ❌ | ✅ |
| `POST` | `/api/v1/ollama/models/pull/{model_name}` | Pull/download a new model | ❌ | ✅ |

### 🌐 **Agentic HTTP Client**
| Method | Endpoint | Description | Auth Required | Status |
|--------|----------|-------------|---------------|--------|
| `POST` | `/api/v1/http/request` | Make HTTP request with agentic features | ✅ | ✅ |
| `GET` | `/api/v1/http/metrics` | Get HTTP client performance metrics | ✅ | ✅ |
| `GET` | `/api/v1/http/requests/{request_id}` | Get specific request details | ✅ | ✅ |
| `GET` | `/api/v1/http/health` | HTTP client health status | ❌ | ✅ |
| `POST` | `/api/v1/http/stream-download` | Stream large file downloads | ✅ | ✅ |

### 🧠 **Dynamic Model Selection**
| Method | Endpoint | Description | Auth Required | Status |
|--------|----------|-------------|---------------|--------|
| `GET` | `/api/v1/models/available` | List available models with capabilities | ✅ | ✅ |
| `POST` | `/api/v1/models/select` | Select optimal model for task | ✅ | ✅ |
| `GET` | `/api/v1/models/performance` | Get model performance metrics | ✅ | ✅ |
| `GET` | `/api/v1/models/{model_name}/stats` | Get specific model statistics | ✅ | ✅ |
| `POST` | `/api/v1/models/refresh` | Refresh model registry | ✅ | ✅ |

### 📋 **Multi-Modal Content Framework**
| Method | Endpoint | Description | Auth Required | Status |
|--------|----------|-------------|---------------|--------|
| `POST` | `/api/v1/content/process` | Process content with automatic type detection | ✅ | ✅ |
| `GET` | `/api/v1/content/{id}` | Get processed content data | ✅ | ✅ |
| `POST` | `/api/v1/content/batch` | Batch process multiple content items | ✅ | ✅ |
| `GET` | `/api/v1/content/cache/stats` | Content cache statistics | ✅ | ✅ |

### 👁️ **Vision AI Integration**
| Method | Endpoint | Description | Auth Required | Status |
|--------|----------|-------------|---------------|--------|
| `POST` | `/api/v1/vision/analyze` | Analyze image with multiple vision tasks | ✅ | ✅ |
| `POST` | `/api/v1/vision/detect-objects` | Detect objects in image | ✅ | ✅ |
| `POST` | `/api/v1/vision/caption` | Generate image caption | ✅ | ✅ |
| `POST` | `/api/v1/vision/search` | Find similar images | ✅ | ✅ |
| `POST` | `/api/v1/vision/ocr` | Extract text from image | ✅ | ✅ |
| `GET` | `/api/v1/vision/models` | List available vision models | ✅ | ✅ |

### 🎵 **Audio AI Integration**
| Method | Endpoint | Description | Auth Required | Status |
|--------|----------|-------------|---------------|--------|
| `POST` | `/api/v1/audio/transcribe` | Convert speech to text | ✅ | ✅ |
| `POST` | `/api/v1/audio/identify-speaker` | Identify speakers in audio | ✅ | ✅ |
| `POST` | `/api/v1/audio/analyze-emotion` | Detect emotions in speech | ✅ | ✅ |
| `POST` | `/api/v1/audio/classify` | Classify audio content | ✅ | ✅ |
| `POST` | `/api/v1/audio/analyze-music` | Extract musical features | ✅ | ✅ |
| `GET` | `/api/v1/audio/models` | List available audio models | ✅ | ✅ |

### 🔄 **Cross-Modal Processing**
| Method | Endpoint | Description | Auth Required | Status |
|--------|----------|-------------|---------------|--------|
| `POST` | `/api/v1/crossmodal/align` | Align text with images | ✅ | ✅ |
| `POST` | `/api/v1/crossmodal/correlate` | Correlate audio with visual content | ✅ | ✅ |
| `POST` | `/api/v1/crossmodal/search` | Multi-modal search | ✅ | ✅ |
| `POST` | `/api/v1/crossmodal/fuse` | Fuse information from multiple modalities | ✅ | ✅ |
| `GET` | `/api/v1/crossmodal/models` | List cross-modal models | ✅ | ✅ |

### 🧠 **Semantic Processing**
| Method | Endpoint | Description | Auth Required | Status |
|--------|----------|-------------|---------------|--------|
| `POST` | `/api/v1/semantic/embed` | Generate embeddings for text | ✅ | ✅ |
| `POST` | `/api/v1/semantic/search` | Perform semantic search | ✅ | ✅ |
| `POST` | `/api/v1/semantic/cluster` | Cluster embeddings | ✅ | ✅ |
| `GET` | `/api/v1/semantic/quality/{id}` | Get content quality score | ✅ | ✅ |
| `POST` | `/api/v1/semantic/chunk` | Intelligent text chunking | ✅ | ✅ |
| `POST` | `/api/v1/semantic/classify` | Content classification and tagging | ✅ | ✅ |
| `POST` | `/api/v1/semantic/extract-relations` | Entity and relationship extraction | ✅ | ✅ |
| `POST` | `/api/v1/semantic/score-importance` | ML-based content prioritization | ✅ | ✅ |
| `POST` | `/api/v1/semantic/detect-duplicates` | Semantic duplicate detection | ✅ | ✅ |
| `POST` | `/api/v1/semantic/build-knowledge-graph` | Knowledge graph construction | ✅ | ✅ |

### 📈 **Analytics & Intelligence**
| Method | Endpoint | Description | Auth Required | Status |
|--------|----------|-------------|---------------|--------|
| `POST` | `/api/v1/analytics/dashboard` | Get comprehensive analytics dashboard | ✅ | ✅ |
| `GET` | `/api/v1/analytics/dashboard/summary` | Get dashboard summary metrics | ✅ | ✅ |
| `POST` | `/api/v1/analytics/insights/content` | Get content performance insights | ✅ | ✅ |
| `GET` | `/api/v1/analytics/insights/content/{content_id}` | Get insights for specific content | ✅ | ✅ |
| `POST` | `/api/v1/analytics/trends` | Analyze content and usage trends | ✅ | ✅ |
| `GET` | `/api/v1/analytics/trends/trending` | Get currently trending content | ✅ | ✅ |
| `POST` | `/api/v1/analytics/performance` | Get detailed performance metrics | ✅ | ✅ |
| `POST` | `/api/v1/analytics/search` | Get search analytics and insights | ✅ | ✅ |
| `POST` | `/api/v1/analytics/health` | Get comprehensive system health | ✅ | ✅ |
| `GET` | `/api/v1/analytics/health/quick` | Get quick system health status | ❌ | ✅ |
| `GET` | `/api/v1/analytics/export/report` | Export comprehensive analytics report | ✅ | ✅ |
| `GET` | `/api/v1/analytics/capabilities` | Get analytics capabilities | ❌ | ✅ |

### 🎭 **Personalization**
| Method | Endpoint | Description | Auth Required | Status |
|--------|----------|-------------|---------------|--------|
| `POST` | `/api/v1/personalization/recommend` | Get personalized recommendations | ✅ | ✅ |
| `POST` | `/api/v1/personalization/track-interaction` | Track user interaction | ✅ | ✅ |
| `GET` | `/api/v1/personalization/insights/{user_id}` | Get user insights | ✅ | ✅ |
| `POST` | `/api/v1/personalization/reset-profile` | Reset user profile | ✅ | ✅ |
| `GET` | `/api/v1/personalization/health` | Get personalization health | ❌ | ✅ |
| `GET` | `/api/v1/personalization/capabilities` | Get personalization capabilities | ❌ | ✅ |
| `GET` | `/api/v1/personalization/stats` | Get personalization stats | ❌ | ✅ |
| `POST` | `/api/v1/personalization/bulk-track` | Bulk track interactions | ✅ | ✅ |
| `GET` | `/api/v1/personalization/recommend/trending` | Get trending personalized content | ✅ | ✅ |

### 📈 **Trend Detection**
| Method | Endpoint | Description | Auth Required | Status |
|--------|----------|-------------|---------------|--------|
| `POST` | `/api/v1/trends/analyze` | Comprehensive trend analysis | ✅ | ✅ |
| `POST` | `/api/v1/trends/predictive-insights` | Get predictive insights | ✅ | ✅ |
| `POST` | `/api/v1/trends/anomalies` | Detect anomalies | ✅ | ✅ |
| `GET` | `/api/v1/trends` | Get detected trends | ✅ | ✅ |
| `GET` | `/api/v1/trends/{trend_id}` | Get trend details | ✅ | ✅ |
| `GET` | `/api/v1/trends/forecast/{metric}` | Get metric forecast | ✅ | ✅ |
| `GET` | `/api/v1/trends/health` | Get trends service health | ❌ | ✅ |
| `GET` | `/api/v1/trends/capabilities` | Get trend detection capabilities | ❌ | ✅ |
| `GET` | `/api/v1/trends/patterns/{pattern_type}` | Get trends by pattern type | ✅ | ✅ |
| `POST` | `/api/v1/trends/analyze-metric` | Analyze specific metric | ✅ | ✅ |
| `GET` | `/api/v1/trends/alerts` | Get trend alerts | ✅ | ✅ |

### 🔍 **Search Analytics**
| Method | Endpoint | Description | Auth Required | Status |
|--------|----------|-------------|---------------|--------|
| `POST` | `/api/v1/search-analytics/report` | Generate search analytics report | ✅ | ✅ |
| `POST` | `/api/v1/search-analytics/track-event` | Track search event | ✅ | ✅ |
| `POST` | `/api/v1/search-analytics/suggestions` | Get search suggestions | ✅ | ✅ |
| `POST` | `/api/v1/search-analytics/insights` | Get search insights | ✅ | ✅ |
| `GET` | `/api/v1/search-analytics/performance` | Get search performance | ✅ | ✅ |
| `GET` | `/api/v1/search-analytics/queries` | Get query analytics | ✅ | ✅ |
| `GET` | `/api/v1/search-analytics/user-behavior` | Get user search behavior | ✅ | ✅ |
| `GET` | `/api/v1/search-analytics/optimization` | Get optimization insights | ✅ | ✅ |
| `POST` | `/api/v1/search-analytics/export` | Export search data | ✅ | ✅ |
| `GET` | `/api/v1/search-analytics/health` | Get search analytics health | ❌ | ✅ |
| `GET` | `/api/v1/search-analytics/capabilities` | Get search analytics capabilities | ❌ | ✅ |
| `GET` | `/api/v1/search-analytics/trends` | Get search trends | ✅ | ✅ |
| `GET` | `/api/v1/search-analytics/popular-queries` | Get popular queries | ✅ | ✅ |
| `GET` | `/api/v1/search-analytics/performance-summary` | Get performance summary | ✅ | ✅ |
| `POST` | `/api/v1/search-analytics/bulk-track` | Bulk track search events | ✅ | ✅ |
| `GET` | `/api/v1/search-analytics/real-time` | Get real-time search metrics | ✅ | ✅ |

### 🔄 **Workflow Automation**
| Method | Endpoint | Description | Auth Required | Status |
|--------|----------|-------------|---------------|--------|
| `POST` | `/api/v1/workflows/definitions` | Create workflow definition | ✅ | ✅ |
| `GET` | `/api/v1/workflows/definitions` | List workflow definitions | ✅ | ✅ |
| `GET` | `/api/v1/workflows/definitions/{id}` | Get workflow definition | ✅ | ✅ |
| `PUT` | `/api/v1/workflows/definitions/{id}` | Update workflow definition | ✅ | ✅ |
| `DELETE` | `/api/v1/workflows/definitions/{id}` | Delete workflow definition | ✅ | ✅ |
| `POST` | `/api/v1/workflows/execute` | Execute workflow | ✅ | ✅ |
| `GET` | `/api/v1/workflows/executions` | List workflow executions | ✅ | ✅ |
| `GET` | `/api/v1/workflows/executions/{id}` | Get execution status | ✅ | ✅ |
| `POST` | `/api/v1/workflows/schedule` | Schedule workflow | ✅ | ✅ |
| `DELETE` | `/api/v1/workflows/executions/{id}` | Cancel workflow execution | ✅ | ✅ |

### 🔗 **Integration Layer**
| Method | Endpoint | Description | Auth Required | Status |
|--------|----------|-------------|---------------|--------|
| `POST` | `/api/v1/integration/webhooks/subscribe` | Subscribe to webhook events | ✅ | ✅ |
| `DELETE` | `/api/v1/integration/webhooks/unsubscribe/{id}` | Unsubscribe from webhooks | ✅ | ✅ |
| `GET` | `/api/v1/integration/webhooks` | List webhook subscriptions | ✅ | ✅ |
| `POST` | `/api/v1/integration/queues/enqueue` | Add item to processing queue | ✅ | ✅ |
| `GET` | `/api/v1/integration/queues/stats` | Get queue statistics | ✅ | ✅ |
| `GET` | `/api/v1/integration/backends/stats` | Get backend service statistics | ✅ | ✅ |
| `POST` | `/api/v1/integration/backends/register` | Register backend service | ✅ | ✅ |
| `DELETE` | `/api/v1/integration/backends/unregister/{id}` | Unregister backend service | ✅ | ✅ |

### 🌐 **Universal Content Connectors**
| Method | Endpoint | Description | Auth Required | Status |
|--------|----------|-------------|---------------|--------|
| `POST` | `/api/v1/content/discover` | Discover content from multiple sources | ✅ | ✅ |
| `POST` | `/api/v1/content/connectors/web` | Web content discovery (RSS, scraping) | ✅ | ✅ |
| `POST` | `/api/v1/content/connectors/social` | Social media content (Twitter, Reddit) | ✅ | ✅ |
| `POST` | `/api/v1/content/connectors/communication` | Communication channels (Email, Slack) | ✅ | ✅ |
| `POST` | `/api/v1/content/connectors/filesystem` | File system content (Local, Cloud) | ✅ | ✅ |

### 🧠 **Knowledge Base**
| Method | Endpoint | Description | Auth Required | Status |
|--------|----------|-------------|---------------|--------|
| `POST` | `/api/v1/knowledge/items` | Create knowledge base item | ✅ | ✅ |
| `GET` | `/api/v1/knowledge/items` | List knowledge base items | ✅ | ✅ |
| `GET` | `/api/v1/knowledge/items/{id}` | Get specific knowledge item | ✅ | ✅ |
| `PUT` | `/api/v1/knowledge/items/{id}` | Update knowledge item | ✅ | ✅ |
| `DELETE` | `/api/v1/knowledge/items/{id}` | Delete knowledge item | ✅ | ✅ |
| `POST` | `/api/v1/knowledge/search` | Search knowledge base | ✅ | ✅ |
| `POST` | `/api/v1/knowledge/embeddings` | Generate embeddings | ✅ | ✅ |
| `GET` | `/api/v1/knowledge/categories` | Get content categories | ✅ | ✅ |
| `POST` | `/api/v1/knowledge/classify` | Classify content | ✅ | ✅ |

### 📖 **Documentation**
| Method | Endpoint | Description | Auth Required | Status |
|--------|----------|-------------|---------------|--------|
| `GET` | `/api/v1/docs/agent-creation` | Comprehensive agent creation guide | ❌ | ✅ |
| `GET` | `/api/v1/docs/frontend-integration` | Frontend integration guide | ❌ | ✅ |
| `GET` | `/api/v1/docs/examples` | Example configurations and usage | ❌ | ✅ |
| `GET` | `/api/v1/agent-types/{type}/documentation` | Agent-specific documentation | ❌ | ✅ |

### 📄 **Logging**
| Method | Endpoint | Description | Auth Required | Status |
|--------|----------|-------------|---------------|--------|
| `GET` | `/api/v1/logs/{task_id}` | Get task logs | ❌ | ✅ |
| `GET` | `/api/v1/logs/history` | Query historical logs | ❌ | ✅ |
| `GET` | `/api/v1/logs/stream/{task_id}` | Server-sent events stream | ❌ | ✅ |

### 🔄 **Learning & Adaptation**
| Method | Endpoint | Description | Auth Required | Status |
|--------|----------|-------------|---------------|--------|
| `POST` | `/api/v1/feedback/submit` | Submit user feedback for model improvement | ✅ | ✅ |
| `GET` | `/api/v1/feedback/stats` | Get feedback statistics | ✅ | ✅ |
| `POST` | `/api/v1/active-learning/select-samples` | Intelligent content selection for review | ✅ | ✅ |
| `POST` | `/api/v1/fine-tuning/start` | Start model fine-tuning job | ✅ | ✅ |
| `GET` | `/api/v1/fine-tuning/{job_id}/status` | Get fine-tuning job status | ✅ | ✅ |
| `POST` | `/api/v1/performance/optimize` | Automated model selection and routing | ✅ | ✅ |
| `GET` | `/api/v1/performance/metrics` | Get performance optimization metrics | ✅ | ✅ |

### ⚡ **Quality Enhancement**
| Method | Endpoint | Description | Auth Required | Status |
|--------|----------|-------------|---------------|--------|
| `POST` | `/api/v1/quality/enhance` | AI-powered content improvement | ✅ | ✅ |
| `POST` | `/api/v1/quality/correct` | Automatic content correction | ✅ | ✅ |
| `GET` | `/api/v1/quality/metrics` | Quality assessment metrics | ✅ | ✅ |

### 🌐 **WebSocket Endpoints**
| Protocol | Endpoint | Description | Auth Required | Status |
|----------|----------|-------------|---------------|--------|
| `WS` | `/ws/logs` | Real-time log streaming | ✅ | ✅ |
| `WS` | `/ws/tasks/{task_id}` | Task-specific updates | ✅ | ✅ |
| `WS` | `/ws/chat/{session_id}` | Chat session updates | ✅ | ✅ |

---

## 🔐 User Authentication & Management

The Agentic Backend provides comprehensive user authentication with JWT tokens and role-based access control.

### 📋 Authentication Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/api/v1/auth/login` | Login with form data (OAuth2) | ❌ |
| `POST` | `/api/v1/auth/login-json` | Login with JSON payload | ❌ |
| `GET` | `/api/v1/auth/me` | Get current user information | ✅ |
| `POST` | `/api/v1/auth/change-password` | Change user password | ✅ |
| `POST` | `/api/v1/auth/admin/change-password` | Admin change any user's password | ✅ |

### 🚀 Login Flow

#### Option 1: JSON Login (Recommended for Frontend)
```bash
POST /api/v1/auth/login-json
Content-Type: application/json

{
  "username": "your-username",
  "password": "your-password"
}
```

**Success Response:**
```json
{
  "access_token": "<TOKEN>",
  "token_type": "bearer"
}
```

#### Option 2: Form Login (OAuth2 Compatible)
```bash
POST /api/v1/auth/login
Content-Type: application/x-www-form-urlencoded

username=your-username&password=your-password
```

### 🔑 Using JWT Tokens

After successful login, include the JWT token in the Authorization header for authenticated requests:

```bash
Authorization: Bearer <TOKEN>
```

### 👤 User Management

#### Get Current User Info
```bash
GET /api/v1/auth/me
Authorization: Bearer <TOKEN>
```

**Response:**
```json
{
  "id": 1,
  "username": "your-username",
  "email": "user@example.com",
  "is_active": true,
  "is_superuser": false,
  "created_at": "2024-01-01T12:00:00Z",
  "updated_at": "2024-01-01T12:00:00Z"
}
```

#### Change Password
```bash
POST /api/v1/auth/change-password
Authorization: Bearer <TOKEN>
Content-Type: application/json

{
  "current_password": "old-password",
  "new_password": "new-secure-password"
}
```

### 👨‍💼 Admin Functions

#### Admin Change Password (Superuser Only)
```bash
POST /api/v1/auth/admin/change-password
Authorization: Bearer <TOKEN>
Content-Type: application/json

{
  "username": "target-user",
  "new_password": "new-password"
}
```

### 🎯 Frontend Integration Examples

#### React Login Hook
```javascript
import { useState } from 'react';

function useAuth() {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token'));

  const login = async (username, password) => {
    const response = await fetch('/api/v1/auth/login-json', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });

    if (response.ok) {
      const data = await response.json();
      setToken(data.access_token);
      localStorage.setItem('token', data.access_token);

      // Get user info
      const userResponse = await fetch('/api/v1/auth/me', {
        headers: { 'Authorization': `Bearer ${data.access_token}` }
      });

      if (userResponse.ok) {
        const userData = await userResponse.json();
        setUser(userData);
      }

      return { success: true };
    } else {
      const error = await response.json();
      return { success: false, error: error.detail };
    }
  };

  const logout = () => {
    setUser(null);
    setToken(null);
    localStorage.removeItem('token');
  };

  return { user, token, login, logout };
}
```

#### Axios Interceptor for Automatic Token Handling
```javascript
import axios from 'axios';

// Create axios instance
const api = axios.create({
  baseURL: '/api/v1'
});

// Request interceptor to add auth token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor to handle token expiration
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Token expired or invalid
      localStorage.removeItem('token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

export default api;
```

### 🔧 User Creation

To create users, use the provided scripts:

```bash
# Create a new user
python scripts/create_user.py

# Or use the database directly
docker-compose exec db psql -U postgres -d ai_db -c "
INSERT INTO users (username, email, hashed_password, is_active, is_superuser)
VALUES ('admin', 'admin@example.com', '$2b$12$...', true, true);
"
```

### ⚠️ Authentication Errors

| Error Code | Description | Solution |
|------------|-------------|----------|
| `401 Unauthorized` | Invalid credentials | Check username/password |
| `400 Bad Request` | Missing required fields | Ensure username and password are provided |
| `403 Forbidden` | Insufficient permissions | Check user role for admin operations |
| `422 Validation Error` | Invalid input format | Check request format and required fields |

### ✅ Current API Status (All Endpoints Working)

**Recently Fixed Issues:**
- ✅ **Security Routes**: Fixed double prefix issue (`/api/v1/security/security/...` → `/api/v1/security/...`)
- ✅ **Database Schema**: Added missing columns (`agent_type_id`, `dynamic_config`, `documentation_url`)
- ✅ **WebSocket Support**: Fully configured and documented
- ✅ **Agent Endpoints**: All CRUD operations working
- ✅ **System Metrics**: CPU, memory, GPU monitoring active
- ✅ **Ollama Integration**: Model management and health checks working
- ✅ **Chat Endpoints**: Fixed missing database tables and async issues - all chat endpoints now working

**Verified Working Endpoints:**
```bash
# Authentication endpoints
POST /api/v1/auth/login                # ✅ User login (form data)
POST /api/v1/auth/login-json           # ✅ User login (JSON payload)
GET  /api/v1/auth/me                   # ✅ Get current user info
POST /api/v1/auth/change-password      # ✅ Change password
POST /api/v1/auth/admin/change-password # ✅ Admin change password

# Core endpoints
GET  /api/v1/health                    # ✅ System health
GET  /api/v1/agents                    # ✅ List agents
POST /api/v1/agents/create             # ✅ Create agent
GET  /api/v1/tasks                     # ✅ List tasks
POST /api/v1/tasks/run                 # ✅ Execute task

# Agentic HTTP Client (Phase 1.2 - IMPLEMENTED)
POST /api/v1/http/request              # ✅ Make HTTP request with agentic features
GET  /api/v1/http/metrics              # ✅ HTTP client performance metrics
GET  /api/v1/http/requests/{id}        # ✅ Get specific request details
GET  /api/v1/http/health               # ✅ HTTP client health status
POST /api/v1/http/stream-download      # ✅ Stream large file downloads

# Dynamic Model Selection (Phase 1.3 - IMPLEMENTED)
GET  /api/v1/models/available          # ✅ List available models with capabilities
POST /api/v1/models/select             # ✅ Select optimal model for task
GET  /api/v1/models/performance        # ✅ Get model performance metrics
GET  /api/v1/models/{name}/stats       # ✅ Get specific model statistics
POST /api/v1/models/refresh            # ✅ Refresh model registry

# Multi-Modal Content Framework (Phase 1.4 - IMPLEMENTED)
POST /api/v1/content/process           # ✅ Process content with automatic type detection
GET  /api/v1/content/{id}              # ✅ Get processed content data
POST /api/v1/content/batch             # ✅ Batch process multiple content items
GET  /api/v1/content/cache/stats       # ✅ Content cache statistics

# Semantic Processing (Phase 1.5 - IMPLEMENTED)
POST /api/v1/semantic/embed            # ✅ Generate embeddings for text
POST /api/v1/semantic/search           # ✅ Perform semantic search
POST /api/v1/semantic/cluster          # ✅ Cluster embeddings
GET  /api/v1/semantic/quality/{id}     # ✅ Get content quality score
POST /api/v1/semantic/chunk            # ✅ Intelligent text chunking

# Vision AI Integration (Phase 3.1 - IMPLEMENTED)
POST /api/v1/vision/analyze            # ✅ Analyze image with multiple vision tasks
POST /api/v1/vision/detect-objects     # ✅ Detect objects in image
POST /api/v1/vision/caption            # ✅ Generate image caption
POST /api/v1/vision/search             # ✅ Find similar images
POST /api/v1/vision/ocr                # ✅ Extract text from image
GET  /api/v1/vision/models             # ✅ List available vision models

# Advanced Analytics Service (Phase 4.1 - IMPLEMENTED)
GET  /api/v1/analytics/usage-patterns  # ✅ Get usage pattern analysis
GET  /api/v1/analytics/content-insights # ✅ Get content performance insights
GET  /api/v1/analytics/trends          # ✅ Get trend analysis and predictions
POST /api/v1/analytics/report          # ✅ Generate comprehensive analytics report
GET  /api/v1/analytics/dashboard       # ✅ Get analytics dashboard data

# Audio AI Integration (Phase 3.1 - IMPLEMENTED)
POST /api/v1/audio/transcribe          # ✅ Convert speech to text
POST /api/v1/audio/identify-speaker    # ✅ Identify speakers in audio
POST /api/v1/audio/analyze-emotion     # ✅ Detect emotions in speech
POST /api/v1/audio/classify            # ✅ Classify audio content
POST /api/v1/audio/analyze-music       # ✅ Extract musical features
GET  /api/v1/audio/models              # ✅ List available audio models

# Cross-Modal Processing (Phase 3.1 - IMPLEMENTED)
POST /api/v1/crossmodal/align          # ✅ Align text with images
POST /api/v1/crossmodal/correlate      # ✅ Correlate audio with visual content
POST /api/v1/crossmodal/search         # ✅ Multi-modal search
POST /api/v1/crossmodal/fuse           # ✅ Fuse information from multiple modalities
GET  /api/v1/crossmodal/models         # ✅ List cross-modal models

# Quality Enhancement (Phase 3.1 - IMPLEMENTED)
POST /api/v1/quality/enhance           # ✅ AI-powered content improvement
POST /api/v1/quality/correct           # ✅ Automatic content correction
GET  /api/v1/quality/metrics           # ✅ Quality assessment metrics

# Semantic Understanding Engine (Phase 3.2 - IMPLEMENTED)
POST /api/v1/semantic/classify         # ✅ Content classification and tagging
POST /api/v1/semantic/extract-relations # ✅ Entity and relationship extraction
POST /api/v1/semantic/score-importance # ✅ ML-based content prioritization
POST /api/v1/semantic/detect-duplicates # ✅ Semantic duplicate detection
POST /api/v1/semantic/build-knowledge-graph # ✅ Knowledge graph construction

# Learning & Adaptation (Phase 3.3 - IMPLEMENTED)
POST /api/v1/feedback/submit           # ✅ Submit user feedback for model improvement
GET  /api/v1/feedback/stats            # ✅ Get feedback statistics
POST /api/v1/active-learning/select-samples # ✅ Intelligent content selection for review
POST /api/v1/fine-tuning/start         # ✅ Start model fine-tuning job
GET  /api/v1/fine-tuning/{job_id}/status # ✅ Get fine-tuning job status
POST /api/v1/performance/optimize      # ✅ Automated model selection and routing
GET  /api/v1/performance/metrics       # ✅ Get performance optimization metrics

# Universal Content Connectors (Phase 2 - IMPLEMENTED)
POST /api/v1/content/discover          # ✅ Discover content from multiple sources
POST /api/v1/content/connectors/web    # ✅ Web content discovery (RSS, scraping)
POST /api/v1/content/connectors/social # ✅ Social media content (Twitter, Reddit)
POST /api/v1/content/connectors/communication # ✅ Communication channels (Email, Slack)
POST /api/v1/content/connectors/filesystem # ✅ File system content (Local, Cloud)

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

# Chat system endpoints
POST /api/v1/chat/sessions             # ✅ Create chat session
GET  /api/v1/chat/sessions             # ✅ List chat sessions
GET  /api/v1/chat/sessions/{id}        # ✅ Get chat session details
GET  /api/v1/chat/sessions/{id}/messages # ✅ Get chat messages
POST /api/v1/chat/sessions/{id}/messages # ✅ Send message & get AI response
GET  /api/v1/chat/sessions/{id}/stats # ✅ Get session statistics
PUT  /api/v1/chat/sessions/{id}/status # ✅ Update session status
DELETE /api/v1/chat/sessions/{id}      # ✅ Delete chat session
GET  /api/v1/chat/templates            # ✅ List chat templates
GET  /api/v1/chat/models               # ✅ List available chat models

# WebSocket endpoints
WS   /ws/logs                          # ✅ Real-time logs
WS   /ws/tasks/{task_id}               # ✅ Task monitoring
```



### 📋 **New API Endpoints (Phase 2)**

#### **Integration Layer Endpoints**
| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/api/v1/integration/webhooks/subscribe` | Subscribe to webhook events | ✅ |
| `DELETE` | `/api/v1/integration/webhooks/unsubscribe/{id}` | Unsubscribe from webhooks | ✅ |
| `GET` | `/api/v1/integration/webhooks` | List webhook subscriptions | ✅ |
| `POST` | `/api/v1/integration/queues/enqueue` | Add item to processing queue | ✅ |
| `GET` | `/api/v1/integration/queues/stats` | Get queue statistics | ✅ |
| `GET` | `/api/v1/integration/backends/stats` | Get backend service statistics | ✅ |
| `POST` | `/api/v1/integration/backends/register` | Register backend service | ✅ |
| `DELETE` | `/api/v1/integration/backends/unregister/{id}` | Unregister backend service | ✅ |

#### **Knowledge Base Endpoints**
| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/api/v1/knowledge/items` | Create knowledge base item | ✅ |
| `GET` | `/api/v1/knowledge/items` | List knowledge base items | ✅ |
| `GET` | `/api/v1/knowledge/items/{id}` | Get specific knowledge item | ✅ |
| `PUT` | `/api/v1/knowledge/items/{id}` | Update knowledge item | ✅ |
| `DELETE` | `/api/v1/knowledge/items/{id}` | Delete knowledge item | ✅ |
| `POST` | `/api/v1/knowledge/search` | Search knowledge base | ✅ |
| `POST` | `/api/v1/knowledge/embeddings` | Generate embeddings | ✅ |
| `GET` | `/api/v1/knowledge/categories` | Get content categories | ✅ |
| `POST` | `/api/v1/knowledge/classify` | Classify content | ✅ |

#### **Workflow Automation Endpoints**
| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/api/v1/workflows/definitions` | Create workflow definition | ✅ |
| `GET` | `/api/v1/workflows/definitions` | List workflow definitions | ✅ |
| `GET` | `/api/v1/workflows/definitions/{id}` | Get workflow definition | ✅ |
| `PUT` | `/api/v1/workflows/definitions/{id}` | Update workflow definition | ✅ |
| `DELETE` | `/api/v1/workflows/definitions/{id}` | Delete workflow definition | ✅ |
| `POST` | `/api/v1/workflows/execute` | Execute workflow | ✅ |
| `GET` | `/api/v1/workflows/executions` | List workflow executions | ✅ |
| `GET` | `/api/v1/workflows/executions/{id}` | Get execution status | ✅ |
| `POST` | `/api/v1/workflows/schedule` | Schedule workflow | ✅ |
| `DELETE` | `/api/v1/workflows/executions/{id}` | Cancel workflow execution | ✅ |

### 🔄 **Integration Examples**

#### **Webhook Integration**
```javascript
// Subscribe to workflow events
const subscription = await fetch('/api/v1/integration/webhooks/subscribe', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    url: 'https://myapp.com/webhook',
    events: ['workflow.completed', 'workflow.failed'],
    headers: { 'Authorization': 'Bearer token123' }
  })
});

// Handle webhook notifications
app.post('/webhook', (req, res) => {
  const { event, data } = req.body;

  if (event === 'workflow.completed') {
    console.log('Workflow completed:', data.execution_id);
    // Handle completion logic
  }
});
```

#### **Queue Processing Integration**
```javascript
// Enqueue processing task
const result = await fetch('/api/v1/integration/queues/enqueue', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    type: 'data_processing',
    priority: 'high',
    data: { file_url: 'https://example.com/data.csv' },
    callback_url: 'https://myapp.com/callback'
  })
});

// Handle processing callback
app.post('/callback', (req, res) => {
  const { status, result } = req.body;
  // Handle processing result
});
```

#### **Load Balancing Integration**
```javascript
// Register backend service
await fetch('/api/v1/integration/backends/register', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    id: 'ml-service-1',
    url: 'http://ml-service:8000',
    supported_request_types: ['ai_processing', 'data_analysis'],
    max_concurrent_requests: 10
  })
});

// Route requests through load balancer
const result = await fetch('/api/v1/integration/load-balance/ai_processing', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    model: 'llama2',
    prompt: 'Analyze this data...'
  })
});
```

### 📊 **Database Schema Details**

#### **Integration Layer Tables**
- `webhook_subscriptions`: Webhook subscription management
- `webhook_delivery_logs`: Webhook delivery tracking and retries
- `queue_items`: Asynchronous processing queue with priorities
- `backend_services`: Backend service registry and health monitoring
- `api_gateway_metrics`: API gateway performance and rate limiting metrics

#### **Knowledge Base Tables**
- `knowledge_base_items`: Core content storage with metadata
- `knowledge_base_media`: Media asset management and caching
- `knowledge_base_analysis`: AI processing results and model usage tracking
- `knowledge_base_embeddings`: Vector embeddings for semantic search
- `knowledge_base_categories`: Content categorization and tagging
- `knowledge_base_search_log`: Search analytics and user behavior tracking

#### **Workflow Tables**
- `workflow_definitions`: Workflow template storage and versioning
- `workflow_executions`: Execution tracking and state management
- `workflow_schedules`: Scheduled and event-triggered workflow management
- `workflow_execution_logs`: Detailed execution logs and error tracking
- `workflow_metrics`: Performance monitoring and optimization data

### 🚀 **Phase 2 Benefits**
1. **Complete Database Persistence**: All services now have full database integration
2. **Enterprise Scalability**: Support for high-concurrency workloads and distributed processing
3. **Robust Error Handling**: Intelligent error recovery and graceful degradation
4. **Production Monitoring**: Comprehensive logging and performance tracking
5. **API Completeness**: All placeholder implementations replaced with production-ready code
6. **Data Integrity**: Proper relationships and constraints for data consistency
7. **Performance Optimization**: Strategic indexing and query optimization
8. **Resource Efficiency**: Proper connection pooling and resource management

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

### 💬 LLM Chat System Endpoints

The Agentic Backend now includes a comprehensive LLM chat system for interactive agent creation and general AI assistance.

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/api/v1/chat/sessions` | Create new chat session | ✅ |
| `GET` | `/api/v1/chat/sessions` | List chat sessions | ❌ |
| `GET` | `/api/v1/chat/sessions/{session_id}` | Get chat session details | ❌ |
| `GET` | `/api/v1/chat/sessions/{session_id}/messages` | Get chat messages | ❌ |
| `POST` | `/api/v1/chat/sessions/{session_id}/messages` | Send message to chat | ✅ |
| `PUT` | `/api/v1/chat/sessions/{session_id}/status` | Update session status | ✅ |
| `GET` | `/api/v1/chat/sessions/{session_id}/stats` | Get session statistics | ❌ |
| `DELETE` | `/api/v1/chat/sessions/{session_id}` | Delete chat session | ✅ |
| `GET` | `/api/v1/chat/templates` | List available chat templates | ❌ |
| `GET` | `/api/v1/chat/models` | List available Ollama models | ❌ |

#### 📊 Chat Performance Metrics

All chat responses now include comprehensive performance metrics to help monitor LLM performance and optimize user experience. These metrics are returned in the `performance_metrics` field of the response.

**Send Message Response Format:**
```json
{
  "session_id": "uuid-string",
  "response": "AI generated response text",
  "model": "llama2:13b",
  "performance_metrics": {
    "response_time_seconds": 2.456,
    "load_time_seconds": 0.123,
    "prompt_eval_time_seconds": 0.789,
    "generation_time_seconds": 1.544,
    "prompt_tokens": 156,
    "response_tokens": 89,
    "total_tokens": 245,
    "tokens_per_second": 57.64,
    "context_length_chars": 2048,
    "model_name": "llama2:13b",
    "timestamp": "2024-01-01T12:00:00.000Z"
  }
}
```

**Performance Metrics Breakdown:**

| Metric | Description | Unit | Example |
|--------|-------------|------|---------|
| `response_time_seconds` | Total time for complete response | seconds | 2.456 |
| `load_time_seconds` | Time to load model into memory | seconds | 0.123 |
| `prompt_eval_time_seconds` | Time to process input prompt | seconds | 0.789 |
| `generation_time_seconds` | Time to generate response | seconds | 1.544 |
| `prompt_tokens` | Number of tokens in input prompt | count | 156 |
| `response_tokens` | Number of tokens generated | count | 89 |
| `total_tokens` | Total tokens processed | count | 245 |
| `tokens_per_second` | Generation speed | tokens/sec | 57.64 |
| `context_length_chars` | Approximate context length | characters | 2048 |
| `model_name` | Model used for generation | string | "llama2:13b" |
| `timestamp` | Response generation timestamp | ISO 8601 | "2024-01-01T12:00:00.000Z" |

**Frontend Integration Example:**
```javascript
// Send message and display performance metrics
async function sendChatMessage(sessionId, message) {
  const response = await fetch(`/api/v1/chat/sessions/${sessionId}/messages`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message })
  });

  const data = await response.json();

  // Display the AI response
  displayMessage(data.response, 'assistant');

  // Display performance metrics
  displayPerformanceMetrics(data.performance_metrics);
}

function displayPerformanceMetrics(metrics) {
  const metricsDiv = document.getElementById('performance-metrics');

  metricsDiv.innerHTML = `
    <div class="metrics-grid">
      <div class="metric">
        <span class="label">Response Time:</span>
        <span class="value">${metrics.response_time_seconds.toFixed(2)}s</span>
      </div>
      <div class="metric">
        <span class="label">Tokens/Second:</span>
        <span class="value">${metrics.tokens_per_second.toFixed(1)}</span>
      </div>
      <div class="metric">
        <span class="label">Total Tokens:</span>
        <span class="value">${metrics.total_tokens}</span>
      </div>
      <div class="metric">
        <span class="label">Model:</span>
        <span class="value">${metrics.model_name}</span>
      </div>
    </div>
  `;
}
```

**CSS Styling Example:**
```css
.metrics-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 10px;
  margin-top: 10px;
  padding: 10px;
  background: #f5f5f5;
  border-radius: 5px;
  font-size: 0.9em;
}

.metric {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.metric .label {
  font-weight: 500;
  color: #666;
}

.metric .value {
  font-weight: 600;
  color: #333;
}
```

**Use Cases for Performance Metrics:**

1. **User Experience Monitoring**: Track response times to ensure optimal user experience
2. **Model Performance Comparison**: Compare different models' speed and efficiency
3. **Cost Optimization**: Monitor token usage for cost analysis
4. **System Performance Tuning**: Identify bottlenecks in the LLM pipeline
5. **Quality Assurance**: Ensure consistent performance across different loads
6. **Debugging**: Identify slow responses and investigate root causes

## 🤖 AI-Assisted Agent Creation Wizard

The Agentic Backend includes a sophisticated AI-assisted agent creation wizard that guides users through creating agents using conversational AI. This wizard integrates with the chat system to provide intelligent, step-by-step agent creation.

### 🎯 Key Features

- **Conversational AI Guidance**: Natural language interaction for agent creation
- **Intelligent Requirements Analysis**: AI analyzes user needs and suggests optimal configurations
- **Automatic Schema Generation**: Creates complete agent schemas from conversation
- **Validation & Best Practices**: Ensures created agents follow security and performance best practices
- **Integration with Secrets**: Automatically suggests and configures secure credential management

### 🔄 Creation Workflow

The agent creation wizard follows a structured workflow:

1. **Requirements Gathering**: AI asks clarifying questions about the desired agent
2. **Analysis & Recommendations**: LLM analyzes requirements and suggests optimal configuration
3. **Schema Generation**: Creates complete agent schema with data models and processing pipeline
4. **Validation**: Validates the generated schema against security and performance requirements
5. **Finalization**: Registers the agent type and creates deployment-ready configuration

### 💬 Integration with Chat System

The wizard integrates seamlessly with the chat endpoints:

#### Start Agent Creation Session
```bash
POST /api/v1/chat/sessions
{
  "session_type": "agent_creation",
  "model_name": "llama2",
  "user_id": "user-123",
  "title": "Create Email Analysis Agent"
}
```

#### Send Creation Request
```bash
POST /api/v1/chat/sessions/{session_id}/messages
{
  "message": "Create an agent that analyzes emails from my Gmail account, categorizes them by importance, and extracts key information like sender, subject, and urgency level."
}
```

#### Continue Conversation
```bash
POST /api/v1/chat/sessions/{session_id}/messages
{
  "message": "I want to use Gmail API and store the results in a custom database table with fields for email_id, importance_score, category, and summary."
}
```

### 📋 Wizard Capabilities

#### Requirements Analysis
- Task type classification (classification, generation, analysis, automation)
- Complexity assessment (simple, moderate, complex)
- Resource estimation (memory, CPU requirements)
- Security requirements identification
- Tool recommendations

#### Configuration Generation
- Complete agent schema creation
- Data model definitions
- Processing pipeline setup
- Tool configurations
- Input/output schema definitions

#### Validation & Optimization
- Schema validation against security policies
- Performance optimization suggestions
- Resource limit compliance
- Best practices implementation

### 🔧 Frontend Integration

#### React Hook for Agent Creation
```javascript
import { useState, useCallback } from 'react';

function useAgentCreationWizard() {
  const [sessionId, setSessionId] = useState(null);
  const [messages, setMessages] = useState([]);
  const [isCreating, setIsCreating] = useState(false);

  const startCreation = useCallback(async (description) => {
    setIsCreating(true);
    try {
      const response = await fetch('/api/v1/chat/sessions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          session_type: 'agent_creation',
          model_name: 'llama2',
          title: 'Agent Creation',
          config: { description }
        })
      });

      const session = await response.json();
      setSessionId(session.id);
      return session;
    } finally {
      setIsCreating(false);
    }
  }, []);

  const sendMessage = useCallback(async (message) => {
    if (!sessionId) return;

    const response = await fetch(`/api/v1/chat/sessions/${sessionId}/messages`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message })
    });

    const result = await response.json();
    setMessages(prev => [...prev, {
      role: 'user',
      content: message,
      timestamp: new Date()
    }, {
      role: 'assistant',
      content: result.response,
      timestamp: new Date()
    }]);

    return result;
  }, [sessionId]);

  return {
    sessionId,
    messages,
    isCreating,
    startCreation,
    sendMessage
  };
}
```

#### Complete Agent Creation UI
```javascript
import React, { useState, useEffect } from 'react';
import { useAgentCreationWizard } from './hooks/useAgentCreationWizard';

function AgentCreationWizard() {
  const {
    sessionId,
    messages,
    isCreating,
    startCreation,
    sendMessage
  } = useAgentCreationWizard();

  const [description, setDescription] = useState('');
  const [currentMessage, setCurrentMessage] = useState('');

  const handleStart = async () => {
    if (!description.trim()) return;
    await startCreation(description);
  };

  const handleSendMessage = async () => {
    if (!currentMessage.trim()) return;
    await sendMessage(currentMessage);
    setCurrentMessage('');
  };

  return (
    <div className="agent-creation-wizard">
      <div className="wizard-header">
        <h2>🤖 AI Agent Creation Wizard</h2>
        <p>Create custom agents with AI assistance</p>
      </div>

      {!sessionId ? (
        <div className="wizard-start">
          <div className="description-input">
            <label htmlFor="agent-description">
              Describe the agent you want to create:
            </label>
            <textarea
              id="agent-description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="e.g., Create an agent that analyzes customer emails, categorizes them by urgency, and extracts key information..."
              rows={4}
            />
          </div>

          <button
            onClick={handleStart}
            disabled={isCreating || !description.trim()}
            className="start-button"
          >
            {isCreating ? '🚀 Starting Creation...' : '🎯 Start Agent Creation'}
          </button>
        </div>
      ) : (
        <div className="wizard-chat">
          <div className="chat-container">
            <div className="messages">
              {messages.map((msg, index) => (
                <div key={index} className={`message ${msg.role}`}>
                  <div className="message-header">
                    <span className="role">
                      {msg.role === 'user' ? '👤 You' : '🤖 AI Assistant'}
                    </span>
                    <span className="timestamp">
                      {msg.timestamp?.toLocaleTimeString()}
                    </span>
                  </div>
                  <div className="message-content">
                    {msg.content}
                  </div>
                </div>
              ))}
            </div>

            <div className="message-input">
              <textarea
                value={currentMessage}
                onChange={(e) => setCurrentMessage(e.target.value)}
                placeholder="Ask questions or provide additional requirements..."
                rows={2}
                onKeyPress={(e) => e.key === 'Enter' && !e.shiftKey && handleSendMessage()}
              />
              <button
                onClick={handleSendMessage}
                disabled={!currentMessage.trim()}
              >
                📤 Send
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default AgentCreationWizard;
```

### 🎯 Best Practices

#### For Users
1. **Be Specific**: Provide detailed descriptions of what you want the agent to do
2. **Include Context**: Mention data sources, output formats, and integration requirements
3. **Iterate**: Use the conversational interface to refine requirements
4. **Review Generated Config**: Always review the generated schema before deployment

#### For Developers
1. **Handle Errors Gracefully**: Implement proper error handling for failed creations
2. **Provide Feedback**: Show clear progress indicators during creation
3. **Validate Input**: Ensure user descriptions are meaningful and actionable
4. **Cache Sessions**: Persist creation sessions for user convenience

### 📚 Implementation Details

#### Backend Architecture

The agent creation wizard consists of several key components:

##### AgentCreationWizard Service (`app/services/agent_creation_wizard.py`)
- Main service class that orchestrates the creation process
- Integrates with ChatService for conversational AI
- Uses Ollama client for LLM-powered analysis
- Validates configurations against security policies

##### Chat Integration (`app/services/chat_service.py`)
- Provides the conversational interface
- Manages chat sessions with different types
- Stores conversation history and metadata
- Handles message routing and responses

##### Database Models
- `ChatSession`: Stores chat session information
- `ChatMessage`: Stores individual messages in conversations
- `AgentType`: Stores registered agent type schemas

#### API Endpoints

The wizard leverages existing chat endpoints with specialized functionality:

##### Chat Sessions
- `POST /api/v1/chat/sessions` - Create new chat session
- `GET /api/v1/chat/sessions` - List chat sessions
- `GET /api/v1/chat/sessions/{session_id}` - Get session details
- `PUT /api/v1/chat/sessions/{session_id}/status` - Update session status
- `DELETE /api/v1/chat/sessions/{session_id}` - Delete session

##### Chat Messages
- `GET /api/v1/chat/sessions/{session_id}/messages` - Get session messages
- `POST /api/v1/chat/sessions/{session_id}/messages` - Send message
- `GET /api/v1/chat/sessions/{session_id}/stats` - Get session statistics

##### Chat Templates
- `GET /api/v1/chat/templates` - List available templates
- `GET /api/v1/chat/models` - List available models

#### Security Considerations

##### Input Validation
- All user inputs are validated before processing
- Malicious content detection prevents injection attacks
- Rate limiting protects against abuse

##### Authentication
- All chat endpoints require API key authentication
- Session-based access control
- User-specific session isolation

##### Data Privacy
- Chat sessions are scoped to individual users
- Sensitive data is encrypted in transit and at rest
- Audit trails track all creation activities

#### Error Handling

##### Common Error Scenarios
1. **Invalid Session Type**: When unsupported session type is provided
2. **Model Unavailable**: When requested LLM model is not available
3. **Schema Validation Failed**: When generated schema doesn't meet requirements
4. **Resource Limits Exceeded**: When creation would exceed system limits

##### Error Response Format
```json
{
  "detail": "Error description",
  "status_code": 400,
  "suggestion": "Suggested action to resolve the error"
}
```

### 📖 Advanced Usage

#### Custom Templates
The wizard supports custom conversation templates for specialized agent types:

```javascript
// Use a custom template
const session = await createChatSession({
  session_type: 'agent_creation',
  model_name: 'llama2',
  config: {
    template: 'email_processor_template',
    custom_parameters: {
      email_provider: 'gmail',
      analysis_depth: 'detailed'
    }
  }
});
```

#### Batch Creation
For creating multiple similar agents:

```javascript
const agents = [
  { name: 'Sales Email Processor', criteria: 'sales-related' },
  { name: 'Support Email Processor', criteria: 'support-tickets' },
  { name: 'Marketing Email Processor', criteria: 'marketing-campaigns' }
];

for (const agent of agents) {
  const session = await createChatSession({
    session_type: 'agent_creation',
    title: agent.name
  });

  await sendMessage(session.id, `Create an email processor focused on ${agent.criteria} emails.`);
  // Continue with specific configuration...
}
```

#### Integration with Existing Systems
The wizard can be integrated with existing agent management systems:

```javascript
// Integrate with agent registry
class AgentRegistryIntegration {
  async createAgentFromWizard(sessionId) {
    // Get final configuration from wizard
    const config = await getWizardConfiguration(sessionId);

    // Register with existing agent registry
    const agent = await registerAgent(config);

    // Update wizard session with registration result
    await updateWizardSession(sessionId, {
      status: 'registered',
      agent_id: agent.id
    });

    return agent;
  }
}
```

### 🔧 Configuration Options

#### Session Configuration
```json
{
  "session_type": "agent_creation",
  "model_name": "llama2",
  "user_id": "optional-user-id",
  "title": "Custom Agent Title",
  "config": {
    "max_iterations": 10,
    "validation_level": "strict",
    "auto_finalize": false,
    "custom_templates": ["template1", "template2"]
  }
}
```

#### Message Configuration
```json
{
  "message": "Your agent description here",
  "model_name": "optional-override-model",
  "metadata": {
    "priority": "high",
    "tags": ["email", "analysis"],
    "custom_data": {}
  }
}
```

### 📊 Analytics and Reporting

#### Creation Metrics
- Total agents created via wizard
- Success rate by agent type
- Average creation time
- Popular configuration patterns

#### User Engagement
- Session duration tracking
- Message count per session
- User satisfaction scores
- Feature usage patterns

#### Performance Metrics
- Response time distribution
- Resource usage patterns
- Error rate by creation step
- Model performance comparison

### 🐛 Troubleshooting

#### Common Issues

#### Debug Mode
Enable debug logging for detailed troubleshooting:

```bash
# Set environment variable
export LOG_LEVEL=DEBUG

# Check application logs
docker-compose logs api
```

#### Support Resources
- Check existing documentation for similar issues
- Review GitHub issues for known problems
- Contact development team for complex issues
- Use the interactive Swagger UI for testing

## �️ Security Features Overview

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
| `POST` | `/api/v1/agents/create` | Create new agent (static or dynamic) with optional secrets | ✅ |
| `GET` | `/api/v1/agents` | List all agents with filtering | ❌ |
| `GET` | `/api/v1/agents/{agent_id}` | Get specific agent | ❌ |
| `PUT` | `/api/v1/agents/{agent_id}` | Update agent | ✅ |
| `DELETE` | `/api/v1/agents/{agent_id}` | Delete agent | ✅ |

### 💬 LLM Chat System Endpoints

The Agentic Backend now includes a comprehensive LLM chat system for interactive agent creation and general AI assistance. All chat responses include detailed performance metrics for monitoring and optimization.

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/api/v1/chat/sessions` | Create new chat session | ✅ |
| `GET` | `/api/v1/chat/sessions` | List chat sessions | ❌ |
| `GET` | `/api/v1/chat/sessions/{session_id}` | Get chat session details | ❌ |
| `GET` | `/api/v1/chat/sessions/{session_id}/messages` | Get chat messages | ❌ |
| `POST` | `/api/v1/chat/sessions/{session_id}/messages` | Send message to chat (includes performance metrics) | ✅ |
| `PUT` | `/api/v1/chat/sessions/{session_id}/status` | Update session status | ✅ |
| `GET` | `/api/v1/chat/sessions/{session_id}/stats` | Get session statistics | ❌ |
| `DELETE` | `/api/v1/chat/sessions/{session_id}` | Delete chat session | ✅ |
| `GET` | `/api/v1/chat/templates` | List available chat templates | ❌ |
| `GET` | `/api/v1/chat/models` | List available Ollama models | ❌ |

### � Secrets Management Endpoints

The Agentic Backend provides comprehensive secret management for storing sensitive data like API keys, passwords, and tokens. All secrets are encrypted using Fernet symmetric encryption.

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/api/v1/agents/{agent_id}/secrets` | Create a new secret for an agent | ✅ |
| `GET` | `/api/v1/agents/{agent_id}/secrets` | List all secrets for an agent | ❌ |
| `GET` | `/api/v1/agents/{agent_id}/secrets/{secret_id}` | Get a specific secret | ✅ |
| `PUT` | `/api/v1/agents/{agent_id}/secrets/{secret_id}` | Update a secret | ✅ |
| `DELETE` | `/api/v1/agents/{agent_id}/secrets/{secret_id}` | Delete a secret (soft delete) | ✅ |
| `GET` | `/api/v1/agents/{agent_id}/secrets/{secret_key}/value` | Get decrypted secret value by key | ✅ |

### ⚡ Task Management Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/api/v1/tasks/run` | Execute task (supports both static and dynamic agents) | ✅ |
| `GET` | `/api/v1/tasks` | List tasks with filtering | ❌ |
| `GET` | `/api/v1/tasks/{task_id}/status` | Get task status | ❌ |
| `DELETE` | `/api/v1/tasks/{task_id}` | Cancel task | ✅ |

## 🔐 Secrets Management

The Agentic Backend provides a secure secrets management system that allows you to store sensitive data (API keys, passwords, tokens) encrypted in the database. Secrets are associated with specific agents and can be accessed programmatically during agent execution.

### Key Features

- **End-to-end encryption**: All secrets are encrypted using Fernet symmetric encryption
- **Agent-specific**: Secrets are scoped to individual agents for security
- **Flexible key-value storage**: Store multiple secrets per agent with custom keys
- **API and frontend access**: Full CRUD operations via REST API
- **Soft deletion**: Secrets can be deactivated without permanent deletion
- **Audit trail**: Creation and update timestamps for all secrets

### Security Considerations

- Secrets are encrypted at rest using the application's `SECRET_KEY`
- Only authenticated users can create, update, or delete secrets
- Secrets are decrypted only when explicitly requested
- Failed decryption attempts are logged for security monitoring
- Secrets are automatically cleaned up when agents are deleted

### Creating Agents with Secrets

You can create an agent with secrets in a single API call:

```json
POST /api/v1/agents/create
{
  "name": "Email Analyzer Agent",
  "description": "Agent that processes emails from IMAP",
  "model_name": "llama2",
  "config": {
    "imap_server": "imap.gmail.com",
    "imap_port": 993
  },
  "secrets": [
    {
      "key": "imap_password",
      "value": "your-secure-password",
      "description": "IMAP mailbox password"
    },
    {
      "key": "api_key",
      "value": "sk-1234567890abcdef",
      "description": "OpenAI API key for analysis"
    }
  ]
}
```

### Managing Secrets

#### Create a Secret
```json
POST /api/v1/agents/{agent_id}/secrets
{
  "secret_key": "database_password",
  "secret_value": "super-secret-db-password",
  "description": "Database connection password"
}
```

#### List Agent Secrets
```json
GET /api/v1/agents/{agent_id}/secrets
```

Response:
```json
[
  {
    "id": "secret-uuid",
    "agent_id": "agent-uuid",
    "secret_key": "imap_password",
    "description": "IMAP mailbox password",
    "is_active": true,
    "created_at": "2024-01-01T12:00:00Z",
    "updated_at": "2024-01-01T12:00:00Z"
  }
]
```

#### Get Secret Details (with optional decryption)
```json
GET /api/v1/agents/{agent_id}/secrets/{secret_id}?decrypt=true
```

Response:
```json
{
  "id": "secret-uuid",
  "agent_id": "agent-uuid",
  "secret_key": "imap_password",
  "encrypted_value": "gAAAAA...",
  "description": "IMAP mailbox password",
  "is_active": true,
  "created_at": "2024-01-01T12:00:00Z",
  "updated_at": "2024-01-01T12:00:00Z",
  "decrypted_value": "your-actual-password"
}
```

#### Get Secret Value by Key (for agent execution)
```json
GET /api/v1/agents/{agent_id}/secrets/imap_password/value
```

Response:
```json
{
  "secret_key": "imap_password",
  "value": "your-actual-password"
}
```

#### Update a Secret
```json
PUT /api/v1/agents/{agent_id}/secrets/{secret_id}
{
  "secret_value": "new-password",
  "description": "Updated password"
}
```

#### Delete a Secret
```json
DELETE /api/v1/agents/{agent_id}/secrets/{secret_id}
```

### Frontend Integration Examples

#### React Hook for Secrets Management
```javascript
import { useState, useEffect } from 'react';

function useAgentSecrets(agentId) {
  const [secrets, setSecrets] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchSecrets();
  }, [agentId]);

  const fetchSecrets = async () => {
    try {
      const response = await fetch(`/api/v1/agents/${agentId}/secrets`);
      const data = await response.json();
      setSecrets(data);
    } catch (error) {
      console.error('Failed to fetch secrets:', error);
    } finally {
      setLoading(false);
    }
  };

  const createSecret = async (secretData) => {
    try {
      const response = await fetch(`/api/v1/agents/${agentId}/secrets`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(secretData)
      });
      if (response.ok) {
        fetchSecrets(); // Refresh the list
      }
    } catch (error) {
      console.error('Failed to create secret:', error);
    }
  };

  return { secrets, loading, createSecret, refetch: fetchSecrets };
}
```

#### React Component for Secret Management
```javascript
function AgentSecretsManager({ agentId }) {
  const { secrets, loading, createSecret } = useAgentSecrets(agentId);
  const [newSecret, setNewSecret] = useState({
    secret_key: '',
    secret_value: '',
    description: ''
  });

  const handleSubmit = async (e) => {
    e.preventDefault();
    await createSecret(newSecret);
    setNewSecret({ secret_key: '', secret_value: '', description: '' });
  };

  if (loading) return <div>Loading secrets...</div>;

  return (
    <div className="secrets-manager">
      <h3>Agent Secrets</h3>

      {/* Existing Secrets */}
      <div className="secrets-list">
        {secrets.map(secret => (
          <div key={secret.id} className="secret-item">
            <strong>{secret.secret_key}</strong>
            <span>{secret.description}</span>
            <small>Created: {new Date(secret.created_at).toLocaleDateString()}</small>
          </div>
        ))}
      </div>

      {/* Add New Secret */}
      <form onSubmit={handleSubmit} className="secret-form">
        <input
          type="text"
          placeholder="Secret Key (e.g., api_key)"
          value={newSecret.secret_key}
          onChange={(e) => setNewSecret({...newSecret, secret_key: e.target.value})}
          required
        />
        <input
          type="password"
          placeholder="Secret Value"
          value={newSecret.secret_value}
          onChange={(e) => setNewSecret({...newSecret, secret_value: e.target.value})}
          required
        />
        <input
          type="text"
          placeholder="Description (optional)"
          value={newSecret.description}
          onChange={(e) => setNewSecret({...newSecret, description: e.target.value})}
        />
        <button type="submit">Add Secret</button>
      </form>
    </div>
  );
}
```

### Best Practices

1. **Use descriptive keys**: Choose meaningful names like `imap_password`, `api_key`, `database_url`
2. **Add descriptions**: Document what each secret is used for
3. **Regular rotation**: Update secrets periodically for security
4. **Access control**: Only grant secret access to agents that need it
5. **Environment-specific**: Use different secrets for development, staging, and production
6. **Backup securely**: Include encrypted secrets in your backup strategy
7. **Monitor access**: Log when secrets are accessed for audit purposes

### Error Handling

The secrets API provides detailed error messages:

- `404 Not Found`: Secret or agent doesn't exist
- `409 Conflict`: Secret key already exists for this agent
- `500 Internal Server Error`: Encryption/decryption failures are logged

### Migration and Deployment

When deploying the secrets feature:

1. Run database migrations to create the `agent_secrets` table
2. Update your application with the new SECRET_KEY environment variable
3. Test secret creation and retrieval in your development environment
4. Update your frontend components to support secret management
5. Train users on secure secret handling practices

### 📄 Logging Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `GET` | `/api/v1/logs/{task_id}` | Get task logs | ❌ |
| `GET` | `/api/v1/logs/history` | Query historical logs | ❌ |
| `GET` | `/api/v1/logs/stream/{task_id}` | Server-sent events stream | ❌ |

## 📊 **Phase 4: Analytics & Intelligence (COMPLETED)**

### 🎯 **Analytics Dashboard Endpoints**

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/api/v1/analytics/dashboard` | Get comprehensive analytics dashboard | ✅ |
| `GET` | `/api/v1/analytics/dashboard/summary` | Get dashboard summary metrics | ✅ |
| `POST` | `/api/v1/analytics/insights/content` | Get content performance insights | ✅ |
| `GET` | `/api/v1/analytics/insights/content/{content_id}` | Get insights for specific content | ✅ |
| `POST` | `/api/v1/analytics/trends` | Analyze content and usage trends | ✅ |
| `GET` | `/api/v1/analytics/trends/trending` | Get currently trending content | ✅ |
| `POST` | `/api/v1/analytics/performance` | Get detailed performance metrics | ✅ |
| `POST` | `/api/v1/analytics/search` | Get search analytics and insights | ✅ |
| `POST` | `/api/v1/analytics/health` | Get comprehensive system health | ✅ |
| `GET` | `/api/v1/analytics/health/quick` | Get quick system health status | ❌ |
| `GET` | `/api/v1/analytics/export/report` | Export comprehensive analytics report | ✅ |
| `GET` | `/api/v1/analytics/capabilities` | Get analytics capabilities | ❌ |

### 🎭 **Personalization Endpoints**

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/api/v1/personalization/recommend` | Get personalized recommendations | ✅ |
| `POST` | `/api/v1/personalization/track-interaction` | Track user interaction | ✅ |
| `GET` | `/api/v1/personalization/insights/{user_id}` | Get user insights | ✅ |
| `POST` | `/api/v1/personalization/reset-profile` | Reset user profile | ✅ |
| `GET` | `/api/v1/personalization/health` | Get personalization health | ❌ |
| `GET` | `/api/v1/personalization/capabilities` | Get personalization capabilities | ❌ |
| `GET` | `/api/v1/personalization/stats` | Get personalization stats | ❌ |
| `POST` | `/api/v1/personalization/bulk-track` | Bulk track interactions | ✅ |
| `GET` | `/api/v1/personalization/recommend/trending` | Get trending personalized content | ✅ |

### 📈 **Trend Detection Endpoints**

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/api/v1/trends/analyze` | Comprehensive trend analysis | ✅ |
| `POST` | `/api/v1/trends/predictive-insights` | Get predictive insights | ✅ |
| `POST` | `/api/v1/trends/anomalies` | Detect anomalies | ✅ |
| `GET` | `/api/v1/trends` | Get detected trends | ✅ |
| `GET` | `/api/v1/trends/{trend_id}` | Get trend details | ✅ |
| `GET` | `/api/v1/trends/forecast/{metric}` | Get metric forecast | ✅ |
| `GET` | `/api/v1/trends/health` | Get trends service health | ❌ |
| `GET` | `/api/v1/trends/capabilities` | Get trend detection capabilities | ❌ |
| `GET` | `/api/v1/trends/patterns/{pattern_type}` | Get trends by pattern type | ✅ |
| `POST` | `/api/v1/trends/analyze-metric` | Analyze specific metric | ✅ |
| `GET` | `/api/v1/trends/alerts` | Get trend alerts | ✅ |

### 🔍 **Search Analytics Endpoints**

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/api/v1/search-analytics/report` | Generate search analytics report | ✅ |
| `POST` | `/api/v1/search-analytics/track-event` | Track search event | ✅ |
| `POST` | `/api/v1/search-analytics/suggestions` | Get search suggestions | ✅ |
| `POST` | `/api/v1/search-analytics/insights` | Get search insights | ✅ |
| `GET` | `/api/v1/search-analytics/performance` | Get search performance | ✅ |
| `GET` | `/api/v1/search-analytics/queries` | Get query analytics | ✅ |
| `GET` | `/api/v1/search-analytics/user-behavior` | Get user search behavior | ✅ |
| `GET` | `/api/v1/search-analytics/optimization` | Get optimization insights | ✅ |
| `POST` | `/api/v1/search-analytics/export` | Export search data | ✅ |
| `GET` | `/api/v1/search-analytics/health` | Get search analytics health | ❌ |
| `GET` | `/api/v1/search-analytics/capabilities` | Get search analytics capabilities | ❌ |
| `GET` | `/api/v1/search-analytics/trends` | Get search trends | ✅ |
| `GET` | `/api/v1/search-analytics/popular-queries` | Get popular queries | ✅ |
| `GET` | `/api/v1/search-analytics/performance-summary` | Get performance summary | ✅ |
| `POST` | `/api/v1/search-analytics/bulk-track` | Bulk track search events | ✅ |
| `GET` | `/api/v1/search-analytics/real-time` | Get real-time search metrics | ✅ |

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
- **Production**: `wss://ollama.example.invalid/ws/...`

#### ⚠️ Socket.IO vs Raw WebSockets

**IMPORTANT:** Our backend uses **raw WebSockets** (FastAPI), NOT Socket.IO!

❌ **Wrong (Socket.IO):**
```javascript
import io from 'socket.io-client';
const socket = io('wss://ollama.example.invalid'); // Uses /socket.io/ path
```

✅ **Correct (Raw WebSocket):**
```javascript
const ws = new WebSocket('wss://ollama.example.invalid/ws/logs?token=YOUR_JWT_TOKEN');
```

#### 🔐 WebSocket Authentication

**All WebSocket connections require JWT authentication:**

- Include your JWT token as a query parameter: `?token=YOUR_JWT_TOKEN`
- The token must be valid and not expired
- Invalid tokens will result in connection rejection with code 1008

**Example:**
```javascript
const token = 'your-jwt-token-here';
const ws = new WebSocket(`wss://ollama.example.invalid/ws/logs?token=${token}`);
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
  ? `wss://ollama.example.invalid/ws/logs?token=${token}`
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
const taskWsUrl = `wss://ollama.example.invalid/ws/tasks/${taskId}`;
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
  const wsUrl = `wss://ollama.example.invalid/ws/tasks/${taskId}?token=${token}`;
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
wss://ollama.example.invalid/ws/logs?token=YOUR_JWT_TOKEN&task_id=456
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

### Example 2: Chat with Performance Metrics

**Send Chat Message with Performance Monitoring:**
```javascript
// Send a message and monitor performance
const response = await fetch('/api/v1/chat/sessions/your-session-id/messages', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer your-api-key'
  },
  body: JSON.stringify({
    message: "Explain quantum computing in simple terms"
  })
});

const data = await response.json();

// Display the response
console.log('AI Response:', data.response);

// Monitor performance metrics
console.log('Performance Metrics:');
console.log('- Response Time:', data.performance_metrics.response_time_seconds, 'seconds');
console.log('- Tokens/Second:', data.performance_metrics.tokens_per_second);
console.log('- Total Tokens:', data.performance_metrics.total_tokens);
console.log('- Model Used:', data.performance_metrics.model_name);

// Expected response format:
// {
//   "session_id": "uuid-string",
//   "response": "Quantum computing uses quantum bits (qubits)...",
//   "model": "llama2:13b",
//   "performance_metrics": {
//     "response_time_seconds": 3.245,
//     "load_time_seconds": 0.056,
//     "prompt_eval_time_seconds": 1.123,
//     "generation_time_seconds": 2.066,
//     "prompt_tokens": 45,
//     "response_tokens": 156,
//     "total_tokens": 201,
//     "tokens_per_second": 75.46,
//     "context_length_chars": 1024,
//     "model_name": "llama2:13b",
//     "timestamp": "2024-01-01T12:00:00.000Z"
//   }
// }
```

### Example 3: Real-time Logging

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

gpus.forEach((gpu, index) => {
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
  -H "Authorization: Bearer <TOKEN>" \
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
- Format: `Authorization: Bearer <TOKEN>

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


---


---


---

## 🧠 Semantic Understanding Engine

The **Semantic Understanding Engine** provides advanced content analysis capabilities including classification, relationship extraction, importance scoring, and duplicate detection.

### Content Classification

**Automatic categorization and tagging of content:**

```bash
POST /api/v1/semantic/classify
{
  "content": "The quarterly earnings report shows a 15% increase in revenue...",
  "categories": ["business", "finance", "reports"],
  "confidence_threshold": 0.7
}
```

**Response:**
```json
{
  "classification_id": "classify_123456",
  "content_type": "text",
  "categories": [
    {
      "category": "business",
      "subcategory": "financial_reports",
      "confidence": 0.92
    },
    {
      "category": "finance",
      "subcategory": "earnings",
      "confidence": 0.88
    }
  ],
  "tags": ["earnings", "revenue", "growth", "quarterly"],
  "processing_time_ms": 450
}
```

### Relationship Extraction

**Extract entities and relationships from content:**

```bash
POST /api/v1/semantic/extract-relations
{
  "content": "Apple Inc. CEO Tim Cook announced the new iPhone 15 at the Steve Jobs Theater...",
  "entity_types": ["person", "organization", "product", "location"],
  "relation_types": ["employed_by", "announced", "located_at"]
}
```

### Importance Scoring

**Score content importance using ML-based prioritization:**

```bash
POST /api/v1/semantic/score-importance
{
  "content": "Breaking news: Major earthquake in California...",
  "context": {
    "user_interests": ["disaster_relief", "technology"],
    "time_sensitivity": "high",
    "geographic_relevance": "local"
  }
}
```

### Duplicate Detection

**Identify semantically similar content:**

```bash
POST /api/v1/semantic/detect-duplicates
{
  "content": "The meeting is scheduled for 3 PM tomorrow",
  "candidate_pool": ["meeting_scheduled_3pm", "tomorrow_3pm_meeting", "3pm_meeting_tomorrow"],
  "similarity_threshold": 0.85
}
```

---

## 📈 Learning & Adaptation

The Agentic Backend includes sophisticated **Learning & Adaptation** capabilities that enable continuous improvement through user feedback, active learning, and model fine-tuning.

### Feedback Loop Integration

**Collect and process user feedback for model improvement:**

```bash
POST /api/v1/feedback/submit
{
  "content_id": "content_123",
  "feedback_type": "correction",
  "original_prediction": "The cat is sleeping",
  "user_correction": "The cat is playing with yarn",
  "confidence_rating": 0.9,
  "additional_context": "Image shows cat with yarn ball"
}
```

### Active Learning

**Intelligent selection of content for manual review:**

```bash
POST /api/v1/active-learning/select-samples
{
  "candidate_content": [
    {"id": "content_001", "text": "Sample text 1..."},
    {"id": "content_002", "text": "Sample text 2..."}
  ],
  "selection_strategy": "uncertainty_sampling",
  "sample_size": 5,
  "model_name": "llama2:13b"
}
```

### Model Fine-tuning

**Fine-tune models with domain-specific data:**

```bash
POST /api/v1/fine-tuning/start
{
  "base_model": "llama2:13b",
  "target_model": "llama2:13b-custom",
  "training_data": [
    {
      "instruction": "Analyze this financial report",
      "input": "Q3 revenue increased by 12%...",
      "output": "Positive financial performance with 12% revenue growth"
    }
  ],
  "task_type": "text_classification",
  "fine_tuning_config": {
    "learning_rate": 2e-5,
    "epochs": 3,
    "batch_size": 8
  }
}
```

### Performance Optimization

**Automated model selection and routing:**

```bash
POST /api/v1/performance/optimize
{
  "task_type": "text_classification",
  "content_data": {"text": "Sample content for analysis..."},
  "constraints": {
    "max_response_time": 5.0,
    "min_accuracy": 0.9
  }
}
```

---
