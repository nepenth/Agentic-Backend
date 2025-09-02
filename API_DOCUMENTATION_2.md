# 📚 Agentic Backend API Documentation

## Overview

The Agentic Backend provides a comprehensive API for building and managing AI-powered agents, processing multimodal content, and orchestrating complex workflows. This documentation serves as the source of truth for all backend API functionality.

## 🔗 Getting Started

### Interactive Documentation
- **Swagger UI**: http://localhost:8000/docs - Interactive API testing
- **ReDoc**: http://localhost:8000/redoc - Clean documentation interface

### Authentication
All API endpoints require authentication using JWT tokens obtained via login.

#### Login Flow
```bash
# JSON Login (Recommended)
POST /api/v1/auth/login-json
Content-Type: application/json

{
  "username": "your-username",
  "password": "your-password"
}

# Response
{
  "access_token": "<TOKEN>",
  "token_type": "bearer"
}

# Form Login (OAuth2 Compatible)
POST /api/v1/auth/login
Content-Type: application/x-www-form-urlencoded

username=your-username&password=your-password
```

#### Using JWT Tokens
Include the token in Authorization header:
```bash
Authorization: Bearer <TOKEN>
```

#### User Management
```bash
# Get current user info
GET /api/v1/auth/me
Authorization: Bearer <TOKEN>

# Response
{
  "id": 1,
  "username": "your-username",
  "email": "user@example.com",
  "is_active": true,
  "is_superuser": false,
  "created_at": "2024-01-01T12:00:00Z",
  "updated_at": "2024-01-01T12:00:00Z"
}

# Change password
POST /api/v1/auth/change-password
Authorization: Bearer <TOKEN>
Content-Type: application/json

{
  "current_password": "old-password",
  "new_password": "new-secure-password"
}

# Admin change password (superuser only)
POST /api/v1/auth/admin/change-password
Authorization: Bearer <TOKEN>
Content-Type: application/json

{
  "username": "target-user",
  "new_password": "new-password"
}
```

#### Frontend Integration Examples

**React Login Hook:**
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

**Axios Interceptor for Automatic Token Handling:**
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

## 🏗️ Core API Features

### Agent Management
| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/api/v1/agents/create` | Create new agent (static or dynamic) with optional secrets | ✅ |
| `GET` | `/api/v1/agents` | List all agents with filtering | ❌ |
| `GET` | `/api/v1/agents/{id}` | Get specific agent | ❌ |
| `PUT` | `/api/v1/agents/{id}` | Update agent | ✅ |
| `DELETE` | `/api/v1/agents/{id}` | Delete agent | ✅ |

### Task Execution
| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/api/v1/tasks/run` | Execute task (supports both static and dynamic agents) | ✅ |
| `GET` | `/api/v1/tasks` | List tasks with filtering | ❌ |
| `GET` | `/api/v1/tasks/{id}/status` | Get task status | ❌ |
| `DELETE` | `/api/v1/tasks/{id}` | Cancel task | ✅ |

### Chat System
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

#### Chat Performance Metrics
All chat responses include comprehensive performance metrics:

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

### System Monitoring
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

### Ollama Model Management
The system provides comprehensive Ollama model management capabilities:

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `GET` | `/api/v1/ollama/models` | List all available Ollama models with metadata | ❌ |
| `GET` | `/api/v1/ollama/models/names` | List available model names only | ❌ |
| `GET` | `/api/v1/ollama/health` | Check Ollama server health | ❌ |
| `POST` | `/api/v1/ollama/models/pull/{model_name}` | Pull/download a new model | ❌ |

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

**Response:**
```json
{
  "status": "pulling",
  "model": "llama2:13b",
  "progress": {
    "total": 3791730599,
    "completed": 1895865299,
    "percentage": 50.0
  }
}
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
  "default_model": "llama2",
  "server_info": {
    "version": "0.1.0",
    "gpu_layers": 35,
    "max_context": 4096
  }
}
```

**Model Usage in Processing Results:**
All processing results now include model usage information:

```json
{
  "task_id": "task_123",
  "status": "completed",
  "result": {
    "analysis": "Image shows a cat sitting on a windowsill...",
    "confidence": 0.94
  },
  "model_usage": {
    "primary_model": "llava:13b",
    "model_version": "v1.5.1",
    "processing_time_ms": 2450,
    "tokens_used": 156,
    "performance_score": 0.92
  },
  "processing_metadata": {
    "http_requests_made": 1,
    "external_api_calls": 0,
    "cache_hits": 2
  }
}
```

## 🚀 Advanced Features

### Agentic HTTP Client Framework
The Agentic Backend includes a sophisticated HTTP client framework designed for resilient external API interactions. This framework provides enterprise-grade reliability with circuit breakers, rate limiting, and comprehensive observability.

**Key Features:**
- **Circuit Breaker Pattern**: Automatic failure detection and recovery
- **Intelligent Retry Logic**: Exponential backoff with jitter
- **Rate Limiting**: Built-in rate limit detection and compliance
- **Request/Response Observability**: Comprehensive logging and metrics
- **Authentication Support**: API keys, OAuth, JWT, and custom auth
- **Streaming Support**: Large file downloads with progress tracking

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/api/v1/http/request` | Make HTTP request with agentic features | ✅ |
| `GET` | `/api/v1/http/metrics` | Get HTTP client performance metrics | ✅ |
| `GET` | `/api/v1/http/requests/{request_id}` | Get specific request details | ✅ |
| `GET` | `/api/v1/http/health` | HTTP client health status | ❌ |
| `POST` | `/api/v1/http/stream-download` | Stream large file downloads | ✅ |

**Making Agentic HTTP Requests:**
```bash
POST /api/v1/http/request
{
  "method": "GET",
  "url": "https://api.twitter.com/2/bookmarks",
  "headers": {
    "Authorization": "Bearer YOUR_TOKEN",
    "Content-Type": "application/json"
  },
  "timeout": 30,
  "retry_config": {
    "max_attempts": 3,
    "backoff_factor": 2.0
  },
  "rate_limit": {
    "requests_per_minute": 60
  }
}
```

**Response:**
```json
{
  "request_id": "req_1234567890",
  "status_code": 200,
  "headers": {
    "content-type": "application/json",
    "x-rate-limit-remaining": "59"
  },
  "content": "{\"data\": [...]}",
  "response_time_ms": 1250,
  "retry_count": 0,
  "rate_limit_info": {
    "remaining": 59,
    "reset_time": "2024-01-01T12:01:00Z"
  }
}
```

### Dynamic Model Selection System
The Agentic Backend provides intelligent AI model selection based on task requirements, performance metrics, and availability. This system ensures optimal model usage across different processing tasks.

**Key Features:**
- **Automatic Model Discovery**: Scans available Ollama models and their capabilities
- **Task-Aware Selection**: Chooses optimal models based on content type and task
- **Performance Tracking**: Monitors model performance for continuous optimization
- **Fallback Mechanisms**: Graceful degradation when preferred models unavailable
- **Model Versioning**: Tracks model versions and performance over time

**Supported Model Types:**
- **Text Models**: `llama2`, `codellama`, `mistral` - For text analysis, summarization, generation
- **Vision Models**: `llava`, `moondream`, `bakllava` - For image analysis and captioning
- **Audio Models**: `whisper` - For speech recognition and audio processing
- **Embedding Models**: `nomic-embed-text`, `all-MiniLM` - For semantic search and similarity

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `GET` | `/api/v1/models/available` | List all available models with capabilities | ✅ |
| `POST` | `/api/v1/models/select` | Select optimal model for task | ✅ |
| `GET` | `/api/v1/models/performance` | Get model performance metrics | ✅ |
| `GET` | `/api/v1/models/{model_name}/stats` | Get specific model statistics | ✅ |
| `POST` | `/api/v1/models/refresh` | Refresh model registry | ✅ |

**Automatic Model Selection:**
```bash
POST /api/v1/models/select
{
  "task_type": "image_captioning",
  "content_type": "image",
  "priority": "quality",
  "max_tokens": 500,
  "requirements": {
    "vision_capable": true,
    "min_performance_score": 0.8
  }
}
```

**Response:**
```json
{
  "selected_model": "llava:13b",
  "model_info": {
    "name": "llava:13b",
    "capabilities": ["vision", "text"],
    "performance_score": 0.92,
    "average_response_time_ms": 2450,
    "supported_formats": ["jpeg", "png", "webp"]
  },
  "fallback_models": ["moondream:1.8b", "bakllava:7b"],
  "selection_reason": "Best vision performance for image captioning"
}
```

### Multi-Modal Content Framework
Multi-modal content processing with automatic type detection.

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/api/v1/content/process` | Process content with automatic type detection | ✅ |
| `GET` | `/api/v1/content/{id}` | Get processed content data | ✅ |
| `POST` | `/api/v1/content/batch` | Batch process multiple content items | ✅ |
| `GET` | `/api/v1/content/cache/stats` | Content cache statistics | ✅ |

### Vision AI Integration
Advanced image analysis and processing using state-of-the-art AI models.

**Key Features:**
- **Object Detection**: Identify and locate objects within images
- **Image Captioning**: Generate descriptive captions for images
- **Visual Search**: Find similar images using visual features
- **Scene Understanding**: Analyze and describe visual scenes
- **OCR Integration**: Extract text from images
- **Quality Assessment**: Evaluate image quality and composition

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/api/v1/vision/analyze` | Analyze image with multiple vision tasks | ✅ |
| `POST` | `/api/v1/vision/detect-objects` | Detect objects in image | ✅ |
| `POST` | `/api/v1/vision/caption` | Generate image caption | ✅ |
| `POST` | `/api/v1/vision/search` | Find similar images | ✅ |
| `POST` | `/api/v1/vision/ocr` | Extract text from image | ✅ |
| `GET` | `/api/v1/vision/models` | List available vision models | ✅ |

**Image Analysis Example:**
```bash
POST /api/v1/vision/analyze
{
  "image_url": "https://example.com/image.jpg",
  "tasks": ["objects", "caption", "scene"],
  "model": "llava:13b",
  "options": {
    "max_objects": 10,
    "confidence_threshold": 0.5
  }
}
```

**Response:**
```json
{
  "analysis_id": "vision_123456",
  "image_url": "https://example.com/image.jpg",
  "results": {
    "objects": [
      {
        "label": "cat",
        "confidence": 0.94,
        "bbox": [120, 80, 280, 220]
      },
      {
        "label": "chair",
        "confidence": 0.87,
        "bbox": [50, 150, 150, 280]
      }
    ],
    "caption": "A cat sitting on a chair in a living room",
    "scene": "indoor domestic setting",
    "quality_score": 0.89
  },
  "processing_time_ms": 2450,
  "model_used": "llava:13b"
}
```

### Audio AI Integration
Comprehensive audio processing with speech recognition and analysis.

**Key Features:**
- **Speech Recognition**: Convert speech to text with high accuracy
- **Speaker Identification**: Identify speakers in audio recordings
- **Emotion Detection**: Analyze emotional content in speech
- **Audio Classification**: Categorize audio by type and content
- **Music Analysis**: Extract musical features and metadata
- **Noise Reduction**: Improve audio quality for better processing

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/api/v1/audio/transcribe` | Convert speech to text | ✅ |
| `POST` | `/api/v1/audio/identify-speaker` | Identify speakers in audio | ✅ |
| `POST` | `/api/v1/audio/analyze-emotion` | Detect emotions in speech | ✅ |
| `POST` | `/api/v1/audio/classify` | Classify audio content | ✅ |
| `POST` | `/api/v1/audio/analyze-music` | Extract musical features | ✅ |
| `GET` | `/api/v1/audio/models` | List available audio models | ✅ |

**Speech Transcription Example:**
```bash
POST /api/v1/audio/transcribe
{
  "audio_url": "https://example.com/audio.mp3",
  "language": "en",
  "model": "whisper-large-v3",
  "options": {
    "timestamps": true,
    "max_speakers": 2
  }
}
```

**Response:**
```json
{
  "transcription_id": "audio_123456",
  "audio_url": "https://example.com/audio.mp3",
  "transcription": {
    "text": "Hello, this is a sample audio recording for testing purposes.",
    "segments": [
      {
        "start": 0.0,
        "end": 2.5,
        "text": "Hello, this is a sample audio recording",
        "confidence": 0.98
      },
      {
        "start": 2.5,
        "end": 4.2,
        "text": "for testing purposes.",
        "confidence": 0.95
      }
    ],
    "language": "en",
    "duration": 4.2
  },
  "speakers": [
    {
      "speaker_id": "speaker_1",
      "segments": [[0.0, 4.2]],
      "confidence": 0.92
    }
  ],
  "processing_time_ms": 3200,
  "model_used": "whisper-large-v3"
}
```

### Cross-Modal Processing
Multi-modal search and analysis combining text, image, and audio.

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/api/v1/crossmodal/align` | Align text with images | ✅ |
| `POST` | `/api/v1/crossmodal/correlate` | Correlate audio with visual content | ✅ |
| `POST` | `/api/v1/crossmodal/search` | Multi-modal search | ✅ |
| `POST` | `/api/v1/crossmodal/fuse` | Fuse information from multiple modalities | ✅ |
| `GET` | `/api/v1/crossmodal/models` | List cross-modal models | ✅ |

### Quality Enhancement
AI-powered content improvement and automatic correction capabilities.

**Key Features:**
- **Content Enhancement**: AI-powered content improvement suggestions
- **Automatic Correction**: Intelligent error detection and correction
- **Quality Assessment**: Comprehensive content quality metrics
- **Style Optimization**: Content optimization for clarity and engagement

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/api/v1/quality/enhance` | AI-powered content improvement | ✅ |
| `POST` | `/api/v1/quality/correct` | Automatic content correction | ✅ |
| `GET` | `/api/v1/quality/metrics` | Quality assessment metrics | ✅ |

**Content Enhancement Example:**
```bash
POST /api/v1/quality/enhance
{
  "content": "The report shows good sales numbers for Q1",
  "enhancement_type": "professional",
  "target_audience": "executives"
}
```

**Response:**
```json
{
  "original_content": "The report shows good sales numbers for Q1",
  "enhanced_content": "The quarterly report demonstrates strong sales performance for Q1, exceeding our projected targets by 15%",
  "improvements": [
    "Added specific metrics",
    "Enhanced professional tone",
    "Improved clarity and impact"
  ],
  "quality_score": 0.87,
  "processing_time_ms": 1200
}
```

### Semantic Processing
Advanced content understanding and analysis capabilities.

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/api/v1/semantic/embed` | Generate embeddings for text | ✅ |
| `POST` | `/api/v1/semantic/search` | Perform semantic search | ✅ |
| `POST` | `/api/v1/semantic/cluster` | Cluster embeddings | ✅ |
| `GET` | `/api/v1/semantic/quality/{id}` | Get content quality score | ✅ |
| `POST` | `/api/v1/semantic/chunk` | Intelligent text chunking | ✅ |
| `POST` | `/api/v1/semantic/classify` | Content classification and tagging | ✅ |
| `POST` | `/api/v1/semantic/extract-relations` | Entity and relationship extraction | ✅ |
| `POST` | `/api/v1/semantic/score-importance` | ML-based content prioritization | ✅ |
| `POST` | `/api/v1/semantic/detect-duplicates` | Semantic duplicate detection | ✅ |
| `POST` | `/api/v1/semantic/build-knowledge-graph` | Knowledge graph construction | ✅ |

### Analytics & Intelligence
Comprehensive analytics and personalization platform.

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
| `POST` | `/api/v1/personalization/recommend` | Get personalized recommendations | ✅ |
| `POST` | `/api/v1/personalization/track-interaction` | Track user interaction | ✅ |
| `GET` | `/api/v1/personalization/insights/{user_id}` | Get user insights | ✅ |
| `POST` | `/api/v1/personalization/reset-profile` | Reset user profile | ✅ |
| `GET` | `/api/v1/personalization/health` | Get personalization health | ❌ |
| `GET` | `/api/v1/personalization/capabilities` | Get personalization capabilities | ❌ |
| `GET` | `/api/v1/personalization/stats` | Get personalization stats | ❌ |
| `POST` | `/api/v1/personalization/bulk-track` | Bulk track interactions | ✅ |
| `GET` | `/api/v1/personalization/recommend/trending` | Get trending personalized content | ✅ |
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

### Security Features
Comprehensive security framework for agent execution.

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

### Workflow Automation
Intelligent workflow orchestration and automation with DAG-based execution.

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

### Integration Layer
API gateway, webhooks, and queue management for enterprise integration.

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

### Universal Content Connectors
Unified interface for diverse data sources and content processing.

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/api/v1/content/discover` | Discover content from multiple sources | ✅ |
| `POST` | `/api/v1/content/connectors/web` | Web content discovery (RSS, scraping) | ✅ |
| `POST` | `/api/v1/content/connectors/social` | Social media content (Twitter, Reddit) | ✅ |
| `POST` | `/api/v1/content/connectors/communication` | Communication channels (Email, Slack) | ✅ |
| `POST` | `/api/v1/content/connectors/filesystem` | File system content (Local, Cloud) | ✅ |

## 🔐 Security & Secrets Management

### Logging Endpoints
Comprehensive logging system for monitoring agent activities and system events.

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `GET` | `/api/v1/logs/{task_id}` | Get task logs | ❌ |
| `GET` | `/api/v1/logs/history` | Query historical logs | ❌ |
| `GET` | `/api/v1/logs/stream/{task_id}` | Server-sent events stream | ❌ |

**Log Query Examples:**
```bash
# Get logs for specific task
GET /api/v1/logs/task_123456

# Query historical logs with filters
GET /api/v1/logs/history?agent_id=agent-uuid&level=error&limit=50

# Stream logs in real-time
GET /api/v1/logs/stream/task_123456
```

**Log Response Format:**
```json
{
  "logs": [
    {
      "timestamp": "2024-01-01T12:00:00Z",
      "level": "info",
      "message": "Task processing started",
      "agent_id": "agent-uuid",
      "task_id": "task-uuid",
      "source": "pipeline",
      "metadata": {
        "step": "data_validation",
        "duration_ms": 150
      }
    }
  ],
  "total_count": 1,
  "limit": 50,
  "offset": 0
}
```

### Secrets Management
Secure storage of sensitive data with encryption.

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| `POST` | `/api/v1/agents/{agent_id}/secrets` | Create a new secret for an agent | ✅ |
| `GET` | `/api/v1/agents/{agent_id}/secrets` | List all secrets for an agent | ❌ |
| `GET` | `/api/v1/agents/{agent_id}/secrets/{secret_id}` | Get a specific secret | ✅ |
| `PUT` | `/api/v1/agents/{agent_id}/secrets/{secret_id}` | Update a secret | ✅ |
| `DELETE` | `/api/v1/agents/{agent_id}/secrets/{secret_id}` | Delete a secret (soft delete) | ✅ |
| `GET` | `/api/v1/agents/{agent_id}/secrets/{secret_key}/value` | Get decrypted secret value by key | ✅ |

**Creating Agents with Secrets:**
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

### Security Limits and Constraints
The security system enforces specific limits optimized for your home-lab hardware configuration (2x Xeon E5-2683 v4, 2x Tesla P40, 158GB RAM).

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

## 🌐 WebSocket Real-time Communication

### Connection Details
- **URL**: `ws://localhost:8000/ws/...` or `wss://domain/ws/...`
- **Authentication**: Include JWT token as query parameter `?token=YOUR_JWT_TOKEN`
- **Heartbeat**: Send `{"type": "ping"}` every 30 seconds
- **Rate Limit**: 100 messages per minute per connection

### Available Endpoints
- `/ws/logs` - Real-time log streaming
- `/ws/tasks/{task_id}` - Task monitoring
- `/ws/chat/{session_id}` - Chat session updates

### Message Format
```json
{
  "type": "log_entry",
  "data": {
    "timestamp": "2024-01-01T12:00:00Z",
    "level": "info",
    "message": "Task completed",
    "agent_id": "agent-uuid",
    "task_id": "task-uuid",
    "source": "pipeline"
  }
}
```

### WebSocket Specifications
| Specification | Value | Details |
|---------------|-------|---------|
| **Heartbeat** | ✅ 30-second ping/pong | Frontend must send ping every 30s, backend responds with pong + timestamp |
| **Connection Limits** | ✅ 50 per user, 200 global | Automatic rejection when exceeded, auto-cleanup on disconnect |
| **Rate Limiting** | ✅ 100 messages/minute | Per-connection limit, includes all message types |
| **Authentication** | ✅ JWT required | Query parameter `?token=YOUR_JWT_TOKEN` |
| **Protocol** | ✅ Raw WebSocket | NOT Socket.IO - use standard WebSocket API |
| **Connection Timeout** | ✅ 90 seconds | Auto-disconnect if no ping received |

## 📖 Documentation & Examples

### Agent Creation Guide
- **URL**: `/api/v1/docs/agent-creation`
- Step-by-step agent creation with AI assistance
- Frontend integration examples
- Best practices and troubleshooting

### AI-Assisted Agent Creation Wizard
The Agentic Backend includes a sophisticated AI-assisted agent creation wizard that guides users through creating agents using conversational AI.

**Key Features:**
- **Conversational AI Guidance**: Natural language interaction for agent creation
- **Intelligent Requirements Analysis**: AI analyzes user needs and suggests optimal configurations
- **Automatic Schema Generation**: Creates complete agent schemas from conversation
- **Validation & Best Practices**: Ensures created agents follow security and performance best practices
- **Integration with Secrets**: Automatically suggests and configures secure credential management

**Wizard Workflow:**
1. **Requirements Gathering**: AI asks clarifying questions about the desired agent
2. **Analysis & Recommendations**: LLM analyzes requirements and suggests optimal configuration
3. **Schema Generation**: Creates complete agent schema with data models and processing pipeline
4. **Validation**: Validates the generated schema against security and performance requirements
5. **Finalization**: Registers the agent type and creates deployment-ready configuration

### Example Workflows

#### Create and Run Agent
```javascript
// 1. Create agent
const agentResponse = await fetch('/api/v1/agents/create', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`
  },
  body: JSON.stringify({
    name: "Text Summarizer",
    model_name: "llama2",
    config: { temperature: 0.3 }
  })
});

// 2. Run task
const taskResponse = await fetch('/api/v1/tasks/run', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`
  },
  body: JSON.stringify({
    agent_id: agentId,
    input: {
      type: "summarize",
      text: "Long text content...",
      length: "short"
    }
  })
});
```

#### Chat with Performance Metrics
```javascript
const chatResponse = await fetch('/api/v1/chat/sessions/session-id/messages', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`
  },
  body: JSON.stringify({
    message: "Explain quantum computing"
  })
});

const data = await chatResponse.json();
console.log('Response:', data.response);
console.log('Performance:', data.performance_metrics);
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

### Task Types and Examples

**1. Text Generation**
```json
{
  "type": "generate",
  "prompt": "Write a short story about a robot learning to paint",
  "system": "You are a creative storyteller"
}
```

**2. Chat Completion**
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

**3. Text Summarization**
```json
{
  "type": "summarize",
  "text": "Long text content here...",
  "length": "short"  // options: short, medium, long
}
```

**4. Text Analysis**
```json
{
  "type": "analyze",
  "text": "Text to analyze...",
  "analysis_type": "sentiment"  // options: sentiment, topics, entities, general
}
```

#### Real-time WebSocket Connection
```javascript
const ws = new WebSocket(`ws://localhost:8000/ws/logs?token=${token}`);

// Heartbeat
setInterval(() => {
  if (ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type: "ping" }));
  }
}, 30000);

// Handle messages
ws.onmessage = (event) => {
  const message = JSON.parse(event.data);
  console.log('Received:', message);
};
```

#### Workflow Automation Example
```javascript
// Define a data processing workflow
const workflowDefinition = {
  name: "Data Processing Pipeline",
  description: "Automated data cleaning and analysis",
  steps: {
    "validate_data": {
      id: "validate_data",
      name: "Validate Input Data",
      type: "data_validation",
      config: { required_fields: ["name", "email", "data"] }
    },
    "clean_data": {
      id: "clean_data",
      name: "Clean Data",
      type: "data_cleaning",
      config: { remove_duplicates: true, fill_missing: true },
      dependencies: ["validate_data"]
    },
    "analyze_data": {
      id: "analyze_data",
      name: "Analyze Data",
      type: "ai_processing",
      config: { model: "llama2", analysis_type: "sentiment" },
      dependencies: ["clean_data"]
    }
  },
  priority: "normal",
  max_execution_time: 1800
};

// Create the workflow
const response = await fetch('/api/v1/workflows/definitions', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(workflowDefinition)
});
```

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

// Handle messages
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

### Example 4: Security Testing and Validation

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

## 🔧 Troubleshooting

### Common Issues

#### Authentication Errors
| Error Code | Description | Solution |
|------------|-------------|----------|
| `401 Unauthorized` | Invalid credentials | Check username/password |
| `400 Bad Request` | Missing required fields | Ensure username and password are provided |
| `403 Forbidden` | Insufficient permissions | Check user role for admin operations |
| `422 Validation Error` | Invalid input format | Check request format and required fields |

#### 401 Unauthorized
- Verify JWT token is valid and not expired
- Check token format: `Bearer your-token-here`

#### 422 Validation Error
- Ensure request body matches expected schema
- Check required fields are provided

#### 500 Internal Server Error
- Check server logs: `docker-compose logs api`
- Verify Ollama connectivity
- Ensure database is accessible

#### WebSocket Connection Failed
- Verify WebSocket URL format
- Check for proxy/firewall blocking
- Ensure server is running

#### Security-Related Errors
| Error | Cause | Solution |
|-------|-------|----------|
| `429 Resource Limit Exceeded` | Agent exceeded memory, CPU, or execution time limits | Check `/api/v1/security/agents/{agent_id}/report` for resource usage |
| `403 Tool Execution Denied` | Tool execution blocked by security policy | Verify tool configuration and permissions |
| `400 Malicious Content Detected` | Input data contains suspicious patterns | Sanitize input data before sending to agent |
| `Security Service Unavailable` | Security middleware not responding | Check security health: `GET /api/v1/security/health` |

#### 5. Security-Related Errors

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

#### 6. Rate Limiting Issues

**Rate Limit Exceeded:**
- **Cause**: Too many requests in short time period
- **Solution**: Implement exponential backoff retry logic
- **Limits**: Check current limits via `GET /api/v1/security/limits`

**Tool-Specific Rate Limits:**
- **Cause**: Individual tool rate limits exceeded
- **Solution**: Space out tool executions or reduce frequency
- **Monitoring**: Check tool execution metrics in agent reports

### Health Checks
```bash
# System health
GET /api/v1/health

# Security health
GET /api/v1/security/health

# Ollama health
GET /api/v1/ollama/health
```

### Testing Tools

#### 1. Built-in Swagger UI ⭐ (Recommended)
- **URL**: http://localhost:8000/docs
- ✅ Interactive testing
- ✅ Authentication support
- ✅ Request/response validation

#### 2. cURL Examples
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

#### 3. Postman Collection
Import the OpenAPI spec from http://localhost:8000/openapi.json

#### 4. HTTPie
```bash
# Install: pip install httpie
http GET localhost:8000/api/v1/health
http POST localhost:8000/api/v1/agents/create Authorization:"Bearer api-key" name="Test"
```

## 📊 System Requirements

### Hardware Configuration
- **CPU**: 32 cores (64 threads)
- **Memory**: 158GB RAM
- **GPU**: 2x Tesla P40
- **Storage**: SSD storage for optimal performance

### Software Dependencies
- **Python**: 3.9+
- **PostgreSQL**: 13+
- **Redis**: 6+
- **Ollama**: Latest version
- **Docker**: 20+

## 🚀 Quick Start

1. **Start the system**:
   ```bash
   docker-compose up -d
   ```

2. **Access documentation**:
   - Swagger UI: http://localhost:8000/docs
   - ReDoc: http://localhost:8000/redoc

3. **Authenticate**:
   ```bash
   curl -X POST http://localhost:8000/api/v1/auth/login-json \
     -H "Content-Type: application/json" \
     -d '{"username": "admin", "password": "password"}'
   ```

4. **Create your first agent**:
   ```bash
   curl -X POST http://localhost:8000/api/v1/agents/create \
     -H "Authorization: Bearer <TOKEN>" \
     -H "Content-Type: application/json" \
     -d '{"name": "Test Agent", "model_name": "llama2"}'
   ```

This enhanced documentation now captures the robust data, examples, explanations, and comprehensive feature set from the original API_DOCUMENTATION.md while maintaining the clean, organized structure. It serves as a complete reference for all backend API functionality with practical implementation examples and detailed troubleshooting guidance.