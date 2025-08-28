from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional


class Settings(BaseSettings):
    # Database
    database_url: str = Field(..., env="DATABASE_URL")
    
    # Redis
    redis_url: str = Field(..., env="REDIS_URL")
    celery_broker_url: str = Field(..., env="CELERY_BROKER_URL")
    celery_result_backend: str = Field(..., env="CELERY_RESULT_BACKEND")
    
    # Ollama
    ollama_base_url: str = Field(..., env="OLLAMA_BASE_URL")
    ollama_default_model: str = Field(default="llama2", env="OLLAMA_DEFAULT_MODEL")
    
    # Logging
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    log_file: Optional[str] = Field(default=None, env="LOG_FILE")
    
    # Security
    secret_key: str = Field(..., env="SECRET_KEY")
    api_key: Optional[str] = Field(default=None, env="API_KEY")
    jwt_algorithm: str = Field(default="HS256", env="JWT_ALGORITHM")
    access_token_expire_minutes: int = Field(default=30, env="ACCESS_TOKEN_EXPIRE_MINUTES")
    
    # Application
    app_name: str = Field(default="Agentic Backend", env="APP_NAME")
    app_version: str = Field(default="0.1.0", env="APP_VERSION")
    debug: bool = Field(default=False, env="DEBUG")
    
    # Celery
    celery_worker_concurrency: int = Field(default=4, env="CELERY_WORKER_CONCURRENCY")
    celery_task_timeout: int = Field(default=300, env="CELERY_TASK_TIMEOUT")
    
    # Redis Streams
    log_stream_name: str = Field(default="agent_logs", env="LOG_STREAM_NAME")
    log_stream_max_len: int = Field(default=10000, env="LOG_STREAM_MAX_LEN")
    
    model_config = {
        "env_file": ".env", 
        "case_sensitive": False,
        "extra": "ignore"  # Allow extra environment variables
    }


settings = Settings()