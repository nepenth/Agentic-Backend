"""
Knowledge Base Database Models
"""

from sqlalchemy import Column, String, Text, Boolean, DateTime, JSON, Integer, Float, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
from datetime import datetime

from app.db.database import Base


class KnowledgeBaseItem(Base):
    """Database model for knowledge base items"""
    __tablename__ = "knowledge_base_items"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_type = Column(String(50), nullable=False)  # 'twitter_bookmark', 'web_content', 'email', etc.
    source_id = Column(String(255), nullable=True)  # Original content identifier
    content_type = Column(String(50), nullable=False)  # 'text', 'image', 'video', 'mixed'
    title = Column(Text, nullable=True)
    summary = Column(Text, nullable=True)
    full_content = Column(Text, nullable=True)
    item_metadata = Column(JSON, default=dict)  # Additional metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)
    processed_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)

    # Relationships
    categories = relationship("KnowledgeBaseCategory", back_populates="item")
    embeddings = relationship("KnowledgeBaseEmbedding", back_populates="item")
    analysis_results = relationship("KnowledgeBaseAnalysis", back_populates="item")
    media_assets = relationship("KnowledgeBaseMedia", back_populates="item")

    # Indexes for performance
    __table_args__ = (
        Index('idx_kb_items_source_type', 'source_type'),
        Index('idx_kb_items_content_type', 'content_type'),
        Index('idx_kb_items_created_at', 'created_at'),
        Index('idx_kb_items_active', 'is_active'),
    )

    def to_dict(self):
        return {
            "id": str(self.id),
            "source_type": self.source_type,
            "source_id": self.source_id,
            "content_type": self.content_type,
            "title": self.title,
            "summary": self.summary,
            "full_content": self.full_content,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "processed_at": self.processed_at.isoformat() if self.processed_at else None,
            "is_active": self.is_active
        }


class KnowledgeBaseCategory(Base):
    """Database model for knowledge base categories"""
    __tablename__ = "knowledge_base_categories"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    item_id = Column(UUID(as_uuid=True), ForeignKey("knowledge_base_items.id"), nullable=False)
    category = Column(String(100), nullable=False)
    sub_category = Column(String(100), nullable=True)
    confidence_score = Column(Float, default=0.0)
    auto_generated = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    model_used = Column(String(100), nullable=True)  # Which model generated this category

    # Relationships
    item = relationship("KnowledgeBaseItem", back_populates="categories")

    # Indexes
    __table_args__ = (
        Index('idx_kb_categories_item_id', 'item_id'),
        Index('idx_kb_categories_category', 'category'),
        Index('idx_kb_categories_confidence', 'confidence_score'),
    )

    def to_dict(self):
        return {
            "id": str(self.id),
            "item_id": str(self.item_id),
            "category": self.category,
            "sub_category": self.sub_category,
            "confidence_score": self.confidence_score,
            "auto_generated": self.auto_generated,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "model_used": self.model_used
        }


class KnowledgeBaseEmbedding(Base):
    """Database model for knowledge base embeddings"""
    __tablename__ = "knowledge_base_embeddings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    item_id = Column(UUID(as_uuid=True), ForeignKey("knowledge_base_items.id"), nullable=False)
    embedding_model = Column(String(100), nullable=False)  # Model used to generate embedding
    embedding_vector = Column(JSON, nullable=False)  # Vector data (could be pgvector in production)
    content_chunk = Column(Text, nullable=True)  # Original text chunk
    chunk_index = Column(Integer, default=0)  # Index of chunk in document
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    item = relationship("KnowledgeBaseItem", back_populates="embeddings")

    # Indexes
    __table_args__ = (
        Index('idx_kb_embeddings_item_id', 'item_id'),
        Index('idx_kb_embeddings_model', 'embedding_model'),
        Index('idx_kb_embeddings_chunk_index', 'chunk_index'),
    )

    def to_dict(self):
        return {
            "id": str(self.id),
            "item_id": str(self.item_id),
            "embedding_model": self.embedding_model,
            "embedding_vector": self.embedding_vector,
            "content_chunk": self.content_chunk,
            "chunk_index": self.chunk_index,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }


class KnowledgeBaseAnalysis(Base):
    """Database model for AI analysis results"""
    __tablename__ = "knowledge_base_analysis"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    item_id = Column(UUID(as_uuid=True), ForeignKey("knowledge_base_items.id"), nullable=False)
    analysis_type = Column(String(50), nullable=False)  # 'llm_explanation', 'vision_interpretation', etc.
    model_used = Column(String(100), nullable=True)
    model_version = Column(String(50), nullable=True)
    model_capabilities = Column(JSON, default=list)  # Array of model capabilities used
    processing_duration_ms = Column(Integer, nullable=True)
    content = Column(Text, nullable=True)  # Analysis result content
    confidence_score = Column(Float, default=0.0)
    tokens_used = Column(Integer, nullable=True)
    analysis_metadata = Column(JSON, default=dict)  # Additional analysis metadata
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    item = relationship("KnowledgeBaseItem", back_populates="analysis_results")

    # Indexes
    __table_args__ = (
        Index('idx_kb_analysis_item_id', 'item_id'),
        Index('idx_kb_analysis_type', 'analysis_type'),
        Index('idx_kb_analysis_model', 'model_used'),
    )

    def to_dict(self):
        return {
            "id": str(self.id),
            "item_id": str(self.item_id),
            "analysis_type": self.analysis_type,
            "model_used": self.model_used,
            "model_version": self.model_version,
            "model_capabilities": self.model_capabilities,
            "processing_duration_ms": self.processing_duration_ms,
            "content": self.content,
            "confidence_score": self.confidence_score,
            "tokens_used": self.tokens_used,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }


class KnowledgeBaseMedia(Base):
    """Database model for media assets"""
    __tablename__ = "knowledge_base_media"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    item_id = Column(UUID(as_uuid=True), ForeignKey("knowledge_base_items.id"), nullable=False)
    media_type = Column(String(50), nullable=False)  # 'image', 'video', 'audio'
    file_path = Column(Text, nullable=True)  # Local file path
    original_url = Column(Text, nullable=True)  # Original source URL
    cached_path = Column(Text, nullable=True)  # Cached file path
    file_size_bytes = Column(Integer, nullable=True)
    mime_type = Column(String(100), nullable=True)
    media_metadata = Column(JSON, default=dict)  # Media-specific metadata
    vision_analysis = Column(JSON, default=dict)  # Vision AI analysis results
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    item = relationship("KnowledgeBaseItem", back_populates="media_assets")

    # Indexes
    __table_args__ = (
        Index('idx_kb_media_item_id', 'item_id'),
        Index('idx_kb_media_type', 'media_type'),
    )

    def to_dict(self):
        return {
            "id": str(self.id),
            "item_id": str(self.item_id),
            "media_type": self.media_type,
            "file_path": self.file_path,
            "original_url": self.original_url,
            "cached_path": self.cached_path,
            "file_size_bytes": self.file_size_bytes,
            "mime_type": self.mime_type,
            "metadata": self.metadata,
            "vision_analysis": self.vision_analysis,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }


class KnowledgeBaseSearchLog(Base):
    """Database model for search logs"""
    __tablename__ = "knowledge_base_search_log"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), nullable=True)
    query = Column(Text, nullable=False)
    results_count = Column(Integer, default=0)
    search_type = Column(String(50), default="semantic")  # 'semantic', 'keyword', 'hybrid'
    search_duration_ms = Column(Integer, nullable=True)
    filters_used = Column(JSON, default=dict)  # Search filters applied
    created_at = Column(DateTime, default=datetime.utcnow)

    # Indexes
    __table_args__ = (
        Index('idx_kb_search_user_id', 'user_id'),
        Index('idx_kb_search_type', 'search_type'),
        Index('idx_kb_search_created_at', 'created_at'),
    )

    def to_dict(self):
        return {
            "id": str(self.id),
            "user_id": str(self.user_id) if self.user_id else None,
            "query": self.query,
            "results_count": self.results_count,
            "search_type": self.search_type,
            "search_duration_ms": self.search_duration_ms,
            "filters_used": self.filters_used,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }