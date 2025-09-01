"""
Vision AI Service for multi-modal content processing.

This service provides computer vision capabilities including:
- Object detection and recognition
- Image captioning and description
- Visual search and similarity
- Scene understanding
- Quality assessment and enhancement
"""

import asyncio
import base64
import json
from typing import Dict, Any, List, Optional, Tuple, Union
from datetime import datetime
from pathlib import Path
import io

from app.config import settings
from app.services.ollama_client import ollama_client
from app.utils.logging import get_logger
from app.db.models.content import ContentItem, ContentProcessingResult

logger = get_logger("vision_ai_service")


class VisionAIError(Exception):
    """Raised when vision AI processing fails."""
    pass


class VisionAIResult:
    """Result of vision AI processing."""

    def __init__(
        self,
        content_id: str,
        objects_detected: List[Dict[str, Any]] = None,
        caption: str = None,
        description: str = None,
        scene_analysis: Dict[str, Any] = None,
        quality_score: float = None,
        processing_time_ms: float = None,
        model_used: str = None,
        confidence_scores: Dict[str, float] = None,
        metadata: Dict[str, Any] = None
    ):
        self.content_id = content_id
        self.objects_detected = objects_detected or []
        self.caption = caption
        self.description = description
        self.scene_analysis = scene_analysis or {}
        self.quality_score = quality_score
        self.processing_time_ms = processing_time_ms
        self.model_used = model_used
        self.confidence_scores = confidence_scores or {}
        self.metadata = metadata or {}
        self.timestamp = datetime.now()

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "content_id": self.content_id,
            "objects_detected": self.objects_detected,
            "caption": self.caption,
            "description": self.description,
            "scene_analysis": self.scene_analysis,
            "quality_score": self.quality_score,
            "processing_time_ms": self.processing_time_ms,
            "model_used": self.model_used,
            "confidence_scores": self.confidence_scores,
            "metadata": self.metadata,
            "timestamp": self.timestamp.isoformat()
        }


class VisionAIService:
    """Service for vision AI processing using Ollama models."""

    def __init__(self):
        self.supported_models = [
            "llava:7b", "llava:13b", "llava:34b",
            "moondream:1.8b", "bakllava:7b",
            "llava-llama3:8b", "llava-phi3:3.8b"
        ]
        self.default_model = settings.vision_ai_default_model if hasattr(settings, 'vision_ai_default_model') else "llava:13b"
        self.max_image_size_mb = getattr(settings, 'vision_max_image_size_mb', 10)
        self.processing_timeout = getattr(settings, 'vision_processing_timeout_seconds', 120)

    async def process_image(
        self,
        image_data: Union[bytes, str, Path],
        operations: List[str] = None,
        model: str = None,
        **kwargs
    ) -> VisionAIResult:
        """
        Process an image with vision AI capabilities.

        Args:
            image_data: Image data as bytes, base64 string, or file path
            operations: List of operations to perform ['caption', 'objects', 'scene', 'quality']
            model: Specific model to use
            **kwargs: Additional processing options

        Returns:
            VisionAIResult with processing results
        """
        start_time = datetime.now()

        try:
            # Prepare image data
            image_b64 = await self._prepare_image_data(image_data)

            # Determine operations to perform
            operations = operations or ['caption', 'objects', 'scene']

            # Select model
            model = model or self.default_model
            if model not in self.supported_models:
                logger.warning(f"Model {model} not in supported list, using default")
                model = self.default_model

            # Process image with selected operations
            result = VisionAIResult(
                content_id=kwargs.get('content_id', 'unknown'),
                model_used=model
            )

            # Perform operations
            if 'caption' in operations:
                result.caption = await self._generate_caption(image_b64, model, **kwargs)

            if 'objects' in operations:
                result.objects_detected = await self._detect_objects(image_b64, model, **kwargs)

            if 'scene' in operations:
                result.scene_analysis = await self._analyze_scene(image_b64, model, **kwargs)

            if 'quality' in operations:
                result.quality_score = await self._assess_quality(image_b64, model, **kwargs)

            # Calculate processing time
            result.processing_time_ms = (datetime.now() - start_time).total_seconds() * 1000

            logger.info(f"Vision AI processing completed for content {result.content_id} in {result.processing_time_ms:.2f}ms")
            return result

        except Exception as e:
            logger.error(f"Vision AI processing failed: {e}")
            processing_time = (datetime.now() - start_time).total_seconds() * 1000
            raise VisionAIError(f"Vision AI processing failed: {str(e)}")

    async def _prepare_image_data(self, image_data: Union[bytes, str, Path]) -> str:
        """Prepare image data for processing."""
        if isinstance(image_data, Path):
            # Read from file
            with open(image_data, 'rb') as f:
                image_bytes = f.read()
        elif isinstance(image_data, str):
            # Assume base64 string
            if image_data.startswith('data:image'):
                # Extract base64 data from data URL
                image_bytes = base64.b64decode(image_data.split(',')[1])
            else:
                # Assume base64 string
                image_bytes = base64.b64decode(image_data)
        else:
            # Assume bytes
            image_bytes = image_data

        # Validate image size
        image_size_mb = len(image_bytes) / (1024 * 1024)
        if image_size_mb > self.max_image_size_mb:
            raise VisionAIError(f"Image size {image_size_mb:.2f}MB exceeds maximum {self.max_image_size_mb}MB")

        # Convert to base64
        return base64.b64encode(image_bytes).decode('utf-8')

    async def _generate_caption(self, image_b64: str, model: str, **kwargs) -> str:
        """Generate a caption for the image."""
        prompt = kwargs.get('caption_prompt',
            "Describe this image in detail, including the main subjects, actions, setting, and any notable features.")

        try:
            response = await ollama_client.generate(
                model=model,
                prompt=f"[IMAGE_DATA:{image_b64}]\n{prompt}",
                system="You are a helpful AI assistant that provides detailed, accurate descriptions of images.",
                options={
                    "temperature": kwargs.get('temperature', 0.7),
                    "num_predict": kwargs.get('max_tokens', 200)
                }
            )

            caption = response.get('response', '').strip()
            logger.debug(f"Generated caption: {caption[:100]}...")
            return caption

        except Exception as e:
            logger.error(f"Caption generation failed: {e}")
            return "Unable to generate caption due to processing error."

    async def _detect_objects(self, image_b64: str, model: str, **kwargs) -> List[Dict[str, Any]]:
        """Detect objects in the image."""
        prompt = kwargs.get('object_detection_prompt',
            "List all objects, people, animals, and notable items visible in this image. For each item, provide: name, approximate location (top-left, center, bottom-right, etc.), and confidence level (high, medium, low). Format as JSON array.")

        try:
            response = await ollama_client.generate(
                model=model,
                prompt=f"[IMAGE_DATA:{image_b64}]\n{prompt}",
                system="You are an expert at object detection and recognition. Always respond with valid JSON.",
                format="json",
                options={
                    "temperature": kwargs.get('temperature', 0.3),
                    "num_predict": kwargs.get('max_tokens', 300)
                }
            )

            result_text = response.get('response', '').strip()

            # Try to parse as JSON
            try:
                objects = json.loads(result_text)
                if isinstance(objects, list):
                    return objects
                else:
                    # Wrap single object in list
                    return [objects]
            except json.JSONDecodeError:
                # Fallback: extract objects from text
                logger.warning(f"Failed to parse object detection JSON: {result_text}")
                return self._extract_objects_from_text(result_text)

        except Exception as e:
            logger.error(f"Object detection failed: {e}")
            return []

    async def _analyze_scene(self, image_b64: str, model: str, **kwargs) -> Dict[str, Any]:
        """Analyze the scene and context of the image."""
        prompt = kwargs.get('scene_analysis_prompt',
            "Analyze this image and provide: 1) Primary scene type (indoor/outdoor, urban/rural, etc.), 2) Time of day, 3) Weather conditions if visible, 4) Overall mood/atmosphere, 5) Main activity or event depicted. Format as JSON object.")

        try:
            response = await ollama_client.generate(
                model=model,
                prompt=f"[IMAGE_DATA:{image_b64}]\n{prompt}",
                system="You are an expert at scene analysis and contextual understanding. Always respond with valid JSON.",
                format="json",
                options={
                    "temperature": kwargs.get('temperature', 0.3),
                    "num_predict": kwargs.get('max_tokens', 250)
                }
            )

            result_text = response.get('response', '').strip()

            # Try to parse as JSON
            try:
                scene_analysis = json.loads(result_text)
                return scene_analysis
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse scene analysis JSON: {result_text}")
                return {"error": "Failed to parse scene analysis", "raw_response": result_text}

        except Exception as e:
            logger.error(f"Scene analysis failed: {e}")
            return {"error": str(e)}

    async def _assess_quality(self, image_b64: str, model: str, **kwargs) -> float:
        """Assess the quality of the image."""
        prompt = kwargs.get('quality_assessment_prompt',
            "Rate the quality of this image on a scale of 0.0 to 1.0, where 1.0 is perfect quality and 0.0 is very poor. Consider factors like: clarity, lighting, composition, resolution, and absence of artifacts. Provide only the numerical score.")

        try:
            response = await ollama_client.generate(
                model=model,
                prompt=f"[IMAGE_DATA:{image_b64}]\n{prompt}",
                system="You are an expert at image quality assessment. Always respond with only a numerical score between 0.0 and 1.0.",
                options={
                    "temperature": kwargs.get('temperature', 0.1),
                    "num_predict": kwargs.get('max_tokens', 50)
                }
            )

            result_text = response.get('response', '').strip()

            # Extract numerical score
            import re
            score_match = re.search(r'(\d+\.?\d*)', result_text)
            if score_match:
                score = float(score_match.group(1))
                return max(0.0, min(1.0, score))  # Clamp to 0.0-1.0 range
            else:
                logger.warning(f"Could not extract quality score from: {result_text}")
                return 0.5  # Default neutral score

        except Exception as e:
            logger.error(f"Quality assessment failed: {e}")
            return 0.5

    def _extract_objects_from_text(self, text: str) -> List[Dict[str, Any]]:
        """Extract objects from text response when JSON parsing fails."""
        objects = []
        lines = text.split('\n')

        for line in lines:
            line = line.strip()
            if not line or len(line) < 3:
                continue

            # Simple object extraction
            if ':' in line:
                parts = line.split(':', 1)
                obj_name = parts[0].strip()
                obj_desc = parts[1].strip() if len(parts) > 1 else ""

                objects.append({
                    "name": obj_name,
                    "description": obj_desc,
                    "confidence": "medium"
                })

        return objects

    async def batch_process_images(
        self,
        image_batch: List[Dict[str, Any]],
        operations: List[str] = None,
        max_concurrent: int = 3
    ) -> List[VisionAIResult]:
        """
        Process multiple images in batch.

        Args:
            image_batch: List of image data dictionaries
            operations: Operations to perform on each image
            max_concurrent: Maximum concurrent processing tasks

        Returns:
            List of VisionAIResult objects
        """
        semaphore = asyncio.Semaphore(max_concurrent)

        async def process_single_image(image_data: Dict[str, Any]) -> VisionAIResult:
            async with semaphore:
                return await self.process_image(
                    image_data=image_data['data'],
                    operations=operations,
                    content_id=image_data.get('content_id', 'batch_item'),
                    **image_data.get('options', {})
                )

        tasks = [process_single_image(img_data) for img_data in image_batch]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Handle exceptions
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Batch processing failed for item {i}: {result}")
                # Create error result
                error_result = VisionAIResult(
                    content_id=image_batch[i].get('content_id', f'batch_item_{i}'),
                    metadata={"error": str(result)}
                )
                processed_results.append(error_result)
            else:
                processed_results.append(result)

        return processed_results

    def get_supported_operations(self) -> List[str]:
        """Get list of supported vision operations."""
        return ['caption', 'objects', 'scene', 'quality']

    def get_supported_models(self) -> List[str]:
        """Get list of supported vision models."""
        return self.supported_models.copy()

    async def health_check(self) -> Dict[str, Any]:
        """Check the health of the vision AI service."""
        try:
            # Test basic Ollama connectivity
            health = await ollama_client.health_check()

            return {
                "service": "vision_ai",
                "status": "healthy" if health.get("status") == "healthy" else "degraded",
                "ollama_status": health.get("status"),
                "supported_models": self.supported_models,
                "default_model": self.default_model,
                "max_image_size_mb": self.max_image_size_mb,
                "supported_operations": self.get_supported_operations()
            }

        except Exception as e:
            return {
                "service": "vision_ai",
                "status": "unhealthy",
                "error": str(e)
            }


# Global instance
vision_ai_service = VisionAIService()