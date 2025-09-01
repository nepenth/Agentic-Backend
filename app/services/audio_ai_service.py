"""
Audio AI Service for speech recognition and audio processing.

This service provides audio processing capabilities including:
- Speech-to-text transcription
- Speaker identification and diarization
- Audio classification and tagging
- Emotion detection from speech
- Audio quality assessment
- Language detection
"""

import asyncio
import base64
import json
from typing import Dict, Any, List, Optional, Tuple, Union
from datetime import datetime
from pathlib import Path
import io
import re

from app.config import settings
from app.services.ollama_client import ollama_client
from app.utils.logging import get_logger

logger = get_logger("audio_ai_service")


class AudioAIError(Exception):
    """Raised when audio AI processing fails."""
    pass


class AudioAIResult:
    """Result of audio AI processing."""

    def __init__(
        self,
        content_id: str,
        transcription: str = None,
        speakers: List[Dict[str, Any]] = None,
        language: str = None,
        emotions: List[Dict[str, float]] = None,
        classification: Dict[str, Any] = None,
        quality_score: float = None,
        processing_time_ms: float = None,
        model_used: str = None,
        confidence_scores: Dict[str, float] = None,
        metadata: Dict[str, Any] = None
    ):
        self.content_id = content_id
        self.transcription = transcription
        self.speakers = speakers or []
        self.language = language
        self.emotions = emotions or []
        self.classification = classification or {}
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
            "transcription": self.transcription,
            "speakers": self.speakers,
            "language": self.language,
            "emotions": self.emotions,
            "classification": self.classification,
            "quality_score": self.quality_score,
            "processing_time_ms": self.processing_time_ms,
            "model_used": self.model_used,
            "confidence_scores": self.confidence_scores,
            "metadata": self.metadata,
            "timestamp": self.timestamp.isoformat()
        }


class AudioAIService:
    """Service for audio AI processing using Ollama models."""

    def __init__(self):
        self.supported_models = [
            "whisper-large-v3", "whisper-base",
            "whisper-medium", "whisper-small",
            "whisper-tiny"
        ]
        self.default_model = getattr(settings, 'audio_ai_default_model', 'whisper-base')
        self.max_audio_size_mb = getattr(settings, 'audio_max_file_size_mb', 25)
        self.processing_timeout = getattr(settings, 'audio_processing_timeout_seconds', 300)

        # Supported audio formats
        self.supported_formats = ['mp3', 'wav', 'flac', 'm4a', 'ogg', 'webm']

    async def process_audio(
        self,
        audio_data: Union[bytes, str, Path],
        operations: List[str] = None,
        model: str = None,
        language: str = None,
        **kwargs
    ) -> AudioAIResult:
        """
        Process audio with AI capabilities.

        Args:
            audio_data: Audio data as bytes, base64 string, or file path
            operations: List of operations ['transcription', 'speakers', 'emotion', 'classification', 'quality']
            model: Specific model to use
            language: Language code for transcription
            **kwargs: Additional processing options

        Returns:
            AudioAIResult with processing results
        """
        start_time = datetime.now()

        try:
            # Prepare audio data
            audio_b64 = await self._prepare_audio_data(audio_data)

            # Determine operations to perform
            operations = operations or ['transcription']

            # Select model
            model = model or self.default_model
            if model not in self.supported_models:
                logger.warning(f"Model {model} not in supported list, using default")
                model = self.default_model

            # Process audio with selected operations
            result = AudioAIResult(
                content_id=kwargs.get('content_id', 'unknown'),
                model_used=model
            )

            # Perform operations
            if 'transcription' in operations:
                transcription_result = await self._transcribe_audio(audio_b64, model, language, **kwargs)
                result.transcription = transcription_result.get('text')
                result.language = transcription_result.get('language', language)

            if 'speakers' in operations and result.transcription:
                result.speakers = await self._identify_speakers(result.transcription, model, **kwargs)

            if 'emotion' in operations and result.transcription:
                result.emotions = await self._detect_emotions(result.transcription, model, **kwargs)

            if 'classification' in operations:
                result.classification = await self._classify_audio(audio_b64, model, **kwargs)

            if 'quality' in operations:
                result.quality_score = await self._assess_audio_quality(audio_b64, model, **kwargs)

            # Calculate processing time
            result.processing_time_ms = (datetime.now() - start_time).total_seconds() * 1000

            logger.info(f"Audio AI processing completed for content {result.content_id} in {result.processing_time_ms:.2f}ms")
            return result

        except Exception as e:
            logger.error(f"Audio AI processing failed: {e}")
            processing_time = (datetime.now() - start_time).total_seconds() * 1000
            raise AudioAIError(f"Audio AI processing failed: {str(e)}")

    async def _prepare_audio_data(self, audio_data: Union[bytes, str, Path]) -> str:
        """Prepare audio data for processing."""
        if isinstance(audio_data, Path):
            # Read from file
            with open(audio_data, 'rb') as f:
                audio_bytes = f.read()
        elif isinstance(audio_data, str):
            # Assume base64 string
            if audio_data.startswith('data:audio'):
                # Extract base64 data from data URL
                audio_bytes = base64.b64decode(audio_data.split(',')[1])
            else:
                # Assume base64 string
                audio_bytes = base64.b64decode(audio_data)
        else:
            # Assume bytes
            audio_bytes = audio_data

        # Validate audio size
        audio_size_mb = len(audio_bytes) / (1024 * 1024)
        if audio_size_mb > self.max_audio_size_mb:
            raise AudioAIError(f"Audio size {audio_size_mb:.2f}MB exceeds maximum {self.max_audio_size_mb}MB")

        # Convert to base64
        return base64.b64encode(audio_bytes).decode('utf-8')

    async def _transcribe_audio(
        self,
        audio_b64: str,
        model: str,
        language: str = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Transcribe audio to text."""
        language_hint = f" in {language}" if language else ""
        prompt = kwargs.get('transcription_prompt',
            f"Transcribe this audio{language_hint}. Provide accurate transcription with proper punctuation and formatting.")

        try:
            response = await ollama_client.generate(
                model=model,
                prompt=f"[AUDIO_DATA:{audio_b64}]\n{prompt}",
                system="You are an expert speech recognition AI. Provide accurate transcriptions with proper punctuation, formatting, and timestamps when possible.",
                options={
                    "temperature": kwargs.get('temperature', 0.0),  # Low temperature for accuracy
                    "num_predict": kwargs.get('max_tokens', 1000)
                }
            )

            transcription = response.get('response', '').strip()

            return {
                "text": transcription,
                "language": language or "unknown",
                "confidence": 0.9  # Placeholder - would be provided by actual Whisper model
            }

        except Exception as e:
            logger.error(f"Audio transcription failed: {e}")
            return {
                "text": "Transcription failed due to processing error.",
                "language": language or "unknown",
                "error": str(e)
            }

    async def _identify_speakers(self, transcription: str, model: str, **kwargs) -> List[Dict[str, Any]]:
        """Identify speakers in transcribed audio."""
        prompt = kwargs.get('speaker_identification_prompt',
            "Analyze this transcription and identify different speakers. For each speaker segment, provide: speaker_id, start_time, end_time, text, and confidence. Format as JSON array.")

        try:
            response = await ollama_client.generate(
                model=model,
                prompt=f"Transcription: {transcription}\n\n{prompt}",
                system="You are an expert at speaker diarization and identification. Always respond with valid JSON.",
                format="json",
                options={
                    "temperature": kwargs.get('temperature', 0.3),
                    "num_predict": kwargs.get('max_tokens', 500)
                }
            )

            result_text = response.get('response', '').strip()

            # Try to parse as JSON
            try:
                speakers = json.loads(result_text)
                if isinstance(speakers, list):
                    return speakers
                else:
                    return [speakers]
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse speaker identification JSON: {result_text}")
                return self._extract_speakers_from_text(result_text)

        except Exception as e:
            logger.error(f"Speaker identification failed: {e}")
            return []

    async def _detect_emotions(self, transcription: str, model: str, **kwargs) -> List[Dict[str, float]]:
        """Detect emotions from speech transcription."""
        prompt = kwargs.get('emotion_detection_prompt',
            "Analyze the emotional content of this transcription. Identify emotions like happiness, sadness, anger, fear, surprise, disgust, and neutral. Provide confidence scores for each emotion detected. Format as JSON array of emotion objects.")

        try:
            response = await ollama_client.generate(
                model=model,
                prompt=f"Transcription: {transcription}\n\n{prompt}",
                system="You are an expert at emotion detection from text and speech. Always respond with valid JSON.",
                format="json",
                options={
                    "temperature": kwargs.get('temperature', 0.3),
                    "num_predict": kwargs.get('max_tokens', 300)
                }
            )

            result_text = response.get('response', '').strip()

            # Try to parse as JSON
            try:
                emotions = json.loads(result_text)
                return emotions
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse emotion detection JSON: {result_text}")
                return self._extract_emotions_from_text(result_text)

        except Exception as e:
            logger.error(f"Emotion detection failed: {e}")
            return [{"emotion": "neutral", "confidence": 0.5}]

    async def _classify_audio(self, audio_b64: str, model: str, **kwargs) -> Dict[str, Any]:
        """Classify audio content type and characteristics."""
        prompt = kwargs.get('audio_classification_prompt',
            "Analyze this audio and classify: 1) Content type (speech, music, sound effects, silence, etc.), 2) Audio quality, 3) Environment (indoor, outdoor, studio, etc.), 4) Primary language if speech, 5) Estimated duration. Format as JSON object.")

        try:
            response = await ollama_client.generate(
                model=model,
                prompt=f"[AUDIO_DATA:{audio_b64}]\n{prompt}",
                system="You are an expert at audio analysis and classification. Always respond with valid JSON.",
                format="json",
                options={
                    "temperature": kwargs.get('temperature', 0.3),
                    "num_predict": kwargs.get('max_tokens', 250)
                }
            )

            result_text = response.get('response', '').strip()

            # Try to parse as JSON
            try:
                classification = json.loads(result_text)
                return classification
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse audio classification JSON: {result_text}")
                return {"error": "Failed to parse classification", "raw_response": result_text}

        except Exception as e:
            logger.error(f"Audio classification failed: {e}")
            return {"error": str(e)}

    async def _assess_audio_quality(self, audio_b64: str, model: str, **kwargs) -> float:
        """Assess the quality of the audio."""
        prompt = kwargs.get('quality_assessment_prompt',
            "Rate the quality of this audio on a scale of 0.0 to 1.0, where 1.0 is perfect quality and 0.0 is very poor. Consider factors like: clarity, background noise, volume levels, distortion, and overall intelligibility. Provide only the numerical score.")

        try:
            response = await ollama_client.generate(
                model=model,
                prompt=f"[AUDIO_DATA:{audio_b64}]\n{prompt}",
                system="You are an expert at audio quality assessment. Always respond with only a numerical score between 0.0 and 1.0.",
                options={
                    "temperature": kwargs.get('temperature', 0.1),
                    "num_predict": kwargs.get('max_tokens', 50)
                }
            )

            result_text = response.get('response', '').strip()

            # Extract numerical score
            score_match = re.search(r'(\d+\.?\d*)', result_text)
            if score_match:
                score = float(score_match.group(1))
                return max(0.0, min(1.0, score))  # Clamp to 0.0-1.0 range
            else:
                logger.warning(f"Could not extract quality score from: {result_text}")
                return 0.5  # Default neutral score

        except Exception as e:
            logger.error(f"Audio quality assessment failed: {e}")
            return 0.5

    def _extract_speakers_from_text(self, text: str) -> List[Dict[str, Any]]:
        """Extract speaker information from text response."""
        speakers = []
        lines = text.split('\n')

        current_speaker = None
        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Look for speaker patterns
            if 'speaker' in line.lower() or 'person' in line.lower():
                speakers.append({
                    "speaker_id": f"speaker_{len(speakers) + 1}",
                    "text": line,
                    "confidence": 0.7
                })

        return speakers

    def _extract_emotions_from_text(self, text: str) -> List[Dict[str, float]]:
        """Extract emotion information from text response."""
        emotions = []
        emotion_keywords = {
            'happy': 'happiness', 'sad': 'sadness', 'angry': 'anger',
            'fear': 'fear', 'surprise': 'surprise', 'disgust': 'disgust',
            'neutral': 'neutral', 'excited': 'excitement', 'calm': 'calm'
        }

        text_lower = text.lower()
        for keyword, emotion in emotion_keywords.items():
            if keyword in text_lower:
                emotions.append({
                    "emotion": emotion,
                    "confidence": 0.6
                })

        if not emotions:
            emotions.append({"emotion": "neutral", "confidence": 0.5})

        return emotions

    async def batch_process_audio(
        self,
        audio_batch: List[Dict[str, Any]],
        operations: List[str] = None,
        max_concurrent: int = 2
    ) -> List[AudioAIResult]:
        """
        Process multiple audio files in batch.

        Args:
            audio_batch: List of audio data dictionaries
            operations: Operations to perform on each audio
            max_concurrent: Maximum concurrent processing tasks

        Returns:
            List of AudioAIResult objects
        """
        semaphore = asyncio.Semaphore(max_concurrent)

        async def process_single_audio(audio_data: Dict[str, Any]) -> AudioAIResult:
            async with semaphore:
                return await self.process_audio(
                    audio_data=audio_data['data'],
                    operations=operations,
                    content_id=audio_data.get('content_id', 'batch_item'),
                    language=audio_data.get('language'),
                    **audio_data.get('options', {})
                )

        tasks = [process_single_audio(audio_data) for audio_data in audio_batch]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Handle exceptions
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Batch processing failed for audio {i}: {result}")
                # Create error result
                error_result = AudioAIResult(
                    content_id=audio_batch[i].get('content_id', f'batch_item_{i}'),
                    metadata={"error": str(result)}
                )
                processed_results.append(error_result)
            else:
                processed_results.append(result)

        return processed_results

    def get_supported_operations(self) -> List[str]:
        """Get list of supported audio operations."""
        return ['transcription', 'speakers', 'emotion', 'classification', 'quality']

    def get_supported_models(self) -> List[str]:
        """Get list of supported audio models."""
        return self.supported_models.copy()

    def get_supported_formats(self) -> List[str]:
        """Get list of supported audio formats."""
        return self.supported_formats.copy()

    async def health_check(self) -> Dict[str, Any]:
        """Check the health of the audio AI service."""
        try:
            # Test basic Ollama connectivity
            health = await ollama_client.health_check()

            return {
                "service": "audio_ai",
                "status": "healthy" if health.get("status") == "healthy" else "degraded",
                "ollama_status": health.get("status"),
                "supported_models": self.supported_models,
                "default_model": self.default_model,
                "max_audio_size_mb": self.max_audio_size_mb,
                "supported_operations": self.get_supported_operations(),
                "supported_formats": self.get_supported_formats()
            }

        except Exception as e:
            return {
                "service": "audio_ai",
                "status": "unhealthy",
                "error": str(e)
            }


# Global instance
audio_ai_service = AudioAIService()