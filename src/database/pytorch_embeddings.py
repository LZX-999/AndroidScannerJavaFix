import torch
import numpy as np
from sentence_transformers import SentenceTransformer
from typing import List, Union
import logging
import os
import gc

class PyTorchEmbeddings:
    """PyTorch-based embedding class compatible with LangChain interfaces."""
    
    def __init__(self, model_name: str = None, device: str = None, dimension: int = None):
        """
        Initialize PyTorch embeddings using sentence-transformers.
        
        Args:
            model_name: Name of the sentence-transformer model to use
            device: Device to run the model on ('cuda', 'cpu', or None for auto-detection)
            dimension: Expected embedding dimension (None for auto-detection from model)
        """
        self.logger = logging.getLogger(__name__)
        
        # Set default model if none provided
        if model_name is None:
            model_name = os.getenv("PYTORCH_EMBEDDING_MODEL", "all-MiniLM-L6-v2")
        
        self.model_name = model_name
        self.expected_dimension = dimension
        
        # Memory management configuration
        self.batch_size = int(os.getenv("PYTORCH_BATCH_SIZE", "8"))  # Reduced from 32
        self.max_text_length = int(os.getenv("PYTORCH_MAX_TEXT_LENGTH", "8192"))  # Maximum characters per text
        self.memory_efficient = os.getenv("PYTORCH_MEMORY_EFFICIENT", "true").lower() == "true"
        
        # Set device (handle auto-detection)
        if device is None or device == "auto" or device == "auto-detect":
            self.device = "cuda" if torch.cuda.is_available() else "cpu"
        else:
            self.device = device
            
        self.logger.info(f"Initializing PyTorch embeddings with model: {model_name} on device: {self.device}")
        self.logger.info(f"Memory settings - Batch size: {self.batch_size}, Max text length: {self.max_text_length}, Memory efficient: {self.memory_efficient}")
        
        try:
            # Load the sentence transformer model
            self.model = SentenceTransformer(model_name, device=self.device)
            self.logger.info(f"Successfully loaded embedding model: {model_name}")
        except Exception as e:
            self.logger.error(f"Failed to load embedding model {model_name}: {e}")
            # Fallback to a smaller, more common model
            fallback_model = "all-MiniLM-L6-v2"
            self.logger.info(f"Falling back to model: {fallback_model}")
            self.model = SentenceTransformer(fallback_model, device=self.device)
            self.model_name = fallback_model
        
        # Validate dimension if provided
        actual_dimension = self.model.get_sentence_embedding_dimension()
        if self.expected_dimension is not None:
            if actual_dimension != self.expected_dimension:
                self.logger.warning(
                    f"Model {self.model_name} has dimension {actual_dimension}, "
                    f"but expected dimension was {self.expected_dimension}. "
                    f"Using actual dimension: {actual_dimension}"
                )
        
        self.dimension = actual_dimension
        self.logger.info(f"Embedding dimension: {self.dimension}")
    
    def _truncate_text(self, text: str) -> str:
        """Truncate text to maximum length to prevent memory issues."""
        if len(text) <= self.max_text_length:
            return text
        
        truncated = text[:self.max_text_length]
        self.logger.debug(f"Truncated text from {len(text)} to {len(truncated)} characters")
        return truncated
    
    def _clear_memory(self):
        """Clear GPU/CPU memory to prevent accumulation."""
        if self.memory_efficient:
            if torch.cuda.is_available() and self.device == "cuda":
                torch.cuda.empty_cache()
            gc.collect()
    
    def embed_documents(self, texts: List[str]) -> List[List[float]]:
        """
        Embed a list of documents with memory management.
        
        Args:
            texts: List of document strings to embed
            
        Returns:
            List of embedding vectors (each as a list of floats)
        """
        if not texts:
            return []
        
        # Truncate texts to prevent memory issues
        truncated_texts = [self._truncate_text(text) for text in texts]
        
        # Log if any texts were truncated
        truncated_count = sum(1 for orig, trunc in zip(texts, truncated_texts) if len(orig) != len(trunc))
        if truncated_count > 0:
            self.logger.warning(f"Truncated {truncated_count} out of {len(texts)} texts to {self.max_text_length} characters")
        
        try:
            # Clear memory before processing
            self._clear_memory()
            
            # For very large batches, process in smaller chunks
            if len(truncated_texts) > self.batch_size * 4:  # If more than 4x batch size
                self.logger.info(f"Processing {len(truncated_texts)} documents in chunks of {self.batch_size * 2}")
                all_embeddings = []
                
                for i in range(0, len(truncated_texts), self.batch_size * 2):
                    chunk = truncated_texts[i:i + self.batch_size * 2]
                    self.logger.debug(f"Processing chunk {i//self.batch_size//2 + 1}/{(len(truncated_texts) + self.batch_size * 2 - 1) // (self.batch_size * 2)}")
                    
                    # Generate embeddings for this chunk
                    chunk_embeddings = self.model.encode(
                        chunk,
                        convert_to_tensor=True,
                        show_progress_bar=False,  # Disable to avoid clutter
                        batch_size=self.batch_size
                    )
                    
                    # Convert to CPU and numpy immediately
                    if isinstance(chunk_embeddings, torch.Tensor):
                        chunk_embeddings = chunk_embeddings.cpu().numpy()
                    
                    all_embeddings.extend(chunk_embeddings.tolist())
                    
                    # Clear memory after each chunk
                    self._clear_memory()
                
                return all_embeddings
            else:
                # Process normally for smaller batches
                embeddings = self.model.encode(
                    truncated_texts,
                    convert_to_tensor=True,
                    show_progress_bar=len(truncated_texts) > 20,
                    batch_size=self.batch_size
                )
                
                # Convert to CPU and numpy, then to list for compatibility
                if isinstance(embeddings, torch.Tensor):
                    embeddings = embeddings.cpu().numpy()
                
                # Clear memory after processing
                self._clear_memory()
                
                return embeddings.tolist()
            
        except Exception as e:
            self.logger.error(f"Error embedding documents: {e}")
            # Try with even smaller batch size if memory error
            if "memory" in str(e).lower() or "allocate" in str(e).lower():
                self.logger.warning(f"Memory error detected, retrying with batch size 1")
                try:
                    self._clear_memory()
                    all_embeddings = []
                    for text in truncated_texts:
                        embedding = self.model.encode(
                            [text],
                            convert_to_tensor=True,
                            show_progress_bar=False,
                            batch_size=1
                        )
                        if isinstance(embedding, torch.Tensor):
                            embedding = embedding.cpu().numpy()
                        all_embeddings.extend(embedding.tolist())
                        self._clear_memory()
                    return all_embeddings
                except Exception as retry_e:
                    self.logger.error(f"Retry with batch size 1 also failed: {retry_e}")
                    raise retry_e
            raise
    
    def embed_query(self, text: str) -> List[float]:
        """
        Embed a single query string with memory management.
        
        Args:
            text: Query string to embed
            
        Returns:
            Embedding vector as a list of floats
        """
        try:
            # Truncate text if necessary
            truncated_text = self._truncate_text(text)
            if len(text) != len(truncated_text):
                self.logger.debug(f"Truncated query from {len(text)} to {len(truncated_text)} characters")
            
            # Clear memory before processing
            self._clear_memory()
            
            # Generate embedding for single query
            embedding = self.model.encode(
                truncated_text,
                convert_to_tensor=True,
                batch_size=1  # Single item, explicit batch size
            )
            
            # Convert to CPU and numpy, then to list for compatibility
            if isinstance(embedding, torch.Tensor):
                embedding = embedding.cpu().numpy()
            
            # Clear memory after processing
            self._clear_memory()
            
            return embedding.tolist()
            
        except Exception as e:
            self.logger.error(f"Error embedding query: {e}")
            raise
    
    def get_embedding_dimension(self) -> int:
        """Get the dimension of the embedding vectors."""
        return self.dimension
    
    def get_model_info(self) -> dict:
        """Get information about the current model."""
        return {
            "model_name": self.model_name,
            "device": self.device,
            "embedding_dimension": self.get_embedding_dimension(),
            "expected_dimension": self.expected_dimension,
            "max_sequence_length": getattr(self.model, 'max_seq_length', 'Unknown')
        }
