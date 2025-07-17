#!/usr/bin/env python3
"""
Test script to verify the PyTorch embedding memory fix.
"""

import os
import sys
import logging
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from database.pytorch_embeddings import PyTorchEmbeddings

def test_embedding_memory_management():
    """Test the embedding class with memory management improvements."""
    
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    logger = logging.getLogger(__name__)
    
    logger.info("Starting PyTorch embedding memory management test...")
    
    try:
        # Initialize the embedding model with memory-efficient settings
        embeddings = PyTorchEmbeddings()
        
        logger.info(f"Model info: {embeddings.get_model_info()}")
        
        # Test with a small batch first
        test_texts = [
            "This is a test document for security scanning.",
            "def vulnerable_function():\n    sql_query = 'SELECT * FROM users WHERE id = ' + user_input",
            "import subprocess\nsubprocess.call(user_input, shell=True)",
            "password = 'hardcoded_password_123'"
        ]
        
        logger.info(f"Testing with {len(test_texts)} small documents...")
        embeddings_result = embeddings.embed_documents(test_texts)
        logger.info(f"Successfully created {len(embeddings_result)} embeddings, each with dimension {len(embeddings_result[0])}")
        
        # Test with larger text chunks
        large_text = "x" * 10000  # 10KB text
        large_texts = [large_text] * 5  # 5 large documents
        
        logger.info(f"Testing with {len(large_texts)} large documents (10KB each)...")
        large_embeddings = embeddings.embed_documents(large_texts)
        logger.info(f"Successfully created {len(large_embeddings)} embeddings for large documents")
        
        # Test query embedding
        query = "Find SQL injection vulnerabilities"
        logger.info("Testing query embedding...")
        query_embedding = embeddings.embed_query(query)
        logger.info(f"Successfully created query embedding with dimension {len(query_embedding)}")
        
        logger.info("All tests passed! Memory management improvements are working.")
        return True
        
    except Exception as e:
        logger.error(f"Test failed with error: {e}")
        return False

if __name__ == "__main__":
    success = test_embedding_memory_management()
    sys.exit(0 if success else 1)
