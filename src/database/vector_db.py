import numpy as np
from langchain_community.vectorstores import Chroma
import tiktoken
import logging
import os
from .pytorch_embeddings import PyTorchEmbeddings
class CodeVectorDatabase:
    COLLECTION_NAME = "code_documents"

    def __init__(self, embedding_model=None, persist_directory="./code_db"):
        self.logger = logging.getLogger(__name__)
        if embedding_model is None:
            # Use PyTorch embeddings by default
            pytorch_model = os.getenv("PYTORCH_EMBEDDING_MODEL", "all-MiniLM-L6-v2")
            device = os.getenv("PYTORCH_DEVICE", None)  # Auto-detect if not specified
            dimension = os.getenv("PYTORCH_EMBEDDING_DIMENSION", None)  # Auto-detect if not specified
            if dimension is not None:
                try:
                    dimension = int(dimension)
                except ValueError:
                    self.logger.warning(f"Invalid PYTORCH_EMBEDDING_DIMENSION value: {dimension}. Using auto-detection.")
                    dimension = None
            
            self.embedding_model = PyTorchEmbeddings(
                model_name=pytorch_model,
                device=device,
                dimension=dimension
            )
            self.logger.info(f"Using PyTorch embeddings - Model: {pytorch_model}, Device: {self.embedding_model.device}, Dimension: {self.embedding_model.dimension}")
        else:
            self.embedding_model = embedding_model
        self.persist_directory = persist_directory
        self.vector_db = None
        try:
            self.tokenizer = tiktoken.encoding_for_model("text-embedding-ada-002")
        except KeyError:
            self.tokenizer = tiktoken.get_encoding("cl100k_base")
        
    def _get_tokens(self, text: str) -> int:
        """Helper function to count tokens in a text string."""
        return len(self.tokenizer.encode(text))

    def index_code_chunks(self, code_chunks):
        """Index code chunks for semantic search with dynamic batching based on token counts."""
        MAX_TOKENS_PER_API_BATCH = 250000

        if not code_chunks:
            return 0

        current_batch_docs = []
        current_batch_tokens = 0
        total_indexed_count = 0

        for i, doc in enumerate(code_chunks):
            doc_content = doc.page_content
            try:
                doc_tokens = self._get_tokens(doc_content)
            except Exception as e:
                source_info = "Unknown source"
                if hasattr(doc, 'metadata') and isinstance(doc.metadata, dict):
                    source_info = doc.metadata.get('source', 'N/A')
                self.logger.debug(f"Warning: Could not tokenize document from {source_info} (index {i}): {e}. Skipping.")
                continue

            if doc_tokens > MAX_TOKENS_PER_API_BATCH:
                source_info = "Unknown source"
                if hasattr(doc, 'metadata') and isinstance(doc.metadata, dict):
                    source_info = doc.metadata.get('source', 'N/A')
                self.logger.debug(f"Warning: Document from {source_info} (index {i}) has {doc_tokens} tokens, exceeding the single batch limit of {MAX_TOKENS_PER_API_BATCH}. Skipping this document.")
                continue

            if current_batch_docs and (current_batch_tokens + doc_tokens > MAX_TOKENS_PER_API_BATCH):
                if not self.vector_db:
                    self.vector_db = Chroma.from_documents(
                        documents=current_batch_docs,
                        embedding=self.embedding_model,
                        persist_directory=self.persist_directory,
                        collection_name=self.COLLECTION_NAME
                    )
                    self.logger.debug(f"Initialized DB with first batch: {len(current_batch_docs)} docs, {current_batch_tokens} tokens.")
                else:
                    self.vector_db.add_documents(documents=current_batch_docs)
                    self.logger.debug(f"Added batch to DB: {len(current_batch_docs)} docs, {current_batch_tokens} tokens.")
                
                total_indexed_count += len(current_batch_docs)
                current_batch_docs = [doc]
                current_batch_tokens = doc_tokens
            else:
                current_batch_docs.append(doc)
                current_batch_tokens += doc_tokens
        
        if current_batch_docs:
            if not self.vector_db:
                self.vector_db = Chroma.from_documents(
                    documents=current_batch_docs,
                    embedding=self.embedding_model,
                    persist_directory=self.persist_directory,
                    collection_name=self.COLLECTION_NAME
                )
                self.logger.debug(f"Initialized DB with final/only batch: {len(current_batch_docs)} docs, {current_batch_tokens} tokens.")
            else:
                self.vector_db.add_documents(documents=current_batch_docs)
                self.logger.debug(f"Added final batch to DB: {len(current_batch_docs)} docs, {current_batch_tokens} tokens.")
            total_indexed_count += len(current_batch_docs)

        if self.vector_db and self.persist_directory:
            try:
                self.vector_db.persist()
                self.logger.debug(f"Persisted database to {self.persist_directory} with collection {self.COLLECTION_NAME}")
            except Exception as e:
                self.logger.debug(f"Error persisting database: {e}")
        
        return total_indexed_count
    
    def retrieve_relevant_code(self, query, n_results=10, filter_criteria=None):
        """Retrieve code chunks relevant to a security topic or vulnerability"""
        if not self.vector_db:
            raise ValueError("No indexed code. Call index_code_chunks first.")
            
        results = self.vector_db.similarity_search(
            query=query,
            k=n_results,
            filter=filter_criteria
        )
        
        return results
    
    def retrieve_by_file_pattern(self, query, file_pattern, n_results=10):
        """Retrieve code chunks from files matching a pattern"""
        filter_criteria = {"relative_path": {"$regex": file_pattern}}
        return self.retrieve_relevant_code(query, n_results, filter_criteria)
    
    def retrieve_by_language(self, query, language, n_results=10):
        """Retrieve code chunks from a specific programming language"""
        filter_criteria = {"language": language}
        return self.retrieve_relevant_code(query, n_results, filter_criteria)
    
    def retrieve_deeplink_relevant_code(self, activity_names, n_results=50):
        """
        Retrieve code chunks specifically from deeplink-related activity files using filename matching
        
        Args:
            activity_names: List of activity class names from manifest (e.g. "com.example.MainActivity")
            n_results: Maximum number of results to return
            
        Returns:
            List of relevant code chunks from files matching the activity names
        """
        if not activity_names:
            self.logger.debug("No activity names provided for deeplink analysis")
            return []
        
        self.logger.debug(f"Retrieving deeplink code for {len(activity_names)} activities: {activity_names}")
        
        # Extract simple class names and create filename patterns
        filename_patterns = []
        simple_names = []
        
        for activity_name in activity_names:
            # Handle both full package names and relative names
            if activity_name.startswith("."):
                simple_name = activity_name[1:]  # Remove leading dot
            else:
                simple_name = activity_name.split(".")[-1]  # Get class name from package
            
            # Handle inner classes (MainActivity$InnerActivity -> MainActivity)
            base_name = simple_name.split("$")[0]
            simple_names.append(base_name)
            
            # Create regex patterns for different file extensions
            filename_patterns.extend([
                f".*/{base_name}\\.java$",
                f".*/{base_name}\\.kt$",
                f".*/{base_name}\\.scala$"
            ])
        
        self.logger.debug(f"Searching for files matching activity names: {simple_names}")
        
        # Use a query focused on deeplink handling patterns
        deeplink_query = (
            "deeplink intent handling onCreate onNewIntent getIntent getData "
            "Uri parse scheme host path query parameter navigation routing"
        )
        
        try:
            # Retrieve more results initially since we'll filter in Python
            initial_results = self.retrieve_relevant_code(
                query=deeplink_query,
                n_results=n_results * 3,  # Get more to compensate for filtering
                filter_criteria=None
            )
            
            self.logger.debug(f"Retrieved {len(initial_results)} initial code chunks for filtering")
            
            # Filter results in Python to match activity files
            # Use the new 'filename' metadata for more efficient matching
            filtered_results = []
            target_filenames = set()
            
            # Create target filename set for fast lookup
            for simple_name in simple_names:
                target_filenames.add(f"{simple_name}.java")
                target_filenames.add(f"{simple_name}.kt")
                target_filenames.add(f"{simple_name}.scala")
            
            self.logger.debug(f"Target filenames for filtering: {target_filenames}")
            
            for chunk in initial_results:
                chunk_filename = chunk.metadata.get('filename', '')
                
                # Direct filename matching - much more efficient
                if chunk_filename in target_filenames:
                    filtered_results.append(chunk)
                    
                    # Stop if we have enough results
                    if len(filtered_results) >= n_results:
                        break
            
            self.logger.debug(f"Filtered to {len(filtered_results)} activity-specific code chunks")
            
            # Log which files were actually found
            found_files = set(chunk.metadata.get('relative_path', '') for chunk in filtered_results)
            if found_files:
                self.logger.debug(f"Found code in files: {list(found_files)}")
            else:
                self.logger.debug(f"No files found matching activity names: {simple_names}")
            
            return filtered_results
            
        except Exception as e:
            self.logger.error(f"Error retrieving deeplink-relevant code: {e}")
            # Fallback: try without filter if filtering fails
            self.logger.debug("Falling back to unfiltered deeplink query")
            return self.retrieve_relevant_code(deeplink_query, n_results)
    
    def retrieve_by_specific_files(self, file_paths, query=None, n_results=50):
        """
        Retrieve code chunks from specific files
        
        Args:
            file_paths: List of specific file paths to retrieve from
            query: Optional specific query, uses generic query if None
            n_results: Maximum number of results
            
        Returns:
            List of code chunks from the specified files
        """
        if not file_paths:
            return []
        
        # Create filter for specific files
        filter_criteria = {
            "$or": [
                {"relative_path": {"$eq": file_path}} for file_path in file_paths
            ]
        }
        
        search_query = query or "code implementation methods functions"
        
        try:
            return self.retrieve_relevant_code(
                query=search_query,
                n_results=n_results,
                filter_criteria=filter_criteria
            )
        except Exception as e:
            self.logger.error(f"Error retrieving code from specific files: {e}")
            return []
