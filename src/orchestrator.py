import os
import argparse
from dotenv import load_dotenv
import time
import logging
from datetime import datetime
import re
import shutil
import tiktoken # For embedding token counting
from typing import Dict, List

# Use relative imports within the src package
from .analysis.security_analyzer import SecurityAnalyzer
from .database.vector_db import CodeVectorDatabase
from .processing.code_processor import CodeProcessor
from .reporting.report_generator import ReportGenerator
from .repository.repo_manager import RepositoryManager
from .agent_workflows.finding_verifier.workflow import verify_findings_workflow

# (Cost calculation logic removed)
# Load environment variables
load_dotenv()



class SecurityAnalysisOrchestrator:
    def __init__(self, api_key=None, extra_ignore_dirs=None, pytorch_config=None):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY") # Updated env var
        if not self.api_key:
            raise ValueError("API key is required. Set GEMINI_API_KEY environment variable or pass explicitly.")
        
        self.extra_ignore_dirs = extra_ignore_dirs if extra_ignore_dirs else [] # Store extra ignore dirs
        self.pytorch_config = pytorch_config or {} # Store PyTorch configuration
        self.logger = logging.getLogger(__name__)
        self.logger.debug("SecurityAnalysisOrchestrator initialized.")
        
    def _verify_findings_via_agent(self, category: str, raw_vulnerabilities: List[Dict]) -> List[Dict]:
        """
        Verify a list of raw vulnerabilities for a specific category using an agent workflow.
        """
        self.logger.info(f"--- Verifying LLM Findings for category '{category}' via Agent Workflow ---")
        self.logger.debug(f"Number of raw vulnerabilities received for category '{category}': {len(raw_vulnerabilities)}")

        if not hasattr(self, 'repo_manager') or not self.repo_manager:
            self.logger.error("RepositoryManager not initialized. Cannot run agent verification workflow.")
            return [dict(r, agent_verification_status="skipped_missing_repo_manager") for r in raw_vulnerabilities]
        
        if not hasattr(self, 'vector_db') or not self.vector_db:
            self.logger.error("CodeVectorDatabase not initialized. Cannot run agent verification workflow.")
            return [dict(r, agent_verification_status="skipped_missing_vector_db") for r in raw_vulnerabilities]

        verified_vulnerabilities_list = verify_findings_workflow(
            category_findings=raw_vulnerabilities,
            category_name=category,
            repo_manager=self.repo_manager,
            vector_db=self.vector_db,
            llm_api_key=self.api_key
        )
        
        self.logger.debug(f"Number of vulnerabilities after actual agent verification for category '{category}': {len(verified_vulnerabilities_list)}")
        if len(raw_vulnerabilities) != len(verified_vulnerabilities_list):
             self.logger.info(f"Agent verification for category '{category}' resulted in a change in finding count: {len(raw_vulnerabilities)} -> {len(verified_vulnerabilities_list)}")
        return verified_vulnerabilities_list
        
    def analyze_repository(self, local_path, output_dir="./reports", analyze_attack_paths: bool = False):
        """Run a complete security analysis on a repository"""
        start_time = time.time()
        self.logger.info(f"--- Starting full security analysis for {local_path} ---")
        
        analysis_stopped_early = False # (Cost tracking logic removed)
        # Step 1: Setup repository
        self.logger.info("--- Step 1: Setting up repository ---")
        self.repo_manager = RepositoryManager(local_path=local_path, extra_ignore_dirs=self.extra_ignore_dirs)
        try:
            repo_dir = self.repo_manager.prepare_repository()
            repo_name = os.path.basename(repo_dir)
            self.logger.debug(f"Repository ready at: {repo_dir}")
        except Exception as e:
             self.logger.debug(f"Failed to prepare repository: {e}", exc_info=True)
             return {"status": "error", "repo_name": local_path, "error": f"Repository preparation failed: {e}"}

        try:
            # Step 2: Process code into analyzable chunks
            self.logger.info("--- Step 2: Processing code ---")
            code_processor = CodeProcessor(self.repo_manager)
            code_chunks = code_processor.process_codebase()
            if not code_chunks:
                 self.logger.debug("Code processing resulted in zero chunks. Analysis may be incomplete.")
                 # Optionally decide to stop if no chunks?

            # (Cost calculation logic removed)

            # Step 3: Index code for efficient retrieval
            self.logger.debug("--- Step 2.5: Indexing code chunks ---")

            # --- Create unique DB path and clear if exists --- 
            db_base_dir = "./vector_dbs" # Base directory for all vector DBs
            # Sanitize repo_name to be filesystem-friendly (replace non-alphanumeric)
            safe_repo_name = re.sub(r'[^a-zA-Z0-9_\-]', '_', repo_name)
            persist_dir = os.path.join(db_base_dir, f"code_db_{safe_repo_name}")
            self.logger.debug(f"Using vector database directory: {persist_dir}")

            # Ensure the base directory exists
            os.makedirs(db_base_dir, exist_ok=True)

            # Clear this specific repo's DB if it exists (ensures fresh analysis)
            if os.path.exists(persist_dir):
                try:
                    self.logger.debug(f"Removing existing vector database for this repo: {persist_dir}")
                    shutil.rmtree(persist_dir)
                    self.logger.debug(f"Successfully removed {persist_dir}")
                except OSError as e:
                    self.logger.debug(f"Failed to remove existing vector database at {persist_dir}: {e}")
                    # Decide if we should proceed - perhaps safer to stop?
                    # For now, log error and continue, but results might be mixed.
            # --- End DB Clear --- 

            # Create vector database with PyTorch configuration
            if self.pytorch_config:
                from .database.pytorch_embeddings import PyTorchEmbeddings
                pytorch_embeddings = PyTorchEmbeddings(
                    model_name=self.pytorch_config.get('model'),
                    device=self.pytorch_config.get('device'),
                    dimension=self.pytorch_config.get('dimension')
                )
                self.vector_db = CodeVectorDatabase(
                    embedding_model=pytorch_embeddings,
                    persist_directory=persist_dir
                )
            else:
                self.vector_db = CodeVectorDatabase(persist_directory=persist_dir)
            indexed_count = self.vector_db.index_code_chunks(code_chunks)
            self.logger.debug(f"{indexed_count} code chunks indexed in vector database ({persist_dir})")
            
            # Step 3: Analyze code for security issues using LLM (Multi-Step)
            self.logger.info("--- Step 3: Analyzing code with LLM ---")
            security_analyzer = SecurityAnalyzer(api_key=self.api_key)
            task = 'Given an implementation query, retrieve relevant code chunks that answer the query'
            # Define security categories to analyze
            security_categories = [
                "deeplink",
                #"authentication",
                #"authorization",
                "injection",
                #"data_protection",
                #"api_security",
                #"configuration",
                #"client_side",
                "webview",
                "path_traversal",
                #"intent",
                "javascriptinterface"
                
            ]
            self.logger.info(f"Analyzing for categories: {', '.join(security_categories)}")
            
            # Change structure to store LLM findings per category for the correlator
            llm_findings_by_category: Dict[str, List[Dict]] = {cat: [] for cat in security_categories}
            # --- NEW: Initialize lists for attack path analysis ---
            all_vulnerabilities = []
            unique_analysis_chunks = {} # Use dict for deduplication {chunk_key: chunk_object}
            # --- End NEW ---

            for category in security_categories:
                self.logger.info(f"--- Analyzing category: {category} ---")
                
                # Use manifest-based analysis for deeplink category
                if category == "deeplink":
                    self.logger.info(f"Using manifest-based analysis for deeplink category")
                    vulnerabilities, input_tokens, output_tokens, manifest_info = security_analyzer.analyze_deeplink_with_manifest(
                        code_chunks, self.repo_manager, self.vector_db
                    )
                    
                    if manifest_info:
                        self.logger.info(f"Manifest analysis found {manifest_info['total_deeplink_activities']} deeplink activities")
                        if manifest_info['schemes']:
                            self.logger.info(f"Custom schemes: {', '.join(manifest_info['schemes'])}")
                        if manifest_info['hosts']:
                            self.logger.info(f"Hosts: {', '.join(manifest_info['hosts'])}")
                    
                    self.logger.debug(f"Raw deeplink vulnerabilities: {vulnerabilities}")
                    verified_vulnerabilities = self._verify_findings_via_agent(category, vulnerabilities)
                    
                    llm_findings_by_category[category].extend(verified_vulnerabilities)
                    all_vulnerabilities.extend(verified_vulnerabilities)
                    
                    # Add relevant chunks for attack path analysis if any were found
                    if vulnerabilities and manifest_info and manifest_info['has_deeplinks']:
                        try:
                            # Extract simple activity names for filename matching
                            activity_names = list(manifest_info['deeplink_activities'].keys())
                            simple_names = []
                            for activity_name in activity_names:
                                if activity_name.startswith("."):
                                    simple_name = activity_name[1:]
                                else:
                                    simple_name = activity_name.split(".")[-1]
                                base_name = simple_name.split("$")[0]
                                simple_names.append(base_name)
                            
                            # Add chunks from files matching activity names
                            for chunk in code_chunks:
                                chunk_file = chunk.metadata.get('relative_path', '')
                                chunk_filename = chunk_file.split('/')[-1] if '/' in chunk_file else chunk_file
                                
                                # Check if this chunk is from an activity file
                                for simple_name in simple_names:
                                    if (chunk_filename == f"{simple_name}.java" or 
                                        chunk_filename == f"{simple_name}.kt" or
                                        chunk_filename == f"{simple_name}.scala"):
                                        chunk_key = (chunk.metadata.get('relative_path', ''), chunk.page_content)
                                        if chunk_key not in unique_analysis_chunks:
                                            unique_analysis_chunks[chunk_key] = chunk
                                        break
                        except Exception as e:
                            self.logger.debug(f"Error adding deeplink chunks to attack path analysis: {e}")
                    
                else:
                    # Standard analysis for other categories
                    self.logger.debug(f"Retrieving initial code chunks for {category} (n=200)...") # Increased n_results
                    relevant_code_chunks = self.vector_db.retrieve_relevant_code(
                        query=f"code related to {category} implementation or security", 
                        n_results=200 # Increased n_results
                    )
                    self.logger.debug(f"Retrieved {len(relevant_code_chunks)} chunks for analysis.")

                    if not relevant_code_chunks:
                        self.logger.info(f"No relevant code found for analysis in category {category}. Skipping.")
                        continue
                        
                    # --- NEW: Add chunks to unique set for attack path analysis ---
                    for chunk in relevant_code_chunks:
                        # Create a simple key (consider hashing content for robustness if needed)
                        chunk_key = (chunk.metadata.get('relative_path', ''), chunk.page_content)
                        if chunk_key not in unique_analysis_chunks:
                            unique_analysis_chunks[chunk_key] = chunk
                    # --- End NEW ---

                    files_involved = {chunk.metadata.get('relative_path') for chunk in relevant_code_chunks}
                    self.logger.debug(f"Proceeding to analysis for {category} on {len(relevant_code_chunks)} chunks across {len(files_involved)} files.")

                    # Pre-computation Check for Analysis Cost

                    if analysis_stopped_early:
                         break 

                    vulnerabilities, input_tokens, output_tokens = security_analyzer.analyze_code_for_category(
                        relevant_code_chunks,
                        category
                    )
                    
                    self.logger.info(f"--- Verifying LLM Findings for category '{category}' via Agent Workflow ---")
                    self.logger.debug(f"Raw vulnerabilities received for category {category}: {vulnerabilities}")
                    verified_vulnerabilities = self._verify_findings_via_agent(category, vulnerabilities)
                    
                    llm_findings_by_category[category].extend(verified_vulnerabilities)
                    all_vulnerabilities.extend(verified_vulnerabilities)


            else:    
                 raw_llm_count = sum(len(v) for v in llm_findings_by_category.values())
                 self.logger.info(f"Completed LLM analysis for all categories. Found {raw_llm_count} raw LLM findings.")
                 
        

            self.logger.info("--- Step 5: Generating final report ---")
            report_generator = ReportGenerator(output_dir=output_dir)
            report_result = report_generator.generate_report(
                repo_name,
                llm_findings_by_category,
            )
            
            duration = time.time() - start_time


            # Update total findings count based on raw LLM findings sent to the report generator
            # The report generator now internally creates ConsolidatedFinding objects.
            # For the orchestrator's summary, we use the count of raw findings we sent.
            total_code_vulns = raw_llm_count
            total_all_findings = total_code_vulns

            self.logger.info(f"--- Analysis complete for {local_path} --- Duration: {duration:.2f} seconds ---")
            self.logger.info(f"Found a total of {total_all_findings} potential security issues (from LLM analysis)")
            
            self.logger.info(f"Reports saved to: {report_result['markdown_path']}")
            
            final_result = {
                "status": "success_partial" if analysis_stopped_early else "success",
                "repo_name": repo_name,
                "total_findings": total_all_findings,
                "report_paths": {
                    "markdown": report_result['markdown_path'],
                    "html": report_result['html_path']
                },
                "duration": duration,
                "analysis_stopped_early": analysis_stopped_early,
                "findings": []
            }
  
            return final_result
            
        except SystemExit as se:
            self.logger.error(f"Analysis stopped prematurely: {se}")
            if 'persist_dir' in locals() and os.path.exists(persist_dir):
                try:
                    self.logger.debug(f"Cleaning up vector database due to SystemExit: {persist_dir}")
                    shutil.rmtree(persist_dir)
                except OSError as e_rm:
                    self.logger.error(f"Failed to remove vector database directory {persist_dir} during SystemExit: {e_rm}")

            error_result = {
                "status": "error", 
                "repo_name": repo_name if 'repo_name' in locals() else local_path,
                "error": str(se),
                "findings": [],
                "report_paths": None, 
                "duration": 0,
                "analysis_stopped_early": True
            }
            return error_result
  
        except Exception as e:
            end_time = time.time()
            duration = end_time - start_time
            self.logger.error(f"Error during security analysis: {e}")
            if 'persist_dir' in locals() and os.path.exists(persist_dir):
                try:
                    self.logger.debug(f"Cleaning up vector database due to Exception: {persist_dir}")
                    shutil.rmtree(persist_dir)
                except OSError as e_rm:
                    self.logger.error(f"Failed to remove vector database directory {persist_dir} during Exception: {e_rm}")
            
            error_result = {
                "status": "error", 
                "repo_name": repo_name if 'repo_name' in locals() else local_path,
                "error": str(e),
                "findings": [],
                "analysis_duration_seconds": duration,
                "report_paths": None,
                "analysis_stopped_early": analysis_stopped_early
            }
            return error_result
        finally:
            # Clean up the specific vector database directory for this repo after analysis,
            # UNLESS it was already cleaned up in SystemExit or Exception blocks
            # Note: persist_dir might not be defined if error occurred before its creation
            if 'persist_dir' in locals() and os.path.exists(persist_dir):
                try:
                    self.logger.debug(f"Final cleanup of vector database: {persist_dir}")
                    shutil.rmtree(persist_dir)
                    self.logger.debug(f"Successfully removed {persist_dir} in finally block")
                except FileNotFoundError:
                    self.logger.debug(f"Vector database {persist_dir} already removed or never created.")
                except OSError as e_rm:
                    self.logger.error(f"Failed to remove vector database directory {persist_dir} in finally block: {e_rm}")
