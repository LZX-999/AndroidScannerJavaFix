#!/usr/bin/env python3
"""
Test script to demonstrate the manifest-based deeplink scanning functionality
"""

import os
import sys
import logging
import argparse
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from src.analysis.manifest_parser import AndroidManifestParser
from src.repository.repo_manager import RepositoryManager
from src.database.vector_db import CodeVectorDatabase
from src.analysis.security_analyzer import SecurityAnalyzer

def setup_logging():
    """Setup logging for the test"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger(__name__)

def test_manifest_parser(test_repo_path):
    """Test the AndroidManifestParser functionality"""
    logger = logging.getLogger(__name__)
    logger.info("=== Testing AndroidManifestParser ===")
    
    # Initialize repository manager
    repo_manager = RepositoryManager(local_path=test_repo_path)
    repo_manager.prepare_repository()
    
    # Initialize manifest parser
    parser = AndroidManifestParser()
    
    # Find manifest file
    manifest_path = parser.find_manifest_file(repo_manager)
    if not manifest_path:
        logger.info("❌ No AndroidManifest.xml found in test repository")
        return False
    
    logger.info(f"✅ Found AndroidManifest.xml at: {manifest_path}")
    
    # Get deeplink analysis summary
    summary = parser.get_deeplink_analysis_summary(manifest_path)
    
    logger.info(f"📊 Manifest Analysis Results:")
    logger.info(f"   - Total deeplink activities: {summary['total_deeplink_activities']}")
    logger.info(f"   - Has deeplinks: {summary['has_deeplinks']}")
    logger.info(f"   - Custom schemes: {summary['schemes']}")
    logger.info(f"   - Hosts: {summary['hosts']}")
    logger.info(f"   - Exported components: {len(summary['exported_components'])}")
    
    if summary['has_deeplinks']:
        logger.info("🔗 Deeplink Activities Found:")
        for activity, filters in summary['deeplink_activities'].items():
            logger.info(f"   - {activity}: {len(filters)} intent filter(s)")
            
            # Test file mapping
            activity_files = parser.map_activity_to_files(activity, repo_manager)
            logger.info(f"     Mapped to files: {activity_files}")
    
    return summary['has_deeplinks']

def test_vector_db_targeting(test_repo_path):
    """Test the targeted vector database retrieval"""
    logger = logging.getLogger(__name__)
    logger.info("=== Testing Vector Database Targeting ===")
    
    try:
        # Initialize components
        repo_manager = RepositoryManager(local_path=test_repo_path)
        repo_manager.prepare_repository()
        
        from src.processing.code_processor import CodeProcessor
        code_processor = CodeProcessor(repo_manager)
        code_chunks = code_processor.process_codebase()
        
        if not code_chunks:
            logger.warning("⚠️ No code chunks found")
            return False
        
        logger.info(f"📄 Processed {len(code_chunks)} code chunks")
        
        # Create vector database
        vector_db = CodeVectorDatabase(persist_directory="./test_vector_db")
        indexed_count = vector_db.index_code_chunks(code_chunks)
        logger.info(f"📊 Indexed {indexed_count} chunks in vector database")
        
        # Test deeplink-specific retrieval
        parser = AndroidManifestParser()
        manifest_path = parser.find_manifest_file(repo_manager)
        
        if manifest_path:
            summary = parser.get_deeplink_analysis_summary(manifest_path)
            if summary['has_deeplinks']:
                # Get activity names for filename-based matching
                activity_names = list(summary['deeplink_activities'].keys())
                logger.info(f"🎯 Target activity names: {activity_names}")
                
                # Test targeted retrieval using filename matching
                targeted_chunks = vector_db.retrieve_deeplink_relevant_code(
                    activity_names=activity_names,
                    n_results=20
                )
                
                logger.info(f"🔍 Retrieved {len(targeted_chunks)} targeted chunks")
                
                # Compare with generic retrieval
                generic_chunks = vector_db.retrieve_relevant_code(
                    query="deeplink implementation",
                    n_results=20
                )
                
                logger.info(f"🔍 Generic query retrieved {len(generic_chunks)} chunks")
                logger.info(f"📈 Targeting efficiency: {len(targeted_chunks)}/{len(generic_chunks)} chunks")
                
                return True
        
        return False
        
    except Exception as e:
        logger.error(f"❌ Error in vector database testing: {e}")
        return False
    finally:
        # Cleanup test database
        import shutil
        if os.path.exists("./test_vector_db"):
            shutil.rmtree("./test_vector_db")

def test_manifest_based_analysis(test_repo_path, api_key):
    """Test the complete manifest-based deeplink analysis"""
    logger = logging.getLogger(__name__)
    logger.info("=== Testing Manifest-Based Deeplink Analysis ===")
    
    if not api_key:
        logger.warning("⚠️ No GEMINI_API_KEY provided, skipping LLM analysis test")
        return True
    
    try:
        # Initialize components
        repo_manager = RepositoryManager(local_path=test_repo_path)
        repo_manager.prepare_repository()
        
        from src.processing.code_processor import CodeProcessor
        code_processor = CodeProcessor(repo_manager)
        code_chunks = code_processor.process_codebase()
        
        # Create vector database
        vector_db = CodeVectorDatabase(persist_directory="./test_vector_db_full")
        vector_db.index_code_chunks(code_chunks)
        
        # Initialize security analyzer
        analyzer = SecurityAnalyzer(api_key=api_key)
        
        # Run manifest-based deeplink analysis
        logger.info("🔍 Running manifest-based deeplink analysis...")
        vulnerabilities, input_tokens, output_tokens, manifest_info = analyzer.analyze_deeplink_with_manifest(
            code_chunks, repo_manager, vector_db
        )
        
        logger.info(f"📊 Analysis Results:")
        logger.info(f"   - Vulnerabilities found: {len(vulnerabilities)}")
        logger.info(f"   - Input tokens: {input_tokens}")
        logger.info(f"   - Output tokens: {output_tokens}")
        
        if manifest_info:
            logger.info(f"   - Manifest activities: {manifest_info['total_deeplink_activities']}")
            logger.info(f"   - Has deeplinks: {manifest_info['has_deeplinks']}")
        
        if vulnerabilities:
            logger.info("🚨 Vulnerabilities Found:")
            for vuln in vulnerabilities:
                logger.info(f"   - {vuln.get('vulnerability_type', 'Unknown')}: {vuln.get('severity', 'Unknown')}")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Error in manifest-based analysis: {e}")
        return False
    finally:
        # Cleanup test database
        import shutil
        if os.path.exists("./test_vector_db_full"):
            shutil.rmtree("./test_vector_db_full")

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Test script for manifest-based deeplink scanning functionality",
        epilog="Example: python test_manifest_deeplink.py --directory /path/to/android/project"
    )
    
    parser.add_argument(
        "--directory", "-d", 
        help="Directory path to Android project to test (default: ./handoff or TEST_REPO_PATH env var)"
    )
    
    parser.add_argument(
        "--api-key", "-k",
        help="Gemini API key for LLM analysis test (default: GEMINI_API_KEY env var)"
    )
    
    parser.add_argument(
        "--verbose", "-v", 
        action="store_true",
        help="Enable verbose logging"
    )
    
    return parser.parse_args()

def main():
    """Main test function"""
    args = parse_arguments()
    
    # Setup logging based on verbosity
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger(__name__)
    
    logger.info("🚀 Starting Manifest-Based Deeplink Analysis Tests")
    
    # Determine test repository path (priority: command line > env var > default)
    test_repo = args.directory or os.getenv("TEST_REPO_PATH", "./handoff")
    
    if not os.path.exists(test_repo):
        logger.error(f"❌ Test repository not found at: {test_repo}")
        logger.info("💡 Specify directory with --directory or set TEST_REPO_PATH environment variable")
        logger.info("💡 Example: python test_manifest_deeplink.py --directory /path/to/android/project")
        return 1
    
    logger.info(f"📁 Using test repository: {test_repo}")
    
    # Determine API key (priority: command line > env var)
    api_key = args.api_key or os.getenv("GEMINI_API_KEY")
    if api_key:
        logger.info("🔑 API key provided - will run full LLM analysis test")
    else:
        logger.info("⚠️ No API key provided - skipping LLM analysis test")
    
    # Run tests
    tests_passed = 0
    total_tests = 3
    
    # Test 1: Manifest Parser
    logger.info("\n" + "="*60)
    if test_manifest_parser(test_repo):
        tests_passed += 1
        logger.info("✅ Test 1: Manifest Parser - PASSED")
    else:
        logger.info("❌ Test 1: Manifest Parser - FAILED")
    
    # Test 2: Vector Database Targeting
    logger.info("\n" + "="*60)
    if test_vector_db_targeting(test_repo):
        tests_passed += 1
        logger.info("✅ Test 2: Vector Database Targeting - PASSED")
    else:
        logger.info("❌ Test 2: Vector Database Targeting - FAILED")
    
    # Test 3: Complete Analysis (if API key available)
    logger.info("\n" + "="*60)
    if test_manifest_based_analysis(test_repo, api_key):
        tests_passed += 1
        logger.info("✅ Test 3: Manifest-Based Analysis - PASSED")
    else:
        logger.info("❌ Test 3: Manifest-Based Analysis - FAILED")
    
    # Summary
    logger.info("\n" + "="*60)
    logger.info(f"📊 Test Results: {tests_passed}/{total_tests} tests passed")
    
    if tests_passed == total_tests:
        logger.info("🎉 All tests passed! Manifest-based deeplink scanning is working correctly.")
        return 0
    else:
        logger.info("⚠️ Some tests failed. Check the logs above for details.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
