# Testing the Manifest-Based Deeplink Scanner

## Quick Usage

The test script now supports command-line arguments for easy testing.

### Basic Usage

```bash
# Show help and available options
python test_manifest_deeplink.py --help

# Test with default directory (./handoff)
python test_manifest_deeplink.py

# Test with specific directory
python test_manifest_deeplink.py --directory /path/to/android/project

# Test with verbose logging
python test_manifest_deeplink.py --directory /path/to/android/project --verbose

# Test with API key for full LLM analysis
python test_manifest_deeplink.py --directory /path/to/android/project --api-key your_gemini_key
```

### Directory Selection Priority

The test script selects the directory to scan in this order:

1. **Command line argument**: `--directory /path/to/project`
2. **Environment variable**: `TEST_REPO_PATH=/path/to/project`  
3. **Default**: `./handoff`

### Examples

```bash
# Test a specific Android project
python test_manifest_deeplink.py -d ~/Downloads/MyAndroidApp

# Test with environment variable
export TEST_REPO_PATH=/home/user/android-projects/sample-app
python test_manifest_deeplink.py

# Full test with API key and verbose output
python test_manifest_deeplink.py \
  --directory /path/to/android/project \
  --api-key your_gemini_api_key \
  --verbose
```

## Test Output

The script runs 3 tests:

1. **Manifest Parser Test**: Tests AndroidManifest.xml parsing and deeplink detection
2. **Vector Database Targeting Test**: Tests filename-based code retrieval  
3. **Complete Analysis Test**: Tests full manifest-based deeplink analysis (requires API key)

### Success Output Example

```
🚀 Starting Manifest-Based Deeplink Analysis Tests
📁 Using test repository: /path/to/android/project
🔑 API key provided - will run full LLM analysis test

============================================================
=== Testing AndroidManifestParser ===
✅ Found AndroidManifest.xml at: /path/to/project/AndroidManifest.xml
📊 Manifest Analysis Results:
   - Total deeplink activities: 2
   - Has deeplinks: True
   - Custom schemes: ['myapp']
   - Hosts: ['example.com']
   - Exported components: 3
🔗 Deeplink Activities Found:
   - com.example.MainActivity: 1 intent filter(s)
     Mapped to files: ['src/main/java/MainActivity.java']
✅ Test 1: Manifest Parser - PASSED

============================================================
=== Testing Vector Database Targeting ===
📄 Processed 45 code chunks
📊 Indexed 45 chunks in vector database
🎯 Target activity names: ['com.example.MainActivity']
🔍 Retrieved 8 targeted chunks
🔍 Generic query retrieved 12 chunks
📈 Targeting efficiency: 8/12 chunks
✅ Test 2: Vector Database Targeting - PASSED

============================================================
=== Testing Manifest-Based Deeplink Analysis ===
🔍 Running manifest-based deeplink analysis...
📊 Analysis Results:
   - Vulnerabilities found: 1
   - Input tokens: 1234
   - Output tokens: 567
   - Manifest activities: 2
   - Has deeplinks: True
🚨 Vulnerabilities Found:
   - Unvalidated URI Parsing: High
✅ Test 3: Manifest-Based Analysis - PASSED

============================================================
📊 Test Results: 3/3 tests passed
🎉 All tests passed! Manifest-based deeplink scanning is working correctly.
```

## Troubleshooting

### Common Issues

1. **"No AndroidManifest.xml found"**
   - Ensure you're pointing to an Android project directory
   - The manifest should be at `<project>/AndroidManifest.xml` or `<project>/app/src/main/AndroidManifest.xml`

2. **"ModuleNotFoundError: No module named 'google'"**
   - Install dependencies: `pip install -r requirements.txt`
   - The google-generativeai package is needed

3. **"No deeplinks found in manifest"**
   - This is normal for projects that don't use deeplinks
   - The test will still pass, just with 0 deeplink activities

4. **"API key not provided"**
   - Test 3 will be skipped without an API key
   - Tests 1 and 2 will still run and validate the core functionality

### Environment Setup

```bash
# Set up environment for testing
export GEMINI_API_KEY="your_api_key_here"
export TEST_REPO_PATH="/path/to/default/android/project"

# Or use command line arguments (recommended)
python test_manifest_deeplink.py \
  --directory /path/to/android/project \
  --api-key your_api_key
```

The test script is designed to work with or without dependencies, gracefully handling missing components and providing useful feedback about what's working and what needs attention.
