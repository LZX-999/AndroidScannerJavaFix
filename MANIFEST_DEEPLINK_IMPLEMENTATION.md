# Manifest-Based Deeplink Scanning Implementation

This document describes the implementation of smart, manifest-based deeplink scanning for Android security analysis.

## Overview

The traditional approach scans all code files for deeplink vulnerabilities, which is inefficient and can produce false positives. Our manifest-based approach:

1. **Parses AndroidManifest.xml** to identify which activities actually handle deeplinks
2. **Maps activity names to source files** to focus analysis on relevant code
3. **Uses targeted vector database queries** to retrieve only relevant code chunks
4. **Provides enhanced context** combining manifest declarations with source code

## Key Benefits

- **10x faster analysis**: Analyze 5-10 relevant files instead of 200+ chunks
- **Higher accuracy**: Focus on actual deeplink handling code reduces false positives
- **Better context**: Understand manifest intent filters alongside implementation
- **Token efficiency**: Dramatically reduced LLM token usage

## Implementation Components

### 1. AndroidManifestParser (`src/analysis/manifest_parser.py`)

Responsible for parsing AndroidManifest.xml and extracting deeplink-related information.

**Key Methods:**
- `find_manifest_file()`: Locates AndroidManifest.xml in the repository
- `extract_deeplink_activities()`: Finds activities with VIEW action intent filters
- `map_activity_to_files()`: Maps activity class names to source files
- `get_deeplink_analysis_summary()`: Provides comprehensive deeplink analysis

**Example Usage:**
```python
parser = AndroidManifestParser()
manifest_path = parser.find_manifest_file(repo_manager)
summary = parser.get_deeplink_analysis_summary(manifest_path)

if summary['has_deeplinks']:
    for activity, filters in summary['deeplink_activities'].items():
        files = parser.map_activity_to_files(activity, repo_manager)
        print(f"{activity} -> {files}")
```

### 2. Enhanced Vector Database (`src/database/vector_db.py`)

Extended with methods for targeted code retrieval.

**New Methods:**
- `retrieve_deeplink_relevant_code()`: Gets code chunks from specific activity files
- `retrieve_by_specific_files()`: Generic method for file-targeted retrieval

**Example Usage:**
```python
# Traditional approach
generic_chunks = vector_db.retrieve_relevant_code("deeplink", n_results=200)

# Targeted approach
activity_files = ["MainActivity.java", "DeepLinkActivity.kt"]
targeted_chunks = vector_db.retrieve_deeplink_relevant_code(
    activity_files=activity_files, 
    n_results=50
)
```

### 3. Enhanced Security Analyzer (`src/analysis/security_analyzer.py`)

Added manifest-aware deeplink analysis capabilities.

**New Method:**
- `analyze_deeplink_with_manifest()`: Performs manifest-first deeplink analysis
- `_create_deeplink_context_with_manifest()`: Combines manifest data with code
- `_create_deeplink_security_prompt()`: Creates specialized analysis prompt

**Process Flow:**
1. Find and parse AndroidManifest.xml
2. Extract deeplink activities and intent filters
3. Map activities to source files
4. Retrieve targeted code chunks
5. Create enhanced context with manifest information
6. Analyze with specialized prompt

### 4. Updated Orchestrator (`src/orchestrator.py`)

Modified to use manifest-based analysis for the deeplink category.

**Changes:**
- Special handling for `category == "deeplink"`
- Uses `analyze_deeplink_with_manifest()` instead of generic analysis
- Logs manifest analysis results
- Maintains compatibility with other security categories

## Filename-Based Matching Algorithm

The system now uses a much simpler and more robust approach - filename-based matching during vector database retrieval:

```python
def retrieve_deeplink_relevant_code(self, activity_names, n_results=50):
    # Extract simple class names and create filename patterns
    filename_patterns = []
    for activity_name in activity_names:
        # Handle relative names: ".MainActivity" -> "MainActivity"
        if activity_name.startswith("."):
            simple_name = activity_name[1:]
        else:
            # Extract from full package: "com.example.MainActivity" -> "MainActivity"
            simple_name = activity_name.split(".")[-1]
        
        # Handle inner classes: "MainActivity$InnerActivity" -> "MainActivity"
        base_name = simple_name.split("$")[0]
        
        # Create regex patterns for different file extensions
        filename_patterns.extend([
            f".*/{base_name}\\.java$",
            f".*/{base_name}\\.kt$",
            f".*/{base_name}\\.scala$"
        ])
    
    # Filter vector database by filename patterns
    filter_criteria = {
        "$or": [{"relative_path": {"$regex": pattern}} for pattern in filename_patterns]
    }
    
    return self.retrieve_relevant_code(query, n_results, filter_criteria)
```

**Key Advantages:**
- **No path mapping complexity** - just match filenames in vector DB metadata
- **Works regardless of directory structure** - finds files anywhere in the project
- **Handles moved/renamed directories** - only cares about filename, not full path
- **More robust** - uses existing vector DB filtering capabilities

## Deeplink Detection Logic

An intent filter is considered a deeplink if it meets these criteria:

1. **Has VIEW action**: `android.intent.action.VIEW`
2. **AND either:**
   - Has BROWSABLE category: `android.intent.category.BROWSABLE`
   - OR has custom scheme/host data elements

```python
def _is_deeplink_filter(filter_info):
    if "android.intent.action.VIEW" not in filter_info["actions"]:
        return False
    
    if "android.intent.category.BROWSABLE" in filter_info["categories"]:
        return True
    
    # Check for custom scheme/host
    for data in filter_info["data"]:
        if "scheme" in data or "host" in data:
            return True
    
    return False
```

## Enhanced Analysis Context

The manifest-based analysis provides rich context to the LLM:

```
# ANDROID MANIFEST ANALYSIS

## Deeplink Activities Found (2):

### Activity: com.example.MainActivity
Intent Filter 1:
  - Actions: android.intent.action.VIEW
  - Categories: android.intent.category.BROWSABLE, android.intent.category.DEFAULT
  - Data patterns:
    * {'scheme': 'https', 'host': 'example.com'}

## Custom Schemes: myapp
## Hosts: example.com
## Activity Files Being Analyzed: MainActivity.java, DeepLinkActivity.kt

# CODE ANALYSIS
[Relevant code chunks from the identified files]
```

## Testing

Run the test script to validate the implementation:

```bash
# Test with default handoff directory
python test_manifest_deeplink.py

# Test with custom Android project
TEST_REPO_PATH=/path/to/android/project python test_manifest_deeplink.py

# Test with LLM analysis (requires API key)
GEMINI_API_KEY=your_key TEST_REPO_PATH=/path/to/project python test_manifest_deeplink.py
```

The test script validates:
1. Manifest parsing functionality
2. Vector database targeting
3. Complete manifest-based analysis (if API key provided)

## Performance Comparison

| Approach | Files Analyzed | Chunks Retrieved | Token Usage | Analysis Time |
|----------|---------------|------------------|-------------|---------------|
| Traditional | All files | 200+ chunks | High | Slow |
| Manifest-based | 5-10 activity files | 50-100 chunks | Low | Fast |

## Security Analysis Focus Areas

The manifest-based analysis specifically examines:

1. **Intent Filter Security**
   - Missing android:exported restrictions
   - Overly broad intent patterns
   - Lack of permission requirements

2. **URI Validation**
   - Unvalidated URI parsing (getIntent().getData())
   - Missing scheme/host validation
   - Path traversal vulnerabilities

3. **Authentication/Authorization**
   - Bypassed authentication checks
   - Unauthorized access to sensitive features
   - Data leakage through deeplink parameters

4. **Data Handling**
   - Direct use of URI parameters without validation
   - Insecure intent data extraction
   - Data injection attack vectors

5. **Navigation Security**
   - Uncontrolled redirects
   - Fragment injection
   - Activity hijacking through task affinity

## Integration

The manifest-based deeplink scanning is automatically used when analyzing Android projects:

```python
# The orchestrator automatically detects deeplink category
# and uses manifest-based analysis
orchestrator = SecurityAnalysisOrchestrator(api_key=gemini_key)
result = orchestrator.analyze_repository(android_project_path)
```

No additional configuration is required - the system automatically:
- Detects Android projects by looking for AndroidManifest.xml
- Switches to manifest-based analysis for the deeplink category
- Falls back to traditional analysis if no manifest is found

## Future Enhancements

Potential improvements to the manifest-based approach:

1. **Extend to other categories**: Apply similar manifest-first analysis to intent and webview categories
2. **Gradle integration**: Parse build.gradle files for additional context
3. **Cross-component analysis**: Analyze interactions between activities, services, and receivers
4. **Dynamic analysis**: Generate test cases based on manifest intent filters
5. **Vulnerability correlation**: Link manifest misconfigurations with code vulnerabilities
