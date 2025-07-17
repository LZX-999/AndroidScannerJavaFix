# Explanation of `code_analysis_tools.py`

This document explains the structure and logic of `src/agent_workflows/finding_verifier/tools/code_analysis_tools.py`, which provides code analysis utilities for the agent workflow, focusing on static analysis, semantic context extraction, and security pattern detection.

---

## Overview

The file defines the `CodeAnalysisTools` class, which acts as a toolkit for analyzing source code in the context of security findings. It leverages repository management, vector search, and tree-sitter parsing to provide semantic and syntactic insights.

---

## Key Components

### 1. **Configuration Patterns**

- **PROTECTION_CHECKS_CONFIG**:  
  A list of dictionaries defining tree-sitter queries for detecting insecure or secure coding patterns (e.g., unsafe SQL execution, HTML escaping). Each entry specifies the language, query, description, and type (protection present or lacking).

- **DATA_SOURCE_PATTERNS**:  
  Categorizes common code patterns as "user_controlled", "internal_generation", "trusted_source", or "file_operations" to help classify data origins in data flow analysis.

- **VARIABLE_ASSIGNMENT_QUERIES**:  
  Tree-sitter queries for finding variable assignments, function call assignments, attribute assignments, and function parameters in Python code.

---

## 2. **CodeAnalysisTools Class**

### **Constructor**

- Initializes with a `RepositoryManager`, `CodeVectorDatabase`, and a `TreeSitterParser`.

---

### **Key Methods**

#### a. `_get_language_from_file_path(file_path)`

- Determines the programming language from the file extension (supports Python, JS, TS).

#### b. `trace_execution_path(finding)`

- Uses tree-sitter to find the enclosing function or class for a vulnerability.
- Returns a summary of the structural context (e.g., function or class) around the vulnerable line.

#### c. `get_code_context_around_line(file_path, line_number, finding, window_size=10)`

- Retrieves the semantic code context (enclosing block) around a specific line using tree-sitter.
- Falls back to a window of lines if semantic context is unavailable.

#### d. `check_for_protections(finding)`

- Runs configured tree-sitter queries to detect the presence or absence of security protections in the relevant file.
- Returns a summary of detected patterns or notes if none are found.

#### e. `search_related_code_snippets(query, n_results=3)`

- Uses the vector database to retrieve code snippets semantically related to a query.
- Formats and returns the results for further analysis.

#### f. `trace_data_flow_backward(finding, max_depth=5)`

- Traces the data flow of a vulnerable variable backward to its sources.
- Identifies if data comes from user input, internal generation, or trusted sources.
- Uses helper methods for extracting variables, tracing assignments, and classifying sources.
- Returns a comprehensive report on data flow and risk.

---

### **Helper Methods**

- `_extract_vulnerable_variable`: Finds the variable at the vulnerable line.
- `_trace_variable_sources`: Traces assignments to the variable in the file.
- `_extract_assignment_info`: Extracts details about each assignment.
- `_determine_source_type`: Classifies the source of data in assignments.
- `_classify_data_sources`: Summarizes and categorizes all sources found.
- `_search_cross_file_assignments`: Uses vector search to find assignments in other files.
- `_generate_data_flow_report`: Formats the data flow analysis into a readable report.

---

## Workflow Summary

1. **Context Extraction:**  
   Finds the structural and semantic context of vulnerabilities.

2. **Protection Checks:**  
   Detects secure and insecure coding patterns using tree-sitter queries.

3. **Data Flow Analysis:**  
   Traces the origin of vulnerable variables and classifies their risk.

4. **Semantic Search:**  
   Retrieves related code snippets using vector search for deeper context.

---

## Logging

- Extensive debug and error logging is used for traceability and troubleshooting.

---

## Dependencies

- Relies on `RepositoryManager` for file access, `CodeVectorDatabase` for semantic search, and `TreeSitterParser` for AST parsing and queries.

---

## Conclusion

This file provides the core code analysis capabilities for the agent workflow, enabling automated, explainable, and context-aware security analysis using static analysis, semantic search, and pattern detection.
