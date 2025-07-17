# Explanation of `agents.py`

This document explains the structure and logic of `src/agent_workflows/finding_verifier/agents.py`, which implements a modular agent-based workflow for verifying security findings using LLMs and code analysis tools.

---

## Overview

The file defines several agent nodes, each responsible for a specific stage in the security finding verification process. Each agent uses a language model (LLM) and code analysis tools to analyze findings, assess exploitability, context, impact, and synthesize results.

---

## Key Components

### 1. **AgentNode (Base Class)**

- **Purpose:** Abstract base class for all agent nodes.
- **Constructor:** Takes an LLM client and code analysis tools.
- **Utility Method:** `_parse_llm_json_output` cleans and parses LLM output, ensuring it matches expected JSON keys.

---

### 2. **ExploitabilityAgentNode**

- **Purpose:** Determines if a vulnerability is exploitable.
- **Workflow:**
  - Gathers context: code around the finding, execution path, data flow, and protections.
  - Constructs a detailed prompt for the LLM, asking for a JSON output with keys: `status`, `confidence`, `reasoning`, `data_source_analysis`.
  - Parses and returns the LLM's analysis.

---

### 3. **ContextAnalysisAgentNode**

- **Purpose:** Analyzes the context of the vulnerability (auth, data access, error handling).
- **Workflow:**
  - Collects code context and related code snippets.
  - Uses exploitability results as input.
  - Prompts the LLM for a JSON output with `risk_level` and `attack_scenario_description`.
  - Parses and returns the LLM's analysis.

---

### 4. **ImpactAssessmentAgentNode**

- **Purpose:** Assesses the business impact of the vulnerability.
- **Workflow:**
  - Uses context and exploitability results.
  - Prompts the LLM for a JSON output with `business_impact_rating` and `specific_consequences`.
  - Parses and returns the LLM's analysis.

---

### 5. **SynthesisAgentNode**

- **Purpose:** Synthesizes all previous analyses into a final, actionable assessment.
- **Workflow:**
  - Combines raw finding, exploitability, context, and impact results.
  - Prompts the LLM for a JSON output with keys: `final_priority`, `actionable_remediation_steps`, `overall_reasoning`, `verified_description`, `verified_severity`.
  - Updates the finding with verification status and details.

---

## Workflow Summary

1. **ExploitabilityAgentNode**: Is the finding exploitable?
2. **ContextAnalysisAgentNode**: What is the context and risk?
3. **ImpactAssessmentAgentNode**: What is the business impact?
4. **SynthesisAgentNode**: What is the final priority and recommended action?

Each agent builds on the results of the previous, using LLMs for structured, explainable outputs.

---

## Logging

- Extensive debug and info logging is used throughout for traceability and troubleshooting.

---

## Error Handling

- If the LLM output is invalid or missing, agents return error results with default values.

---

## Dependencies

- Relies on `GeminiClient` for LLM interaction and `CodeAnalysisTools` for static/dynamic code analysis.
- Uses types from `graph_state.py` for structured results.

---

## Conclusion

This file implements a robust, multi-stage agent workflow for automated, explainable security finding verification, leveraging both code analysis and LLM reasoning.
