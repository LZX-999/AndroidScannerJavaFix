# Why Do All Agent Classes in `agents.py` Take the Same Arguments?

## Inheritance and Constructor Delegation

All four agent classes in `agents.py` (`ExploitabilityAgentNode`, `ContextAnalysisAgentNode`, `ImpactAssessmentAgentNode`, `SynthesisAgentNode`) inherit from a common base class called `AgentNode`.

### Base Class: `AgentNode`

- The `AgentNode` class defines an `__init__` constructor that takes two arguments:
  - `llm_client` (e.g., a GeminiClient instance)
  - `code_tools` (e.g., a CodeAnalysisTools instance)
- This constructor sets up the shared dependencies for all agent nodes.

### Subclasses

- Each agent class (e.g., `ExploitabilityAgentNode`) **inherits** from `AgentNode` and does **not** override the constructor.
- This means they automatically use the base class constructor, so they must be instantiated with the same arguments: `llm_client` and `code_tools`.

### Usage in `workflow.py`

- When you see code like `ExploitabilityAgentNode(gemini_client, code_analysis_tools)` in `workflow.py`, it matches the constructor defined in the base class.
- This is possible because of inheritance: the subclass uses the base class's `__init__` unless it defines its own.

### Why Use This Pattern?

- **Consistency:** All agent nodes are created in the same way, making the workflow code simpler and less error-prone.
- **Code Reuse:** Shared logic (like storing dependencies or utility methods) lives in the base class, avoiding duplication.
- **Extensibility:** If a new agent node is added, it can inherit the same constructor and shared logic.

### Summary

This is a standard object-oriented inheritance pattern. The base class defines the constructor and shared logic, and all subclasses inherit this behavior. The arguments passed during instantiation in `workflow.py` match the base class constructor, not the subclass, unless the subclass overrides it.
