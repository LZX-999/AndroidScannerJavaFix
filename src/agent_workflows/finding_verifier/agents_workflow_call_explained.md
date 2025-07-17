# Why Is `.run` Called Without Arguments in `workflow.py`?

## The Mechanism: Function References and Workflow Engines

In `workflow.py`, agent nodes like `ExploitabilityAgentNode` are added to a `StateGraph` using:

```python
graph.add_node("exploitability_analysis", exploitability_agent.run)
```

Notice that `.run` is referenced **without parentheses or arguments**.

## How Does This Work?

- `exploitability_agent.run` is a **function reference** (not a function call).
- The `StateGraph` (from the `langgraph` library) expects each node to be a callable that takes the current workflow state as an argument.
- When the workflow is executed (e.g., via `compiled_graph.invoke(initial_state)`), the workflow engine automatically calls each node's function, passing the current state as the argument.

## Example

- You do **not** call `.run(state)` directly.
- Instead, you register the function, and the workflow engine calls it for you:

```python
# Registration (no arguments)
graph.add_node("exploitability_analysis", exploitability_agent.run)

# Execution (engine supplies the state)
final_graph_state = compiled_graph.invoke(initial_state)
```

- Internally, the engine does something like:
  ```python
  next_state = exploitability_agent.run(current_state)
  ```

## Why Use This Pattern?

- **Decouples** the workflow definition from the execution logic.
- **Ensures** that each agent node receives the correct state at the right time.
- **Simplifies** the workflow code: you only need to provide function references, not manage state passing yourself.

## Summary

Although `.run` is referenced without arguments in `workflow.py`, the workflow engine (StateGraph/LangGraph) is responsible for calling it with the workflow state at runtime. This is a common pattern in workflow and graph-based execution frameworks.
