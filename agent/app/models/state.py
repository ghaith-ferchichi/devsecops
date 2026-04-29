from typing import TypedDict, Annotated

from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages


class AgentState(TypedDict):
    """Base state shared by all workflows."""
    workflow_type: str
    repo_full_name: str
    trigger_ref: str
    current_stage: str
    error: str
    task_id: str  # Correlation ID — bound to structlog contextvars
    messages: Annotated[list[BaseMessage], add_messages]
