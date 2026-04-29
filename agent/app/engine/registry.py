import structlog
from langgraph.graph.state import CompiledStateGraph as CompiledGraph
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

log = structlog.get_logger().bind(service="registry")

WORKFLOW_REGISTRY: dict[str, CompiledGraph] = {}


def register_all_workflows(checkpointer: AsyncPostgresSaver) -> None:
    """Register all active workflow graphs in the registry."""
    from app.workflows.pr_review.graph import build_pr_review_graph

    pr_graph = build_pr_review_graph(checkpointer)
    WORKFLOW_REGISTRY["pull_request"] = pr_graph
    log.info("workflow_registered", workflow="pull_request")

    # Future workflows:
    # WORKFLOW_REGISTRY["build_completed"] = pipeline_gate_graph
    # WORKFLOW_REGISTRY["scheduled_audit"] = audit_graph
    # WORKFLOW_REGISTRY["cve_alert"] = cve_watch_graph
    # WORKFLOW_REGISTRY["runtime_alert"] = incident_triage_graph
    # WORKFLOW_REGISTRY["compliance_check"] = compliance_drift_graph
