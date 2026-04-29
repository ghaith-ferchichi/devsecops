from langgraph.graph import END, StateGraph
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

from app.workflows.pr_review.state import PRReviewState
from app.workflows.pr_review.nodes import (
    intake_node,
    classify_node,
    scan_full_node,
    scan_fs_node,
    skip_scan_node,
    analyze_review_node,
    escalate_node,
    report_node,
    error_node,
)
from app.workflows.pr_review.edges import route_scans, route_risk


def build_pr_review_graph(checkpointer: AsyncPostgresSaver):
    """Build and compile the PR review LangGraph workflow."""
    builder = StateGraph(PRReviewState)

    # Add nodes
    builder.add_node("intake", intake_node)
    builder.add_node("classify", classify_node)
    builder.add_node("scan_full", scan_full_node)
    builder.add_node("scan_fs", scan_fs_node)
    builder.add_node("skip_scan", skip_scan_node)
    builder.add_node("analyze", analyze_review_node)
    builder.add_node("escalate", escalate_node)
    builder.add_node("report", report_node)
    builder.add_node("error_node", error_node)

    # Set entry point
    builder.set_entry_point("intake")

    # Linear edges
    builder.add_edge("intake", "classify")

    # Conditional: classify → scan routing
    builder.add_conditional_edges(
        "classify",
        route_scans,
        {
            "scan_full": "scan_full",
            "scan_fs": "scan_fs",
            "skip_scan": "skip_scan",
            "error_node": "error_node",
        },
    )

    # All scan nodes → analyze
    builder.add_edge("scan_full", "analyze")
    builder.add_edge("scan_fs", "analyze")
    builder.add_edge("skip_scan", "analyze")

    # Conditional: analyze → risk routing
    builder.add_conditional_edges(
        "analyze",
        route_risk,
        {
            "escalate": "escalate",
            "report": "report",
            "error_node": "error_node",
        },
    )

    # Escalate → report
    builder.add_edge("escalate", "report")

    # Terminal edges
    builder.add_edge("report", END)
    builder.add_edge("error_node", END)

    # Compile with checkpointer and interrupt_before for Slack approval gate
    graph = builder.compile(
        checkpointer=checkpointer,
        interrupt_before=["escalate"],
    )

    return graph
