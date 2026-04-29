from app.config import get_settings
from app.workflows.pr_review.state import PRReviewState


def route_scans(state: PRReviewState) -> str:
    """Route to the appropriate scan node based on classification and Dockerfile presence."""
    if state.get("error"):
        return "error_node"

    classification = state.get("pr_classification", "feature")
    if classification == "docs":
        return "skip_scan"
    if state.get("has_dockerfile", False):
        return "scan_full"
    return "scan_fs"


def route_risk(state: PRReviewState) -> str:
    """Route based on risk score — HIGH/CRITICAL escalate only if Slack is configured."""
    if state.get("error"):
        return "error_node"

    risk = state.get("risk_score", "MEDIUM")
    if risk in ("CRITICAL", "HIGH"):
        settings = get_settings()
        if settings.slack_escalation_enabled:
            return "escalate"
    return "report"
