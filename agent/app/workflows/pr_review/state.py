from typing import Literal

from app.models.state import AgentState


class PRReviewState(AgentState):
    """Extended state for the PR review workflow."""
    # Input
    pr_number: int
    clone_url: str
    head_branch: str
    head_sha: str
    base_branch: str
    pr_title: str
    pr_body: str
    pr_url: str
    sender: str

    # Populated by nodes
    repo_path: str
    diff: str
    has_dockerfile: bool
    docker_image_tag: str
    pr_classification: str  # "feature" | "dependency" | "infrastructure" | "docs" | "config"
    files_changed: list[str]
    scan_results: dict  # {"trivy_image": {...}, "trivy_fs": {...}, "gitleaks": {...}}
    security_review: str  # Full markdown review from LLM
    risk_score: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    verdict: Literal["APPROVE", "REQUEST_CHANGES", "BLOCK"]
    approval_status: str  # "auto" | "pending" | "approved" | "rejected"
    repo_history: list[dict]  # Past reviews for context injection
    started_at: str  # ISO timestamp

    # Code-quality review (populated by code_review_node)
    code_review_summary: str      # 2-4 sentence overall assessment
    code_review_comments: list[dict]  # [{file, line, severity, type, title, description, suggestion}]
