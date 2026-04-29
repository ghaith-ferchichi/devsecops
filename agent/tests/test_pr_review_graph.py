import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.fixture
def initial_state():
    """Build an initial PRReviewState dict for testing."""
    return {
        "workflow_type": "pull_request",
        "repo_full_name": "testorg/testrepo",
        "trigger_ref": "42",
        "current_stage": "pending",
        "error": "",
        "messages": [],
        "pr_number": 42,
        "clone_url": "https://github.com/testorg/testrepo.git",
        "head_branch": "feature/auth",
        "head_sha": "abc123def456789",
        "pr_title": "Add user authentication endpoint",
        "pr_body": "Implements JWT-based auth.",
        "pr_url": "https://github.com/testorg/testrepo/pull/42",
        "sender": "devuser",
        "repo_path": "",
        "diff": "",
        "has_dockerfile": False,
        "docker_image_tag": "",
        "pr_classification": "",
        "files_changed": [],
        "scan_results": {},
        "security_review": "",
        "risk_score": "INFO",
        "verdict": "APPROVE",
        "approval_status": "auto",
        "repo_history": [],
        "started_at": "",
    }


@pytest.mark.asyncio
async def test_intake_node_success(initial_state):
    """Test intake node clones repo and fetches diff successfully."""
    with (
        patch("app.workflows.pr_review.nodes.github_api") as mock_github,
        patch("app.workflows.pr_review.nodes.git_service") as mock_git,
        patch("app.workflows.pr_review.nodes.docker_service") as mock_docker,
        patch("app.workflows.pr_review.nodes.knowledge") as mock_knowledge,
    ):
        mock_github.post_pr_comment = AsyncMock()
        mock_git.clone_repo = AsyncMock(return_value="/tmp/agent-workspace/testrepo")
        mock_git.get_pr_diff = AsyncMock(return_value="diff --git a/app.py b/app.py\n+new code")
        mock_git.truncate_diff = MagicMock(side_effect=lambda x: x)
        mock_git.extract_changed_files = MagicMock(return_value=["app.py"])
        mock_docker.check_dockerfile = AsyncMock(return_value=False)
        mock_knowledge.get_repo_history = AsyncMock(return_value=[])

        from app.workflows.pr_review.nodes import intake_node
        result = await intake_node(initial_state)

        assert result["current_stage"] == "intake"
        assert result["repo_path"] == "/tmp/agent-workspace/testrepo"
        assert result["files_changed"] == ["app.py"]
        assert result["has_dockerfile"] is False
        assert "error" not in result


@pytest.mark.asyncio
async def test_intake_node_clone_failure(initial_state):
    """Test intake node handles clone failure gracefully."""
    with (
        patch("app.workflows.pr_review.nodes.github_api") as mock_github,
        patch("app.workflows.pr_review.nodes.git_service") as mock_git,
    ):
        mock_github.post_pr_comment = AsyncMock()
        mock_git.clone_repo = AsyncMock(side_effect=RuntimeError("clone failed"))

        from app.workflows.pr_review.nodes import intake_node
        result = await intake_node(initial_state)

        assert result["error"] == "clone failed"


@pytest.mark.asyncio
async def test_classify_node_docs(initial_state):
    """Test classify node identifies docs-only PR."""
    initial_state["files_changed"] = ["README.md", "docs/setup.md"]
    initial_state["pr_title"] = "Update documentation"

    with patch("app.workflows.pr_review.nodes.get_classifier_llm") as mock_llm_factory:
        mock_llm = MagicMock()
        mock_response = MagicMock()
        mock_response.content = json.dumps({
            "classification": "docs",
            "reasoning": "Only markdown files changed",
            "risk_hint": "low",
            "focus_areas": ["documentation"],
        })
        mock_llm.ainvoke = AsyncMock(return_value=mock_response)
        mock_llm_factory.return_value = mock_llm

        from app.workflows.pr_review.nodes import classify_node
        result = await classify_node(initial_state)

        assert result["pr_classification"] == "docs"


@pytest.mark.asyncio
async def test_skip_scan_node(initial_state):
    """Test skip_scan node returns empty scan results."""
    initial_state["pr_classification"] = "docs"

    from app.workflows.pr_review.nodes import skip_scan_node
    result = await skip_scan_node(initial_state)

    assert result["scan_results"] == {}
    assert result["current_stage"] == "scan"


@pytest.mark.asyncio
async def test_route_scans_docs():
    """Test route_scans routes docs to skip_scan."""
    from app.workflows.pr_review.edges import route_scans
    state = {"pr_classification": "docs", "has_dockerfile": False, "error": ""}
    assert route_scans(state) == "skip_scan"


@pytest.mark.asyncio
async def test_route_scans_with_dockerfile():
    """Test route_scans routes to scan_full when Dockerfile present."""
    from app.workflows.pr_review.edges import route_scans
    state = {"pr_classification": "feature", "has_dockerfile": True, "error": ""}
    assert route_scans(state) == "scan_full"


@pytest.mark.asyncio
async def test_route_scans_error():
    """Test route_scans routes to error_node on error."""
    from app.workflows.pr_review.edges import route_scans
    state = {"pr_classification": "feature", "has_dockerfile": False, "error": "something went wrong"}
    assert route_scans(state) == "error_node"


@pytest.mark.asyncio
async def test_route_risk_critical():
    """Test route_risk routes CRITICAL to escalate."""
    from app.workflows.pr_review.edges import route_risk
    state = {"risk_score": "CRITICAL", "error": ""}
    assert route_risk(state) == "escalate"


@pytest.mark.asyncio
async def test_route_risk_low():
    """Test route_risk routes LOW to report."""
    from app.workflows.pr_review.edges import route_risk
    state = {"risk_score": "LOW", "error": ""}
    assert route_risk(state) == "report"


@pytest.mark.asyncio
async def test_error_node(initial_state):
    """Test error_node posts failure comment."""
    initial_state["error"] = "Trivy timeout"
    initial_state["current_stage"] = "scan"

    with (
        patch("app.workflows.pr_review.nodes.github_api") as mock_github,
        patch("app.workflows.pr_review.nodes.slack_api") as mock_slack,
    ):
        mock_github.post_pr_comment = AsyncMock()
        mock_slack.send_notification = AsyncMock()

        from app.workflows.pr_review.nodes import error_node
        result = await error_node(initial_state)

        assert result["current_stage"] == "error"
        mock_github.post_pr_comment.assert_called_once()
        call_args = mock_github.post_pr_comment.call_args
        assert "SECURITY AI AGENT" in call_args[1]["body"] or "SECURITY AI AGENT" in call_args[0][2]
