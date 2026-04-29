import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.fixture
def mock_pool():
    """Create a mock async connection pool."""
    mock_cur = AsyncMock()
    mock_cur.description = [
        ("pr_number",), ("pr_title",), ("classification",),
        ("risk_score",), ("verdict",), ("scan_summary",), ("created_at",),
    ]
    mock_cur.fetchall = AsyncMock(return_value=[
        (1, "Fix auth bug", "feature", "HIGH", "REQUEST_CHANGES", {}, "2024-01-01"),
        (2, "Update deps", "dependency", "LOW", "APPROVE", {}, "2024-01-02"),
    ])
    mock_cur.fetchone = AsyncMock(return_value=None)

    mock_conn = AsyncMock()
    mock_conn.cursor = MagicMock(return_value=mock_cur)
    mock_conn.commit = AsyncMock()
    mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_conn.__aexit__ = AsyncMock()

    mock_cur.__aenter__ = AsyncMock(return_value=mock_cur)
    mock_cur.__aexit__ = AsyncMock()

    pool = AsyncMock()
    pool.connection = MagicMock(return_value=mock_conn)

    return pool, mock_conn, mock_cur


@pytest.mark.asyncio
async def test_get_repo_history(mock_pool):
    """Test fetching repo review history."""
    pool, mock_conn, mock_cur = mock_pool

    with patch("app.services.knowledge._pool", pool):
        with patch("app.services.knowledge._get_pool", return_value=pool):
            from app.services.knowledge import get_repo_history
            results = await get_repo_history("testorg/testrepo", limit=10)

    assert len(results) == 2
    assert results[0]["pr_number"] == 1
    assert results[0]["risk_score"] == "HIGH"
    assert results[1]["classification"] == "dependency"


@pytest.mark.asyncio
async def test_save_scan_result(mock_pool):
    """Test saving a scan result to the database."""
    pool, mock_conn, mock_cur = mock_pool

    with patch("app.services.knowledge._pool", pool):
        with patch("app.services.knowledge._get_pool", return_value=pool):
            from app.services.knowledge import save_scan_result
            await save_scan_result(
                repo="testorg/testrepo",
                scan_type="trivy_fs",
                trigger_type="pr_review",
                trigger_ref="42",
                summary={"CRITICAL": 1, "HIGH": 3},
            )

    mock_cur.execute.assert_called_once()
    call_args = mock_cur.execute.call_args
    assert "INSERT INTO scan_results" in call_args[0][0]


@pytest.mark.asyncio
async def test_save_pr_review(mock_pool):
    """Test upserting a PR review record."""
    pool, mock_conn, mock_cur = mock_pool

    with patch("app.services.knowledge._pool", pool):
        with patch("app.services.knowledge._get_pool", return_value=pool):
            from app.services.knowledge import save_pr_review
            await save_pr_review(
                repo="testorg/testrepo",
                pr_number=42,
                pr_title="Add auth",
                pr_author="devuser",
                classification="feature",
                risk_score="HIGH",
                verdict="REQUEST_CHANGES",
                review_markdown="## Review\nIssues found.",
                scan_summary={"trivy_fs": {"CRITICAL": 1}},
                files_changed=["app.py", "auth.py"],
            )

    mock_cur.execute.assert_called_once()
    call_args = mock_cur.execute.call_args
    assert "INSERT INTO pr_reviews" in call_args[0][0]
    assert "ON CONFLICT" in call_args[0][0]


@pytest.mark.asyncio
async def test_update_repo_profile(mock_pool):
    """Test upserting repo profile with risk score."""
    pool, mock_conn, mock_cur = mock_pool

    with patch("app.services.knowledge._pool", pool):
        with patch("app.services.knowledge._get_pool", return_value=pool):
            from app.services.knowledge import update_repo_profile
            await update_repo_profile("testorg/testrepo", "HIGH")

    mock_cur.execute.assert_called_once()
    call_args = mock_cur.execute.call_args
    assert "INSERT INTO repo_profiles" in call_args[0][0]


@pytest.mark.asyncio
async def test_get_repo_profile_not_found(mock_pool):
    """Test getting a repo profile that doesn't exist."""
    pool, mock_conn, mock_cur = mock_pool
    mock_cur.fetchone = AsyncMock(return_value=None)

    with patch("app.services.knowledge._pool", pool):
        with patch("app.services.knowledge._get_pool", return_value=pool):
            from app.services.knowledge import get_repo_profile
            result = await get_repo_profile("nonexistent/repo")

    assert result is None
