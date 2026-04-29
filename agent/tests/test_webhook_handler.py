import json
from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from tests.conftest import make_signature


@pytest.fixture
def mock_settings():
    """Override settings for testing."""
    with patch("app.routers.webhooks.get_settings") as mock:
        settings = mock.return_value
        settings.github_webhook_secret = "test-webhook-secret"
        yield settings


@pytest.fixture
def mock_dispatch():
    with patch("app.routers.webhooks.dispatch_event", new_callable=AsyncMock) as mock:
        yield mock


@pytest.fixture
def mock_validate():
    with patch("app.routers.webhooks.validate_webhook_signature", new_callable=AsyncMock) as mock:
        yield mock


@pytest.mark.asyncio
async def test_invalid_hmac_returns_403(sample_pr_webhook, mock_settings, mock_validate):
    """Test that an invalid HMAC signature returns 403."""
    mock_validate.return_value = False

    from app.main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        body = json.dumps(sample_pr_webhook).encode()
        resp = await client.post(
            "/webhooks/github",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-GitHub-Event": "pull_request",
                "X-Hub-Signature-256": "sha256=invalid",
            },
        )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_non_pull_request_event_ignored(sample_pr_webhook, mock_settings, mock_validate):
    """Test that non-pull_request events are ignored."""
    mock_validate.return_value = True

    from app.main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        body = json.dumps(sample_pr_webhook).encode()
        resp = await client.post(
            "/webhooks/github",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-GitHub-Event": "push",
                "X-Hub-Signature-256": make_signature(body, "test-webhook-secret"),
            },
        )
    assert resp.status_code == 200
    assert resp.json()["message"] == "event ignored"


@pytest.mark.asyncio
async def test_pull_request_closed_action_ignored(sample_pr_webhook, mock_settings, mock_validate):
    """Test that pull_request with action='closed' is ignored."""
    mock_validate.return_value = True
    sample_pr_webhook["action"] = "closed"

    from app.main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        body = json.dumps(sample_pr_webhook).encode()
        resp = await client.post(
            "/webhooks/github",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-GitHub-Event": "pull_request",
                "X-Hub-Signature-256": make_signature(body, "test-webhook-secret"),
            },
        )
    assert resp.status_code == 200
    assert resp.json()["message"] == "action ignored"


@pytest.mark.asyncio
async def test_valid_pull_request_returns_202(
    sample_pr_webhook, mock_settings, mock_validate, mock_dispatch
):
    """Test that a valid pull_request opened returns 202 with task_id."""
    mock_validate.return_value = True

    from app.main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        body = json.dumps(sample_pr_webhook).encode()
        resp = await client.post(
            "/webhooks/github",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-GitHub-Event": "pull_request",
                "X-Hub-Signature-256": make_signature(body, "test-webhook-secret"),
            },
        )
    assert resp.status_code == 202
    data = resp.json()
    assert data["message"] == "processing"
    assert "task_id" in data
