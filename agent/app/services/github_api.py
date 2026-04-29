import hashlib
import hmac

import httpx
import structlog

from app.config import get_settings

log = structlog.get_logger().bind(service="github_api")

GITHUB_API = "https://api.github.com"


def _headers() -> dict[str, str]:
    settings = get_settings()
    return {
        "Authorization": f"Bearer {settings.github_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


async def post_pr_comment(repo: str, pr_number: int, body: str) -> None:
    """Post a comment on a pull request."""
    url = f"{GITHUB_API}/repos/{repo}/issues/{pr_number}/comments"
    log.info("posting_pr_comment", repo=repo, pr=pr_number, body_len=len(body))

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(url, headers=_headers(), json={"body": body})
        resp.raise_for_status()

    log.info("pr_comment_posted", repo=repo, pr=pr_number)


async def set_commit_status(
    repo: str, sha: str, state: str, description: str
) -> None:
    """Set a commit status (success, failure, error, pending)."""
    url = f"{GITHUB_API}/repos/{repo}/statuses/{sha}"
    log.info("setting_commit_status", repo=repo, sha=sha[:8], state=state)

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            url,
            headers=_headers(),
            json={
                "state": state,
                "description": description,
                "context": "security-ai-agent",
            },
        )
        resp.raise_for_status()

    log.info("commit_status_set", repo=repo, sha=sha[:8], state=state)


async def post_pr_review(
    repo: str,
    pr_number: int,
    body: str,
    comments: list[dict],
    event: str = "COMMENT",
) -> None:
    """Submit a formal GitHub PR review with optional inline comments.

    Args:
        repo: "owner/repo"
        pr_number: pull request number
        body: top-level review summary (appears in the Conversation tab)
        comments: list of dicts with keys:
            path (str)        — file path as shown in the diff
            line (int)        — new-file line number
            side (str)        — "RIGHT" for added/context lines (default)
            body (str)        — comment text; wrap suggested code in
                               ```suggestion\\n<code>\\n``` for Apply button
        event: "COMMENT" | "APPROVE" | "REQUEST_CHANGES"
    """
    url = f"{GITHUB_API}/repos/{repo}/pulls/{pr_number}/reviews"
    log.info("posting_pr_review", repo=repo, pr=pr_number,
             inline_count=len(comments), event=event)

    # Normalise comments — GitHub requires `side` and expects no extra keys
    clean_comments = []
    for c in comments:
        entry: dict = {
            "path": c["path"],
            "line": c["line"],
            "side": c.get("side", "RIGHT"),
            "body": c["body"],
        }
        clean_comments.append(entry)

    payload: dict = {"body": body, "event": event}
    if clean_comments:
        payload["comments"] = clean_comments

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(url, headers=_headers(), json=payload)
        if resp.status_code not in (200, 201):
            log.error("pr_review_failed", status=resp.status_code, body=resp.text[:300])
            resp.raise_for_status()

    log.info("pr_review_posted", repo=repo, pr=pr_number, inline_count=len(clean_comments))


async def validate_webhook_signature(
    body: bytes, signature: str, secret: str
) -> bool:
    """Validate GitHub webhook HMAC-SHA256 signature."""
    if not signature or not secret:
        log.warning("missing_signature_or_secret")
        return False

    expected = "sha256=" + hmac.new(
        secret.encode(), body, hashlib.sha256
    ).hexdigest()

    is_valid = hmac.compare_digest(expected, signature)
    if not is_valid:
        log.warning("invalid_webhook_signature")
    return is_valid
