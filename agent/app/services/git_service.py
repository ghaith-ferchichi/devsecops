import asyncio
import re
from pathlib import Path

import httpx
import structlog

from app.config import get_settings

log = structlog.get_logger().bind(service="git")


async def clone_repo(clone_url: str, branch: str, workspace: str) -> Path:
    """Shallow-clone a repo branch into the workspace directory."""
    settings = get_settings()

    # Inject token for private repo access
    if settings.github_token:
        clone_url = clone_url.replace(
            "https://github.com",
            f"https://{settings.github_token}@github.com",
        )

    repo_name = clone_url.rstrip("/").split("/")[-1].replace(".git", "")
    dest = Path(workspace) / repo_name
    if dest.exists():
        import shutil
        shutil.rmtree(dest)

    log.info("cloning_repo", url=clone_url[:40] + "...", branch=branch, dest=str(dest))

    proc = await asyncio.create_subprocess_exec(
        "git", "clone", "--depth", "1", "--branch", branch, clone_url, str(dest),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()

    if proc.returncode != 0:
        error_msg = stderr.decode().strip()
        log.error("clone_failed", returncode=proc.returncode, stderr=error_msg)
        raise RuntimeError(f"git clone failed: {error_msg}")

    log.info("clone_success", dest=str(dest))
    return dest


async def get_local_diff(repo_path: Path, base_branch: str) -> str:
    """Fetch the base branch tip and produce a -U15 diff inside the cloned repo."""
    log.info("local_diff_start", path=str(repo_path), base=base_branch)

    proc = await asyncio.create_subprocess_exec(
        "git", "fetch", "--depth=1", "origin", base_branch,
        cwd=str(repo_path),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
    if proc.returncode != 0:
        raise RuntimeError(f"git fetch failed: {stderr.decode().strip()}")

    proc = await asyncio.create_subprocess_exec(
        "git", "diff", "-U15", "FETCH_HEAD..HEAD",
        cwd=str(repo_path),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
    diff = stdout.decode()
    log.info("local_diff_generated", length=len(diff))
    return diff


async def get_pr_diff(repo_full_name: str, pr_number: int) -> str:
    """Fetch the PR diff from GitHub API."""
    settings = get_settings()
    url = f"https://api.github.com/repos/{repo_full_name}/pulls/{pr_number}"

    async with httpx.AsyncClient(timeout=60) as client:
        resp = await client.get(
            url,
            headers={
                "Authorization": f"Bearer {settings.github_token}",
                "Accept": "application/vnd.github.v3.diff",
            },
        )
        resp.raise_for_status()
        diff = resp.text

    log.info("diff_fetched", repo=repo_full_name, pr=pr_number, length=len(diff))
    return diff


def extract_changed_files(diff: str) -> list[str]:
    """Parse changed file paths from a unified diff."""
    pattern = r"^diff --git a/.+ b/(.+)$"
    return list(dict.fromkeys(re.findall(pattern, diff, re.MULTILINE)))


def truncate_diff(diff: str, max_chars: int = 30000) -> str:
    """Truncate diff if it exceeds max_chars."""
    if len(diff) <= max_chars:
        return diff
    return diff[:max_chars] + (
        f"\n\n... [DIFF TRUNCATED — {len(diff)} chars, showing first {max_chars}] ..."
    )
