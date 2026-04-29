"""Artifact store — persists raw scanner outputs and PR summaries to disk.

Directory layout:
    {artifacts_path}/
    ├── scans/
    │   └── {owner}-{repo}/
    │       └── pr-{number}/
    │           ├── trivy_image.json
    │           ├── trivy_fs.json
    │           ├── gitleaks.json
    │           ├── semgrep.json
    │           ├── checkov.json
    │           ├── osv.json
    │           └── summary.json
    └── logs/
        └── agent.log   (written by main.py log handler)
"""

import json
from datetime import datetime, timezone
from pathlib import Path

import structlog

log = structlog.get_logger().bind(service="artifact_store")


def _pr_dir(base: str, repo: str, pr_number: int) -> Path:
    """Return (and create) the directory for a specific PR's artifacts."""
    safe_repo = repo.replace("/", "-")
    path = Path(base) / "scans" / safe_repo / f"pr-{pr_number}"
    path.mkdir(parents=True, exist_ok=True)
    return path


def save_scan_artifact(
    base: str, repo: str, pr_number: int, scanner: str, data: dict
) -> None:
    """Write raw scanner output to <pr_dir>/<scanner>.json."""
    try:
        dest = _pr_dir(base, repo, pr_number) / f"{scanner}.json"
        with open(dest, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)
        log.debug("artifact_saved", scanner=scanner, path=str(dest))
    except Exception as exc:
        log.warning("artifact_save_failed", scanner=scanner, error=str(exc))


def save_pr_summary(
    base: str, repo: str, pr_number: int, summary: dict
) -> None:
    """Write final PR review metadata to <pr_dir>/summary.json."""
    try:
        dest = _pr_dir(base, repo, pr_number) / "summary.json"
        summary = {**summary, "saved_at": datetime.now(timezone.utc).isoformat()}
        with open(dest, "w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=2, default=str)
        log.debug("summary_saved", pr=pr_number, path=str(dest))
    except Exception as exc:
        log.warning("summary_save_failed", pr=pr_number, error=str(exc))
