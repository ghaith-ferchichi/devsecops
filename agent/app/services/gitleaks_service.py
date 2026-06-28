import asyncio
import json
import os
import tempfile

import structlog

log = structlog.get_logger().bind(service="gitleaks")


async def scan_repo(repo_path: str) -> dict:
    """Run Gitleaks secret detection on the repo."""
    log.info("scanning_secrets", path=repo_path)

    # --no-git scans the working-tree files directly instead of git history.
    # The PR clone's history doesn't always carry the secret in a detectable
    # patch (shallow/squashed), so filesystem mode is the reliable choice for
    # reviewing the current state of the changed files.
    #
    # Gitleaks 8.30+ does not reliably stream the JSON report to /dev/stdout
    # (it silently writes nothing), so we write to a temp file and read it back.
    fd, report_path = tempfile.mkstemp(suffix=".json", prefix="gitleaks-")
    os.close(fd)
    try:
        proc = await asyncio.create_subprocess_exec(
            "gitleaks", "detect",
            "--source", repo_path,
            "--no-git",
            "--report-format", "json",
            "--report-path", report_path,
            "--no-banner",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()

        # Gitleaks exits with code 1 when findings exist, 0 when clean
        if proc.returncode not in (0, 1):
            error_msg = stderr.decode().strip()
            log.error("gitleaks_scan_failed", returncode=proc.returncode, stderr=error_msg)
            return {"findings": [], "count": 0, "error": error_msg}

        try:
            with open(report_path, encoding="utf-8") as f:
                output = f.read().strip()
        except OSError:
            output = ""
    finally:
        try:
            os.unlink(report_path)
        except OSError:
            pass

    if not output or output == "null":
        log.info("gitleaks_clean", path=repo_path)
        return {"findings": [], "count": 0}

    try:
        findings = json.loads(output)
    except json.JSONDecodeError:
        log.warning("gitleaks_parse_error", output=output[:200])
        return {"findings": [], "count": 0, "error": "Failed to parse output"}

    if not isinstance(findings, list):
        findings = []

    parsed = [
        {
            "RuleID": f.get("RuleID", ""),
            "Description": f.get("Description", ""),
            "File": f.get("File", ""),
            "StartLine": f.get("StartLine", 0),
            "EndLine": f.get("EndLine", 0),
            "Match": f.get("Match", "")[:50] + "..." if len(f.get("Match", "")) > 50 else f.get("Match", ""),
        }
        for f in findings
    ]

    log.info("gitleaks_findings", count=len(parsed), path=repo_path)
    return {"findings": parsed, "count": len(parsed)}
