import asyncio
import json

import structlog

log = structlog.get_logger().bind(service="gitleaks")


async def scan_repo(repo_path: str) -> dict:
    """Run Gitleaks secret detection on the repo."""
    log.info("scanning_secrets", path=repo_path)

    proc = await asyncio.create_subprocess_exec(
        "gitleaks", "detect",
        "--source", repo_path,
        "--report-format", "json",
        "--report-path", "/dev/stdout",
        "--no-banner",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()

    output = stdout.decode().strip()

    # Gitleaks exits with code 1 when findings exist, 0 when clean
    if proc.returncode not in (0, 1):
        error_msg = stderr.decode().strip()
        log.error("gitleaks_scan_failed", returncode=proc.returncode, stderr=error_msg)
        return {"findings": [], "count": 0, "error": error_msg}

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
