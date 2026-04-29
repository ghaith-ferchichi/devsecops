import asyncio
import json

import structlog

log = structlog.get_logger().bind(service="checkov")


async def scan_iac(repo_path: str) -> dict:
    """Run Checkov IaC security scan on the repository."""
    log.info("scanning_iac", path=repo_path)

    proc = await asyncio.create_subprocess_exec(
        "checkov",
        "-d", repo_path,
        "--output", "json",
        "--quiet",
        "--compact",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()

    output = stdout.decode().strip()
    if not output:
        log.info("checkov_no_output", path=repo_path)
        return {"scan_type": "checkov", "failed_checks": [], "passed": 0, "failed": 0}

    try:
        raw = json.loads(output)
    except json.JSONDecodeError:
        error_msg = stderr.decode().strip()[-500:]
        log.warning("checkov_parse_error", output=output[:200], stderr=error_msg)
        return {"scan_type": "checkov", "failed_checks": [], "passed": 0, "failed": 0, "error": "JSON parse failed"}

    return parse_checkov_output(raw)


def parse_checkov_output(raw: dict | list) -> dict:
    """Parse Checkov JSON output into structured results."""
    # Checkov can return a list (multiple frameworks) or a single dict
    if isinstance(raw, list):
        all_failed = []
        total_passed = 0
        total_failed = 0
        for framework_result in raw:
            passed, failed, checks = _extract_framework(framework_result)
            total_passed += passed
            total_failed += failed
            all_failed.extend(checks)
    else:
        total_passed, total_failed, all_failed = _extract_framework(raw)

    log.info("checkov_parsed", passed=total_passed, failed=total_failed)

    return {
        "scan_type": "checkov",
        "failed_checks": all_failed[:20],
        "passed": total_passed,
        "failed": total_failed,
        "raw": raw,
    }


def _extract_framework(result: dict) -> tuple[int, int, list[dict]]:
    """Extract checks from a single framework result."""
    summary = result.get("summary", {})
    passed = summary.get("passed", 0)
    failed = summary.get("failed", 0)

    failed_checks = []
    for check in result.get("results", {}).get("failed_checks", []):
        failed_checks.append({
            "check_id": check.get("check_id", ""),
            "check_type": check.get("check_type", ""),
            "resource": check.get("resource", ""),
            "file_path": check.get("file_path", ""),
            "guideline": check.get("guideline", ""),
            "severity": check.get("severity", "MEDIUM"),
        })

    return passed, failed, failed_checks
