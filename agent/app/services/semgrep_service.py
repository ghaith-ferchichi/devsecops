import asyncio
import json

import structlog

log = structlog.get_logger().bind(service="semgrep")


async def scan_directory(path: str) -> dict:
    """Run Semgrep SAST scan on the repository directory."""
    log.info("scanning_sast", path=path)

    proc = await asyncio.create_subprocess_exec(
        "semgrep", "scan",
        "--config", "p/security-audit",
        "--config", "p/owasp-top-ten",
        "--json",
        "--quiet",
        path,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()

    if proc.returncode not in (0, 1):
        error_msg = stderr.decode().strip()[-500:]
        log.error("semgrep_scan_failed", returncode=proc.returncode, stderr=error_msg)
        return {"scan_type": "semgrep", "findings": [], "count": 0, "summary": {}, "error": error_msg}

    output = stdout.decode().strip()
    if not output:
        return {"scan_type": "semgrep", "findings": [], "count": 0, "summary": {}}

    try:
        raw = json.loads(output)
    except json.JSONDecodeError:
        log.warning("semgrep_parse_error", output=output[:200])
        return {"scan_type": "semgrep", "findings": [], "count": 0, "summary": {}, "error": "JSON parse failed"}

    return parse_semgrep_output(raw)


def parse_semgrep_output(raw: dict) -> dict:
    """Parse Semgrep JSON output into structured findings."""
    results = raw.get("results", [])

    findings = []
    for r in results:
        findings.append({
            "check_id": r.get("check_id", ""),
            "path": r.get("path", ""),
            "start_line": r.get("start", {}).get("line", 0),
            "end_line": r.get("end", {}).get("line", 0),
            "message": r.get("extra", {}).get("message", ""),
            "severity": r.get("extra", {}).get("severity", "WARNING"),
            "metadata": {
                "category": r.get("extra", {}).get("metadata", {}).get("category", ""),
                "confidence": r.get("extra", {}).get("metadata", {}).get("confidence", ""),
                "cwe": r.get("extra", {}).get("metadata", {}).get("cwe", []),
                "owasp": r.get("extra", {}).get("metadata", {}).get("owasp", []),
            },
        })

    summary = {"ERROR": 0, "WARNING": 0, "INFO": 0}
    for f in findings:
        sev = f["severity"]
        if sev in summary:
            summary[sev] += 1

    log.info("semgrep_parsed", count=len(findings), summary=summary)

    return {
        "scan_type": "semgrep",
        "findings": findings,
        "count": len(findings),
        "summary": summary,
        "raw": raw,
    }
