import asyncio
import json

import structlog

from app.config import get_settings

log = structlog.get_logger().bind(service="trivy")

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


async def scan_image(image_tag: str, severity: str | None = None) -> dict:
    """Run Trivy image scan and return parsed results."""
    settings = get_settings()
    sev = severity or settings.trivy_severity

    log.info("scanning_image", image=image_tag, severity=sev)

    proc = await asyncio.create_subprocess_exec(
        "trivy", "image",
        "--format", "json",
        "--severity", sev,
        "--timeout", "5m0s",
        image_tag,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()

    if proc.returncode != 0:
        error_msg = stderr.decode().strip()
        log.error("trivy_image_scan_failed", returncode=proc.returncode, stderr=error_msg)
        return {"scan_type": "trivy_image", "summary": {}, "vulnerabilities": [], "error": error_msg}

    raw = json.loads(stdout.decode())
    return parse_trivy_output(raw, "trivy_image")


async def scan_filesystem(path: str, severity: str | None = None) -> dict:
    """Run Trivy filesystem scan and return parsed results."""
    settings = get_settings()
    sev = severity or settings.trivy_severity

    log.info("scanning_filesystem", path=path, severity=sev)

    proc = await asyncio.create_subprocess_exec(
        "trivy", "fs",
        "--format", "json",
        "--severity", sev,
        path,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()

    if proc.returncode != 0:
        error_msg = stderr.decode().strip()
        log.error("trivy_fs_scan_failed", returncode=proc.returncode, stderr=error_msg)
        return {"scan_type": "trivy_fs", "summary": {}, "vulnerabilities": [], "error": error_msg}

    raw = json.loads(stdout.decode())
    return parse_trivy_output(raw, "trivy_fs")


def parse_trivy_output(raw: dict, scan_type: str) -> dict:
    """Parse Trivy JSON output into a structured result."""
    all_vulns = []
    results = raw.get("Results", [])

    for result in results:
        vulns = result.get("Vulnerabilities") or []
        for v in vulns:
            all_vulns.append({
                "VulnerabilityID": v.get("VulnerabilityID", ""),
                "PkgName": v.get("PkgName", ""),
                "InstalledVersion": v.get("InstalledVersion", ""),
                "FixedVersion": v.get("FixedVersion", ""),
                "Severity": v.get("Severity", "UNKNOWN"),
                "Title": v.get("Title", ""),
                "Description": v.get("Description", "")[:200],
                "Target": result.get("Target", ""),
            })

    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for v in all_vulns:
        sev = v["Severity"]
        if sev in summary:
            summary[sev] += 1

    # Sort by severity and take top 15
    all_vulns.sort(key=lambda v: SEVERITY_ORDER.get(v["Severity"], 99))
    top_vulns = all_vulns[:15]

    log.info(
        "trivy_parsed",
        scan_type=scan_type,
        total=len(all_vulns),
        summary=summary,
    )

    return {
        "scan_type": scan_type,
        "summary": summary,
        "vulnerabilities": top_vulns,
        "total_count": len(all_vulns),
        "raw": raw,
    }
