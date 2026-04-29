import asyncio
import json

import structlog

log = structlog.get_logger().bind(service="osv")


async def scan_lockfiles(repo_path: str) -> dict:
    """Run OSV-Scanner on the repository to find dependency vulnerabilities."""
    log.info("scanning_dependencies", path=repo_path)

    proc = await asyncio.create_subprocess_exec(
        "osv-scanner",
        "--json",
        "-r", repo_path,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()

    # osv-scanner exits 0 = clean, 1 = vulns found, other = error
    if proc.returncode not in (0, 1):
        error_msg = stderr.decode().strip()[-500:]
        log.error("osv_scan_failed", returncode=proc.returncode, stderr=error_msg)
        return {"scan_type": "osv", "vulnerabilities": [], "count": 0, "error": error_msg}

    output = stdout.decode().strip()
    if not output:
        log.info("osv_clean", path=repo_path)
        return {"scan_type": "osv", "vulnerabilities": [], "count": 0}

    try:
        raw = json.loads(output)
    except json.JSONDecodeError:
        log.warning("osv_parse_error", output=output[:200])
        return {"scan_type": "osv", "vulnerabilities": [], "count": 0, "error": "JSON parse failed"}

    return parse_osv_output(raw)


def parse_osv_output(raw: dict) -> dict:
    """Parse OSV-Scanner JSON output into structured vulnerabilities."""
    vulns = []
    results = raw.get("results", [])

    for result in results:
        source = result.get("source", {})
        source_path = source.get("path", "")

        for pkg in result.get("packages", []):
            pkg_info = pkg.get("package", {})
            pkg_name = pkg_info.get("name", "")
            pkg_version = pkg_info.get("version", "")
            pkg_ecosystem = pkg_info.get("ecosystem", "")

            for vuln in pkg.get("vulnerabilities", []):
                vulns.append({
                    "id": vuln.get("id", ""),
                    "summary": vuln.get("summary", "")[:200],
                    "severity": _extract_severity(vuln),
                    "package_name": pkg_name,
                    "package_version": pkg_version,
                    "ecosystem": pkg_ecosystem,
                    "source_file": source_path,
                    "aliases": vuln.get("aliases", [])[:3],
                    "fixed_version": _extract_fixed_version(vuln, pkg_name),
                })

    log.info("osv_parsed", count=len(vulns))

    return {
        "scan_type": "osv",
        "vulnerabilities": vulns[:20],
        "count": len(vulns),
        "raw": raw,
    }


def _extract_severity(vuln: dict) -> str:
    """Extract the highest severity from a vulnerability's severity list."""
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "MEDIUM": 2, "LOW": 3}
    best = "UNKNOWN"
    best_rank = 99

    for sev in vuln.get("database_specific", {}).get("severity", ""):
        if isinstance(sev, str) and sev.upper() in severity_order:
            rank = severity_order[sev.upper()]
            if rank < best_rank:
                best = sev.upper()
                best_rank = rank

    for sev_entry in vuln.get("severity", []):
        score = sev_entry.get("score", "")
        if "CRITICAL" in str(score).upper():
            return "CRITICAL"
        elif "HIGH" in str(score).upper():
            if best_rank > 1:
                best = "HIGH"
                best_rank = 1

    return best


def _extract_fixed_version(vuln: dict, pkg_name: str) -> str:
    """Try to extract the fixed version from affected ranges."""
    for affected in vuln.get("affected", []):
        if affected.get("package", {}).get("name", "") == pkg_name:
            for rng in affected.get("ranges", []):
                for event in rng.get("events", []):
                    if "fixed" in event:
                        return event["fixed"]
    return ""
