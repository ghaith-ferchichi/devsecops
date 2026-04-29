OWASP_CHECKLIST = """
## OWASP Top 10 Security Checklist
1. **A01 Broken Access Control** — Missing authorization checks, IDOR, privilege escalation
2. **A02 Cryptographic Failures** — Weak algorithms, hardcoded keys, missing encryption
3. **A03 Injection** — SQL, NoSQL, OS command, LDAP injection via unsanitized input
4. **A04 Insecure Design** — Missing threat modeling, insecure business logic
5. **A05 Security Misconfiguration** — Default credentials, verbose errors, unnecessary features
6. **A06 Vulnerable Components** — Known CVEs in dependencies, outdated packages
7. **A07 Auth Failures** — Weak passwords, missing MFA, session fixation
8. **A08 Data Integrity Failures** — Insecure deserialization, unsigned updates
9. **A09 Logging Failures** — Missing audit logs, sensitive data in logs
10. **A10 SSRF** — Unvalidated URLs, internal network access from user input
"""

RISK_SCORE_DESCRIPTIONS = {
    "CRITICAL": "Actively exploitable vulnerability with immediate business impact",
    "HIGH": "Significant security flaw requiring prompt remediation",
    "MEDIUM": "Security concern that should be addressed before merge",
    "LOW": "Minor security improvement opportunity",
    "INFO": "Informational finding, no security impact",
}

VERDICT_DESCRIPTIONS = {
    "APPROVE": "No blocking security issues found",
    "REQUEST_CHANGES": "Security issues found that must be fixed before merge",
    "BLOCK": "Critical security vulnerabilities — merge must be blocked",
}


def format_trivy_summary(scan_results: dict) -> str:
    """Format Trivy scan results into a readable summary for the LLM prompt."""
    parts = []

    for scan_type in ("trivy_image", "trivy_fs"):
        result = scan_results.get(scan_type)
        if not result or result.get("error"):
            continue

        summary = result.get("summary", {})
        total = result.get("total_count", 0)
        vulns = result.get("vulnerabilities", [])

        parts.append(f"### {scan_type.replace('_', ' ').title()} — {total} vulnerabilities")
        parts.append(
            f"| CRITICAL | HIGH | MEDIUM | LOW |\n"
            f"|----------|------|--------|-----|\n"
            f"| {summary.get('CRITICAL', 0)} | {summary.get('HIGH', 0)} "
            f"| {summary.get('MEDIUM', 0)} | {summary.get('LOW', 0)} |"
        )

        if vulns:
            parts.append("\n**Top vulnerabilities:**")
            for v in vulns[:10]:
                parts.append(
                    f"- **{v['Severity']}** `{v['VulnerabilityID']}` in `{v['PkgName']}` "
                    f"({v['InstalledVersion']} → {v.get('FixedVersion', 'no fix')}): {v.get('Title', 'N/A')}"
                )

    return "\n\n".join(parts) if parts else "No Trivy scan results available."


def format_gitleaks_findings(scan_results: dict) -> str:
    """Format Gitleaks findings into a readable summary for the LLM prompt."""
    gitleaks = scan_results.get("gitleaks", {})
    if gitleaks.get("error"):
        return "### Secrets Scan\nGitleaks scan failed."

    findings = gitleaks.get("findings", [])
    count = gitleaks.get("count", 0)

    if count == 0:
        return "### Secrets Scan\nNo secrets detected by Gitleaks."

    parts = [f"### Secrets Scan — {count} finding(s)"]
    for f in findings:
        parts.append(
            f"- **{f.get('RuleID', 'unknown')}** in `{f.get('File', '?')}` "
            f"(line {f.get('StartLine', '?')}): {f.get('Description', '')}"
        )

    return "\n".join(parts)


def format_semgrep_findings(scan_results: dict) -> str:
    """Format Semgrep SAST findings for the LLM prompt."""
    semgrep = scan_results.get("semgrep", {})
    if semgrep.get("error"):
        return "### SAST (Semgrep)\nSemgrep scan failed."

    findings = semgrep.get("findings", [])
    count = semgrep.get("count", 0)
    summary = semgrep.get("summary", {})

    if count == 0:
        return "### SAST (Semgrep)\nNo SAST findings."

    parts = [
        f"### SAST (Semgrep) — {count} finding(s)",
        f"Severity breakdown: ERROR={summary.get('ERROR', 0)}, "
        f"WARNING={summary.get('WARNING', 0)}, INFO={summary.get('INFO', 0)}",
    ]

    shown = 0
    for f in findings:
        if f["severity"] == "INFO":
            continue
        if shown >= 15:
            break
        cwe = f.get("metadata", {}).get("cwe", [])
        cwe_str = f" (CWE: {', '.join(cwe[:2])})" if cwe else ""
        parts.append(
            f"- **{f['severity']}** `{f['check_id']}` in `{f['path']}:{f['start_line']}`{cwe_str}\n"
            f"  {f.get('message', '')[:150]}"
        )
        shown += 1

    return "\n".join(parts)


def format_checkov_findings(scan_results: dict) -> str:
    """Format Checkov IaC findings for the LLM prompt."""
    checkov = scan_results.get("checkov", {})
    if checkov.get("error"):
        return "### IaC Security (Checkov)\nCheckov scan failed."

    failed_checks = checkov.get("failed_checks", [])
    passed = checkov.get("passed", 0)
    failed = checkov.get("failed", 0)

    if failed == 0:
        return f"### IaC Security (Checkov)\nAll {passed} checks passed. No misconfigurations found."

    parts = [f"### IaC Security (Checkov) — {failed} failed / {passed} passed"]

    for c in failed_checks[:15]:
        parts.append(
            f"- **{c.get('check_id', '?')}** ({c.get('check_type', '?')}) "
            f"in `{c.get('file_path', '?')}` resource `{c.get('resource', '?')}`"
        )

    return "\n".join(parts)


def format_osv_findings(scan_results: dict) -> str:
    """Format OSV-Scanner dependency vulnerability findings for the LLM prompt."""
    osv = scan_results.get("osv", {})
    if osv.get("error"):
        return "### Dependency Vulnerabilities (OSV-Scanner)\nOSV scan failed."

    vulns = osv.get("vulnerabilities", [])
    count = osv.get("count", 0)

    if count == 0:
        return "### Dependency Vulnerabilities (OSV-Scanner)\nNo known vulnerabilities in dependencies."

    parts = [f"### Dependency Vulnerabilities (OSV-Scanner) — {count} finding(s)"]

    for v in vulns[:15]:
        aliases = ", ".join(v.get("aliases", []))
        alias_str = f" ({aliases})" if aliases else ""
        fixed = v.get("fixed_version", "")
        fix_str = f" → fix: {fixed}" if fixed else ""
        parts.append(
            f"- **{v.get('severity', 'UNKNOWN')}** `{v['id']}`{alias_str} in "
            f"`{v['package_name']}@{v['package_version']}` ({v.get('ecosystem', '?')}){fix_str}\n"
            f"  {v.get('summary', '')[:150]}"
        )

    return "\n".join(parts)


def format_repo_history(history: list[dict]) -> str:
    """Format past PR reviews into a context summary."""
    if not history:
        return "No previous reviews for this repository."

    parts = [f"This repository has had {len(history)} previous review(s)."]

    risk_counts: dict[str, int] = {}
    for review in history:
        risk = review.get("risk_score", "UNKNOWN")
        risk_counts[risk] = risk_counts.get(risk, 0) + 1

    risk_summary = ", ".join(f"{k}: {v}" for k, v in sorted(risk_counts.items()))
    parts.append(f"Risk distribution: {risk_summary}")

    parts.append("\nRecent reviews:")
    for review in history[:5]:
        parts.append(
            f"- PR #{review.get('pr_number', '?')} ({review.get('classification', '?')}) "
            f"— Risk: {review.get('risk_score', '?')}, Verdict: {review.get('verdict', '?')}"
        )

    return "\n".join(parts)
