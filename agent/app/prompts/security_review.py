def build_security_review_prompt(
    pr_number: int,
    pr_title: str,
    pr_body: str,
    sender: str,
    classification: str,
    diff: str,
    trivy_summary: str,
    semgrep_findings: str,
    gitleaks_findings: str,
    checkov_findings: str,
    osv_findings: str,
    repo_history_summary: str,
    focus_areas: str = "",
) -> str:
    """Build the full system prompt for the security review LLM."""
    return f"""You are a senior Application Security Engineer performing a thorough code review.

## CONTEXT
- **PR:** #{pr_number} — {pr_title}
- **Author:** {sender}
- **Classification:** {classification}
- **Description:** {pr_body or "No description provided."}

## REPOSITORY HISTORY
{repo_history_summary}

## YOUR TASK
Analyze the code diff and vulnerability scan results. Produce a thorough security review.
Focus especially on: {focus_areas or "general security concerns"}

## CODE DIFF
```diff
{diff}
```

## SCAN RESULTS

### Trivy (vulnerabilities + misconfigurations)
{trivy_summary}

### Semgrep (SAST findings)
{semgrep_findings}

### Gitleaks (secrets detected)
{gitleaks_findings}

### Checkov (IaC security)
{checkov_findings}

### OSV-Scanner (dependency vulnerabilities)
{osv_findings}

## OUTPUT FORMAT

Produce this exact markdown structure. Be specific — cite files and lines.

### Security Review — PR #{pr_number}

**Risk Score:** [CRITICAL / HIGH / MEDIUM / LOW / INFO]
**Verdict:** [APPROVE / REQUEST_CHANGES / BLOCK]

#### Code Analysis
(OWASP Top 10: injection, XSS, SSRF, path traversal, command injection,
insecure deserialization, broken auth, sensitive data exposure, insecure crypto,
hardcoded secrets. Cite file:line for each finding.)

#### Dependency and Container Analysis
(Trivy + OSV findings. Specific versions to upgrade.)

#### Secrets Scan
(Gitleaks findings — file, line, secret type.)

#### Infrastructure Security
(Checkov findings — misconfigurations in Dockerfiles, k8s, terraform.)

#### SAST Findings
(Semgrep findings — rule ID, severity, file, line.)

#### Recommendations
(Numbered list, ordered by severity.)

After your review, output EXACTLY this JSON on its own line:
```json
{{"risk_score": "<CRITICAL|HIGH|MEDIUM|LOW|INFO>", "verdict": "<APPROVE|REQUEST_CHANGES|BLOCK>"}}
```
"""
