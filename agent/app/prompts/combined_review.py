"""
Combined security analysis + code-quality review prompt.

The model produces a markdown security review followed by a single JSON block
containing risk metadata and inline code review comments.  Parsing is done by
the analyze_review_node via regex on the JSON block at the end.
"""
from __future__ import annotations


def build_combined_review_prompt(
    pr_number: int,
    pr_title: str,
    pr_body: str,
    sender: str,
    classification: str,
    diff: str,
    annotated_diff: str,
    trivy_summary: str,
    semgrep_findings: str,
    gitleaks_findings: str,
    checkov_findings: str,
    osv_findings: str,
    repo_history_summary: str,
) -> str:
    return f"""You are a senior Application Security Engineer and code reviewer.
Perform both a security review and a code quality review for this pull request.

## CONTEXT
- **PR:** #{pr_number} — {pr_title}
- **Author:** {sender}
- **Classification:** {classification}
- **Description:** {pr_body or "No description provided."}

## REPOSITORY HISTORY
{repo_history_summary}

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

## ANNOTATED DIFF FOR INLINE COMMENTS
Lines prefixed with a number are added/context lines eligible for inline comments.
Lines starting with "   -" are removed lines — do NOT reference their line numbers.

{annotated_diff[:8000]}

---

## OUTPUT FORMAT — JSON FIRST, then markdown

═══════════════════════════════════════════════════════════════════
**STEP 1 — MANDATORY JSON BLOCK (must be the FIRST content of your reply):**
═══════════════════════════════════════════════════════════════════

Output the JSON object below on its very first line. No prose, no fences,
no leading whitespace before it. Replace the placeholders.

{{"risk_score": "<CRITICAL|HIGH|MEDIUM|LOW|INFO>", "verdict": "<APPROVE|REQUEST_CHANGES|BLOCK>", "code_review_summary": "<2-4 sentence overall code quality assessment>", "comments": [{{"file": "<path as shown in diff>", "line": <integer>, "severity": "<critical|high|medium|low>", "type": "<security|bug|performance|style|maintainability>", "title": "<max 60 chars>", "description": "<1-3 sentences>", "suggestion": "<corrected code or empty string>"}}]}}

RULES for the JSON block:
- It MUST be the very FIRST line of your reply (before any markdown).
- It MUST be valid JSON parseable by Python json.loads() — single-line, no fences.
- If there are no inline issues, output `"comments": []`.

RULES for comments[]:
- Only reference lines appearing in the annotated diff above.
- `line` must match exactly a line number shown — never invent numbers.
- `suggestion` must contain only replacement code, or empty string.
- Output the 5–8 most important comments, prioritising security and bugs.
- For every security finding you mention in the markdown below (SQL injection,
  XSS, path traversal, command injection, weak crypto, IDOR, CSRF, insecure
  deserialization, hardcoded secrets), include a matching comment in this
  JSON block IF the line appears in the annotated diff.

═══════════════════════════════════════════════════════════════════
**STEP 2 — MARKDOWN SECURITY REVIEW (after the JSON, on a new line):**
═══════════════════════════════════════════════════════════════════

### Security Review — PR #{pr_number}

**Risk Score:** [must match the JSON `risk_score`]
**Verdict:** [must match the JSON `verdict`]

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
"""
