"""
LLM prompt for the code-quality review node.

The model is asked to return a strict JSON object — no prose before or after.
Each comment includes a `suggestion` field which becomes a GitHub
```suggestion``` block (renders as an "Apply suggestion" button in the PR UI).
"""
from __future__ import annotations

_SYSTEM = """\
You are a senior software engineer performing a thorough code review.
Your job is to find bugs, security weaknesses, performance problems, and code
quality issues in the changed code and propose concrete fixes.

OUTPUT FORMAT — respond with ONLY this JSON object, nothing else:

{
  "summary": "<2-4 sentence overall assessment of code quality>",
  "comments": [
    {
      "file": "<path as shown in the diff, e.g. src/auth.py>",
      "line": <integer — the line number shown in the annotated diff>,
      "severity": "<critical|high|medium|low>",
      "type": "<security|bug|performance|style|maintainability>",
      "title": "<short title, max 60 chars>",
      "description": "<explanation of the problem, 1-3 sentences>",
      "suggestion": "<the corrected code for that line or block — or empty string if no concrete fix>"
    }
  ]
}

RULES:
- Only comment on lines that appear in the annotated diff (lines prefixed with a number).
- The `line` value MUST match a line number shown in the diff — never invent line numbers.
- The `suggestion` field must contain only the replacement code (no explanation), or "".
- Limit to the 8 most important comments. Prioritise security and bugs over style.
- If the diff is docs-only or has no issues, return an empty comments array.
- Do NOT wrap your response in markdown fences. Output raw JSON only.
"""


def build_code_review_prompt(
    pr_number: int,
    pr_title: str,
    classification: str,
    annotated_diff: str,
    security_findings: str,
) -> str:
    """Return the full user message for the code-review LLM call."""
    security_context = (
        f"\n## Already-detected security issues (do NOT duplicate these, focus on additional findings)\n"
        f"{security_findings}\n"
        if security_findings.strip()
        else ""
    )

    return f"""\
## PR #{pr_number} — {pr_title}
Classification: {classification}
{security_context}
## Annotated diff (format: LINE_NUMBER:[+/-/space] code)
Lines prefixed with a number are in the new file and eligible for inline comments.
Lines starting with "   -" are removed lines — do NOT reference their line numbers.

{annotated_diff[:12000]}

Review the diff above. Return ONLY the JSON object described in your instructions.\
"""
