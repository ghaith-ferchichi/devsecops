# BTE Security AI Agent — Agent Internals

> An event-driven security and code quality automation engine built with **FastAPI + LangGraph + Ollama** (two-model pipeline: Qwen2.5-Coder 7B classify + 14B combined security/quality review) plus a real-time ops-assistant chat with 20 infrastructure monitoring tools, tool-result caching, and a benchmarked model selection.

---

## Table of Contents

- [Overview](#overview)
- [Two-Model LLM Architecture](#two-model-llm-architecture)
- [LangGraph Workflow — PR Review](#langgraph-workflow--pr-review)
  - [Graph Topology](#graph-topology)
  - [Node Reference](#node-reference)
  - [Scan Selection Matrix](#scan-selection-matrix)
  - [Conditional Routing](#conditional-routing)
- [Combined Review Pipeline](#combined-review-pipeline)
- [SAST JSON Cleaning](#sast-json-cleaning)
- [Diff Context — Local -U15 Diff](#diff-context--local--u15-diff)
- [Autonomous Scheduler](#autonomous-scheduler)
- [AlertManager Integration](#alertmanager-integration)
- [Artifact Store](#artifact-store)
- [Diff Parser](#diff-parser)
- [Services](#services)
- [Chat Ops — BTE Security AI Agent](#chat-ops--bte-security-ai-agent)
- [Prometheus Metrics](#prometheus-metrics)
- [Circuit Breaker & Graceful Degradation](#circuit-breaker--graceful-degradation)
- [Redis Caching & Rate Limiting](#redis-caching--rate-limiting)
- [Security Design](#security-design)
- [Configuration](#configuration)
- [Project Structure](#project-structure)
- [Work Methodology Recommendation](#work-methodology-recommendation)
- [Running Tests](#running-tests)

---

## Overview

The **BTE Security AI Agent** is a production-grade DevSecOps automation engine. It listens for GitHub webhook events, orchestrates six security scanning tools in parallel, performs dual-model LLM analysis using local Qwen2.5-Coder models, and posts actionable security reviews + inline code quality suggestions directly on pull requests.

It also runs autonomous background tasks: a 30-minute disk guard with auto-cleanup, a daily VPS health digest to Slack, and an AlertManager webhook endpoint for Prometheus-triggered auto-remediation.

### What It Does

When a Pull Request is opened or updated on GitHub:

1. **Validates** the webhook (HMAC-SHA256), deduplicates (Redis), rate-limits
2. **Clones** the repository at the PR branch
3. **Classifies** the PR using the 7B fast model (feature / dependency / infrastructure / docs / config)
4. **Scans** in parallel using a classification-driven scanner matrix:
   - **Trivy** — container image + filesystem CVE scanning
   - **Semgrep** — SAST (`p/security-audit` + `p/owasp-top-ten`)
   - **Gitleaks** — secret/credential detection
   - **Checkov** — Infrastructure-as-Code security
   - **OSV-Scanner** — dependency vulnerability scanning
5. **Analyzes + Reviews** diff + scanner output using a **single** 14B model call → full security review (OWASP Top 10, risk score, verdict) + structured JSON inline code review comments in one combined prompt
6. **Posts** the GitHub PR Review with inline `suggestion` blocks (Apply button) and the security review as a PR comment
7. **Escalates** HIGH/CRITICAL findings to Slack for human approval (optional)
8. **Persists** all raw SAST outputs to `./artifacts/scans/`, writes structured logs to `./artifacts/logs/`
9. **Stores** results in PostgreSQL for cross-PR intelligence and trend analysis

---

## Two-Model LLM Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                  Ollama — CPU-only inference                      │
│                  Port 11434 — internal Docker network only        │
│                                                                   │
│  qwen2.5-coder:7b  ──► classify_node                             │
│     4.7 GB            ~8–12 tok/s    JSON-forced                  │
│     num_ctx=4096      num_predict=512  temp=0.0  format="json"    │
│                                                                   │
│  qwen2.5-coder:14b ──► analyze_review_node  (combined call)      │
│     9.0 GB            ~3–6 tok/s    markdown + JSON tail          │
│     num_ctx=12288     num_predict=2500  temp=0.1                  │
│     Output: security review markdown + {risk_score, verdict,      │
│             code_review_summary, comments[]}                      │
└──────────────────────────────────────────────────────────────────┘
```

### LLM Factory Functions

| Function | Model | num_ctx | num_predict | format | Use |
|----------|-------|---------|-------------|--------|-----|
| `get_fast_llm()` | 7b | 4096 | 512 | `"json"` | `classify_node` |
| `get_combined_llm()` | 14b | 12288 | 2500 | none | `analyze_review_node` |
| `get_deep_llm()` | 14b | 8192 | 1500 | none | (retained for standalone security analysis) |
| `get_review_llm()` | 14b | 8192 | 2048 | `"json"` | (retained for standalone code review) |

All instances are `@lru_cache` — constructed once per process, reused for all calls.

### Why a Single Combined Call

Before: two sequential 14B calls — `analyze_node` then `code_review_node` — 13–23 min total.

After: one combined call `analyze_review_node` — 6–11 min total.

The combined prompt passes both the plain diff (for security narrative) and the annotated diff (for line-numbered inline comments) in a single request. The LLM produces the security review markdown + code review JSON in one pass.

### Why 14B Instead of 32B

On 12 CPU cores with no GPU and AVX2:
- 32B: ~1–2.5 tok/s → 14–34 min for 2048 tokens
- 14B: ~3–6 tok/s → 6–11 min for 2048 tokens

The 32B model adds marginal quality benefit for code pattern recognition — not worth 3–4× slower inference.

### Ollama Performance Tuning

| Setting | Value | Rationale |
|---------|-------|-----------|
| `OLLAMA_FLASH_ATTENTION=1` | enabled | Reduces attention memory from O(n²) to O(n) at 16K context |
| `OLLAMA_KV_CACHE_TYPE=q8_0` | 8-bit | Halves KV RAM (~650 MB saved at 16K context) |
| `OLLAMA_NUM_THREAD=12` | all cores | Pins to 12 Haswell cores; auto-selects `libggml-cpu-haswell.so` |
| `OLLAMA_MAX_LOADED_MODELS=1` | one at a time | All RAM to the active model |
| `OLLAMA_NUM_PARALLEL=1` | single request | All 12 cores dedicated to one inference |
| `OLLAMA_KEEP_ALIVE=20m` | 20 minutes | Keep model warm between PR pipeline stages |
| `shm_size: 2gb` | shared memory | Thread sync buffers (was 64 MB default) |
| `ulimits.nofile: 65536` | file descriptors | Raised for high-concurrency model serving |
| Memory limit: `42g` | Docker constraint | Safely fits 14B (9 GB) with full OS headroom |

### Model Lifecycle (RAM Management)

Only one model loads into RAM at a time. The Chat UI calls `_unload_other_models()` before switching models (`keep_alive: 0` API call). The PR pipeline runs the two model calls sequentially — each evicts naturally after `keep_alive=10m` expires or when the next model loads.

---

## LangGraph Workflow — PR Review

### Graph Topology

```
START
  │
  ▼
intake_node
  │  Redis dedup + rate limit, clone repo, local -U15 diff, get history
  ▼
classify_node           ← LLM call #1: 7B fast, JSON-forced, num_ctx=4096
  │  circuit breaker fallback → _fallback_classify() (regex)
  ▼
route_scans()
  ├── "docs"        ──► skip_scan_node
  ├── has_dockerfile ──► scan_full_node    (build + full scanner suite)
  └── default       ──► scan_fs_node      (filesystem suite)
         │
         └─── (all branches converge)
                │
                ▼
          [parallel asyncio.gather()]
          Trivy FS + Gitleaks + Semgrep|Checkov|OSV (by matrix)
          + save raw JSON to ./artifacts/
                │
                ▼
          analyze_review_node     ← LLM call #2: 14B combined, num_ctx=12288
                │  single call produces:
                │  • security review markdown (OWASP Top 10, CVEs, secrets, IaC)
                │  • risk_score + verdict
                │  • code_review_summary + inline comments JSON
                │  posts GitHub PR Review with inline suggestion blocks
                │  saves to PostgreSQL
                ▼
          route_risk()
                ├── CRITICAL|HIGH ──► escalate_node  (PAUSED — Slack gate)
                │                         │
                │                 POST /callbacks/slack resumes
                │                         │
                └── MEDIUM|LOW|INFO ──► report_node
                                           │  PR comment, commit status
                                           │  saves summary.json to ./artifacts/
                                           ▼
                                          END

  Any node sets state["error"] ──► error_node ──► END
```

### Node Reference

#### `intake_node`

```python
async def intake_node(state: PRReviewState) -> dict:
```

1. Redis dedup: `SET NX dedup:{repo}:{pr}:{sha}` — returns early if duplicate
2. Rate limit: max 3 concurrent pipelines per repo
3. Posts `"Security review in progress..."` placeholder comment to PR
4. Clones PR branch: `git clone --depth 1 --branch {head_branch} {url}`
5. **Local -U15 diff** — `git fetch --depth=1 origin {base_branch}` then `git diff -U15 FETCH_HEAD..HEAD` (15 lines of context; fallback to GitHub API -U3 diff if fetch fails)
6. `git_service.truncate_diff()` — caps at 30,000 chars
7. Detects Dockerfile: `check_dockerfile(repo_path)`
8. Extracts changed files from diff headers
9. `knowledge.get_repo_history()` — last 10 PR reviews for context injection

#### `classify_node`

```python
async def classify_node(state: PRReviewState) -> dict:
```

Calls `get_fast_llm()` (7B, `format="json"`, `num_predict=512`, `num_ctx=4096`, `temperature=0.0`).

Prompt: PR title + body + list of changed files.
Output: `{"classification": "feature|dependency|infrastructure|docs|config", "risk_hint": "..."}`
Fallback: `_fallback_classify()` — regex on file extensions and names:

| Pattern | Classification |
|---------|---------------|
| `Dockerfile`, `*.tf`, `*.yaml` (k8s) | `infrastructure` |
| `requirements.txt`, `package.json`, `go.sum`, `*.lock` | `dependency` |
| `*.md`, `*.rst`, `*.txt` | `docs` |
| `*.yml`, `*.toml`, `.env.*` | `config` |
| Everything else | `feature` |

#### `scan_full_node` / `scan_fs_node` / `skip_scan_node`

```python
async def _run_scan(name: str, coro, repo_path: str) -> tuple[str, dict]:
```

Central scan runner with Redis caching, Prometheus timing, and error isolation:

```python
# Cache hit → skip scanner, return cached result
cached = await cache.get_scan(cache_key)
if cached:
    agent_cache_hits.inc()
    coro.close()          # cleanly discard unawaited coroutine
    return name, cached

# Cache miss → run scanner → cache result (skip raw to save Redis memory)
result = await coro
cache_result = {k: v for k, v in result.items() if k != "raw"}
await cache.set_scan(cache_key, cache_result, ttl=3600)
```

After `asyncio.gather()`, raw outputs are saved to disk:

```python
artifact_store.save_scan_artifact(
    settings.artifacts_path,
    state["repo_full_name"],
    state["pr_number"],
    scan_type,
    result.get("raw") or {k: v for k, v in result.items() if k != "raw"},
)
```

#### `analyze_review_node` ← **Combined security + code quality (replaces two separate nodes)**

```python
async def analyze_review_node(state: PRReviewState) -> dict:
```

Calls `get_combined_llm()` (14B, `num_ctx=12288`, `num_predict=2500`, `temperature=0.1`).

**Prompt structure** (`prompts/combined_review.py`):
```
[PR metadata: number, title, author, classification]
[Repository history: last 10 PR reviews with risk distribution]
[Plain diff — for security narrative (OWASP Top 10 analysis)]
[SAST-cleaned scanner output: Trivy, Semgrep, Gitleaks, Checkov, OSV]
[Annotated diff — with line numbers, for inline comment targeting]
[Combined output format instructions]
```

**Output format** — two sections in one LLM response:

1. **Security review markdown** — full narrative with sections:
   - Code Analysis (OWASP Top 10, file:line citations)
   - Dependency and Container Analysis
   - Secrets Scan
   - Infrastructure Security
   - SAST Findings
   - Recommendations (numbered, ordered by severity)

2. **JSON tail** (parsed by regex) — all on one line:
```json
{"risk_score": "HIGH", "verdict": "REQUEST_CHANGES", "code_review_summary": "...", "comments": [...]}
```

**Parsing:**
- Security review = everything before the JSON object
- `risk_score` / `verdict` extracted via regex; defaults to `MEDIUM` / `REQUEST_CHANGES` on failure
- `comments[]` validated line-by-line against actual diff (hallucinated lines dropped)

**Inline comment posting** (same as former `code_review_node`):
- Posts formal GitHub PR Review via `post_pr_review()`
- Each comment: severity emoji + title + description + optional `suggestion` block
- Severity emoji: `critical` → 🔴, `high` → 🟠, `medium` → 🟡, `low` → 🔵

**Knowledge persistence:**
- `knowledge.save_pr_review()` — upserts to PostgreSQL `pr_reviews`
- `knowledge.update_repo_profile()` — recalculates rolling risk average

**Circuit breaker fallback:**
- `_build_degraded_review()` — scan-only review with risk from counts
- No inline comments posted
- Still saves to knowledge base

#### `escalate_node`

Only runs when `SLACK_ESCALATION_ENABLED=true`. Posts Slack Block Kit message with Approve/Reject buttons. Graph checkpoints to PostgreSQL and **pauses**:

```python
graph = builder.compile(
    checkpointer=checkpointer,
    interrupt_before=["escalate"],
)
```

Flow:
1. `analyze_review_node` completes → graph checkpoints to PostgreSQL → **pauses**
2. `escalate_node` sends Slack Block Kit message with Approve/Reject buttons
3. `POST /callbacks/slack` resumes graph with `approval_status = "approved" | "rejected"`
4. Graph continues to `report_node`

If the container restarts mid-pause, the graph auto-resumes from the PostgreSQL checkpoint.

#### `report_node`

1. Formats final PR comment: security review + code quality summary + inline comment count
2. `github_api.post_pr_comment()` — updates placeholder comment
3. `github_api.set_commit_status()` — `success` / `failure` / `error`
4. `slack_api.send_notification()` — summary to security channel
5. `artifact_store.save_pr_summary()` — saves `summary.json`
6. `docker_service.remove_image()` + `shutil.rmtree(repo_path)` — cleanup
7. `cache.release_rate_limit()` — decrements concurrent counter
8. Emits `agent_reviews_total`, `agent_pipeline_duration_seconds`

### Scan Selection Matrix

```python
SCAN_MATRIX = {
    "feature":        {"semgrep"},
    "dependency":     {"osv"},
    "infrastructure": {"checkov"},
    "config":         set(),
    "docs":           set(),
}
```

Trivy FS + Gitleaks always run (except `docs`). Extra scanners run based on classification.
When a Dockerfile is detected → `scan_full_node`: Docker builds the image, Trivy also scans it.

### Conditional Routing

```python
# edges.py

def route_scans(state: PRReviewState) -> str:
    if state.get("error"):
        return "error_node"
    if state.get("pr_classification") == "docs":
        return "skip_scan"
    if state.get("has_dockerfile"):
        return "scan_full"
    return "scan_fs"


def route_risk(state: PRReviewState) -> str:
    if state.get("error"):
        return "error_node"
    risk = state.get("risk_score", "MEDIUM")
    if risk in ("CRITICAL", "HIGH"):
        settings = get_settings()
        if settings.slack_escalation_enabled:
            return "escalate"
    return "report"
```

---

## Combined Review Pipeline

### `app/prompts/combined_review.py`

Builds the unified prompt that asks the 14B model to produce both a full security review and structured code quality comments in a single call.

**System/user message structure:**
- PR metadata + repo history
- Plain diff (for security narrative, capped at 30,000 chars)
- SAST-cleaned scanner summaries
- Annotated diff (line-numbered, capped at 8,000 chars — for inline comment targeting)
- Combined output format instructions

**Output parsing in `analyze_review_node()`:**

```python
json_match = re.search(
    r'\{"risk_score"\s*:\s*"(?P<rs>CRITICAL|HIGH|MEDIUM|LOW|INFO)"\s*,'
    r'\s*"verdict"\s*:\s*"(?P<v>APPROVE|REQUEST_CHANGES|BLOCK)"'
    r'.*?\}',
    raw, re.DOTALL,
)
if json_match:
    data = json.loads(raw[json_match.start():])
    risk_score = data.get("risk_score", "MEDIUM")
    verdict = data.get("verdict", "REQUEST_CHANGES")
    code_review_summary = data.get("code_review_summary", "")
    raw_comments = data.get("comments", [])

review_text = raw[:json_match.start()].strip() if json_match else raw
```

### Line Validation

```python
for c in raw_comments:
    file_path = str(c.get("file", "")).strip()
    line = c.get("line")
    valid_lines = diff_lines_for_file(parsed_diff, file_path)
    if line not in valid_lines:
        log.warning("analyze_review_invalid_line", file=file_path, line=line)
        continue          # drop hallucinated line — not in actual diff
    valid_comments.append(c)
```

### GitHub PR Review Posting

```python
await github_api.post_pr_review(
    repo=state["repo_full_name"],
    pr_number=state["pr_number"],
    body=review_body,           # appears in Conversation tab
    comments=github_comments,   # appear on Files Changed tab
    event="COMMENT",
)
```

Each inline comment:
```markdown
🔴 **[CRITICAL] SQL Injection**

Raw string interpolation in SQL query allows attacker-controlled input.

```suggestion
query = "SELECT * FROM users WHERE name = %s"
cursor.execute(query, (username,))
```
```

---

## SAST JSON Cleaning

Scanner outputs are filtered before the LLM prompt to reduce token consumption. The LLM receives a curated summary, not raw JSON.

### Trivy (`trivy_service.py` + `templates.py`)

**Raw fields kept per vulnerability:**
```python
{
    "VulnerabilityID": "CVE-2023-1234",
    "PkgName": "libssl",
    "InstalledVersion": "1.1.1f",
    "FixedVersion": "1.1.1n",
    "Severity": "HIGH",
    "Title": "OpenSSL ...",
    # "Description": dropped — Title is sufficient, saves ~200 chars/vuln
    # "References": dropped — URL arrays add no analytical value
    # "CVSS": dropped — severity label is enough
    # "Target": dropped — noisy path strings
}
```

### Gitleaks (`gitleaks_service.py`)

**`Match` field is REDACTED** — even truncated to 50 chars, it exposes part of the real secret in the LLM prompt:

```python
# Safe — RuleID + File + StartLine is sufficient for the LLM
# Match field omitted entirely
```

### Semgrep (`semgrep_service.py` + `templates.py`)

**Pinned rulesets** (changed from non-deterministic `--config auto`):
```bash
semgrep scan --config p/security-audit --config p/owasp-top-ten --json --quiet
```

**INFO-level findings collapsed** — only `ERROR` and `WARNING` get individual entries. INFO severity is shown in the summary count only. The model needs actionable findings, not informational notices.

```python
for f in findings:
    if f["severity"] == "INFO":
        continue          # already shown in count
    if shown >= 15:
        break
    # ... format finding
```

### Checkov (`templates.py`)

**`guideline` field dropped** — the `check_id` (e.g., `CKV_DOCKER_2`) already encodes the rule identity. The guideline is usually a generic URL or NIST boilerplate (~150 chars per finding, saved ~2,250 chars for 15 findings):

```python
# Before
f"  Guideline: {c.get('guideline', 'N/A')[:150]}"

# After — removed entirely
```

### Token Savings Estimate

| Section | Before | After | Reduction |
|---------|--------|-------|-----------|
| Trivy (30 vulns) | ~6,000 chars | ~2,500 chars | ~58% |
| Gitleaks (Match omitted) | ~400 chars | ~200 chars | 50% |
| Semgrep (INFO collapsed) | ~2,000 chars | ~1,200 chars | 40% |
| Checkov (guideline removed) | ~1,500 chars | ~800 chars | 47% |
| **Total SAST** | **~9,900 chars** | **~4,700 chars** | **~52%** |

A 52% smaller prompt means less KV cache pressure, faster inference, and fewer context-overflow hallucinations at `num_ctx=12288`.

---

## Diff Context — Local -U15 Diff

### Problem

The GitHub API always returns `-U3` unified diff (3 lines of context). This is insufficient for:
- Understanding the security impact of a change (missing surrounding code)
- Generating accurate inline comment `suggestion` blocks (model can't see enough context)

### Solution

`get_local_diff(repo_path, base_branch)` in `git_service.py`:

```python
async def get_local_diff(repo_path: Path, base_branch: str) -> str:
    """Fetch base branch tip and produce -U15 diff inside the cloned repo."""

    # Fetch just the tip of the base branch (shallow — only metadata needed)
    proc = await asyncio.create_subprocess_exec(
        "git", "fetch", "--depth=1", "origin", base_branch,
        cwd=str(repo_path), ...
    )

    # Generate diff with 15 lines of context
    proc = await asyncio.create_subprocess_exec(
        "git", "diff", "-U15", "FETCH_HEAD..HEAD",
        cwd=str(repo_path), ...
    )
    return stdout.decode()
```

The cloned repo's `origin` remote already contains the token-injected URL (set during `clone_repo()`), so no additional authentication is needed for the fetch.

**Fallback:** If `get_local_diff()` raises (e.g., base branch name unavailable), `intake_node` falls back to `get_pr_diff()` via GitHub API.

### State Changes

`PRReviewState` now includes `base_branch: str` (populated from `pull_request.base.ref` in the webhook payload).

---

## Autonomous Scheduler

`app/services/scheduler.py` — two asyncio background tasks started at application lifespan.

### Disk Guard (every 30 minutes)

```python
async def _disk_guard_loop() -> None:
    while True:
        await _check_disk()
        await asyncio.sleep(30 * 60)
```

`_check_disk()`:
1. `shutil.disk_usage("/")` → updates `agent_disk_used_percent` + `agent_disk_free_gb` Prometheus gauges
2. `pct >= 90` → `_prune_build_cache()` + Slack 🔴 alert
3. `pct >= 80` → Slack 🟡 alert only

`_prune_build_cache()`:
```bash
docker builder prune -f
```
Safe — only removes unused build layers. Running containers unaffected. Returns human-readable result (e.g., `"Docker build cache pruned (Total reclaimed space: 2.4 GB)"`).

### Daily Health Digest (09:00 UTC)

```python
async def _health_digest_loop() -> None:
    while True:
        next9 = next_09_00_utc()
        await asyncio.sleep((next9 - now).total_seconds())
        await _post_health_digest()
```

`_post_health_digest()` collects and posts to Slack:
- 💾 Disk usage (% + free GB, with 🟢/🟡/🔴 icon)
- 🤖 Ollama status (loaded model or `"idle"`)
- 🐳 All container states (`docker ps`, with 🟢/🔴 icons)
- 🚨 Active Prometheus firing alerts (or `"✅ No active alerts"`)

---

## AlertManager Integration

### Prometheus → AlertManager → Agent → Slack

```
Prometheus fires alert
    │
    ▼ POST webhook
AlertManager (prom/alertmanager:latest, port 9093)
    │ route: receiver=devsecops-agent
    ▼ POST /webhooks/alertmanager
FastAPI agent
    ├── firing: send Slack Block Kit (🔴/🟡)
    ├── DiskCritical: docker builder prune -f
    └── resolved: send Slack 🔵 resolution
```

### Alert Rules (`prometheus/alerts.rules.yml`)

12 active rules across 4 groups:

*Group: disk*
| Alert | Condition | For | Severity |
|-------|-----------|-----|----------|
| `DiskWarning` | `(size - free) / size > 0.80` (node-exporter) | 5m | warning |
| `DiskCritical` | `(size - free) / size > 0.90` (node-exporter) | 2m | critical |
| `AgentDiskWarning` | `agent_disk_used_percent > 80` (agent gauge, no node-exporter needed) | 5m | warning |
| `AgentDiskCritical` | `agent_disk_used_percent > 90` (agent gauge, no node-exporter needed) | 2m | critical |

*Group: agent*
| Alert | Condition | For | Severity |
|-------|-----------|-----|----------|
| `AgentDown` | `up{job="devsecops-agent"} == 0` | 1m | critical |
| `AgentHighErrorRate` | `rate(agent_errors_total[5m]) > 0.1` | 5m | warning |
| `AgentReviewBacklog` | `agent_reviews_total offset 24h == agent_reviews_total` | 1m | info |

*Group: ollama*
| Alert | Condition | For | Severity |
|-------|-----------|-----|----------|
| `OllamaDown` | `ollama_reachable == 0` | 5m | critical |
| `OllamaNoModelLoaded` | `ollama_models_loaded_total == 0` | 60m | info |

> `OllamaDown` uses the `ollama_reachable` Gauge (set by the agent's 30s Ollama poller in `main.py`) — not model load count. This ensures idle Ollama (no model loaded) does not trigger a false "down" alert. `OllamaNoModelLoaded` has a 60m window so normal inter-review idle time is not alerted.

### Webhook Handler (`routers/webhooks.py`)

```python
@router.post("/webhooks/alertmanager", status_code=200)
async def alertmanager_webhook(request: Request, background_tasks: BackgroundTasks):
    payload = await request.json()
    alerts = payload.get("alerts", [])
    background_tasks.add_task(_handle_alerts, alerts, payload.get("groupLabels", {}))
    return {"message": "received", "count": len(alerts)}
```

`_handle_alerts()`:
- Separates `firing` vs `resolved`
- Auto-cleans on `DiskCritical`
- Formats and posts Slack Block Kit notifications

---

## Artifact Store

`app/services/artifact_store.py`

### Directory Layout

```
{artifacts_path}/
├── scans/
│   └── {owner}-{repo}/
│       └── pr-{number}/
│           ├── trivy_image.json
│           ├── trivy_fs.json
│           ├── gitleaks.json
│           ├── semgrep.json
│           ├── checkov.json
│           ├── osv.json
│           └── summary.json   ← final verdict, risk, files, duration, inline_comments
└── logs/
    ├── agent.log              ← structured JSON lines (rotating)
    └── agent.log.1 ...
```

### Hook Points

- **`scan_full_node` / `scan_fs_node`** — saves each scanner's raw output after `asyncio.gather()`
- **`report_node`** — saves `summary.json` with verdict, risk, files changed, duration, inline comment count

---

## Diff Parser

`app/services/diff_parser.py`

### `parse_diff(diff: str) → dict[str, FileChange]`

```python
@dataclass
class FileChange:
    filename: str
    added_lines: set[int]    # line numbers of + lines in new file
    context_lines: set[int]  # line numbers of context lines in new file
```

State machine:
```
for line in diff:
    if "+++ b/":    current_file = extract filename
    elif "@@ ":     new_line_num = parse +N from hunk header
    elif "+":       added_lines.add(new_line_num); new_line_num += 1
    elif " ":       context_lines.add(new_line_num); new_line_num += 1
    elif "-":       pass  # removed line — no new-file counter advance
```

### `diff_lines_for_file(parsed_diff, filename) → set[int]`

Returns `added_lines | context_lines` — the complete set of valid line numbers the model may reference. Comments on lines not in this set are silently dropped (hallucination guard).

### `format_diff_with_line_numbers(diff: str) → str`

Rewrites diff lines with visible annotations:
```
+++ b/app/auth.py
@@ -42,7 +42,10 @@
  42|    def login(username, password):
+ 43|+       query = f"SELECT * FROM users WHERE name='{username}'"
  44|        cursor.execute(query)
```

This is the form passed to the combined prompt for inline comment targeting (capped at 8,000 chars).

---

## Services

### `git_service.py`

- `clone_repo(clone_url, branch, workspace)` — `--depth 1` + token-injected URL
- `get_local_diff(repo_path, base_branch)` — `git fetch --depth=1 origin {base}` + `git diff -U15 FETCH_HEAD..HEAD` ← **NEW**
- `get_pr_diff(repo, pr_number)` — GitHub API fallback (`Accept: application/vnd.github.v3.diff`, -U3)
- `truncate_diff(diff)` — caps at 30,000 chars
- `extract_changed_files(diff)` — parses `diff --git a/... b/...` headers

### `semgrep_service.py`

```bash
# Before (non-deterministic)
semgrep scan --config auto --json --quiet

# After (pinned, reproducible)
semgrep scan --config p/security-audit --config p/owasp-top-ten --json --quiet
```

`p/security-audit` — general security rules (OWASP Top 10, injection, XSS, SSRF)
`p/owasp-top-ten` — explicit OWASP Top 10 ruleset

### `trivy_service.py`

- `scan_image(image_tag)` — `trivy image --format json`
- `scan_filesystem(path)` — `trivy fs --format json`
- `parse_trivy_output(raw, scan_type)` — flattens `Results[].Vulnerabilities[]`, severity summary, top-15 sorted, keeps `raw` for artifact store

### `gitleaks_service.py`

- `scan_repo(path)` — `gitleaks detect --report-format json`
- Exit code 1 = findings (not an error)
- `Match` field omitted — exposes secret content in LLM prompt (security risk)

### `checkov_service.py`

- `scan_iac(path)` — `checkov -d {path} --output json --quiet --compact`
- Handles both single dict and list (multi-framework) output

### `osv_service.py`

- `scan_lockfiles(path)` — `osv-scanner --json -r {path}`
- Extracts nested `results[].packages[].vulnerabilities[]`

### `scheduler.py` ← **NEW**

- `start_scheduler()` — creates and returns asyncio Tasks (called from `main.py` lifespan)
- `_disk_guard_loop()` — 30-min disk check cycle
- `_health_digest_loop()` — daily 09:00 UTC digest
- `_prune_build_cache()` — `docker builder prune -f` (safe, recoverable)
- `_post_health_digest()` — collects disk / containers / Ollama / alerts, posts Slack Block Kit

### `github_api.py`

```python
async def post_pr_comment(repo, pr_number, body) -> None
async def set_commit_status(repo, sha, state, description) -> None
async def post_pr_review(repo, pr_number, body, comments, event="COMMENT") -> None
async def validate_webhook_signature(body, signature, secret) -> bool
```

`post_pr_review()` posts a formal GitHub PR Review with optional inline comments (appear on Files Changed tab with Apply suggestion button).

### `knowledge.py`

- `AsyncConnectionPool` (min=2, max=10) on PostgreSQL
- `get_repo_history(repo, limit=10)` — past PR reviews for context injection
- `save_scan_result(...)` — stores scanner results
- `save_pr_review(...)` — upserts PR review (`ON CONFLICT DO UPDATE`)
- `update_repo_profile(repo, risk_score)` — recalculates rolling risk average

### `cache.py`

- `is_duplicate(key)` — SET NX with TTL
- `check_rate_limit(repo, max_concurrent=3)` — INCR + EXPIRE
- `release_rate_limit(repo)` — DECR
- `get_scan(key)` / `set_scan(key, result, ttl=3600)` — JSON cache
- All gracefully degrade — returns safe defaults if Redis is unavailable

---

## Chat Ops — BTE Security AI Agent

### Identity

The chat interface (`GET /ui`) is the **BTE Security AI Agent** — an AI-powered security and infrastructure operations assistant. Always identifies itself as:
> *"BTE Security AI Agent — your DevSecOps operations assistant."*

Complex reports end with a **"BTE Agent Assessment"** conclusion block.

### Custom ReAct Loop (`app/routers/chat.py`)

`qwen2.5-coder` outputs tool calls as plain text JSON — not via Ollama's native tool-call API.

**LLM configuration (Sprint 7 — anti-hallucination tuned):**
| Parameter | Value | Reason |
|-----------|-------|--------|
| Default model | `qwen2.5-coder:7b` | Benchmarked: 80% tool accuracy, 100% args format, ~5 tok/s warm |
| `num_ctx` | `6144` (7b/14b) / `16384` (32b) | Prompt ~1,940 tokens → 4,200 tokens free for observations + answers. More context = less forgetting = fewer hallucinated values |
| `num_predict` | `800` | Room for complete multi-container/metric answers. Truncated answers caused model to summarise the rest from memory |
| `temperature` | `0.0` | Fully deterministic — eliminates creative "filling in" of metric values |
| `keep_alive` | `10m` | Model stays warm between questions |

**Model benchmark** (5-query suite, full system prompt, CPU-only):
| Model | Size | Speed (warm) | Tool Accuracy | Args OK | UI Tag |
|-------|------|-------------|---------------|---------|--------|
| `qwen2.5-coder:7b` | 4.7 GB | ~5 tok/s | **80%** | **100%** | ✅ Recommended |
| `qwen2.5-coder:14b` | 9.0 GB | ~3.2 tok/s | 80% | 100% | Deep analysis |
| `llama3.2:3b` | 2.0 GB | ~8 tok/s | 0% (full prompt) | — | ❌ Experimental |
| `granite3.1-dense:2b` | 1.6 GB | ~8.5 tok/s | 0% | — | ❌ Incompatible |

> `llama3.2:3b` fails under the full 7,577-char system prompt — context saturates. `granite3.1-dense:2b` uses IBM's proprietary tool-call schema, not our `{"name":…,"arguments":…}` format.

**ReAct loop steps:**
```
1. Stream LLM tokens into buffer
2. Detect tool call shape: starts with "{" OR "```"
3. Parse JSON — 4-pass extractor:
     Pass 1: plain JSON object
     Pass 2: ```json ... ``` fenced block
     Pass 3: JSON embedded after text (scan for last { occurrence)
     Pass 4: fenced block embedded after text
4. Dedup check: if tool+args already called this turn → skip, inject "STOP — write final answer"
5. No-tool guard (step 0 only): if the model answered without calling a tool AND the question
   contains live-data keywords (cpu, disk, container, alerts, logs, status, etc.) →
   intercept, inject "STOP — you answered from training data. Call a tool NOW."
6. Invoke tool via asyncio.run_in_executor (sync tools in threadpool)
   Tool results served from in-memory cache if within TTL (see Tool Result Caching below)
7. Inject: [OBSERVATION: tool_name]\n{result}\n[/OBSERVATION]
           + "Every number/status/name MUST appear verbatim in an [OBSERVATION] block.
              NEVER invent or recall values from training data."
8. Loop (max 8 tool calls per response)
9. Final LLM response → stream as "token" SSE events
```

### Tool Result Caching (`app/routers/chat.py`)

All tool results are cached in-memory with per-tool TTLs to avoid redundant subprocess / network calls within a short window:

| Tool | TTL | Rationale |
|------|-----|-----------|
| `list_images` | 120s | Images are static between deploys |
| `query_prometheus_range` | 120s | Historical data is immutable |
| `disk_usage` | 60s | Disk never changes in 60s |
| `query_database` | 60s | Security DB data is slow-changing |
| `list_scan_artifacts` | 60s | Artifacts directory rarely changes |
| `prometheus_alerts` | 30s | Alert state changes slowly |
| `redis_info` | 30s | Redis stats stable over 30s |
| `jenkins_status` | 30s | Build state stable over 30s |
| `query_prometheus` | 20s | Prometheus scrapes every 15s |
| `vps_status` | 20s | RSS/load barely changes second-to-second |
| `list_containers` | 20s | Container list stable |
| `ollama_status` | 20s | Model load state stable |
| `network_stats` | 15s | Cumulative counters — short TTL |
| `system_net_io` | 15s | Cumulative counters — short TTL |
| `container_stats` | 10s | CPU/RAM — fastest-changing metric |
| `restart_service` | 0 | Never cached (write operation) |

Cache key: `"tool_name:sorted_json_args"`. A second identical question within the TTL returns instantly from cache — LLM generation is still the bottleneck, but tool execution (0.5–3s per call) is free.

### 20 Monitoring Tools (`app/workflows/ops_assistant/tools.py`)

All tools are **read-only** except `restart_service` (whitelist-restricted).

**VPS / Host:**
| Tool | Returns |
|------|---------|
| `vps_status()` | CPU model/cores, RAM used/free/%, disk, uptime, load avg 1/5/15, swap |
| `disk_usage()` | All mounted filesystems (`df -h`) |
| `top_processes(sort_by)` | Top 20 by CPU or memory |
| `network_stats()` | Listening sockets + established TCP connections |
| `system_net_io()` | Cumulative bytes RX/TX per interface |

> **Host metrics via `query_prometheus`:** node-exporter (added 2026-04-23) exposes ~1000 real host metrics scraped from `/host/proc` and `/host/sys`. The system prompt includes ready-to-use PromQL patterns. For historical data or per-core CPU, always prefer `query_prometheus` over `vps_status`.
>
> | Question | Use |
> |---------|-----|
> | Quick RAM/CPU/disk snapshot | `vps_status` |
> | CPU % history / per-core breakdown | `query_prometheus` → `node_cpu_seconds_total` |
> | Disk I/O read/write MB/s | `query_prometheus` → `node_disk_read_bytes_total` |
> | Network bandwidth RX/TX | `query_prometheus` → `node_network_receive_bytes_total` |

**Docker:**
| Tool | Returns |
|------|---------|
| `list_containers()` | Name, status, image, ports for all containers |
| `container_logs(container, tail, since)` | Last N lines — smart tail-first truncation at 4000 chars |
| `container_stats()` | Live CPU%, memory usage, network I/O |
| `inspect_container(container)` | State, health, restart policy, mounts, last 5 health log entries |
| `list_images()` | All images with name, size, creation date |
| `restart_service(service)` | Restart allowed: `agent`, `grafana`, `prometheus`, `nginx`, `victoriametrics` |

**Ollama / LLM:**
| Tool | Returns |
|------|---------|
| `ollama_status()` | Loaded models (RAM consumed, expires_at), all installed models with sizes |

**Prometheus / Alerting:**
| Tool | Returns |
|------|---------|
| `query_prometheus(promql)` | Execute any PromQL instant query via `/api/v1/query` |
| `query_prometheus_range(promql, duration, step)` | Range query over `duration` window (e.g. `"1h"`, `"6h"`, `"24h"`) — returns min/max/avg/latest + trend sparkline. Use for *"has X been high?"* type questions |
| `prometheus_alerts()` | Active firing/pending alerts — or "✓ no active alerts" |

**Redis:**
| Tool | Returns |
|------|---------|
| `redis_info()` | Memory, hit rate %, clients, keyspace, persistence status |

**Jenkins:**
| Tool | Returns |
|------|---------|
| `jenkins_status()` | Last build result per job, duration, health |

**Scan Artifacts:**
| Tool | Returns |
|------|---------|
| `list_scan_artifacts(repo, pr_number)` | Directory listing of saved SAST JSON files |
| `read_scan_artifact(repo, pr_number, scanner)` | Contents of a specific scanner JSON |

**Database:**
| Tool | Returns |
|------|---------|
| `query_database(sql)` | Read-only SELECT — up to 50 rows as JSON array |

### SSE Event Protocol

| Event | Fields | Description |
|-------|--------|-------------|
| `status` | `content` | Immediate first event — "Loading model…" |
| `thinking_start` | `step` | Model is building a tool call |
| `thinking_token` | `content` | Raw token in tool call JSON |
| `thinking_end` | — | Tool call complete |
| `tool_start` | `name`, `args`, `step` | Tool about to run |
| `tool_end` | `name`, `content` | Tool result returned |
| `token` | `content` | Final answer text token |
| `replace_text` | `content` | Pre-call text that wasn't a tool call |
| `error` | `content` | Exception |
| `done` | — | Stream complete |

### Anti-Hallucination Design

1. **Observation format:** `[OBSERVATION: name]…[/OBSERVATION]` — model must copy live data exactly
2. **Hard ANTI-HALLUCINATION block in system prompt (5 rules):**
   - NEVER answer from training data — VPS state changes every second
   - ANY live-state question (CPU, RAM, containers, alerts, logs, metrics) requires a tool call first
   - Every value in the final answer MUST appear verbatim in an `[OBSERVATION]` block
   - "approximately", "typically", "usually" are forbidden when describing live system state
   - If you answered without a tool, stop and call the correct tool immediately
3. **No-tool guard (code-level):** If step 0 produces a final answer without any tool call AND the question contains live-data keywords → intercept, inject `"STOP — you answered from training data. Call a tool NOW."`, force another generation step. Covers ~30 keyword triggers (cpu, disk, container, alerts, logs, status, current, now, etc.)
4. **Strengthened observation injection:** After every tool result: `"Every number, percentage, status, name, and timestamp you write MUST appear verbatim in one of the [OBSERVATION] blocks above. NEVER invent, estimate, or recall values from training data."`
5. **Full DB schema:** All 6 table schemas in system prompt — prevents column name hallucination
6. **History serialization:** `(In a previous step I used: tool_name)` — neutral summary, never replays JSON that could be mimicked
7. **Explicit tool selection rules:** System prompt maps every question type to the correct tool
8. **PromQL patterns:** 4 ready-to-use PromQL expressions — model never guesses metric names
9. **Dedup guard (code-level):** Tracks `{tool_name}:{sorted_args_json}` per response — blocks repeated calls, eliminates infinite loops

### System Prompt Design

Current: 8,186 chars / ~2,047 tokens (Sprint 6 compression + Sprint 7 anti-hallucination block):

| Section | Sprint 5 | Sprint 6 | Sprint 7 |
|---------|---------|---------|---------|
| Identity + Tone | 295 tok | 45 tok | 45 tok |
| Infra overview | 134 tok | 42 tok | 42 tok |
| Prometheus metrics | 321 tok | 140 tok | 140 tok |
| Tool use/selection | 815 tok | 320 tok | 320 tok |
| **ANTI-HALLUCINATION** | — | — | **+153 tok** |
| Monitoring chains | 266 tok | 90 tok | 90 tok |
| Response format | 146 tok | 30 tok | 30 tok |
| DB schema + Tool list | 968 tok | 968 tok | 968 tok (fixed) |

With `num_ctx=6144` and ~2,047 prompt tokens, ~4,100 tokens remain free — enough for 6–8 full tool observations before running out of context. This eliminates the "context overflow → hallucination" failure mode that occurred at 4096 ctx.

---

## Prometheus Metrics

### HTTP Metrics (auto — `prometheus-fastapi-instrumentator`)
- `http_requests_total{method, handler, status}`
- `http_request_duration_seconds`
- `http_requests_in_progress`

### Custom Pipeline Metrics (`app/metrics/custom.py`)

All Ollama metrics are polled and re-exported by the agent every 30 seconds from Ollama's `/api/ps` endpoint. No direct Ollama scrape job is needed.

| Metric | Type | Labels | Emitted when |
|--------|------|--------|-------------|
| `agent_reviews_total` | Counter | `risk_score`, `verdict` | `report_node` completes |
| `agent_llm_duration_seconds` | Histogram | `model`, `node` | Each LLM call |
| `agent_scan_duration_seconds` | Histogram | `scanner` | Each scanner |
| `agent_pipeline_duration_seconds` | Histogram | — | Full pipeline end |
| `agent_errors_total` | Counter | `stage` | `error_node` |
| `agent_cache_hits_total` | Counter | — | Redis cache hit |
| `ollama_reachable` | Gauge | — | Every 30s poll (1=reachable, 0=unreachable) |
| `ollama_models_loaded_total` | Gauge | — | Every 30s poll |
| `ollama_model_loaded` | Gauge | `model` | Every 30s poll |
| `ollama_model_size_bytes` | Gauge | `model` | Every 30s poll |
| `ollama_model_vram_bytes` | Gauge | `model` | Every 30s poll |
| `agent_disk_used_percent` | Gauge | — | Every 30s (scheduler) |
| `agent_disk_free_gb` | Gauge | — | Every 30s (scheduler) |

### `ollama_reachable` — Design Note

`ollama_reachable` is the key metric for Ollama connectivity monitoring:

```python
# main.py — _poll_ollama_metrics() — runs every 30s
try:
    resp = await client.get(f"{settings.ollama_base_url}/api/ps")
    if resp.status_code == 200:
        ollama_reachable.set(1)   # Ollama is up and responding
        ...
    else:
        ollama_reachable.set(0)   # HTTP error response
except Exception:
    ollama_reachable.set(0)       # Connection refused / timeout
```

This separates two distinct states that were previously conflated:
- **Ollama idle** (up, no model loaded) → `ollama_reachable=1`, `ollama_models_loaded_total=0` → only `OllamaNoModelLoaded` (info, 60m window) may fire
- **Ollama down** (unreachable) → `ollama_reachable=0` → `OllamaDown` fires (critical, 5m)

---

## Circuit Breaker & Graceful Degradation

```
CLOSED (normal)
  ├── LLM success → reset failure count
  └── LLM failure → increment count
       └── 3 consecutive failures → OPEN (5 min cooldown)

OPEN (degraded)
  ├── classify_node → _fallback_classify() (regex)
  └── analyze_review_node → _build_degraded_review() (scan counts only, no inline comments)
       └── After 5 min → attempt LLM again
```

**Full degradation stack:**

| Component | Failure | Fallback |
|-----------|---------|----------|
| LLM (7B classify) | Circuit open | Regex file-extension classification |
| LLM (14B combined) | Circuit open | Scan-only degraded review |
| LLM (14B combined) | Exception | Degraded fallback, no inline comments posted |
| Redis | Unavailable | Skip dedup, cache, rate limit |
| Slack | Token missing | Skip notifications, log warning |
| Any scanner | Process error | Continue pipeline with other scanners |
| Docker build | Timeout/failure | Fall back to filesystem-only scan |
| `get_local_diff()` | fetch failure | Fall back to GitHub API diff (-U3) |

---

## Redis Caching & Rate Limiting

```
Webhook dedup:    dedup:{repo}:{pr_number}:{head_sha}   SET NX  TTL=1h
Rate limiting:    rate:{repo_full_name}                  INCR    TTL=10min (max 3)
Scan caching:     scan:{scanner}:{repo_path}             JSON    TTL=1h
```

Scan cache is critical: if the same branch is updated twice within an hour, all scanners return in milliseconds instead of re-running.

---

## Security Design

### HMAC Webhook Validation
```python
expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
is_valid = hmac.compare_digest(expected, signature)  # Timing-safe
```
Requests with invalid or missing signatures → `403 Forbidden`.

### Ollama Not Host-Exposed

Port `11434` is no longer bound on the host interface. Ollama is accessible only within the Docker network (`devsecops-net`). This prevents external `ollama pull` calls that could fill the disk.

### ⚠️ Known Security Gaps (not yet fixed)

Live audit (2026-04-28) revealed several services with host port bindings that should be internal-only:

| Service | Port | Risk | Fix |
|---------|------|------|-----|
| `redis` | `6379` host, **no auth** | Anyone can read/write cached scan results, dedup keys, rate limit counters | Remove `ports:` from docker-compose.yml; add `--requirepass` |
| `prometheus` | `9090` host, no auth | Exposes all scrape targets, alert rules, and metric values | Remove `ports:` — access via nginx `/prometheus/` |
| `alertmanager` | `9093` host, no auth | Alert silence/inhibit API publicly accessible | Remove `ports:` |
| `victoriametrics` | `8428` host, no auth | Long-term metrics queryable without auth; bots found scanning it | Remove `ports:` |
| `devsecops-agent` | `8000` host | Direct port access bypasses nginx Basic Auth on `/ui` and `/chat/` | Remove `ports:` — nginx is the only entry point |
| `open-webui` | `3001` host, `ENABLE_SIGNUP=true` | Anyone can create an account and use Ollama models directly, bypassing all pipeline controls | Remove `ports:`; set `ENABLE_SIGNUP=false` after first admin account is created |
| `jenkins` | `8080`, `50000` host | Direct access bypasses nginx routing and exposes Jenkins build infrastructure | Remove `ports:`; route exclusively via nginx `/jenkins/` |
| `grafana` | `3000` host | Accessible directly — Grafana has its own auth but direct binding is unnecessary | Optional: remove `ports:`, access only via nginx `/grafana/` |

All inter-container communication uses the Docker network (`devsecops-net`) and does not require host port bindings. Only `nginx:80/443` needs public exposure.

### Token Injection (never stored)
```python
clone_url = clone_url.replace("https://github.com", f"https://{token}@github.com")
```
The injected URL is only in the local variable — it is stored in the cloned repo's `.git/config` inside the ephemeral workspace (cleaned up by `report_node`).

### Repo Cleanup
```python
shutil.rmtree(repo_path)
await docker_service.remove_image(docker_image_tag)
```

### No External LLM APIs
All inference runs locally via Ollama. No code or diffs leave the VPS.

### Gitleaks Match Field Omitted
The `Match` field (partial secret value) is never passed to the LLM prompt — only `RuleID`, `File`, and `StartLine` are included.

### Diff Truncation
`git_service.truncate_diff()` caps at 30,000 chars — prevents LLM context overflow and resource exhaustion from maliciously large diffs.

---

## Configuration

```env
# GitHub
GITHUB_TOKEN=ghp_xxxx
GITHUB_WEBHOOK_SECRET=your-secret

# Ollama — two-model setup
OLLAMA_BASE_URL=http://ollama:11434
OLLAMA_MODEL_FAST=qwen2.5-coder:7b      # classify_node
OLLAMA_MODEL_DEEP=qwen2.5-coder:14b     # analyze_review_node (combined)
OLLAMA_MODEL_REVIEW=qwen2.5-coder:14b   # retained for reference
OLLAMA_TIMEOUT=900                       # 15 min max per call

# Slack (optional — degrades gracefully)
SLACK_BOT_TOKEN=xoxb-xxxx
SLACK_CHANNEL_ID=C0XXXXXXXXX
SLACK_SIGNING_SECRET=your-signing-secret
SLACK_ESCALATION_ENABLED=false

# PostgreSQL
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
POSTGRES_USER=devsecops
POSTGRES_PASSWORD=strong-password
POSTGRES_DB=devsecops_db

# Redis (optional — degrades gracefully)
REDIS_URL=redis://redis:6379/0

# Grafana
GRAFANA_PASSWORD=admin-password

# Open WebUI
WEBUI_SECRET_KEY=your-random-secret

# Agent
AGENT_LOG_LEVEL=INFO
AGENT_WORKSPACE=/tmp/agent-workspace
TRIVY_SEVERITY=CRITICAL,HIGH,MEDIUM
ARTIFACTS_PATH=/opt/devsecops/artifacts

# Jenkins (for jenkins_status tool)
JENKINS_URL=http://jenkins:8080
JENKINS_USER=admin
JENKINS_API_TOKEN=your-api-token
```

---

## Project Structure

```
app/
├── main.py                     # FastAPI app, lifespan, structlog (console+file), Ollama poller,
│                               # scheduler startup (disk_guard + health_digest tasks)
├── config.py                   # Pydantic settings (all env vars incl. artifacts_path)
│
├── engine/
│   ├── checkpointer.py         # AsyncPostgresSaver — __aenter__/__aexit__ pattern
│   ├── dispatcher.py           # dispatch_event() — routes webhook to WORKFLOW_REGISTRY
│   └── registry.py             # WORKFLOW_REGISTRY dict
│
├── llm/
│   └── ollama.py               # get_fast_llm() (7b, 4096 ctx)
│                               # get_combined_llm() (14b, 12288 ctx) ← NEW
│                               # get_deep_llm() (14b, 8192 ctx) — retained
│                               # get_review_llm() (14b, 8192 ctx, json) — retained
│                               # + circuit breaker state + check_ollama_health()
│
├── metrics/
│   └── custom.py               # All custom Prometheus metrics (Counter/Histogram/Gauge)
│                               # incl. agent_disk_used_percent + agent_disk_free_gb ← NEW
│
├── models/
│   ├── state.py                # AgentState base TypedDict
│   ├── github_webhooks.py      # Pydantic models — to_initial_state() now sets base_branch ← UPDATED
│   └── db.py                   # SQL table definitions reference
│
├── prompts/
│   ├── classifier.py           # Fast 7B classification prompt + JSON schema
│   ├── security_review.py      # Deep 14B security analysis prompt (OWASP Top 10)
│   ├── code_review.py          # Code quality prompt → {summary, comments[]}
│   ├── combined_review.py      # Combined security+quality prompt → markdown + JSON ← NEW
│   └── templates.py            # SAST formatters — Checkov guideline removed,
│                               # Semgrep INFO collapsed ← UPDATED
│
├── routers/
│   ├── webhooks.py             # POST /webhooks/github — HMAC + BackgroundTask dispatch
│   │                           # POST /webhooks/alertmanager — alert routing ← NEW
│   ├── callbacks.py            # POST /callbacks/slack — LangGraph resume
│   ├── health.py               # GET /health, GET /readiness
│   └── chat.py                 # GET /ui, GET /chat/models (annotated with benchmark metadata)
│                               # POST /chat/stream — 7b default, num_ctx=6144, num_predict=800, temp=0.0
│                               # no-tool guard (step-0 intercept for live-data questions)
│                               # tool-result cache (14 tools, per-tool TTLs 10–120s)
│                               # dedup guard (blocks repeated tool+args), custom ReAct + SSE
│
├── services/
│   ├── artifact_store.py       # save_scan_artifact() + save_pr_summary()
│   ├── cache.py                # Redis: init/close, dedup, rate limit, scan cache
│   ├── checkov_service.py      # Checkov subprocess + parser
│   ├── diff_parser.py          # parse_diff(), format_diff_with_line_numbers()
│   ├── docker_service.py       # build_image(), remove_image(), check_dockerfile()
│   ├── git_service.py          # clone_repo(), get_local_diff() ← NEW, get_pr_diff(), truncate_diff()
│   ├── github_api.py           # post_pr_comment(), set_commit_status(), post_pr_review()
│   ├── gitleaks_service.py     # Gitleaks subprocess + parser (Match field omitted)
│   ├── knowledge.py            # PostgreSQL pool: get_repo_history, save_pr_review, etc.
│   ├── osv_service.py          # OSV-Scanner subprocess + parser
│   ├── scheduler.py            # Autonomous scheduler ← NEW
│   │                           # disk_guard (30 min) + health_digest (09:00 UTC daily)
│   ├── semgrep_service.py      # Semgrep — p/security-audit + p/owasp-top-ten ← UPDATED
│   ├── slack_api.py            # send_notification(), request_approval()
│   └── trivy_service.py        # Trivy subprocess + parser
│
├── static/
│   └── index.html              # BTE Security AI Agent UI — dark theme, SSE client,
│                               # thinking/tool blocks, markdown rendering, localStorage history
│
└── workflows/
    ├── pr_review/
    │   ├── state.py            # PRReviewState TypedDict — added base_branch ← UPDATED
    │   ├── nodes.py            # analyze_review_node() ← NEW (replaces analyze + code_review)
    │   │                       # analyze_node(), code_review_node() — retained for reference
    │   ├── edges.py            # route_scans(), route_risk()
    │   └── graph.py            # StateGraph — 9 nodes, route_risk on "analyze" ← UPDATED
    └── ops_assistant/
        ├── graph.py            # SYSTEM_PROMPT (8,186 chars / ~2,047 tokens)
        │                       # includes ANTI-HALLUCINATION block (5 hard rules)
        │                       # TOOL_MAP + _tool_list_text() — 20 tools
        └── tools.py            # 20 infrastructure monitoring tools + ALL_TOOLS registry
                                # includes query_prometheus_range() for trend/history queries
```

---

## Work Methodology Recommendation

### Recommended: Agile Scrum (2-Week Sprints)

This agent codebase is a living system — requirements emerge from production gaps (disk emergency → disk guard, monitoring gaps → `ollama_reachable`). Agile Scrum's iterative model matches this reality better than any waterfall or big-design-upfront approach.

**Comparison:**

| Approach | Fit | Reason |
|----------|-----|--------|
| **Waterfall** | ❌ | Requirements for AI/security tooling are not fully knowable upfront. The combined LLM call optimization, the monitoring metric design, and the diff context fix were all discovered after initial deployment — not during design. |
| **Kanban** | ⚠ | Good for pure ops maintenance (patching, alert tuning). Lacks sprint goals, so feature delivery (combined prompt, Grafana dashboard) has no forcing function. |
| **Agile Scrum** | ✅ | 2-week sprints produce shippable increments. Retrospectives surface production gaps. Backlog is a living list. Works for teams of 1–3. |

**Sprint cadence for this agent:**

| Sprint | Goal | Key deliverables |
|--------|------|-----------------|
| 1 | Foundation | FastAPI, LangGraph skeleton, GitHub webhook, PostgreSQL checkpointing |
| 2 | Scanner Pipeline | 7B classify + 14B review, Trivy/Gitleaks/Semgrep/Checkov/OSV, PR comments |
| 3 | Ops & Reliability | Redis dedup, AlertManager, disk guard, daily digest, Prometheus alerts |
| 4 | Quality & Performance | Combined LLM call, local -U15 diff, SAST token reduction, monitoring fixes, Grafana |
| 5 | Host Monitoring + Chat Precision | node-exporter, 12 alert rules, nginx DNS fix, chat 14b default, PromQL prompt injection |
| 6 | Chat Speed + Model Benchmarking | 7b default (benchmarked), prompt compressed 36%, tool caching, dedup guard, `query_prometheus_range`, UI copy buttons + timing, model tag badges |
| 7 | VPS Audit + Anti-Hallucination | VictoriaMetrics crash fixed, AlertManager 404 fixed, nginx WebSocket+root+auth, 3 Grafana dashboards, no-tool guard, ANTI-HALLUCINATION block, temp=0.0, num_ctx=6144, num_predict=800 |

**Definition of Done (per story):**
1. Deployed and running in Docker Compose
2. Agent logs clean (no errors for new code path)
3. Prometheus metrics reflect new behavior
4. README updated
5. At least one real PR review (or real alert) processed through new code

**Recommended ceremonies at this scale:**

| Ceremony | Cadence | Duration |
|----------|---------|----------|
| Sprint Planning | Every 2 weeks | 1 hour |
| Standup (async log for solo) | Daily | 10 min |
| Sprint Review / Demo | End of sprint | 30 min |
| Retrospective | End of sprint | 30 min |
| Backlog Refinement | Mid-sprint | 30 min |

---

## Running Tests

```bash
cd agent
pip install pytest pytest-asyncio

# All tests
python -m pytest tests/ -v

# By module
python -m pytest tests/test_webhook_handler.py -v
python -m pytest tests/test_pr_review_graph.py -v
python -m pytest tests/test_trivy_parsing.py -v
python -m pytest tests/test_semgrep_parsing.py -v
python -m pytest tests/test_knowledge_service.py -v
```

| Test file | Coverage |
|-----------|---------|
| `test_webhook_handler.py` | HMAC validation (403 on bad sig), event filtering, 202 for valid PRs |
| `test_pr_review_graph.py` | Node functions (intake, classify, skip_scan, error), edge routing |
| `test_trivy_parsing.py` | Trivy JSON (counts, sorting, field extraction), empty output, edge cases |
| `test_semgrep_parsing.py` | Semgrep SAST, Checkov IaC (single + multi-framework), OSV-Scanner |
| `test_knowledge_service.py` | PostgreSQL CRUD (mocked pool) |

---

*BTE Security AI Agent — built for the BTE DevSecOps platform.*
