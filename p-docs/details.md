# BTE Security AI Agent — Complete Project Details

> Exhaustive documentation of the project: context, architecture, components,
> methodology, incidents, results, and report structure.

---

## Part 1: The Story — Why This Project Exists

You did your end-of-studies internship at the **Banque de Tunisie et des Emirats (BTE)** —
a Tunisian bank founded on August 10, 1982, from a partnership between the Tunisian
government and the Abu Dhabi Investment Authority (ADIA). The bank transformed in 2004
from an investment bank into a universal bank. It has a Direction des Systèmes d'Information
(DSI) responsible for protecting and modernizing the bank's digital infrastructure, with
a dedicated digital platform called **NEO BTE**.

### The problem they had

When developers at the bank submit code changes (called "Pull Requests" on GitHub),
someone has to manually review them for security issues — SQL injections, exposed
passwords, vulnerable dependencies, misconfigured Dockerfiles. This process was:

- **Slow** — often 48+ hours for a security review
- **Inconsistent** — quality depended on which reviewer was available
- **Non-traceable** — no centralized history of risks per repository
- **Non-blocking** — no automatic CI gate to prevent vulnerable code from being merged
- **Non-scalable** — review capacity does not grow with the developer team

### The constraint

A bank cannot send its code to OpenAI, Anthropic, or any cloud AI service. Banking
regulations from the Banque Centrale de Tunisie (BCT) and SWIFT confidentiality
requirements forbid it.

### Your mission

Build a system that automatically reviews every Pull Request for security issues
using local AI, with results published directly on GitHub in less than 7 minutes —
and run it entirely on the bank's own server.

---

## Part 2: What You Actually Built

You built a **DevSecOps automation engine** running on a single VPS (Virtual Private
Server) — 12 cores Intel Haswell AVX2, 45 GB RAM, no GPU. The whole system runs in
12 Docker containers and processes a complete security review in 6–11 minutes per
Pull Request.

### Pipeline flow

```
[Developer pushes PR] → [GitHub] → [HMAC webhook] → [nginx] → [Agent]
                                                                  │
                                              ┌───────────────────┘
                                              ▼
                                       [LangGraph workflow]
                                              │
                              ┌───────────────┼───────────────┐
                              ▼               ▼               ▼
                       Clone repo      Classify (7B LLM)   Get history
                                              │
                                              ▼
                              [5 SAST scanners in parallel]
                              Trivy + Gitleaks + Semgrep + Checkov + OSV
                                              │
                                              ▼
                              [14B LLM combined analysis]
                                              │
                                              ▼
                              [Post review on GitHub PR]
                              + inline suggestions on changed lines
                              + commit status (pass/fail)
                              + save to PostgreSQL
```

The whole thing is autonomous — no human intervention required.

---

## Part 3: The 12 Containers Explained

Each container does one specific job. They communicate over a private Docker network
called `devsecops-net`.

### The Brain
- **`devsecops-agent`** — the FastAPI Python application. This is the heart. It receives
  webhooks, runs the LangGraph workflow, calls the LLMs, executes scanners, posts
  results to GitHub. About 120 MB of RAM.

### The AI
- **`ollama`** — runs the language models locally. Two models are used:
  `qwen2.5-coder:7b` (4.7 GB, fast classification) and `qwen2.5-coder:14b` (9 GB,
  deep security analysis). Port 11434 is internal-only — completely isolated from
  the internet.

### The Memory
- **`postgres`** — PostgreSQL 16 database that does two jobs: stores all PR reviews
  and scan results forever (knowledge base), and stores LangGraph checkpoints so
  the pipeline can resume after a container restart.
- **`redis`** — fast in-memory cache for three jobs: dedupes webhooks (GitHub may
  send the same one twice), rate-limits (max 3 pipelines per repo at once), and
  caches scan results for 1 hour.

### The Gateway
- **`nginx`** — the only container exposed to the internet (ports 80 and 443).
  It routes traffic to the right internal service and protects the chat UI with
  HTTP Basic Auth.

### The Eyes (Observability)
- **`prometheus`** — scrapes metrics every 15 seconds from the agent and from
  node-exporter. Stores 30 days of data.
- **`victoriametrics`** — long-term storage (90 days). Prometheus pushes metrics
  to it via remote_write.
- **`grafana`** — 3 dashboards visualizing the metrics (VPS Host, DevSecOps Agent,
  PR Reviews).
- **`node-exporter`** — runs on the host network (not the Docker bridge) to read
  real CPU, RAM, disk, and network metrics from `/proc` and `/sys`.
- **`alertmanager`** — receives alerts from Prometheus and forwards them to the
  agent, which then sends them to Slack.

### The Auxiliary
- **`jenkins`** — CI/CD server already used by BTE. The agent's chat can query
  its build status.
- **`open-webui`** — web interface for direct interaction with Ollama models
  (separate from the PR pipeline).

---

## Part 4: The Two-Model LLM Architecture

Using a single 14B model for everything would be slow and wasteful. Classification
is a simple JSON tag — it doesn't need 9 GB of model weights. So you split the work.

### The two models

| Model | Size | Speed (CPU) | Job |
|-------|------|-------------|-----|
| `qwen2.5-coder:7b` | 4.7 GB | ~5 tok/s | **Classification** — categorize the PR (feature, dependency, infrastructure, config, docs). Takes ~30 seconds. |
| `qwen2.5-coder:14b` | 9.0 GB | ~3.2 tok/s | **Security analysis** — full OWASP Top 10 review, risk score, verdict, inline comments. Takes 6–11 minutes. |

### Why not 32B?

Tested it — takes 14–34 minutes per review. Marginally better quality, much worse
speed. Not worth it.

### The model benchmark you ran

| Model | Size | Speed | Tool Accuracy | Args Format | Decision |
|-------|------|-------|---------------|-------------|----------|
| `qwen2.5-coder:7b` | 4.7 GB | ~5 tok/s | 80% | 100% | ✅ Default chat |
| `qwen2.5-coder:14b` | 9.0 GB | ~3.2 tok/s | 80% | 100% | PR review |
| `llama3.2:3b` | 2.0 GB | ~8 tok/s | 0% (full prompt) | — | ❌ Experimental |
| `granite3.1-dense:2b` | 1.6 GB | ~8.5 tok/s | 0% | — | ❌ Incompatible |

**Findings:** `llama3.2:3b` saturates its 4096-token context with the system prompt
alone (no room to reason). `granite3.1-dense:2b` uses IBM's proprietary tool-call
schema (incompatible). `qwen2.5-coder:7b` is 43% faster than 14b with identical
80% accuracy, so it became the default chat model.

### The key optimization (Sprint 5)

The original design used the 14B model **TWICE** — once for security analysis,
once for code quality review. Total time: 13–23 minutes. You merged them into a
single combined call producing both outputs at once. Total time: 6–11 minutes.
**50% faster** with no quality loss.

### Ollama performance tuning

| Setting | Value | Effect |
|---------|-------|--------|
| `OLLAMA_FLASH_ATTENTION=1` | enabled | Reduces KV cache from O(n²) to O(n) |
| `OLLAMA_KV_CACHE_TYPE=q8_0` | 8-bit | Halves KV RAM (~650 MB saved at 16K ctx) |
| `OLLAMA_NUM_THREAD=12` | all cores | Pins to 12 Haswell cores |
| `OLLAMA_MAX_LOADED_MODELS=1` | one at a time | All RAM to active model |
| `OLLAMA_NUM_PARALLEL=1` | single request | All 12 cores for one inference |
| `OLLAMA_KEEP_ALIVE=20m` | 20 minutes | Keep model warm |
| `shm_size: 2gb` | shared memory | Thread sync buffers |
| Memory limit `42g` | Docker constraint | Fits 14B (9 GB) + headroom |

---

## Part 5: The 5 Security Scanners

When the agent runs scans, it uses different tools for different categories. Each
one is an industry-standard SAST (Static Application Security Testing) tool.

| Tool | Catches | Why this one |
|------|---------|--------------|
| **Trivy** | CVE vulnerabilities in dependencies and Docker images | Lightweight, fast, daily-updated CVE database |
| **Gitleaks** | Exposed secrets (API keys, passwords, tokens) | 130+ predefined rules, can omit the actual secret value from output (security) |
| **Semgrep** | OWASP Top 10 (SQL injection, XSS, SSRF, etc.) | Pinned rulesets `p/security-audit` + `p/owasp-top-ten` for deterministic results |
| **Checkov** | Misconfigured Dockerfiles, Terraform, Kubernetes YAML | Pip-installable, broad IaC coverage |
| **OSV-Scanner** | Vulnerable dependencies (cross-references Google's OSV database) | Free, open-source, no API key |

### Parallel execution

These run in parallel via Python's `asyncio.gather()` — if one fails, the others
keep going. Results are cached in Redis for 1 hour (so re-running on the same code
is instant).

### Scan matrix

| Classification | Trivy FS | Gitleaks | Semgrep | Checkov | OSV |
|----------------|----------|----------|---------|---------|-----|
| `feature` | ✓ | ✓ | ✓ | | |
| `dependency` | ✓ | ✓ | | | ✓ |
| `infrastructure` | ✓ | ✓ | | ✓ | |
| `config` | ✓ | ✓ | | | |
| `docs` | | | | | |

When a Dockerfile is detected, the image is also built and Trivy scans the image
in addition to the filesystem.

### The token-reduction trick

Raw scanner output is huge JSON. You filter it to keep only what matters before
sending to the LLM:

| Section | Before | After | Reduction | Technique |
|---------|--------|-------|-----------|-----------|
| Trivy (30 vulns) | ~6 000 chars | ~2 500 chars | 58% | Removed Description, References, CVSS, Target |
| Gitleaks | ~400 chars | ~200 chars | 50% | Match field omitted (security) |
| Semgrep | ~2 000 chars | ~1 200 chars | 40% | INFO findings collapsed to count |
| Checkov | ~1 500 chars | ~800 chars | 47% | Guideline URL removed |
| **Total** | **~9 900 chars** | **~4 700 chars** | **52%** | — |

Result: **52% fewer tokens** going to the LLM, freeing context space for actual
code analysis.

---

## Part 6: LangGraph — The Workflow Engine

The pipeline isn't a simple script. It's a **state machine** with 9 nodes, branches,
error handling, and the ability to pause and resume.

### The graph topology

```
START
  │
  ▼
intake_node          ← Clone repo, get diff, dedupe webhook, rate limit
  │
  ▼
classify_node        ← LLM 7B → {feature/dependency/infrastructure/config/docs}
  │
  ▼
[route_scans]        ← Decision: which scanner suite?
  │
  ├──► docs        → skip_scan_node    (no scans for documentation)
  ├──► Dockerfile? → scan_full_node    (scan the built image too)
  └──► default     → scan_fs_node      (filesystem only)
       │
       ▼
analyze_review_node  ← LLM 14B combined → security review + inline comments
  │
  ▼
[route_risk]         ← Decision: escalate to human?
  │
  ├──► HIGH/CRITICAL → escalate_node   (PAUSE for Slack approval)
  └──► default       → report_node     (post to GitHub)
       │
       ▼
       END
```

### Detailed node descriptions

**`intake_node`**
1. Redis dedup: `SET NX dedup:{repo}:{pr}:{sha}` — early return if duplicate
2. Rate limit: max 3 concurrent pipelines per repo
3. Posts placeholder comment to PR: "Security review in progress…"
4. Clones PR branch: `git clone --depth 1 --branch {head_branch} {url}`
5. Local -U15 diff: `git fetch --depth=1 origin {base_branch}` then
   `git diff -U15 FETCH_HEAD..HEAD` (fallback to GitHub API -U3 diff if fetch fails)
6. `truncate_diff()` — caps at 30 000 chars
7. Detects Dockerfile via `check_dockerfile()`
8. Extracts changed files from diff headers
9. `knowledge.get_repo_history()` — last 10 PR reviews for context

**`classify_node`**
- Calls `get_fast_llm()` (7B, `format="json"`, `num_predict=512`, `num_ctx=4096`,
  `temperature=0.0`)
- Output: `{"classification": "feature|dependency|infrastructure|docs|config", "risk_hint": "..."}`
- Fallback: `_fallback_classify()` regex on file extensions and names if LLM fails

**`scan_full_node` / `scan_fs_node`**
- Central scan runner with Redis caching, Prometheus timing, error isolation
- Cache hit → skip scanner, return cached result
- Cache miss → run scanner → cache result (skip raw to save Redis memory)
- After `asyncio.gather()`, raw outputs saved to disk in
  `./artifacts/scans/{owner}-{repo}/pr-{number}/`

**`analyze_review_node`** ← Combined security + code quality
- Calls `get_combined_llm()` (14B, `num_ctx=12288`, `num_predict=2500`,
  `temperature=0.1`)
- Single prompt produces: security review markdown + JSON tail
  `{risk_score, verdict, code_review_summary, comments[]}`
- Comments validated line-by-line against actual diff (hallucinated lines dropped)
- Posts formal GitHub PR Review with inline suggestion blocks
- Saves to PostgreSQL knowledge base

**`escalate_node`**
- Only runs when `SLACK_ESCALATION_ENABLED=true`
- Posts Slack Block Kit message with Approve/Reject buttons
- Graph checkpoints to PostgreSQL and pauses
- `POST /callbacks/slack` resumes the graph

**`report_node`**
- Updates placeholder comment with final review
- Sets commit status (success/failure)
- Sends Slack notification
- Saves `summary.json` to artifacts
- Cleans up: removes Docker image, removes repo clone
- Releases Redis rate limit
- Emits final metrics

**`error_node`**
- Catches any exception
- Posts failure comment to PR
- Sends Slack error alert
- Releases Redis rate limit

### The magic of LangGraph

The state of the workflow is persisted in PostgreSQL after every node via
`AsyncPostgresSaver`. If the container crashes mid-pipeline (8 minutes into a
10-minute review), the workflow resumes from the last checkpoint. Nothing is lost.

---

## Part 7: The Chat Operational Assistant

You built a **second product** alongside the PR pipeline: an interactive chat at
`/ui` that lets operators ask questions about the infrastructure in natural language.

### Example queries it answers
- "What is the current CPU usage?"
- "How much RAM is each container using?"
- "Show me the last 5 PR reviews from the database"
- "Has Ollama been responsive in the last hour?"
- "Are there any active Prometheus alerts?"
- "What is the disk usage right now?"
- "Show me the Trivy results for owner/repo PR 3"

### How it works (custom ReAct loop)

The qwen2.5-coder model doesn't speak Ollama's native tool-call API — it outputs
tool calls as plain text JSON. You wrote a custom 4-pass JSON extractor that handles
all the variations (raw JSON, fenced code blocks, embedded JSON after text, fenced
embedded after text).

When it detects a tool call, it executes the tool, injects the result as an
`[OBSERVATION]` block, and lets the model continue.

### The ReAct loop steps

```
1. Stream LLM tokens into buffer
2. Detect tool call shape: starts with "{" OR "```"
3. Parse JSON — 4-pass extractor
4. Dedup check: if tool+args already called this turn → skip, inject "STOP"
5. No-tool guard (step 0 only): if model answered without tool AND question
   contains live-data keywords → intercept, force tool call
6. Invoke tool via asyncio.run_in_executor (sync tools in threadpool)
   Tool results served from in-memory cache if within TTL
7. Inject: [OBSERVATION: tool_name]\n{result}\n[/OBSERVATION]
           + "Every value MUST appear verbatim in an OBSERVATION block."
8. Loop (max 8 tool calls per response)
9. Final LLM response → stream as "token" SSE events
```

### The 20 monitoring tools available to the chat

**VPS / Host (5):**
- `vps_status` — CPU model/cores, RAM used/free/%, disk, uptime, load avg
- `disk_usage` — all mounted filesystems (df -h)
- `top_processes` — top 20 by CPU or memory
- `network_stats` — listening sockets + established TCP connections
- `system_net_io` — cumulative bytes RX/TX per interface

**Docker (6):**
- `list_containers` — name, status, image, ports
- `container_logs` — last N lines, smart truncation at 4000 chars
- `container_stats` — live CPU%, memory, network I/O
- `inspect_container` — state, health, mounts, last 5 health log entries
- `list_images` — all images with name, size, creation date
- `restart_service` — whitelist-restricted (agent, grafana, prometheus, nginx, victoriametrics)

**Ollama (1):**
- `ollama_status` — loaded models, RAM consumed, all installed models

**Prometheus (3):**
- `query_prometheus` — instant PromQL query
- `query_prometheus_range` — range query, returns min/max/avg/latest + sparkline
- `prometheus_alerts` — active firing/pending alerts

**Redis (1):**
- `redis_info` — memory, hit rate %, clients, keyspace, persistence

**Jenkins (1):**
- `jenkins_status` — last build result per job, duration, health

**Scan Artifacts (2):**
- `list_scan_artifacts` — directory listing of saved SAST JSONs
- `read_scan_artifact` — contents of a specific scanner JSON

**Database (1):**
- `query_database` — read-only SELECT, up to 50 rows

### Tool result caching (per-tool TTLs)

| Tool | TTL | Rationale |
|------|-----|-----------|
| `list_images` | 120s | Images are static between deploys |
| `query_prometheus_range` | 120s | Historical data is immutable |
| `disk_usage` | 60s | Disk doesn't change in 60s |
| `query_database` | 60s | Security DB data slow-changing |
| `prometheus_alerts` | 30s | Alert state changes slowly |
| `redis_info` | 30s | Redis stats stable over 30s |
| `jenkins_status` | 30s | Build state stable over 30s |
| `query_prometheus` | 20s | Prometheus scrapes every 15s |
| `vps_status` | 20s | RSS/load barely changes second-to-second |
| `list_containers` | 20s | Container list stable |
| `ollama_status` | 20s | Model load state stable |
| `network_stats` | 15s | Cumulative counters — short TTL |
| `container_stats` | 10s | CPU/RAM — fastest-changing metric |
| `restart_service` | 0 | Never cached (write operation) |

### The anti-hallucination system (6 layers)

A big problem with LLMs is that they invent metric values. You built 6 layers of
protection:

1. **`temperature=0.0`** — fully deterministic, no creative invention
2. **`num_ctx=6144`** — enough room for tool observations without overflow
   (4 100 tokens free after the system prompt)
3. **`num_predict=800`** — complete answers, no truncation (truncated answers
   caused the model to fill in from training memory)
4. **Code-level no-tool guard** — if the model tries to answer a live-data
   question without calling a tool, the agent intercepts and forces a tool call.
   Triggers on ~30 keywords (cpu, disk, container, alerts, logs, status, etc.)
5. **System prompt rules** — 5 explicit "never invent values" rules:
   - NEVER answer from training data
   - ANY live-state question requires a tool call first
   - Every value in the final answer MUST appear verbatim in an `[OBSERVATION]` block
   - "approximately", "typically", "usually" forbidden for live state
   - If you answered without a tool, stop and call the correct tool immediately
6. **Strengthened observation injection** — every tool result reminds the model:
   "every number, percentage, status, name MUST appear verbatim in an
   `[OBSERVATION]` block. NEVER invent."

After Sprint 7, hallucinations were completely eliminated.

### SSE event protocol

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

---

## Part 8: Autonomous Operations

The system manages itself. Two background tasks run permanently inside the agent.

### Disk Guard (every 30 minutes)
- Checks disk usage via `shutil.disk_usage("/")`
- Updates Prometheus gauges (`agent_disk_used_percent`, `agent_disk_free_gb`)
- At >80%: Slack warning (🟡)
- At >90%: automatic `docker builder prune -f` + Slack critical alert (🔴)

### Daily Health Digest (09:00 UTC)
Every morning, posts to Slack a complete status report:
- 💾 Disk usage (% + free GB, with 🟢/🟡/🔴 icon)
- 🤖 Ollama status (loaded model or "idle")
- 🐳 All container states (`docker ps`, with 🟢/🔴 icons)
- 🚨 Active Prometheus firing alerts (or "✅ No active alerts")

### AlertManager Webhook
Prometheus alerts flow:
```
Prometheus → AlertManager → POST /webhooks/alertmanager → Agent → Slack
```

The agent enriches the alert with context and sends a formatted Slack Block Kit
message:
- 🔴 firing critical alert
- 🟡 firing warning alert
- 🔵 resolved alert

For `DiskCritical` alerts, the agent also auto-runs `docker builder prune -f`.

---

## Part 9: Observability — How You Watch the System

### Custom Prometheus metrics (14)

The agent exposes metrics at `/metrics`:

| Metric | Type | Labels | Emitted when |
|--------|------|--------|--------------|
| `agent_reviews_total` | Counter | `risk_score`, `verdict` | `report_node` completes |
| `agent_llm_duration_seconds` | Histogram | `model`, `node` | Each LLM call |
| `agent_scan_duration_seconds` | Histogram | `scanner` | Each scanner |
| `agent_pipeline_duration_seconds` | Histogram | — | Full pipeline end |
| `agent_errors_total` | Counter | `stage` | `error_node` |
| `agent_cache_hits_total` | Counter | — | Redis cache hit |
| `ollama_reachable` | Gauge | — | Every 30s poll (1=reachable, 0=down) |
| `ollama_models_loaded_total` | Gauge | — | Every 30s poll |
| `ollama_model_loaded` | Gauge | `model` | Every 30s poll |
| `ollama_model_size_bytes` | Gauge | `model` | Every 30s poll |
| `ollama_model_vram_bytes` | Gauge | `model` | Every 30s poll |
| `agent_disk_used_percent` | Gauge | — | Every 30s (scheduler) |
| `agent_disk_free_gb` | Gauge | — | Every 30s (scheduler) |

### The `ollama_reachable` design note

This metric distinguishes two states that were previously confused:
- **Ollama idle** (up, no model loaded, normal between reviews):
  `ollama_reachable=1`, `ollama_models_loaded_total=0` → only
  `OllamaNoModelLoaded` (info, 60m window) may fire
- **Ollama down** (unreachable): `ollama_reachable=0` → `OllamaDown` fires
  (critical, 5m)

Before this metric, alerts misfired every time Ollama was simply idle.

### 12 Alert Rules in 4 groups

**Disk group (4 rules):**
- `DiskWarning` — `(size - free)/size > 0.80` (node-exporter), 5m, warning
- `DiskCritical` — `(size - free)/size > 0.90` (node-exporter), 2m, critical
- `AgentDiskWarning` — `agent_disk_used_percent > 80` (agent gauge), 5m, warning
- `AgentDiskCritical` — `agent_disk_used_percent > 90` (agent gauge), 2m, critical

**Host group (3 rules):**
- `HostHighCPU` — `100 - avg(rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100 > 85`, 5m, warning
- `HostHighMemory` — `(1 - node_memory_MemAvailable/node_memory_MemTotal) * 100 > 88`, 3m, critical
- `HostDiskIOHigh` — `rate(node_disk_io_time_seconds_total[5m]) > 0.9`, 5m, warning

**Agent group (3 rules):**
- `AgentDown` — `up{job="devsecops-agent"} == 0`, 1m, critical
- `AgentHighErrorRate` — `rate(agent_errors_total[5m]) > 0.1`, 5m, warning
- `AgentReviewBacklog` — `agent_reviews_total offset 24h == agent_reviews_total`, 1m, info

**Ollama group (2 rules):**
- `OllamaDown` — `ollama_reachable == 0`, 5m, critical
- `OllamaNoModelLoaded` — `ollama_models_loaded_total == 0`, 60m, info

### 3 Grafana dashboards

1. **VPS Host Monitoring** (13 panels) — CPU/RAM/disk/network from node-exporter
2. **DevSecOps AI Agent** (33 panels in 5 rows) — pipeline durations, scanner times,
   review counts, Ollama status, network/disk I/O
3. **PR Security Reviews** (5 panels, PostgreSQL data) — review volume, risk
   distribution, verdict breakdown, pipeline duration, recent PRs table

---

## Part 10: The Methodology — How You Worked

You worked solo for 5 months — 4 months of development, 1 month of writing.
The methodology you adopted is **Agile Scrum adapté + Kanban interne**.

### Outer framework: Agile Scrum
- 8 sprints × 2 weeks = 4 months
- 5 milestones (M1 through M5) — each is a demonstrable working feature
- Definition of Done: deployed + verified in production + documented + validated
  by a real event

### Inner discipline: Kanban
- Within each sprint, a Kanban board with 4 columns
  (Backlog / In Progress / Blocked / Done)
- **WIP limit = 1**: only one task in progress at a time
- Production incidents jump to the top of the backlog automatically

### The 5 milestones

| Milestone | Name | Definition of Done |
|-----------|------|-------------------|
| **M1** | Pipeline alive | One real PR reviewed end-to-end — comment posted on GitHub |
| **M2** | Full intelligence | All 5 scanners + LLM 14B review with risk score and verdict |
| **M3** | Self-operating | Disk guard, daily digest, AlertManager → Slack working without intervention |
| **M4** | Full observability | 4 Prometheus targets green, 12 alerts calibrated, 3 dashboards live |
| **M5** | Production hardened | node-exporter host monitoring, anti-hallucination chat, complete VPS audit |

### The 8 sprints

| Sprint | Weeks | Goal | Key deliverables |
|--------|-------|------|------------------|
| 1 | 1–2 | Foundations | VPS, Docker Compose, FastAPI, GitHub webhook, PostgreSQL |
| 2 | 3–4 | LLM + Classification | 7B model, LangGraph, first PR analyzed end-to-end → **M1** |
| 3 | 5–6 | Scanner pipeline | 5 parallel scanners, 52% SAST token reduction, Redis cache |
| 4 | 7–8 | LLM 14B review | Combined call, GitHub inline review → **M2** |
| 5 | 9–10 | Autonomy + Chat | Disk guard, Slack, AlertManager, 20-tool chat assistant → **M3** |
| 6 | 11–12 | Observability | 4 Prometheus targets, 12 alerts, 3 Grafana dashboards → **M4** |
| 7 | 13–14 | Optimization | Model benchmark, prompt compression 36%, tool cache |
| 8 | 15–16 | Hardening | VPS audit, anti-hallucination, validation → **M5** |
| — | 17–20 | Documentation | Final report writing, soutenance preparation |

### What WIP=1 prevented

The temptation to start something new while the current task is "almost done" is
constant. By forcing yourself to deploy and validate every feature before pulling
the next card, you ended the project with **zero half-finished features**.

### The governing principle

> **Ship something real every day.**

Not "write code" — deploy and verify. `docker compose up -d`, trigger a real
event (a PR webhook, a disk check, a Prometheus scrape), observe the result. A
day where 300 lines were written but nothing is deployed is worth less than a day
where 30 lines were written and a new scanner is running in production.

---

## Part 11: Real Production Incidents (and how you handled them)

Three real incidents shaped the system.

### Incident 1: Disk emergency (April 20, 2026)

A partial download of the 32B model left a 242 GB orphaned blob
(`sha256-c430a9b9...`) with no manifest — unusable but consuming disk. Combined
with `llama3.2:3b` and Docker build cache, disk reached **92% usage**. No alert
existed yet to catch this.

**Resolution:**
```bash
docker exec ollama ollama rm sha256-c430a9b9...   # 242 GB
docker exec ollama ollama rm llama3.2:3b           # 2 GB
docker builder prune -f                            # ~1.5 GB
# Result: 92% → 14% disk. 233 GB freed. No services interrupted.
```

This emergency directly drove the disk guard scheduler and AlertManager
integration — both became immediate top-priority Kanban cards.

### Incident 2: VictoriaMetrics down 9 days (discovered April 28, 2026)

On April 19, when the disk hit 0 bytes free, VictoriaMetrics panicked with
`FATAL: cannot create directory: no space left on device` and exited with code 2.
`restart: unless-stopped` couldn't restart it (disk was still full at that
moment). After the disk was freed on April 20, the container stayed `exited` and
was never noticed. Prometheus continued sending data into a void for 9 days.

You discovered it during the VPS audit on April 28. Restarted with
`docker compose restart victoriametrics`. Storage opened cleanly — 10.9M rows
recovered intact. Prometheus remote_write resumed.

**Prevention:** Lower disk alert threshold from 80%/90% to 70%/80%. Use
`restart: always` instead of `unless-stopped`.

### Incident 3: AlertManager broken since deployment (discovered same audit)

The Prometheus config was missing `path_prefix: /alertmanager/` in the
`alerting.alertmanagers` section. Every alert was sent to `/api/v2/alerts`
(404 from AlertManager) instead of `/alertmanager/api/v2/alerts`. AlertManager
had **never received a single alert** since day one. `OllamaNoModelLoaded` was
firing in Prometheus but the agent webhook never received it.

**Fix:** Added `path_prefix: /alertmanager/` to `prometheus.yml`. Required
container restart (bind-mount inode issue — hot reload applied config but
container kept old file).

These three incidents turned into permanent improvements: lower disk thresholds,
better restart policies, monitoring of monitoring.

---

## Part 12: Security Design

### HMAC webhook validation
```python
expected = "sha256=" + hmac.new(secret.encode(), body, sha256).hexdigest()
is_valid = hmac.compare_digest(expected, signature)  # timing-safe
```
Requests with invalid or missing signatures → 403 Forbidden.

### Ollama not host-exposed
Port 11434 is no longer bound on the host interface. Ollama is accessible only
within the Docker network (`devsecops-net`). This prevents external `ollama
pull` calls that could fill the disk.

### Token injection (never stored)
```python
clone_url = clone_url.replace("https://github.com",
                              f"https://{token}@github.com")
```
The injected URL is only in the local variable — stored in the cloned repo's
`.git/config` inside the ephemeral workspace (cleaned up by `report_node`).

### Repo cleanup
```python
shutil.rmtree(repo_path)
await docker_service.remove_image(docker_image_tag)
```

### No external LLM APIs
All inference runs locally via Ollama. No code or diffs leave the VPS.

### Gitleaks Match field omitted
The `Match` field (partial secret value) is never passed to the LLM prompt —
only `RuleID`, `File`, and `StartLine` are included.

### Diff truncation
`git_service.truncate_diff()` caps at 30 000 chars — prevents LLM context
overflow and resource exhaustion from maliciously large diffs.

### Known security gaps (not yet fixed)

| Service | Port | Risk | Fix |
|---------|------|------|-----|
| `redis` | `6379` host, no auth | Anyone can read/write cache, dedup keys | Remove `ports:`, add `--requirepass` |
| `prometheus` | `9090` host, no auth | Exposes scrape targets, alert rules | Remove `ports:` — access via nginx |
| `alertmanager` | `9093` host, no auth | Alert silence/inhibit API public | Remove `ports:` |
| `victoriametrics` | `8428` host, no auth | Long-term metrics queryable | Remove `ports:` |
| `devsecops-agent` | `8000` host | Bypasses nginx Basic Auth on /ui | Remove `ports:` |
| `open-webui` | `3001` host, signup enabled | Anyone can create account | Remove `ports:`, disable signup |
| `jenkins` | `8080` host | Direct Jenkins access bypasses nginx | Remove `ports:` |

---

## Part 13: The Final Numbers

| Metric | Value |
|--------|-------|
| Containers deployed | 12 |
| Docker images | 12 |
| LLM models available | 4 (`qwen2.5-coder:7b/14b/32b`, `mistral-nemo:12b`) |
| Active models in pipeline | 2 (7B + 14B) |
| Security scanners | 5 |
| Custom Prometheus metrics | 14 |
| Prometheus scrape targets | 4 |
| Alert rules | 12 (in 4 groups) |
| Grafana dashboards | 3 |
| LangGraph nodes | 9 |
| Chat monitoring tools | 20 |
| PostgreSQL tables | 6 (+ 4 LangGraph checkpoint tables) |
| Real PRs validated | 2 (PR #11 and #12, both HIGH risk, REQUEST_CHANGES) |
| Average pipeline duration | ~6 minutes |
| Token reduction (SAST cleaning) | 52% |
| Token reduction (system prompt) | 36% |
| Disk freed during emergency | 233 GB |
| Metrics retention | 30 days local + 90 days VictoriaMetrics |

### PR review timing breakdown

| Stage | Duration |
|-------|----------|
| `intake_node` (clone + diff) | 5–10s |
| `classify_node` (LLM 7B) | ~30s |
| `scan_fs_node` (parallel) | 5–7s (cached) |
| `analyze_review_node` (LLM 14B combined) | 5.5–10 min |
| `report_node` | ~1s |
| **Total** | **6–11 min** |

---

## Part 14: The Report Structure

You wrote a **5-chapter academic report** in French following the standard PFE
format.

### Chapters

1. **Introduction générale** — Context, problem statement, project presentation,
   roadmap (3 paragraphs of flowing prose)

2. **Chapitre 1: Étude préalable du sujet** — BTE presentation (with logo,
   identity card, organigram, sectors), existing analysis, problem, proposed
   solution, methodology (Agile Scrum + Kanban), 5 milestones, 8-sprint Gantt

3. **Chapitre 2: État de l'art et choix technologiques** — DevOps, CI/CD (CI +
   CD figures), DevSecOps, OWASP Top 10, LLM/Ollama, LangGraph, 5 SAST tools,
   observability stack, requirements (functional + non-functional)

4. **Chapitre 3: Conception de la solution** — 12-container architecture,
   2-model LLM, 9-node LangGraph workflow, 3 interaction diagrams (webhook,
   pipeline, chat ReAct), diff parser, database schema (6 tables), chat
   anti-hallucination 6 layers, monitoring architecture

5. **Chapitre 4: Réalisation et résultats** — Hardware/software environment,
   implementation phase by phase (7 phases), validation tests (HMAC, dedup,
   circuit breaker, disk guard), real PR results

6. **Conclusion générale et Perspectives** — Achievements (8 checked goals),
   methodology lessons, future improvements

### Front matter
- Cover page
- Black cover page
- Signatures page
- Remerciements
- Table des matières
- Liste des figures
- Liste des tableaux
- **Liste des abréviations** (33 acronyms specific to this project)

### Back matter
- **Webographie** (29 bibliographic entries)
- **Résumé** page (Arabic + French + English abstracts)

### Final state of the chapters

| File | Lines | Citations | Figures | Tables |
|------|-------|-----------|---------|--------|
| `introduction.tex` | 46 | 0 | 0 | 0 |
| `chapter_1.tex` | 336 | 4 | 6 | 2 |
| `chapitre_2.tex` | 524 | 23 | 7 | 7 |
| `chapitre_3.tex` | 530 | 12 | 12 | 5 |
| `chapitre_4.tex` | 604 | 20 | 24 | 7 |
| `conclusion.tex` | 53 | 0 | 0 | 0 |

---

## Part 15: What Makes This Project Unique

Three things distinguish your project from a standard internship.

### 1. It's actually in production

It's not a prototype. It's running 24/7 on a real VPS, processing real Pull
Requests, managing itself autonomously. You handled real incidents in real time
— the 242 GB disk emergency, the 9-day VictoriaMetrics outage, the silently
broken AlertManager. Each became a permanent improvement.

### 2. The constraint forced creativity

"No code can leave the bank" is what forced the local-LLM architecture, which
is what makes the project genuinely interesting technically. Most AI projects
today just call OpenAI. Yours doesn't. Building a 6-minute on-CPU LLM pipeline
that's competitive with cloud-based reviews is a real engineering achievement.

### 3. The methodology matches the work

You didn't pretend to do daily standups. You honestly described what you did —
Kanban for daily work, Scrum for the calendar — and explained why the
combination fits a solo project in a production environment. That intellectual
honesty is rare in academic reports.

---

*BTE Security AI Agent — built for the BTE DevSecOps platform — 2026*
