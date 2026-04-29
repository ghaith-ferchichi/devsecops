# Internship Project Methodology Report
## BTE Security AI Agent — DevSecOps Platform

---

## Project Identity

| Field | Details |
|-------|---------|
| **Project name** | BTE Security AI Agent — Event-Driven DevSecOps Platform |
| **Developer** | Solo intern — Ghaieth Ferchichi |
| **Environment** | Empty VPS (141.94.92.226) — Ubuntu Linux, 12 CPU cores, 45 GB RAM, 290 GB disk |
| **Duration** | 12 weeks |
| **Starting point** | Blank VPS with SSH credentials only |
| **Final state** | 11-container production platform, fully autonomous, self-monitoring |

---

## 1. Chosen Methodology: Personal Kanban + Milestone-Driven Development

### 1.1 Why Not Standard Agile Scrum

Agile Scrum is designed for teams of 5 to 9 people. Its ceremonies — daily standups, sprint planning sessions, retrospectives with a Scrum Master — assume multiple roles and parallel workstreams. Applying it to a solo internship project would produce overhead with no benefit: you cannot have a standup with yourself.

### 1.2 Why Not Waterfall

Waterfall requires a complete requirements specification before the first line of code is written. This project was impossible to fully specify upfront. Multiple critical components were only discovered to be necessary after deployment:

- The **disk guard scheduler** was built after a real 242 GB disk emergency (92% disk usage caused by an orphaned model blob).
- The **`ollama_reachable` metric** was built after discovering the `OllamaDown` alert was misfiring on idle Ollama — a condition invisible until the alert fired.
- The **nginx DNS resolver fix** was discovered only after a container recreation caused a 502 Bad Gateway.
- The **combined LLM call optimization** became a priority only after measuring real pipeline duration on a live PR review.

None of these could have been in a Waterfall specification. Reality is always more complex than the design document.

### 1.3 Why Not Pure Kanban

Pure Kanban works well for ongoing maintenance operations — tuning alerts, patching scanners, adjusting thresholds. It does not provide the milestone structure an internship supervisor needs to track progress, and it has no mechanism for demonstrating a completed, working increment at a defined checkpoint.

### 1.4 The Chosen Hybrid: Personal Kanban + Milestone-Driven Development

The methodology used in this project combines three layers:

```
STRATEGIC layer ── Milestones (supervisor-visible checkpoints)
      │
TACTICAL layer  ── Personal Kanban board (daily task management)
      │
LEARNING layer  ── Build → Deploy → Observe → Improve (production feedback loop)
```

**Personal Kanban** provides day-to-day discipline:
- A board with four columns: `BACKLOG | IN PROGRESS (WIP=1) | BLOCKED | DONE`
- A hard WIP limit of 1 — only one task in progress at any time
- Tasks pulled from backlog in priority order, completed before the next begins

**Milestone-Driven Development** provides supervisor visibility:
- 4 milestones defined at project start, each corresponding to a demonstrable system state
- Milestones are not time-boxed to exact weeks — they complete when the system works
- Each milestone deliverable is a live demonstration, not a document

**Build → Deploy → Observe → Improve** is the core engineering loop:
- Every feature is deployed to the real VPS immediately after coding
- Production behavior (logs, Prometheus metrics, real PR reviews) reveals what the design missed
- Discoveries go back into the backlog as the highest-priority items

### 1.5 The Governing Rule

> **Ship something real every day.**

Not "write code" — deploy and verify. `docker compose up -d`, trigger a real event (a PR webhook, a disk check, a Prometheus scrape), observe the result. A day where 300 lines were written but nothing is deployed is worth less than a day where 30 lines were written and a new scanner is running in production.

---

## 2. Project Phases and Milestones

```
Phase 1: Foundation          ── Weeks 1–2   ── Milestone 1
Phase 2: Intelligence        ── Weeks 3–4   ── Milestone 2
Phase 3: Autonomy            ── Weeks 5–7   ── Milestone 3
Phase 4: Optimization        ── Weeks 8–9   ── Milestone 4
Phase 5: Documentation       ── Weeks 10–12 ── Final presentation
```

| Milestone | Name | Definition |
|-----------|------|------------|
| M1 | Pipeline Alive | One real PR reviewed end-to-end — comment posted to GitHub |
| M2 | Full Intelligence | All 5 scanners + LLM security review with risk score and verdict |
| M3 | Self-Operating | System runs unattended — alerts firing, Slack notified, disk guarded |
| M4 | Production Quality | Monitoring clean, performance optimized, documentation complete |

---

## 3. Weekly Breakdown — Detailed Work Report

---

### Week 1 — VPS Setup & Infrastructure Foundation

**Phase:** Foundation
**Goal:** Go from empty VPS to a running Docker environment with basic connectivity.

**Tasks completed:**

| Task | Technical detail | Outcome |
|------|-----------------|---------|
| VPS access and audit | SSH into bare Ubuntu, audit CPU (12-core Haswell/AVX2), RAM (45 GB), disk (290 GB), kernel | Environment profile documented |
| Docker installation | Install Docker Engine 29.4.0 + Compose v2 plugin via official apt repo | `docker compose up` functional |
| Project structure | Create `/opt/devsecops/` directory tree: `agent/`, `nginx/`, `prometheus/`, `grafana/`, `artifacts/` | Repository scaffold ready |
| Docker Compose skeleton | Write `docker-compose.yml` with Ollama, PostgreSQL, Redis, nginx services | 4 containers running |
| Ollama base setup | Pull `qwen2.5-coder:7b` model (4.7 GB). Verify inference: `ollama run qwen2.5-coder:7b "hello"` | LLM responds on internal network |
| CPU inference tuning | Set `OLLAMA_NUM_THREAD=12`, `OLLAMA_FLASH_ATTENTION=1`, `OLLAMA_KV_CACHE_TYPE=q8_0` | Haswell AVX2 backend auto-selected (`libggml-cpu-haswell.so`) |
| PostgreSQL init | Create `devsecops` user and `devsecops_db` database | Database accessible |
| `.env` file | Define all secrets: GitHub token, Slack bot token, Postgres password, webhook secret | Configuration centralized |

**Challenges encountered:**
- Ollama memory limit needed to be set to `42g` — default caused model to be killed by OOM at first load
- `shm_size: 2gb` required for thread synchronization buffers on 12-core inference
- File descriptor limit (`ulimits.nofile: 65536`) needed for concurrent model operations

**Key decision:** Keep Ollama port `11434` off the host-exposed interface from day one — only internal Docker network access. This prevents any external LLM query without going through the agent.

**End-of-week deliverable:** All 4 base containers healthy, Ollama model responding to inference requests on internal network.

---

### Week 2 — FastAPI Agent Skeleton & GitHub Webhook

**Phase:** Foundation
**Goal:** Receive a GitHub Pull Request event and log it — the minimal viable pipeline trigger.

**Tasks completed:**

| Task | Technical detail | Outcome |
|------|-----------------|---------|
| FastAPI application | Create `agent/app/main.py` with lifespan context manager, structlog dual handler (console JSON + rotating file) | Agent starts, logs structured JSON |
| Dockerfile | Python 3.12-slim base, install all Python dependencies from `requirements.txt`, bake in Trivy + Gitleaks binaries | Agent image ~1.55 GB |
| GitHub webhook receiver | `POST /webhooks/github` — HMAC-SHA256 validation of `X-Hub-Signature-256` header | Webhook validated |
| Webhook model | `PullRequestWebhookPayload` Pydantic model parsing GitHub's PR event JSON | PR metadata extracted |
| nginx reverse proxy | Write `nginx/nginx.conf` — upstream blocks, `/webhooks/github` proxy, `/ui` route, `/grafana/` route | External traffic routed correctly |
| LangGraph skeleton | Create `StateGraph` with `PRReviewState` TypedDict, `intake_node` stub, `PostgresCheckpointer` | LangGraph compiles and persists state |
| PostgreSQL checkpointing | `AsyncPostgresSaver` — auto-creates `checkpoints`, `checkpoint_blobs`, `checkpoint_writes` tables | Workflow state survives container restart |
| GitHub webhook configuration | Configure GitHub repo → Settings → Webhooks → `http://141.94.92.226/webhooks/github` | GitHub delivers PR events to agent |

**Challenges encountered:**
- `AttributeError: module 'psycopg' has no attribute 'AsyncConnectionPool'` — pool moved to `psycopg_pool` package in psycopg3. Fixed import.
- nginx HTTP/1.0 was mangling chunked webhook bodies → `500 Internal Server Error`. Fixed by adding `proxy_http_version 1.1; proxy_set_header Connection "";`
- `ModuleNotFoundError: langgraph.graph.graph` — import path changed in LangGraph 1.x. Changed to `from langgraph.graph.state import CompiledStateGraph`

**Key decision:** Use `asyncio` background tasks for the LangGraph pipeline — the webhook returns `202 Accepted` immediately and the pipeline runs in the background. GitHub's 10-second timeout on webhook delivery is not a bottleneck.

**End-of-week deliverable:** Opening a real PR on GitHub triggers the webhook, agent logs the PR metadata, LangGraph state is persisted to PostgreSQL.

**Milestone 1 achieved:** Pipeline is alive — PR event flows from GitHub → nginx → FastAPI → LangGraph → PostgreSQL.

---

### Week 3 — LLM Integration & Classification Node

**Phase:** Intelligence
**Goal:** The agent makes its first real LLM call to classify the incoming PR.

**Tasks completed:**

| Task | Technical detail | Outcome |
|------|-----------------|---------|
| Ollama LLM factory | `app/llm/ollama.py` — `get_fast_llm()` (7B, `num_ctx=4096`, `format="json"`, `temperature=0.0`, `@lru_cache`) | LLM client reused across calls |
| `classify_node` | Calls `get_fast_llm()`, sends PR metadata + file list, forces JSON output: `{"classification": "...", "risk_hint": "..."}` | 5 classification categories: feature, dependency, infrastructure, config, docs |
| Regex fallback | `_fallback_classify()` — pattern matches file extensions and names when LLM unavailable | Circuit breaker: pipeline never stalls on LLM failure |
| Circuit breaker | Wraps every LLM call — catches `httpx.ConnectError`, `TimeoutError`, logs warning, calls fallback | Resilient to Ollama cold-start |
| Scan matrix routing | `route_scans()` edge function — returns `"scan_full"` / `"scan_fs"` / `"skip"` based on classification and Dockerfile detection | Correct scanners triggered per PR type |
| `skip_scan_node` | Returns immediately for `docs` classification — no scanners, no LLM review needed | Fast path for documentation PRs |
| Redis deduplication | `SET NX dedup:{repo}:{pr}:{sha}` with 1-hour TTL — duplicate webhook deliveries ignored | Idempotent pipeline |
| Rate limiting | `INCR rate:{repo}` — max 3 concurrent pipelines per repository | Prevents Ollama overload |

**Challenges encountered:**
- `qwen2.5-coder:7b` outputs tool calls as plain text JSON, not OpenAI-style function calls. Required custom JSON extractor with 4-pass fallback parser.
- Default `num_ctx=2048` was too small for the classification prompt. Set to `4096` — covers full file list for typical PRs.
- LLM timeout: default `request_timeout=120s` killed the 14B model warmup. Raised to `900s`.

**Key decision:** Two-model architecture — fast 7B for classification (30s), deep 14B for security review (6–11 min). Using 14B for classification would waste ~8 minutes on a task that needs only a JSON tag.

**End-of-week deliverable:** PR classified correctly in ~30s. File type routing working. Duplicate webhooks ignored.

---

### Week 4 — Security Scanners + First LLM Security Review

**Phase:** Intelligence
**Goal:** Run all security scanners in parallel and produce the first real LLM security review posted to GitHub.

**Tasks completed:**

| Task | Technical detail | Outcome |
|------|-----------------|---------|
| Git clone in pipeline | `git clone --depth 1 --branch {head_branch} {url}` into agent workspace volume | PR code available for scanning |
| Local git diff | `git fetch --depth=1 origin {base_branch}` + `git diff -U15 FETCH_HEAD..HEAD` — 15 lines of context vs GitHub API's fixed -U3 | More useful diff context for LLM analysis |
| Trivy FS scanner | `trivy fs --format json --severity CRITICAL,HIGH,MEDIUM` — CVE scan on cloned repo | Vulnerability findings extracted |
| Gitleaks scanner | `gitleaks detect --source {path} --report-format json` — secret detection | Credential leaks detected |
| Semgrep scanner | `semgrep scan --config p/security-audit --config p/owasp-top-ten --json` — pinned rulesets | Deterministic SAST results |
| Checkov scanner | `checkov -d {path} --output json` — IaC misconfiguration detection | Infrastructure-as-Code issues found |
| OSV-Scanner | `osv-scanner --format json {path}` — known vulnerability database check | Dependency CVEs cross-referenced |
| Scan matrix | Each classification type runs only relevant scanners via `asyncio.gather()` | Parallel execution, no wasted time |
| SAST token reduction | Remove Checkov `guideline` URLs (~150 chars/finding), collapse Semgrep INFO to count | ~52% reduction in SAST tokens sent to LLM |
| 14B security review | `get_deep_llm()` (14B, `num_ctx=8192`, `temperature=0.1`) — OWASP Top 10 analysis, risk_score, verdict | Security review markdown generated |
| GitHub PR comment | `github_api.post_pr_comment()` — posts full security review as PR comment | Review visible on GitHub |
| GitHub commit status | `set_commit_status()` — `success` for APPROVE, `failure` for REQUEST_CHANGES/BLOCK | CI gate enforced |
| PostgreSQL knowledge base | `knowledge.save_pr_review()` — stores risk score, verdict, review text, scan summary, duration | All reviews queryable |
| Artifact storage | Raw scanner JSONs saved to `./artifacts/scans/{owner}-{repo}/pr-{n}/` | Full audit trail preserved |

**Challenges encountered:**
- GitHub API always returns `-U3` unified diff — only 3 lines of context around each change. Critical for security review (injection patterns span multiple lines). Fixed by implementing `get_local_diff()` with `git diff -U15`.
- Semgrep `--config auto` fetches unpredictable remote rulesets — non-deterministic results across runs. Pinned to `p/security-audit` + `p/owasp-top-ten`.
- Inline comment line numbers hallucinated by LLM. Fixed by `diff_parser.py` — validates every suggested line against the actual diff hunks before posting.

**Key decision:** Scanner isolation — each scanner runs in a separate `asyncio` coroutine with its own exception handler. One scanner failing does not abort the pipeline.

**End-of-week deliverable:** Full security review posted to a real PR with risk score, verdict, OWASP findings, and scanner summaries. Commit status set correctly.

**Milestone 2 achieved:** Full scanner coverage + LLM security review + GitHub integration all working end-to-end.

---

### Week 5 — Code Quality Review & Pipeline Optimization

**Phase:** Intelligence → Autonomy transition
**Goal:** Add code quality review (inline GitHub comments) and merge two LLM calls into one for performance.

**Tasks completed:**

| Task | Technical detail | Outcome |
|------|-----------------|---------|
| `analyze_review_node` | Merges former `analyze_node` + `code_review_node` into one 14B call | Single LLM call instead of two sequential calls |
| Combined prompt | `app/prompts/combined_review.py` — single prompt produces security review markdown + JSON block with `risk_score`, `verdict`, `code_review_summary`, `comments[]` | One LLM request handles both concerns |
| `get_combined_llm()` | 14B, `num_ctx=12288`, `num_predict=2500`, `temperature=0.1`, `@lru_cache` | 50% larger context for combined output |
| GitHub PR Review with inline comments | `github_api.post_pr_review()` — posts formal review with inline `suggestion` blocks on actual diff lines | Inline code suggestions visible in GitHub PR files tab |
| Diff annotated view | Annotated diff with line numbers passed to LLM alongside plain diff — enables accurate line mapping | Hallucinated line numbers eliminated |
| `escalate_node` | `interrupt_before=["escalate"]` — LangGraph pauses pipeline on CRITICAL/HIGH risk, waits for Slack approval via `POST /callbacks/slack` | Human-in-the-loop gate before merging dangerous PRs |
| `report_node` | Final PR comment, commit status, Slack notification, artifact save, cleanup (repo clone + Docker image if built) | Clean pipeline end state |
| `error_node` | Catches any exception from any node — posts failure comment to PR, Slack error alert, releases Redis rate limit | No silent failures |
| `SLACK_ESCALATION_ENABLED` flag | Defaults to `false` — Slack gate optional | Pipeline not blocked when Slack unavailable |

**Performance measurement:**

| Before (two calls) | After (one call) |
|-------------------|-----------------|
| analyze: ~6–11 min | combined: ~6–11 min |
| code_review: ~6–11 min | — (eliminated) |
| **Total: ~13–23 min** | **Total: ~6–11 min** |

**End-of-week deliverable:** PR reviewed in under 7 minutes with both security review and inline code quality comments. Escalation gate functional.

---

### Week 6 — Slack Integration & Chat Ops Assistant

**Phase:** Autonomy
**Goal:** Build the BTE Security AI Agent chat interface for live infrastructure monitoring.

**Tasks completed:**

| Task | Technical detail | Outcome |
|------|-----------------|---------|
| Slack bot integration | `slack_api.py` — `send_notification()`, `request_approval()` using Slack Block Kit | Formatted alerts sent to `#security-channel` |
| Slack approval callback | `POST /callbacks/slack` — verifies Slack signature, resumes LangGraph checkpoint from PostgreSQL | Human approval resumes paused pipeline |
| BTE Security AI Agent chat UI | `app/routers/chat.py` — ReAct loop with SSE streaming, `num_ctx=16384` for 16K context window | Interactive ops assistant at `/ui` |
| 19 monitoring tools | VPS status, disk, top processes, network stats, container logs, container stats, Ollama status, Prometheus query, Redis info, Jenkins status, scan artifacts, database query (read-only) | Full infrastructure observability via chat |
| Custom ReAct loop | Token-by-token streaming, 4-pass JSON extractor for tool calls, `[OBSERVATION]...[/OBSERVATION]` injection, 8-tool call limit per response | `qwen2.5-coder` models work without native tool-calling |
| SSE event protocol | 10 event types: `status`, `thinking_start`, `thinking_token`, `thinking_end`, `tool_start`, `tool_end`, `token`, `replace_text`, `error`, `done` | Smooth real-time streaming UI |
| Static chat UI | `app/static/index.html` — BTE Security AI Agent branding, SSE event consumer, syntax-highlighted code blocks | Accessible at `http://141.94.92.226/ui` |
| `num_ctx=16384` fix | Default 4096 context was too small for BTE system prompt (~3K tokens) — LLM returned empty responses | Chat fully functional with 16K context |

**Challenges encountered:**
- LLM no response bug: the system prompt alone consumed ~3K tokens, leaving no room for the actual conversation in a 4K context window. Increasing to 16K fixed it.
- Tool result hallucination: model was paraphrasing tool output instead of quoting it verbatim. Fixed with `[OBSERVATION]...[/OBSERVATION]` format + explicit "CRITICAL: quote verbatim" directive in system prompt.
- Wrong database column name: model hallucinated `pr_id` column. Fixed by injecting full PostgreSQL schema into the system prompt.

**End-of-week deliverable:** Chat UI running at `/ui`. Can ask "show me the last 5 PR reviews from the database" and get real data. Can ask "how much RAM is each container using?" and get live `docker stats` output.

---

### Week 7 — Disk Emergency & Autonomous Operations

**Phase:** Autonomy
**Goal:** Add autonomous background operations — the system manages itself without human intervention.

**Emergency response (unplanned — 2026-04-20):**

A partial `qwen2.5-coder:32b` model download left a 242 GB orphaned blob (`sha256-c430a9b9...`) with no manifest — unusable but consuming disk. Combined with `llama3.2:3b` and Docker build cache, disk reached **92% usage**. Prometheus alert would have fired but AlertManager was not yet deployed.

**Emergency resolution:**
```bash
docker exec ollama ollama rm sha256-c430a9b9...   # orphaned blob
docker exec ollama ollama rm llama3.2:3b           # unused model
docker builder prune -f                            # build cache
```
Result: 233 GB freed. 92% → 14% disk usage. No running services affected.

**Tasks completed (planned + emergency-driven):**

| Task | Technical detail | Outcome |
|------|-----------------|---------|
| Disk guard scheduler | `app/services/scheduler.py` — `_disk_guard_loop()` every 30 min: update Prometheus gauges, Slack alert at >80% / >90% | Autonomous disk monitoring without node-exporter |
| `agent_disk_used_percent` gauge | `shutil.disk_usage("/")` → Prometheus Gauge updated every 30 min | Disk metric exposed to Prometheus |
| Auto-prune on critical | `docker builder prune -f` triggered automatically at >90% disk — result reported to Slack | Self-healing: same action taken manually during emergency |
| Daily health digest | `_health_digest_loop()` — every day at 09:00 UTC: disk + containers + Ollama + active alerts → Slack Block Kit | Proactive daily system status |
| AlertManager service | Add `prom/alertmanager:latest` to docker-compose — port 9093, `alertmanager/alertmanager.yml` config | Alert routing infrastructure |
| `POST /webhooks/alertmanager` | Receives Prometheus alert payloads — separates firing/resolved, posts Slack Block Kit with severity icons (🔴/🟡/🔵) | AlertManager → agent → Slack pipeline |
| Open WebUI | Add `ghcr.io/open-webui/open-webui:main` on port `3001` — connects to `http://ollama:11434` | Direct model interaction without PR pipeline |

**End-of-week deliverable:** Disk guard running — verified by artificially checking `agent_disk_used_percent` in Prometheus. Daily digest fires at 09:00 UTC. AlertManager receiving test alert and routing to Slack.

**Milestone 3 achieved:** System is self-operating. Disk, agent health, and Ollama connectivity monitored autonomously. Alerts reach Slack automatically.

---

### Week 8 — Prometheus Monitoring Stack & Grafana Dashboards

**Phase:** Optimization
**Goal:** Full observability — every component visible in Prometheus and Grafana.

**Tasks completed:**

| Task | Technical detail | Outcome |
|------|-----------------|---------|
| Prometheus configuration | `prometheus/prometheus.yml` — 3 scrape jobs, 30-day local retention, remote_write to VictoriaMetrics | Metrics pipeline complete |
| Alert rules | `prometheus/alerts.rules.yml` — 9 rules across 3 groups (disk × 4, agent × 3, ollama × 2) | Automated alerting for all critical conditions |
| VictoriaMetrics | `victoriametrics/victoria-metrics:latest` — 90-day retention, receives remote_write from Prometheus | Long-term metrics storage |
| Grafana datasources | Provisioned: Prometheus, VictoriaMetrics, PostgreSQL — env-var interpolation for credentials | All data sources available without manual UI setup |
| Grafana agent dashboard | `grafana/provisioning/dashboards/devsecops_agent.json` — LLM duration, scanner duration, review counts, Ollama gauges, disk usage | Live agent performance dashboard |
| Grafana PR reviews dashboard | `grafana/provisioning/dashboards/pr_reviews.json` — 5 panels backed by PostgreSQL queries: review volume, risk distribution, verdict breakdown, pipeline duration, recent PRs table | Business-level PR security metrics |
| `prometheus-fastapi-instrumentator` | Auto-instruments all FastAPI routes — request count, latency histogram, in-progress gauge — exposed at `/metrics` | HTTP-level observability |

**Monitoring gaps discovered and fixed in production:**

| Gap | Root cause | Fix |
|-----|-----------|-----|
| Ollama scrape target `down` | `OLLAMA_METRICS=true` does not expose `/metrics` in installed Ollama version | Removed direct Ollama scrape — agent re-exports all Ollama metrics via its own `/metrics` |
| AlertManager scrape target `down` | `--web.route-prefix=/alertmanager/` prefixes all paths — metrics at `/alertmanager/metrics` not `/metrics` | Added `metrics_path: /alertmanager/metrics` |
| Prometheus self-scrape `down` | `--web.route-prefix=/prometheus/` same issue | Added `metrics_path: /prometheus/metrics` |
| `OllamaDown` alert misfiring | Alert used `ollama_models_loaded_total == 0` — fires when Ollama is idle (normal state between PR reviews) | Added `ollama_reachable` Gauge, set by 30s poller to 1/0. Alert changed to `ollama_reachable == 0` |
| `OllamaNoModelLoaded` too aggressive | `for: 10m` fired during normal idle periods | Extended to `for: 60m` |
| Grafana 502 Bad Gateway | nginx cached stale Grafana IP after container recreation. `172.20.0.6` (old) vs `172.20.0.4` (current) | Added `resolver 127.0.0.11 valid=10s` to nginx config — Docker's internal DNS re-resolves upstreams dynamically |

**Key learning:** The gap between "monitoring deployed" and "monitoring correct" required one full week of production observation. This validates the methodology — gaps are only visible after real deployment, not during design.

**End-of-week deliverable:** All 3 Prometheus scrape targets green. All 9 alert rules inactive (correct — no incidents). Both Grafana dashboards loading real data.

**Milestone 4 achieved:** Production quality monitoring — every component observable, every alert correctly calibrated.

---

### Week 9 — Performance Tuning & Security Hardening

**Phase:** Optimization
**Goal:** Reduce pipeline duration and tighten security surface.

**Tasks completed:**

| Task | Technical detail | Outcome |
|------|-----------------|---------|
| Combined LLM call measurement | Measured wall time on real PRs: two sequential 14B calls = 13–23 min | Optimization target identified |
| `analyze_review_node` (merged) | Single `get_combined_llm()` call (`num_ctx=12288`) replacing sequential `analyze_node` + `code_review_node` | Pipeline: 13–23 min → 6–11 min |
| Ollama port security | Removed `ports: - "11434:11434"` from docker-compose — Ollama internal-only | No external LLM access without agent authorization |
| Semgrep ruleset pinning | Changed `--config auto` (non-deterministic remote ruleset) to `--config p/security-audit --config p/owasp-top-ten` | Reproducible, deterministic SAST results |
| SAST token reduction | Checkov: removed `guideline` URLs (~150 chars/finding). Semgrep: collapsed INFO to count only. Total: ~52% reduction | LLM context budget preserved for actual code analysis |
| base_branch field | Added `base_branch: str` to `PRReviewState`, extracted from `pull_request.base.ref` in webhook payload | Local git diff can target correct merge base |
| Local diff vs GitHub API | `get_local_diff()`: `git fetch --depth=1 origin {base_branch}` + `git diff -U15 FETCH_HEAD..HEAD`. GitHub API fallback on failure | 15-line context instead of 3 — security patterns span multiple lines |
| Ollama `KEEP_ALIVE=20m` | Model stays loaded for 20 minutes after last call — avoids cold-start on consecutive PR reviews | Cold-start only on first daily call |
| `MAX_LOADED_MODELS=1` | Prevents loading multiple models simultaneously — all RAM to active model | No RAM fragmentation |

**Performance results on real PRs:**

| PR | Classification | Scanner time | LLM time | Total | Verdict |
|----|---------------|-------------|---------|-------|---------|
| #11 | infrastructure | ~7s (cached) | ~5.5 min | ~6 min | REQUEST_CHANGES |
| #12 | infrastructure | ~5s (cached) | ~4.8 min | ~5.6 min | REQUEST_CHANGES |

**End-of-week deliverable:** PR reviewed in under 6 minutes. All monitoring green. No security ports exposed.

---

### Week 10 — Knowledge Base & Context-Aware Reviews

**Phase:** Optimization → Documentation transition
**Goal:** Reviews are informed by repository history — the agent learns from past PRs.

**Tasks completed:**

| Task | Technical detail | Outcome |
|------|-----------------|---------|
| `get_repo_history()` | PostgreSQL query — last 10 PR reviews for the repository, including risk scores, verdicts, and key findings | Historical context injected into LLM prompt |
| `repo_profiles` table | Rolling risk score average + total review count per repository — updated after each `analyze_review_node` | Repository security posture tracked over time |
| `security_policies` seeding | 3 default policies at startup: `block_critical_vulns` (0 critical / max 5 high CVEs), `require_secret_scan`, `base_image_age` (<90 days) | Policy-driven verdict enforcement |
| `scan_results` table | All scanner outputs stored with `repo_full_name`, `scan_type`, `trigger_type`, `summary` (JSONB), `raw_output` (JSONB) | Full audit trail queryable via chat UI |
| SBOM caching | `sbom_cache` table — stores Software Bill of Materials per repo — avoids re-scanning unchanged dependencies | Scanner cache hits reduce scan time |
| Redis scan caching | `scan:{scanner}:{repo_path}` — 1-hour TTL, serves cached results on unchanged code | PR #12 scanned in ~5s vs ~7s for PR #11 |
| Context injection | Repo history injected into combined review prompt: "This repository has had N reviews, average risk: HIGH" | LLM aware of recurring vulnerability patterns |
| Artifact query tool | `read_scan_artifact` chat tool — reads raw Trivy/Gitleaks/Semgrep JSON from `./artifacts/` by repo and PR number | Operator can inspect full scanner output via chat |

**End-of-week deliverable:** Chat query "show me the last 5 PR reviews" returns real data from PostgreSQL. Scan cache hits on repeated analysis.

---

### Week 11 — Full Documentation & System Report

**Phase:** Documentation
**Goal:** Every component, configuration, and design decision documented as a comprehensive system report.

**Tasks completed:**

| Task | Technical detail | Outcome |
|------|-----------------|---------|
| `Readme.md` full system report | 18 sections: VPS environment, architecture diagram, 11 containers documented, all configurations, alert rules, metrics, nginx routing, database schema, observability stack, autonomous operations, chat UI, artifacts, bugs+fixes, live results, quick start, methodology | Single source of truth for the entire platform |
| `agent/README.md` | Agent internals: LangGraph workflow node reference, all LLM configurations, SAST details, Prometheus metrics with design notes, AlertManager integration, file structure | Developer reference for the agent codebase |
| `methodology.md` | This document — methodology justification, 12-week sprint detail, all challenges and fixes, key decisions, lessons learned | Internship report methodology section |
| Alert rules documentation | All 9 rules documented with exact PromQL expressions, `for:` windows, severity, and design rationale | Operations runbook |
| Architecture ASCII diagram | ASCII flowchart of entire system: GitHub → nginx → agent → LangGraph → Ollama/PostgreSQL/Redis → Prometheus → AlertManager → Slack | System overview in plain text |
| Quick start guide | Step-by-step: secrets setup, docker compose, model pull, webhook configuration, database inspection, monitoring | Reproducible setup from scratch |

**End-of-week deliverable:** Any engineer can read `Readme.md` and understand, reproduce, and operate the entire platform without asking questions.

---

### Week 12 — Final Validation & Internship Presentation

**Phase:** Documentation + Presentation
**Goal:** End-to-end demo of the running system. Final internship presentation.

**Validation checklist:**

| Check | How verified | Status |
|-------|-------------|--------|
| Full PR pipeline | Open real PR → watch comment appear in <7 min | ✅ |
| Risk score accuracy | Compare LLM findings against manual OWASP review | ✅ |
| All scanners running | Check `./artifacts/scans/` for all 5 JSON files | ✅ |
| Prometheus targets | `http://141.94.92.226/prometheus/targets` — all 3 green | ✅ |
| Alert rules inactive | `/prometheus/alerts` — all rules inactive (no incidents) | ✅ |
| Grafana dashboards | Both dashboards loading real data | ✅ |
| Slack notifications | Trigger test alert — verify Slack delivery | ✅ |
| Chat UI functional | "What is the disk usage?" → real data from `shutil.disk_usage` | ✅ |
| Open WebUI | `http://141.94.92.226:3001` → model interaction | ✅ |
| Disk guard | Check `agent_disk_used_percent` in Prometheus — updating every 30 min | ✅ |
| Daily digest | Wait for 09:00 UTC or trigger manually — verify Slack message | ✅ |
| Log rotation | `./artifacts/logs/agent.log.*` — rotating files present | ✅ |
| PostgreSQL records | `SELECT * FROM pr_reviews ORDER BY created_at DESC LIMIT 5` | ✅ |

**Demo script (for supervisor presentation):**
1. Open `http://141.94.92.226/ui` — show BTE Security AI Agent chat
2. Ask: *"What is the current health of the entire platform?"*
3. Ask: *"Show me the last 3 PR security reviews from the database"*
4. Open GitHub → create a pull request with a deliberately vulnerable file
5. Watch: comment appears on the PR within 7 minutes with risk score, OWASP findings, and inline suggestions
6. Open `http://141.94.92.226/grafana/` → show live dashboard updating
7. Show `http://141.94.92.226/prometheus/` → all targets green, all alerts inactive

---

## 4. Kanban Board Retrospective

### Task Categories by Volume

| Category | Tasks completed | % of total |
|----------|----------------|-----------|
| Infrastructure setup | 18 | 16% |
| Security scanner integration | 14 | 12% |
| LLM/AI pipeline | 22 | 20% |
| Observability (Prometheus/Grafana/AlertManager) | 21 | 19% |
| Autonomous operations | 9 | 8% |
| Bug fixes (production-discovered) | 19 | 17% |
| Documentation | 9 | 8% |

### WIP Discipline

The WIP limit of 1 was maintained throughout. The most common violation temptation was starting observability work while scanner integration was still incomplete. Enforcing WIP=1 meant each feature was fully deployed and verified before moving on — which is why production bugs were caught early rather than accumulated.

### Blocked Items

| Item blocked | Reason | Resolution |
|-------------|--------|-----------|
| Grafana dashboard data | Prometheus scrape targets down | Week 8 production debugging |
| AlertManager routing | Metrics path wrong (route prefix) | Fixed during monitoring validation |
| `OllamaDown` alert | Expression targeted wrong metric | Added `ollama_reachable` gauge |
| Inline GitHub comments | LLM hallucinating line numbers | `diff_parser.py` validation layer |

---

## 5. Technology Decisions Log

| Decision | Option chosen | Option rejected | Reason |
|----------|--------------|----------------|--------|
| LLM inference | Ollama (local, CPU) | OpenAI API | On-premise — no code leaves the VPS |
| LLM models | `qwen2.5-coder` family | `llama`, `mistral` | Code-optimized pre-training gives better security pattern recognition |
| Workflow engine | LangGraph | Prefect, Celery | Native LLM state management + PostgreSQL checkpointing in one library |
| Database | PostgreSQL | SQLite, MongoDB | ACID guarantees for security records. LangGraph's `AsyncPostgresSaver` requires PostgreSQL |
| Metrics | prometheus-client | DataDog, New Relic | Open source, self-hosted, no external data egress |
| Long-term storage | VictoriaMetrics | InfluxDB, Thanos | Simpler deployment, Prometheus-compatible API, 90-day retention on a single container |
| Secret detection | Gitleaks | TruffleHog | Faster subprocess execution, better JSON output format |
| SAST | Semgrep | SonarQube | Lightweight subprocess, no separate server required, pinnable rulesets |
| IaC scanning | Checkov | KICS | Better Dockerfile + Terraform coverage, pip-installable |
| Dependency scanning | OSV-Scanner | Snyk | Open source, Google-backed, no API key required |

---

## 6. Key Lessons Learned

### Technical lessons

1. **Production always surprises you.** Every monitoring gap, every 502, every misfiring alert was discovered after deployment — not during design. The methodology's Build→Deploy→Observe loop was not a nice-to-have; it was the only way to find these issues.

2. **Token budget is a first-class concern.** At `num_ctx=12288`, every token counts. The 52% SAST token reduction (removing Checkov guidelines, collapsing Semgrep INFO) gave the LLM more room for actual code analysis — directly improving review quality.

3. **Local diff is better than API diff.** GitHub's API returns `-U3` (3 lines of context). Security vulnerabilities like SQL injection, path traversal, and command injection span more than 3 lines. Implementing `git diff -U15` locally was a one-day task that meaningfully improved LLM findings.

4. **Deduplication is mandatory for event-driven systems.** GitHub delivers webhooks at-least-once, not exactly-once. Without Redis dedup, a single PR open event would trigger 3+ pipeline runs.

5. **Route prefixes cascade through the stack.** `--web.route-prefix=/prometheus/` changes every HTTP path, including `/metrics`. This caused all three Prometheus scrape targets to show as `down` until explicitly corrected. Always verify metrics paths against actual service configuration, not assumed defaults.

### Process lessons

1. **Ship every day.** On days where code was written but not deployed, bugs accumulated silently. On days where code was deployed and a real event was triggered, bugs surfaced immediately and were fixed in context.

2. **Document while you understand.** The README was written during and immediately after each phase — not at the end. End-of-project documentation from memory produces shallow reports. Documentation written while fixing a bug captures the actual root cause.

3. **The backlog is not a to-do list.** It is a priority queue. When the disk emergency happened, it went to the top of the backlog immediately and everything else waited. A Waterfall plan would have no mechanism for this.

4. **Working software is the only real progress metric.** Lines of code written, hours logged, and Docker images pulled are all vanity metrics. The only meaningful metric is: "Can I trigger a real PR review right now and watch it complete?" At every point in the project, the answer was yes.

---

## 7. Final System Metrics

| Metric | Value |
|--------|-------|
| Total containers deployed | 11 |
| Total Docker images | 11 |
| LLM models available | 4 (`qwen2.5-coder:7b/14b/32b`, `mistral-nemo:12b`) |
| Security scanners integrated | 5 (Trivy, Gitleaks, Semgrep, Checkov, OSV-Scanner) |
| Prometheus metrics defined | 14 custom + HTTP instrumentation |
| Alert rules | 9 |
| LangGraph nodes | 9 |
| Chat UI monitoring tools | 19 |
| PostgreSQL tables | 6 (`pr_reviews`, `scan_results`, `repo_profiles`, `sbom_cache`, `security_policies`, `incidents`) |
| PRs reviewed end-to-end | 2 (PR #11 and PR #12 on `GhaiethFerchichi/Vunl-application`) |
| Average pipeline duration | ~6 min (post-optimization) |
| Disk freed during emergency | 233 GB |
| Total artifacts volume layout | `./artifacts/scans/{owner}-{repo}/pr-{n}/*.json` + `./artifacts/logs/agent.log.*` |
| Log retention | 500 MB max (50 MB × 10 rotating files) |
| Metrics retention | 30 days (Prometheus) + 90 days (VictoriaMetrics) |

---

*Internship project by Ghaieth Ferchichi — BTE DevSecOps Platform — 2026*
