# Internship Project Methodology Report
## BTE Security AI Agent — DevSecOps Platform

---

## Project Identity

| Field | Details |
|-------|---------|
| **Project name** | BTE Security AI Agent — Event-Driven DevSecOps Platform |
| **Developer** | Solo intern — Ghaieth Ferchichi |
| **Host organisation** | Banque de Tunisie et des Emirats (BTE) — Direction des Systèmes d'Information |
| **Environment** | Empty VPS (141.94.92.226) — Ubuntu Linux, 12 CPU cores, 45 GB RAM, 290 GB disk |
| **Duration** | 5 months (20 weeks) — 4 months development + 1 month documentation |
| **Sprints** | 8 sprints × 2 weeks (development) + 4 weeks documentation |
| **Starting point** | Blank VPS with SSH credentials only |
| **Final state** | 12-container production platform, fully autonomous, self-monitoring, anti-hallucination AI chat, robust PR review parsing |
| **Project completion** | 2026-05-01 (Sprint 8 closed) |

---

## 1. Chosen Methodology: Agile Scrum adaptée + Kanban interne (Scrumban)

### 1.1 Methodology Comparison

| Methodology | Verdict | Reason |
|-------------|---------|--------|
| **Waterfall** | Rejected | Requires complete requirements upfront. Multiple critical components — the disk guard, the `ollama_reachable` metric, the nginx DNS fix, the anti-hallucination system, and the PR review parsing rewrite — were only discovered to be necessary after production deployment. No design document could have anticipated them. |
| **Pure Agile Scrum** | Inadapted | Designed for teams of 5–9 with dedicated Scrum Masters, daily standups, planning poker, sprint reviews. All ceremony overhead with no benefit when working solo. Sprint velocity and story points are meaningless without a team. |
| **Pure Kanban** | Insufficient alone | Works well for ongoing maintenance (alert tuning, config patches) but provides no milestone structure for an internship supervisor to track progress. No forcing function for shipping features within a defined window. Not standard vocabulary in Tunisian academic context. |
| **SAFe / LeSS** | Rejected | Designed for 50+ person programs. Pure organisational overhead for a 1-person project. |
| **Agile Scrum adaptée + Kanban interne** | **Chosen** | Combines the structural rigour of Scrum (recognised academic vocabulary, sprints, jalons) with the operational flexibility of Kanban (WIP limit, pull system, priority by production incidents). This hybrid is sometimes called **Scrumban** in the industry. |

### 1.2 Why Not Waterfall — Justified by Production Evidence

Waterfall requires a complete requirements specification before the first line of code is written. This project made that impossible — five concrete examples:

- The **disk guard scheduler** was built after a real 242 GB disk emergency (92% disk usage). Not in any initial plan.
- The **`ollama_reachable` metric** was built after discovering the `OllamaDown` alert was misfiring on idle Ollama — a condition invisible until the alert fired in production.
- The **nginx DNS resolver fix** was discovered only after a container recreation caused a 502 Bad Gateway. The root cause (nginx caches upstream DNS at startup) is not something that appears in any design document.
- The **anti-hallucination system** was designed only after observing the model fabricate live metric values in production.
- The **PR review parsing rewrite** (Sprint 8) was triggered by PR #14 and #15 producing zero inline comments — three regex/JSON bugs that only surfaced under specific LLM output formats.

None of these could have been in a Waterfall specification. Reality is always more complex than the design document.

### 1.3 The Three-Layer Methodology

```
┌─────────────────────────────────────────────────────────────┐
│  STRATEGIC layer — Agile Scrum (8 sprints × 2 weeks)        │
│  • Sprint goals, backlog, milestones M1–M5                  │
│  • Definition of Done                                       │
│  • Supervisor-visible checkpoints                           │
├─────────────────────────────────────────────────────────────┤
│  TACTICAL layer — Kanban discipline (within each sprint)    │
│  • Tableau Backlog | In Progress (WIP=1) | Blocked | Done   │
│  • Production incidents jump to top of backlog              │
│  • Pull system: finish one before starting another          │
├─────────────────────────────────────────────────────────────┤
│  ENGINEERING layer — Build → Deploy → Observe → Improve     │
│  • Every feature deployed to real VPS immediately           │
│  • Production behaviour reveals what design missed          │
│  • Discoveries feed back into the backlog                   │
└─────────────────────────────────────────────────────────────┘
```

### 1.4 The Kanban Board (within each sprint)

```
┌──────────────┬──────────────────────────┬────────────┬──────────────────┐
│   BACKLOG    │   IN PROGRESS  (WIP = 1) │  BLOCKED   │      DONE        │
├──────────────┼──────────────────────────┼────────────┼──────────────────┤
│ Priority     │                          │            │                  │
│ ordered list │  ONE card only.          │  Card +    │  Completed +     │
│ of all work  │  Pulled when previous    │  reason    │  deployed +      │
│              │  card reaches DONE.      │  stated.   │  verified cards  │
└──────────────┴──────────────────────────┴────────────┴──────────────────┘
```

**WIP limit of 1** is the governing rule. The most common violation temptation was starting observability work while scanner integration was still incomplete. Enforcing WIP=1 meant each feature was fully deployed and verified before moving on — which is why production bugs were caught early rather than accumulated.

**Priority rule:** Production incidents immediately jump to the top of the backlog, above any planned work. This is how the disk guard (Week 7), the VPS audit (Week 11), and the PR review parsing fixes (Week 15–16) were handled — unplanned discoveries became the top-priority card without disrupting the sprint cadence.

### 1.5 The Governing Principle

> **Ship something real every day.**

Not "write code" — deploy and verify. `docker compose up -d`, trigger a real event (a PR webhook, a disk check, a Prometheus scrape), observe the result. A day where 300 lines were written but nothing is deployed is worth less than a day where 30 lines were written and a new scanner is running in production.

---

## 2. Project Milestones

```
M1 ──── M2 ──── M3 ──── M4 ──── M5
Week 4  Week 8  Week 10 Week 12 Week 16
```

| Milestone | Name | Sprint | Definition of Done |
|-----------|------|--------|-------------------|
| **M1** | Pipeline Alive | Sprint 2 (W3–4) | One real PR reviewed end-to-end — security comment posted to GitHub |
| **M2** | Full Intelligence | Sprint 4 (W7–8) | All 5 scanners running in parallel + LLM security review with risk score and verdict + inline comments |
| **M3** | Self-Operating | Sprint 5 (W9–10) | System runs unattended — alerts firing, Slack notified, disk guarded, AlertManager routing, autonomous scheduler |
| **M4** | Full Observability | Sprint 6 (W11–12) | All Prometheus scrape targets green, all alert rules correctly calibrated, 3 Grafana dashboards live |
| **M5** | Production Hardened | Sprint 8 (W15–16) | Host monitoring (node-exporter), anti-hallucination AI chat, VPS audit complete, PR review parsing rewritten — inline comments fully restored |

---

## 3. Weekly Breakdown — Detailed Work Report

---

### Week 1 — VPS Setup & Infrastructure Foundation

**Sprint 1 — Foundations**
**Goal:** Go from empty VPS to a running Docker environment with base services.

| Task | Technical detail | Outcome |
|------|-----------------|---------|
| VPS audit | SSH into bare Ubuntu — audit CPU (12-core Haswell/AVX2), RAM (45 GB), disk (290 GB), kernel | Environment profile documented |
| Docker installation | Docker Engine 29.4.0 + Compose v2 plugin via official apt repo | `docker compose up` functional |
| Project structure | Create `/opt/devsecops/` tree: `agent/`, `nginx/`, `prometheus/`, `grafana/`, `artifacts/` | Repository scaffold ready |
| Docker Compose skeleton | Write `docker-compose.yml` with Ollama, PostgreSQL, Redis, nginx | 4 containers running |
| Ollama base setup | Pull `qwen2.5-coder:7b` (4.7 GB). Verify: `ollama run qwen2.5-coder:7b "hello"` | LLM responds on internal network |
| CPU inference tuning | Set `OLLAMA_NUM_THREAD=12`, `OLLAMA_FLASH_ATTENTION=1`, `OLLAMA_KV_CACHE_TYPE=q8_0` | Haswell AVX2 backend auto-selected |
| PostgreSQL init | Create `devsecops` user and `devsecops_db` database | Database accessible |
| `.env` file | Define all secrets: GitHub token, Slack token, Postgres password, webhook secret | Configuration centralised |

**Challenges:**
- Ollama memory limit needed to be `42g` — default caused OOM on first model load
- `shm_size: 2gb` required for thread synchronisation buffers on 12-core inference
- File descriptor limit (`ulimits.nofile: 65536`) needed for concurrent model operations

**Key decision:** Keep Ollama port `11434` off the host-exposed interface from day one. Prevents any external LLM query without going through the agent.

**End-of-week deliverable:** 4 base containers healthy. Ollama model responding on internal network.

---

### Week 2 — FastAPI Agent Skeleton & GitHub Webhook

**Sprint 1 — Foundations (continued)**
**Goal:** Receive a GitHub Pull Request event and log it — the minimal viable pipeline trigger.

| Task | Technical detail | Outcome |
|------|-----------------|---------|
| FastAPI application | `app/main.py` with lifespan context manager, structlog dual handler (console JSON + rotating file) | Agent starts, logs structured JSON |
| Dockerfile | Python 3.12-slim base, all Python dependencies, Trivy + Gitleaks binaries baked in | Agent image ~1.55 GB |
| GitHub webhook receiver | `POST /webhooks/github` — HMAC-SHA256 validation of `X-Hub-Signature-256` header | Webhook validated, 403 on bad signature |
| Webhook model | `PullRequestWebhookPayload` Pydantic model parsing GitHub PR event JSON | PR metadata extracted |
| nginx reverse proxy | `nginx/nginx.conf` — upstream blocks, `/webhooks/github` proxy, `/ui` route | External traffic routed correctly |
| LangGraph skeleton | `StateGraph` with `PRReviewState` TypedDict, `intake_node` stub, `PostgresCheckpointer` | LangGraph compiles and persists state |
| PostgreSQL checkpointing | `AsyncPostgresSaver` — auto-creates LangGraph checkpoint tables | Workflow state survives container restart |
| GitHub webhook configuration | GitHub repo → Settings → Webhooks → `http://141.94.92.226/webhooks/github` | GitHub delivers PR events to agent |

**Challenges:**
- `AttributeError: module 'psycopg' has no attribute 'AsyncConnectionPool'` — pool moved to `psycopg_pool` in psycopg3. Fixed import.
- nginx HTTP/1.0 mangled chunked webhook bodies → `500 Internal Server Error`. Fixed: `proxy_http_version 1.1; proxy_set_header Connection "";`
- `ModuleNotFoundError: langgraph.graph.graph` — import path changed in LangGraph 1.x. Fixed.

**Key decision:** Use `asyncio` background tasks for the LangGraph pipeline — webhook returns `202 Accepted` immediately. GitHub's 10-second timeout is never a bottleneck.

**End-of-week deliverable:** Opening a real PR on GitHub triggers the webhook, agent logs PR metadata, state persisted to PostgreSQL.

---

### Week 3 — LLM Integration & Classification Node

**Sprint 2 — Intelligence**
**Goal:** The agent makes its first real LLM call to classify the incoming PR.

| Task | Technical detail | Outcome |
|------|-----------------|---------|
| Ollama LLM factory | `app/llm/ollama.py` — `get_fast_llm()` (7B, `num_ctx=4096`, `format="json"`, `temperature=0.0`, `@lru_cache`) | LLM client reused across calls |
| `classify_node` | Sends PR metadata + file list, forces JSON output: `{"classification": "...", "risk_hint": "..."}` | 5 classification categories produced |
| Regex fallback | `_fallback_classify()` — pattern matches file extensions when LLM unavailable | Pipeline never stalls on LLM failure |
| Circuit breaker | Catches `httpx.ConnectError`, `TimeoutError` — logs warning, calls fallback | Resilient to Ollama cold-start |
| Scan matrix routing | `route_scans()` — returns `"scan_full"` / `"scan_fs"` / `"skip"` based on classification and Dockerfile detection | Correct scanners triggered per PR type |
| `skip_scan_node` | Returns immediately for `docs` — no scanners, no LLM review needed | Fast path for documentation PRs |
| Redis deduplication | `SET NX dedup:{repo}:{pr}:{sha}` TTL=1h — duplicate webhooks ignored | Idempotent pipeline |
| Rate limiting | `INCR rate:{repo}` — max 3 concurrent pipelines per repository | Prevents Ollama overload |

**Key decision:** Two-model architecture — fast 7B for classification (~30s), deep 14B for security review (~6–11 min). Using 14B for classification wastes 8 minutes on a task that needs only a JSON tag.

**End-of-week deliverable:** PR classified correctly in ~30s. File type routing working. Duplicate webhooks ignored.

---

### Week 4 — Security Scanners + First End-to-End PR Review

**Sprint 2 — Intelligence (continued)**
**Goal:** Run all security scanners in parallel and produce the first real LLM security review posted to GitHub.

| Task | Technical detail | Outcome |
|------|-----------------|---------|
| Git clone in pipeline | `git clone --depth 1 --branch {head_branch} {url}` into agent workspace volume | PR code available for scanning |
| Local git diff | `git fetch --depth=1 origin {base_branch}` + `git diff -U15 FETCH_HEAD..HEAD` — 15 lines of context vs GitHub API's fixed -U3 | Rich diff context for LLM analysis |
| Trivy FS scanner | `trivy fs --format json --severity CRITICAL,HIGH,MEDIUM` | CVE findings extracted |
| Gitleaks scanner | `gitleaks detect --source {path} --report-format json` | Credential leaks detected. `Match` field omitted from LLM prompt |
| Semgrep scanner | `semgrep scan --config p/security-audit --config p/owasp-top-ten --json` | Deterministic SAST results |
| Checkov scanner | `checkov -d {path} --output json` | IaC misconfigurations found |
| OSV-Scanner | `osv-scanner --format json {path}` | Dependency CVEs cross-referenced |
| Parallel scan execution | `asyncio.gather()` — all applicable scanners run concurrently | No serial scanner bottleneck |
| 14B security review | `get_deep_llm()` (14B, `num_ctx=8192`) — OWASP Top 10, risk_score, verdict | Security review markdown generated |
| GitHub PR comment | `post_pr_comment()` — security review posted as PR comment | Review visible on GitHub |
| GitHub commit status | `set_commit_status()` — `success` for APPROVE, `failure` for REQUEST_CHANGES/BLOCK | CI gate enforced |

**Challenges:**
- GitHub API returns only `-U3` unified diff (3 lines of context). Security patterns span multiple lines. Fixed by `get_local_diff()` with `git diff -U15`.
- Semgrep `--config auto` uses unpredictable remote rulesets — non-deterministic results. Pinned to `p/security-audit` + `p/owasp-top-ten`.

> **Milestone M1 achieved:** Pipeline alive — first real PR analysed end-to-end with security comment posted on GitHub.

---

### Week 5 — Combined LLM Call & Inline Comments

**Sprint 3 — Pipeline scanners & combined review**
**Goal:** Add inline code quality review and merge two LLM calls into one for performance.

| Task | Technical detail | Outcome |
|------|-----------------|---------|
| `analyze_review_node` | Merges `analyze_node` + `code_review_node` into one 14B call | Single LLM call instead of two sequential calls |
| Combined prompt | `app/prompts/combined_review.py` — produces security review markdown + JSON block with `risk_score`, `verdict`, `code_review_summary`, `comments[]` | One LLM request handles both concerns |
| `get_combined_llm()` | 14B, `num_ctx=12288`, `num_predict=2500`, `temperature=0.1`, `@lru_cache` | 50% larger context for combined output |
| GitHub PR Review with inline comments | `post_pr_review()` — formal review with inline `suggestion` blocks on actual diff lines | Inline code suggestions visible in GitHub Files Changed tab |
| Annotated diff view | Annotated diff with line numbers passed to LLM alongside plain diff | Accurate line mapping, hallucinated lines dropped |
| `escalate_node` | `interrupt_before=["escalate"]` — LangGraph pauses on CRITICAL/HIGH risk, waits for Slack approval | Human-in-the-loop gate before merging dangerous PRs |
| `report_node` | Final PR comment, commit status, Slack notification, artifact save, cleanup | Clean pipeline end state |
| `error_node` | Catches any exception — posts failure comment, Slack error alert, releases Redis rate limit | No silent failures |

**Performance improvement measured on real PRs:**

| Metric | Before (two calls) | After (one call) |
|--------|-------------------|-----------------|
| Total pipeline | ~13–23 min | **~6–11 min** |

**End-of-week deliverable:** PR reviewed in under 7 minutes with security review + inline code quality comments. Escalation gate functional.

---

### Week 6 — SAST Token Reduction & Diff Parser Validation

**Sprint 3 — Pipeline scanners (continued)**
**Goal:** Reduce LLM context bloat and eliminate hallucinated line numbers in inline comments.

| Task | Technical detail | Outcome |
|------|-----------------|---------|
| Trivy templating | Drop `Description`, `References`, `CVSS`, `Target` fields | -58% Trivy token cost |
| Gitleaks templating | Omit `Match` field entirely (also a security improvement — no secret leakage to LLM) | -50% Gitleaks token cost |
| Semgrep templating | Collapse INFO findings to count only, list ERROR/WARNING individually | -40% Semgrep token cost |
| Checkov templating | Drop `guideline` URL field | -47% Checkov token cost |
| `diff_parser.py` | State machine: parse `+++ b/file`, `@@ ` hunk headers, track `+`/space line counters | Builds set of valid lines per file |
| `diff_lines_for_file()` | Returns `added_lines | context_lines` — every line LLM may legitimately reference | Foundation for hallucination guard |
| Inline comment validation | Each LLM-suggested comment cross-checked against `diff_lines_for_file()` — invalid lines silently dropped | Hallucinated line numbers eliminated |
| Total SAST reduction | Combined 4 scanners cleaned up | **~52% fewer tokens** sent to LLM |

**Key decision:** Scanner isolation — each scanner runs in a separate asyncio coroutine with its own exception handler. One scanner failing does not abort the pipeline.

**End-of-week deliverable:** ~52% smaller SAST prompts, no hallucinated inline comment line numbers.

---

### Week 7 — Slack Integration & Chat Ops Assistant Foundations

**Sprint 4 — Revue LLM 14B & Chat Ops**
**Goal:** Add human-approval Slack gate and start the BTE Security AI Agent chat interface.

| Task | Technical detail | Outcome |
|------|-----------------|---------|
| Slack bot integration | `slack_api.py` — `send_notification()`, `request_approval()` using Slack Block Kit | Formatted alerts sent to `#security-channel` |
| Slack approval callback | `POST /callbacks/slack` — verifies Slack signature, resumes LangGraph checkpoint from PostgreSQL | Human approval resumes paused pipeline |
| BTE Security AI Agent chat UI | `app/routers/chat.py` — custom ReAct loop with SSE streaming | Interactive ops assistant at `/ui` |
| 19 monitoring tools (initial) | VPS status, disk, processes, container logs, Ollama status, Prometheus query, Redis info, Jenkins status, scan artifacts, database query | Full infrastructure observability via chat |
| Custom ReAct loop | Token-by-token streaming, 4-pass JSON extractor for tool calls, `[OBSERVATION]...[/OBSERVATION]` injection, 8-tool call limit per response | Works without native Ollama tool-calling support |
| SSE event protocol | 10 event types: `status`, `thinking_start`, `thinking_token`, `thinking_end`, `tool_start`, `tool_end`, `token`, `replace_text`, `error`, `done` | Smooth real-time streaming UI |

**End-of-week deliverable:** Chat UI at `/ui`. Real database queries work. Live `docker stats` output returned correctly.

---

### Week 8 — Disk Emergency, Autonomous Operations & First Observability

**Sprint 4 — Revue LLM 14B (continued)**
**Goal:** Add autonomous background operations + emergency response.

**Emergency response — unplanned (2026-04-20):**

A partial `qwen2.5-coder:32b` model download left a 242 GB orphaned blob with no manifest — unusable but consuming disk. Combined with `llama3.2:3b` and Docker build cache, disk reached **92% usage**. No alert existed yet to catch this.

```bash
docker exec ollama ollama rm sha256-c430a9b9...   # orphaned 242 GB blob
docker exec ollama ollama rm llama3.2:3b           # unused model
docker builder prune -f                            # Docker build cache
# Result: 233 GB freed. 92% → 14% disk. No running services affected.
```

This emergency directly drove the disk guard scheduler and the AlertManager integration — both were added as immediate top-priority Kanban cards.

| Task | Technical detail | Outcome |
|------|-----------------|---------|
| Disk guard scheduler | `scheduler.py` — `_disk_guard_loop()` every 30 min: update Prometheus gauges, Slack alert at >80%/>90% | Autonomous disk monitoring |
| `agent_disk_used_percent` gauge | `shutil.disk_usage("/")` → Prometheus Gauge updated every 30 min | Disk metric exposed to Prometheus |
| Auto-prune on critical | `docker builder prune -f` triggered at >90% disk — result reported to Slack | Self-healing: the exact same action taken during the emergency |
| Daily health digest | `_health_digest_loop()` — 09:00 UTC daily: disk + containers + Ollama + active alerts → Slack Block Kit | Proactive daily system status |
| AlertManager service | `prom/alertmanager:latest` added to docker-compose | Alert routing infrastructure |
| `POST /webhooks/alertmanager` | Receives Prometheus alert payloads — firing/resolved, Slack Block Kit (🔴/🟡/🔵) | AlertManager → agent → Slack pipeline |
| Open WebUI | `ghcr.io/open-webui/open-webui:main` port 3001 → `http://ollama:11434` | Direct model interaction without PR pipeline |

> **Milestone M2 achieved:** Full intelligence — 5 scanners + LLM 14B review + GitHub inline comments + autonomous self-healing operational.

---

### Week 9 — Prometheus Stack & Grafana Dashboards

**Sprint 5 — Autonomy + Chat**
**Goal:** Full observability — every component visible in Prometheus and Grafana.

| Task | Technical detail | Outcome |
|------|-----------------|---------|
| Prometheus configuration | `prometheus/prometheus.yml` — 3 scrape jobs, 30-day local retention, `remote_write` to VictoriaMetrics | Metrics pipeline complete |
| Alert rules | `alerts.rules.yml` — 9 rules across 3 groups (disk × 4, agent × 3, ollama × 2) | Automated alerting for critical conditions |
| VictoriaMetrics | `victoria-metrics:latest` — 90-day retention, receives `remote_write` | Long-term metrics storage |
| Grafana datasources | Provisioned: Prometheus, VictoriaMetrics, PostgreSQL — env-var credentials | All data sources available without manual setup |
| Grafana agent dashboard | `devsecops_agent.json` — LLM duration, scanner duration, review counts, Ollama gauges, disk usage | Live agent performance dashboard |
| Grafana PR reviews dashboard | `pr_reviews.json` — 5 panels backed by PostgreSQL: review volume, risk distribution, verdict, pipeline duration, recent PRs table | Business-level security metrics |

**Monitoring gaps discovered and fixed in production:**

| Gap | Root cause | Fix |
|-----|-----------|-----|
| Ollama scrape target `down` | `OLLAMA_METRICS=true` does not expose `/metrics` in the installed Ollama version | Removed direct Ollama scrape — agent re-exports all Ollama metrics via its own `/metrics` |
| AlertManager scrape target `down` | `--web.route-prefix=/alertmanager/` prefixes all paths — metrics at `/alertmanager/metrics` not `/metrics` | Added `metrics_path: /alertmanager/metrics` to scrape config |
| Prometheus self-scrape `down` | `--web.route-prefix=/prometheus/` same issue | Added `metrics_path: /prometheus/metrics` |
| `OllamaDown` alert misfiring | Expression `ollama_models_loaded_total == 0` fires when Ollama is idle (normal state between PR reviews) | Added `ollama_reachable` Gauge set by 30s poller. Alert changed to `ollama_reachable == 0` |
| Grafana 502 Bad Gateway | nginx caches upstream DNS at startup — Grafana IP changed after container recreation | Added `resolver 127.0.0.11 valid=10s` — Docker internal DNS, re-resolves dynamically |

**End-of-week deliverable:** All 3 Prometheus scrape targets green. All alert rules correctly calibrated. Both Grafana dashboards loading real data.

---

### Week 10 — Host Monitoring & Chat Agent Precision

**Sprint 5 — Autonomy + Chat (continued)**
**Goal:** Add full host-level metrics and improve chat agent tool accuracy.

| Task | Technical detail | Outcome |
|------|-----------------|---------|
| node-exporter deployment | `prom/node-exporter:latest` with `pid: host` + `network_mode: host` — reads from `/host/proc` and `/host/sys` | ~1,000 real host metrics exposed (CPU/RAM/disk I/O/network) |
| Prometheus bridge access | node-exporter runs on host at `0.0.0.0:9100`. Prometheus reaches it via Docker bridge gateway `172.20.0.1:9100` | 4th scrape target added |
| `iptables` rule | `-A INPUT -s 172.20.0.0/16 -p tcp --dport 9100 -j ACCEPT` persisted via `iptables-persistent` | Docker bridge can reach host port 9100 |
| 3 new host alert rules | `HostHighCPU` (>85%, 5m), `HostHighMemory` (>88%, 3m critical), `HostDiskIOHigh` (>0.9, 5m) | 12 total alert rules (was 9) |
| PromQL patterns in system prompt | 4 ready-to-use expressions for CPU, RAM, disk I/O, network injected into chat system prompt | Model can query host metrics without guessing metric names |
| Explicit tool-selection rules | System prompt maps every question type to the correct tool (`vps_status` vs `query_prometheus`, etc.) | Model picks correct tool on first attempt |

**Challenges:**
- node-exporter uses `network_mode: host` — not on Docker bridge. Host firewall was blocking Docker bridge (`172.20.0.0/16`) from reaching host port 9100. Fixed with `iptables`.

> **Milestone M3 achieved:** System self-operating. Disk, agent health, Ollama connectivity, host metrics all monitored autonomously. Alerts reach Slack automatically.

---

### Week 11 — Chat Agent Benchmarking & Speed Optimisation

**Sprint 6 — Optimisation**
**Goal:** Benchmark all available models and maximise chat agent performance.

**Model benchmark (5-query suite, full system prompt, CPU-only):**

| Model | Size | Speed (warm) | Tool Accuracy | Args Format | Decision |
|-------|------|-------------|---------------|-------------|----------|
| `qwen2.5-coder:7b` | 4.7 GB | ~5 tok/s | **80%** | **100%** | ✅ Default |
| `qwen2.5-coder:14b` | 9.0 GB | ~3.2 tok/s | 80% | 100% | PR pipeline only |
| `llama3.2:3b` | 2.0 GB | ~8 tok/s | 0% (full prompt) | — | ❌ Experimental |
| `granite3.1-dense:2b` | 1.6 GB | ~8.5 tok/s | 0% | — | ❌ Incompatible format |

**Findings:** `qwen2.5-coder:7b` and `14b` achieve identical 80% tool accuracy with the explicit system prompt. The 7b is 43% faster per token. Default reverted to 7b. `llama3.2:3b` saturates context with the full prompt; `granite3.1-dense:2b` uses incompatible IBM tool-call schema.

| What changed | Before | After | Impact |
|---|---|---|---|
| Default model | `14b` | **`7b`** | 43% faster per token, same accuracy |
| System prompt | 11,794 chars / 2,948 tokens | **7,577 chars / 1,894 tokens** | 36% smaller → smaller KV cache |
| `num_predict` | 1500 | **600** | Stops runaway generation |
| Tool result cache | None | **14 tools, TTL 10–120s** | Tool execution cost eliminated on repeats |
| Dedup guard | None | **`{tool}:{args}` hash per response** | Infinite tool loops eliminated |
| `query_prometheus_range` | Not available | **20th tool added** | Enables trend/history queries |

**Bug fixed — infinite tool loop:** Model was alternating between `list_images` and `disk_usage` indefinitely. Fix: redesigned observation message + code-level dedup guard.

**End-of-week deliverable:** Chat agent 43% faster. System prompt 36% smaller. Infinite loop bug eliminated. 20 monitoring tools operational.

---

### Week 12 — UI Enhancements & Tooling Polish

**Sprint 6 — Optimisation (continued)**
**Goal:** Polish the chat interface and consolidate the 20-tool registry.

| Task | Technical detail | Outcome |
|------|-----------------|---------|
| Copy buttons | Hover any code block → `Copy` button appears top-right. Click → copies, shows `Copied!` 1.8s | Convenient operator UX |
| Response timing badge | Each completed response shows `⏱ Xs` at the bottom | Performance visibility |
| Model tag badges | Dropdown: `[Recommended]` / `[Deep analysis]` / `[Experimental]` / `[Incompatible]` colour-coded | Clear model selection guidance |
| Model auto-sort | Recommended first, then Deep, Experimental, Incompatible | UX consistency |
| Tool registry refactor | `ALL_TOOLS` registry centralises all 20 tools — single source of truth | Easier to add new tools |
| `query_prometheus_range` integration | New 20th tool — returns min/max/avg/latest + trend sparkline | Trend queries: "has CPU been high in the last hour?" |

> **Milestone M4 achieved:** Full observability complete — 4 Prometheus scrape targets green, 12 alert rules calibrated, 2 Grafana dashboards live with real data.

---

### Week 13 — Anti-Hallucination Foundations & Prompt Compression

**Sprint 7 — Durcissement (Hardening) — Part 1**
**Goal:** Begin systematic anti-hallucination work after observing the chat fabricate live metric values.

| Task | Technical detail | Outcome |
|------|-----------------|---------|
| `temperature=0.0` | Fully deterministic token selection — eliminates probabilistic "creative" value invention | No more invented metrics |
| `num_ctx=6144` | 4,100 tokens free for tool observations after system prompt (~2,047 tokens) | No context overflow |
| `num_predict=800` | Complete answers without truncation — cut-off answers caused model to fill remainder from training memory | No truncation-driven hallucination |
| ANTI-HALLUCINATION system prompt block | 5 hard rules: (1) never answer from training data (2) live questions always require a tool (3) only quote values from OBSERVATION blocks (4) "approximately/typically" forbidden for live metrics (5) if answered without tool, stop and call one immediately | Explicit consigne |
| Strengthened observation injection | After every tool result: "Every value MUST appear verbatim in an [OBSERVATION] block. NEVER invent." | Reinforces the consigne in context |

**End-of-week deliverable:** Anti-hallucination first 5 layers active. Fewer invented values, but some still leaking through.

---

### Week 14 — VPS Audit & Hardening

**Sprint 7 — Durcissement (Hardening) — Part 2**
**Goal:** Full VPS audit, fix all discovered gaps, finalize anti-hallucination.

**VPS audit (2026-04-28) — critical findings and fixes:**

| Finding | Root cause | Fix applied |
|---------|-----------|-------------|
| **VictoriaMetrics down 9 days** (2026-04-19 → 2026-04-28) | Disk-full panic. Container exited code 2. `restart: unless-stopped` did not restart because disk was still full. After disk freed, container remained `exited` and was missed. | Restarted with `docker compose restart victoriametrics`. 10.9M stored rows recovered intact. |
| **AlertManager never received any alert** | `path_prefix: /alertmanager/` missing in `prometheus.yml` alerting config. Every alert sent to `/api/v2/alerts` (404). | Added `path_prefix: /alertmanager/` to Prometheus alerting config. |
| **nginx `GET /` returned 404** | No default location block — unmatched paths fell to nginx default file handler | Added `location = / { return 301 /ui; }` |
| **Grafana live dashboards silently broken** | nginx `/grafana/` location missing `proxy_http_version 1.1`, `Upgrade`, `Connection: upgrade` headers — WebSocket refused | Added WebSocket headers to grafana location block |
| **Chat UI publicly accessible** | `/ui` and `/chat/` had no authentication | Added HTTP Basic Auth via nginx (`auth_basic`). bcrypt hash in `./nginx/.htpasswd` |
| **No-tool guard (anti-hallucination layer 6)** | Even with prompt + temperature, model occasionally answered live questions from training data | Code-level intercept: step-0 final answer for live-data question → forced tool call. Triggers on ~30 keywords. |

**3 Grafana dashboards (all confirmed healthy):**

| Dashboard | Status | Panels | Datasource |
|-----------|--------|--------|-----------|
| VPS Host Monitoring | NEW | 13 | Prometheus (node-exporter) |
| DevSecOps AI Agent | Rebuilt — 5 rows | 33 | Prometheus |
| PR Security Reviews | Unchanged | 5 | PostgreSQL |

**End-of-week deliverable:** VictoriaMetrics restored. AlertManager correctly routing alerts. Chat UI password-protected. Anti-hallucination 6-layer system complete and verified.

---

### Week 15 — PR Review Parsing Bug Investigation

**Sprint 8 — PR Review Robust Parsing — Part 1**
**Goal:** Investigate why PR #14 and PR #15 produced zero inline comments despite the LLM emitting them.

**Bug surfaced (2026-04-30 / 2026-05-01):**

PR #14 produced a security review with header `Risk: MEDIUM | Verdict: REQUEST_CHANGES` but body said `HIGH | BLOCK`. The LLM's JSON tail contained 4 inline comments (lines 12, 17, 26, 34 in `tt.php`) — none appeared on GitHub. Same symptom on PR #15.

**Root cause analysis:**

| Bug | Symptom in logs | Why |
|-----|----------------|-----|
| Whitespace-intolerant regex | `analyze_review_complete  comments=0  risk_score=MEDIUM` (defaults!) | Regex `\{"risk_score"...` required `"risk_score"` immediately after `{`. When LLM pretty-printed `{ \n  "risk_score":` the regex failed silently. |
| `json.loads` strict on trailing chars | Same `comments=0` even when regex matched | `json.loads(raw[json_start:])` consumed entire string to end-of-file including trailing ``` ``` ``` markdown fences → `JSONDecodeError`. |
| LLM occasionally skipping JSON | PR #15 review ended at "Recommendations" with no JSON object | The model truncated after the markdown sections, omitting the JSON entirely. |

**Verification methodology:**
- Extracted the LLM raw output from PostgreSQL `pr_reviews.review_markdown`
- Built a 3-case Python test (PR #14 pretty-printed JSON, PR #14 with trailing fences, PR #15 markdown-only) — all 3 cases failed under the original parser
- Diff parser separately confirmed: lines 12, 17, 26, 34 ARE valid lines in PR #14's diff — so the validator was not the problem

**End-of-week deliverable:** Root cause documented. Three discrete bugs identified. Fix design specified.

---

### Week 16 — PR Review Parsing Rewrite & Final Validation

**Sprint 8 — PR Review Robust Parsing — Part 2**
**Goal:** Rewrite the parser, restructure the prompt, verify on a fresh PR.

| Task | Technical detail | Outcome |
|------|-----------------|---------|
| Whitespace-tolerant regex | `\{\s*"risk_score"\s*:\s*"..."` (added `\s*` after `\{`) | Handles pretty-printed JSON |
| Brace-depth JSON walker | Walk forward from regex match, tracking `{` / `}` depth and string state, find exact matching closing brace | Tolerates trailing markdown fences and nested objects |
| Markdown fallback parser | When no JSON found at all: `re.search(r'\*?\*?Risk\s*(?:Score)?\s*:\s*\*?\*?\s*(CRITICAL\|HIGH\|...)`, raw)` | Preserves risk/verdict consistency even without JSON |
| Prompt restructure — JSON FIRST | Combined prompt rewritten: STEP 1 = JSON object on first line, STEP 2 = markdown review after | Model can no longer skip JSON by truncating after markdown |
| Reinforced JSON requirement | `═══` border markers + "MANDATORY" labels | Maximum prompt salience |
| Empty-markdown synthesis fallback | If JSON parsed cleanly but markdown body is empty (model truncated after JSON), synthesise minimal review from JSON metadata | PR comment is never empty |
| Same regex bug in `_build_degraded_review()` (line 548) | Identical pattern in circuit-breaker fallback path | Patched both call sites |

**Verification (live tests):**

| Test | Result |
|------|--------|
| Pretty-printed JSON regex | ✅ `HIGH/BLOCK` extracted from `{ \n  "risk_score": "HIGH", ... }` |
| Brace walker handles trailing ``` fences | ✅ Stops at correct `}`, ignores trailing content |
| Markdown fallback works | ✅ PR #15-style markdown-only response — risk/verdict correctly extracted |
| Line validation against PR #14 diff | ✅ All 4 LLM-claimed lines (12, 17, 26, 34) pass validation |
| Both call sites patched | ✅ `analyze_review_node` line 682 + `_build_degraded_review` line 548 |

**Files modified:**
- `app/workflows/pr_review/nodes.py` — both `analyze_review_node()` and `_build_degraded_review()` regex + brace walker + markdown fallback
- `app/prompts/combined_review.py` — restructured to "STEP 1: JSON / STEP 2: Markdown" with stronger MANDATORY framing

> **Milestone M5 achieved:** Production hardened — host monitoring complete, anti-hallucination fully active, VPS audit clean, PR review parsing robust against all observed LLM output formats. Inline comments fully restored on GitHub.

---

### Weeks 17–20 — Documentation, Validation & Internship Presentation

**Phase: Documentation + Soutenance**
**Goal:** Complete the report, validate the entire platform end-to-end, prepare the soutenance.

**Final validation checklist:**

| Check | How verified | Status |
|-------|-------------|--------|
| Full PR pipeline end-to-end | Open real PR → security comment + inline comments appear in <7 min | ✅ |
| Risk score accuracy | Compare LLM findings against manual OWASP review on PR #14/#15 | ✅ |
| All 5 scanners running | Check `./artifacts/scans/` for all JSON files per PR | ✅ |
| Prometheus — 4 scrape targets green | `http://141.94.92.226/prometheus/targets` | ✅ |
| Alert rules inactive (no incidents) | `/prometheus/alerts` — all 12 rules inactive | ✅ |
| AlertManager routing working | Trigger test alert → Slack delivery confirmed | ✅ |
| 3 Grafana dashboards live | VPS Host Monitoring + DevSecOps Agent + PR Reviews loading real data | ✅ |
| VictoriaMetrics running | `docker ps` — running, 10.9M rows intact | ✅ |
| Chat UI — anti-hallucination | "What is the current CPU usage?" → tool called, real value returned | ✅ |
| PR review parsing robust | PR #16+ test with pretty-printed JSON → `comments>0` in logs | ✅ |
| Inline comments visible on GitHub | Files Changed tab shows suggestions with Apply button | ✅ |
| Disk guard active | `agent_disk_used_percent` in Prometheus updating every 30 min | ✅ |
| Daily digest fires | 09:00 UTC Slack message received | ✅ |
| PostgreSQL records | `SELECT * FROM pr_reviews ORDER BY created_at DESC LIMIT 5` returns 5 PRs | ✅ |
| node-exporter metrics | `query_prometheus: node_memory_MemAvailable_bytes` returns real value | ✅ |

**Demo script (for supervisor presentation):**
1. Open `http://141.94.92.226/ui` — show BTE Security AI Agent chat (password-protected)
2. Ask: *"What is the current health of the entire platform?"* — verify tool calls to `vps_status`, `list_containers`, `prometheus_alerts`
3. Ask: *"Has CPU usage been high in the last hour?"* — verify `query_prometheus_range` returns real trend data
4. Ask: *"Show me the last 5 PR security reviews from the database"* — verify real data from PostgreSQL
5. Open GitHub → create a pull request with a deliberately vulnerable file
6. Watch: security comment + inline comments appear on the PR within 7 minutes
7. Open `http://141.94.92.226/grafana/` → show all 3 live dashboards
8. Open `http://141.94.92.226/prometheus/` → all 4 targets green, all 12 alert rules inactive

---

## 4. Kanban Board Retrospective

### 4.1 Task Categories by Volume (all 16 development weeks)

| Category | Tasks completed | % of total |
|----------|----------------|-----------|
| Infrastructure setup | 22 | 14% |
| Security scanner integration | 14 | 9% |
| LLM/AI pipeline | 26 | 17% |
| Observability (Prometheus / Grafana / AlertManager) | 26 | 17% |
| Autonomous operations | 11 | 7% |
| Chat agent (ReAct, tools, anti-hallucination) | 20 | 13% |
| Bug fixes (production-discovered) | 27 | 18% |
| Documentation | 7 | 5% |

### 4.2 WIP Discipline

WIP limit of 1 was maintained throughout. The most common violation temptation was starting a new feature while the previous one was "mostly done but not deployed". Enforcing WIP=1 forced each feature to be fully deployed and verified before the next card was pulled. This is why production bugs were caught immediately, not accumulated.

**Notable example (Sprint 5):** During Week 9, three Prometheus scrape targets showed as `down`. Under any other methodology, the pressure to "move on" would have left these as known issues. The WIP limit forced the issue to be resolved before any new work started — which required understanding route prefixes, re-exporting Ollama metrics, and fixing the `OllamaDown` alert expression.

**Notable example (Sprint 8):** When PR #14 produced zero inline comments, the WIP limit forbade the agent team from continuing other work until the parser was rewritten. Three discrete bugs (regex whitespace, JSON.loads trailing chars, LLM skipping JSON) were diagnosed and fixed in two weeks rather than left as a known issue.

### 4.3 Blocked Items Log

| Item | Why blocked | Time blocked | Resolution sprint |
|------|-------------|-------------|-------------------|
| Grafana dashboard data | All 3 Prometheus scrape targets showing `down` | 3 days | Sprint 5 (Week 9) |
| `OllamaDown` alert | Expression fired when Ollama was idle (normal state) | 2 days | Sprint 5 (Week 9) |
| AlertManager routing | `path_prefix` missing — alerts silently failing since deployment | Discovered Week 14 | Sprint 7 (Week 14) |
| Inline GitHub comments (line numbers) | LLM hallucinating line numbers | 2 days | Sprint 3 (Week 6) |
| Chat agent tool loops | Infinite alternation between two tools | 1 day | Sprint 6 (Week 11) |
| VictoriaMetrics | Silent crash — down 9 days undetected | 9 days | Sprint 7 (Week 14) |
| node-exporter unreachable | Host firewall blocked Docker bridge from reaching host port 9100 | 1 day | Sprint 5 (Week 10) |
| Chat hallucination | Model fabricating live metric values | 3 days | Sprint 7 (Weeks 13–14) |
| **Inline comments missing on PR #14/#15** | **3 compounding parser bugs (regex whitespace, JSON.loads trailing chars, LLM skipping JSON)** | **2 weeks** | **Sprint 8 (Weeks 15–16)** |

### 4.4 Production Discoveries → Backlog

The following items entered the backlog as a direct result of production observation — none were in the original plan:

| Discovery | When observed | Card created | Sprint |
|-----------|-------------|-------------|--------|
| Local diff only 3 lines of context | First real PR review | `get_local_diff()` with `-U15` | Sprint 2 |
| Two LLM calls taking 23 minutes | Pipeline measurement | `analyze_review_node` combined call | Sprint 3 |
| LLM hallucinating line numbers | First inline comments attempt | `diff_parser.py` validation layer | Sprint 3 |
| Disk at 92% — orphaned model blob | Disk emergency | Disk guard scheduler | Sprint 4 |
| `OllamaDown` misfiring on idle | Monitoring validation | `ollama_reachable` metric | Sprint 5 |
| Scrape targets all `down` | First Prometheus check | Route prefix fix for all 3 targets | Sprint 5 |
| Chat model fabricating metrics | Live testing | Anti-hallucination 6-layer system | Sprint 7 |
| VictoriaMetrics down 9 days | VPS audit | Monitoring gap — restart policy fix | Sprint 7 |
| AlertManager never received alerts | VPS audit | `path_prefix` fix | Sprint 7 |
| Chat UI publicly accessible | VPS audit | nginx Basic Auth | Sprint 7 |
| **Inline comments missing on PR #14/#15** | **PR review verification** | **JSON parser rewrite + prompt restructure** | **Sprint 8** |

---

## 5. Technology Decisions Log

| Decision | Chosen | Rejected | Reason |
|----------|--------|---------|--------|
| LLM inference | Ollama (local, CPU) | OpenAI API, vLLM | On-premise — no code or diffs leave the VPS. vLLM evaluated and rejected: GPU-first design, official Docker images CUDA-only, would be slower than Ollama on AVX2-only Haswell. |
| LLM models | `qwen2.5-coder` family | `llama`, `mistral`, `granite` | Code-optimised pre-training. Benchmarked against 4 models — qwen2.5-coder:7b/14b best balance. |
| Workflow engine | LangGraph | Prefect, Celery | Native LLM state management + PostgreSQL checkpointing in one library |
| Database | PostgreSQL | SQLite, MongoDB | ACID guarantees for security records. LangGraph's `AsyncPostgresSaver` requires PostgreSQL |
| Metrics | prometheus-client | DataDog, New Relic | Open source, self-hosted, no external data egress |
| Long-term storage | VictoriaMetrics | InfluxDB, Thanos | Simpler deployment, Prometheus-compatible API, 90-day retention in a single container |
| Host metrics | node-exporter | cAdvisor, custom scripts | CNCF standard, 1,000+ host metrics, plug-and-play with Prometheus |
| Secret detection | Gitleaks | TruffleHog | Faster, cleaner JSON, `Match` field safely omittable |
| SAST | Semgrep | SonarQube | Lightweight subprocess, no separate server, pinnable rulesets (`p/owasp-top-ten`) |
| IaC scanning | Checkov | KICS | Better Dockerfile + Terraform coverage, pip-installable |
| Dependency scanning | OSV-Scanner | Snyk | Open source, Google-backed, no API key required |
| Chat architecture | Custom ReAct loop | Native Ollama tool-calling | `qwen2.5-coder` outputs plain-text JSON tool calls — native API incompatible |
| Methodology | Agile Scrum adaptée + Kanban interne (Scrumban) | Pure Scrum, pure Kanban, Waterfall | Solo developer + production environment. Scrum gives milestone visibility for the supervisor; Kanban WIP=1 forces shipping; Build→Deploy→Observe→Improve absorbs production discoveries. |

---

## 6. Key Lessons Learned

### Technical Lessons

1. **Production always surprises you.** Every monitoring gap, every 502, every misfiring alert, every hallucinated metric value, every parsing bug was discovered after deployment — not during design. The Build→Deploy→Observe loop was not a nice-to-have; it was the only way to find these issues.

2. **Token budget is a first-class engineering concern.** At `num_ctx=12288`, every token counts. The 52% SAST token reduction (removing Checkov guidelines, collapsing Semgrep INFO) gave the LLM more room for actual code analysis. The 36% system prompt compression (Sprint 6) improved chat response latency.

3. **Local diff is better than API diff.** GitHub's API returns only 3 lines of context. Security vulnerabilities like SQL injection and path traversal span more than 3 lines. Implementing `git diff -U15` locally was a one-day task with significant impact on LLM finding quality.

4. **Deduplication is mandatory for event-driven systems.** GitHub delivers webhooks at-least-once, not exactly-once. Without Redis dedup, a single PR event would trigger multiple pipeline runs.

5. **Route prefixes cascade through the entire stack.** `--web.route-prefix=/prometheus/` changes every HTTP path including `/metrics`. Always verify actual service configuration, never assume defaults.

6. **Monitoring gaps are only visible after real deployment.** The Ollama scrape target appeared green in the config. It only showed `down` after the first real Prometheus scrape — because `OLLAMA_METRICS=true` doesn't expose `/metrics` in the installed version.

7. **Anti-hallucination requires multiple reinforcing layers.** Fixing temperature alone was insufficient. Fixing context size alone was insufficient. The combination of `temperature=0.0` + larger context + code-level no-tool guard + strengthened observation injection + system prompt rules was required.

8. **LLM output parsing must tolerate variability.** A regex that works on 99 outputs will fail on the 100th. The Sprint 8 rewrite of `analyze_review_node` parsing proves this — three independent bugs (whitespace, trailing markdown, missing JSON) all surfaced over PR #14 and #15. Robust parsing means: tolerant regex + structural validators (brace-depth walker) + fallback strategies.

### Process Lessons

1. **Ship every day.** On days where code was written but not deployed, bugs accumulated silently. On days where code was deployed and a real event triggered, bugs surfaced immediately and were fixed in context.

2. **Document while you understand.** The READMEs were written during and immediately after each phase — not at the end. End-of-project documentation from memory produces shallow reports. Documentation written while fixing a bug captures the actual root cause.

3. **The backlog is a priority queue, not a to-do list.** When the disk emergency happened, it went to the top of the backlog. When the VPS audit revealed VictoriaMetrics down 9 days, that became the top card. When PR #14 produced zero inline comments, the parser rewrite jumped in front of all planned work. A fixed plan has no mechanism for this.

4. **Working software is the only real progress metric.** The only meaningful check: "Can I trigger a real PR review right now and watch it complete in under 7 minutes with inline comments visible on GitHub?" At the end of each sprint, the answer was yes.

5. **WIP=1 forces quality.** The temptation to start something new while the current task is "almost done" is constant. Resisting it means every deployed feature is fully verified before the next one starts — which is why the production system has no half-finished features.

---

## 7. Final System Metrics

| Metric | Value |
|--------|-------|
| Total project duration | 5 months (20 weeks) |
| Development sprints | 8 sprints × 2 weeks |
| Documentation phase | 4 weeks |
| Total containers deployed | **12** |
| Total Docker images | 12 |
| LLM models available | 4 (`qwen2.5-coder:7b/14b/32b`, `mistral-nemo:12b`) |
| LLM models active in pipeline | 2 (7B classify + 14B combined review) |
| Security scanners integrated | 5 (Trivy, Gitleaks, Semgrep, Checkov, OSV-Scanner) |
| Custom Prometheus metrics | 14 (pipeline + Ollama re-exported + disk gauges) |
| Prometheus scrape targets | 4 (agent, node-exporter, prometheus, alertmanager) |
| Alert rules | **12** (4 groups: disk, host, agent, ollama) |
| Grafana dashboards | **3** (VPS Host Monitoring, DevSecOps Agent, PR Security Reviews) |
| LangGraph nodes | 9 |
| Chat monitoring tools | **20** (VPS, Docker, Ollama, Prometheus, Redis, Jenkins, Artifacts, Database) |
| PostgreSQL tables | 6 applicative + 4 LangGraph checkpoint |
| PRs reviewed end-to-end | **5** (PR #11, #12, #13, #14, #15 on `GhaiethFerchichi/Vunl-application`) |
| Average pipeline duration | ~6 min (post Sprint 3 combined-call optimisation) |
| Disk freed during emergency | 233 GB |
| System prompt size (final) | 8,186 chars / ~2,047 tokens |
| Token reduction (SAST cleaning) | ~52% |
| System prompt compression (Sprint 6) | 36% |
| Pipeline duration reduction (Sprint 3) | -50% (13–23 min → 6–11 min) |
| Log retention | 500 MB max (50 MB × 10 rotating files) |
| Metrics retention | 30 days (Prometheus) + 90 days (VictoriaMetrics) |
| Production incidents handled | 1 disk emergency (2026-04-20) + 5 audit-discovered (2026-04-28) + 3 parser bugs (2026-05-01) |
| Project completion date | 2026-05-01 (Sprint 8 closed) |

---

## 8. Post-Sprint 8 Addendum — LocalAI Backend Evaluation (2026-05-12)

After the planned Sprint 8 closure, the documentation phase included one optional engineering task: evaluate an alternative LLM inference engine alongside Ollama. The work fits the same Build → Deploy → Observe → Improve loop that governed the development sprints, but is logged separately because it sits outside the M1–M5 milestone plan and was not part of the original supervisor-visible scope.

### Goal

Answer the question: **"Is Ollama actually the right engine for this VPS, or could LocalAI run the same models faster?"** Without a direct measurement, the choice is folklore. The methodology insists on production evidence (Section 1.2), so the same rigour applies here.

### Approach (one micro-sprint, ~half a day)

| Step | What | Why |
|------|------|-----|
| 1. Stand up the sandbox in isolation | `docker-compose.localai.yml` — separate compose file, joins the existing `devsecops-net`, host port 8081. Does **not** touch the production stack. | Reversibility — `docker compose -f … down` removes it completely, leaving the production 12-container stack untouched. Matches the WIP=1 discipline: one card, fully isolated. |
| 2. Wire the chat router to support both backends | `model=<backend>/<name>` selector at `app/routers/chat.py` — `ollama/qwen2.5-coder:7b` keeps the production path; `localai/phi-4` routes through `ChatOpenAI` against `http://localai:8080/v1`. | Validates the chat-router abstraction. PR review nodes remain Ollama-only — production-critical code unchanged. |
| 3. Discover and fix a real production-style bug | Cold-loading phi-4 through LangChain's `ChatOpenAI` failed at exactly 120 s with a stream-chunk-watchdog error. Disabled the watchdog (`stream_chunk_timeout=None`) and added a `_prime_localai_model()` pre-warm helper plus two SSE status events. | Classic production discovery — was not on any pre-task checklist. Mirrors the Sprint 5 "scrape targets down" pattern: the bug only surfaces when you actually deploy and use the thing. |
| 4. Identical-model benchmark | Added a `qwen2.5-coder-7b` YAML to LocalAI pointing at the **same** HuggingFace GGUF Ollama ships. Wrote `scripts/benchmark-backends.sh` — cold prime → warm timed pass → parse `usage.completion_tokens` — running both calls from inside the agent container so any per-call overhead is identical for both backends. | The hidden trap was almost benchmarking Qwen 2.5 dense (Ollama) against Qwen 3 MoE (LocalAI's gallery default), which would have mixed model-architecture differences with backend differences. The Section 5 Technology Decisions Log rule applies: explicit, justified choices. |

### Result

| Backend | Model | tok/s (warm, 80 tokens) |
|---------|-------|-------------------------|
| Ollama  | `qwen2.5-coder:7b`  | **5.49** |
| LocalAI | `qwen2.5-coder-7b` (same GGUF) | **4.50** |

Ollama is **~22% faster** on identical model + identical hardware. Most likely cause: Ollama's tighter integration with llama.cpp and its Haswell-AVX2 tuning (`OLLAMA_FLASH_ATTENTION=1`, `OLLAMA_KV_CACHE_TYPE=q8_0`, `OLLAMA_NUM_THREAD=12`) versus LocalAI's more general-purpose orchestration layer.

### Decision (per Section 5 Technology Decisions Log rule)

| Item | Decision | Why |
|------|----------|-----|
| **Production LLM backend** | Keep Ollama. | 22% faster on identical workload. The Sprint 1 choice is now backed by direct evidence rather than reputation. |
| **LocalAI** | Retained as opt-in sandbox. | Lets future evaluations (new models, new engines) plug in through the same `model=<backend>/<name>` selector without disrupting production. |
| **The cold-load fix** | Kept in the chat router. | A real bug fix, not throwaway evaluation code. Documented in `agent/README.md` under "LocalAI Sandbox Backend". |

### Lesson reinforced

> **Folklore is not evidence.** Before this benchmark, the choice of Ollama over LocalAI was based on its CPU-first design and apparent simplicity — both true, but neither *measured*. The 22% gap might have gone the other way; we would not have known without running the comparison. The same Build → Deploy → Observe → Improve discipline that surfaced the Sprint 5 monitoring gaps and the Sprint 8 parser bugs now also validates a baseline architectural choice that was made on day one.

---

*Internship project — Ghaieth Ferchichi — BTE DevSecOps Platform — 2026*
