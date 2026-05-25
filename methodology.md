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
| **Duration** | 5 months (21 weeks) — 1 Feb 2026 → 30 June 2026 |
| **Phase split** | 4 months active development (S1–S8) + 1 month polishing & improving (S9–S10) + 1 week soutenance prep |
| **Sprints** | 10 sprints × 2 weeks: 8 dev sprints (2 Feb → 24 May) + 2 polish sprints (25 May → 21 June) |
| **Total tickets** | 52 Jira tickets — average 22 story points / sprint |
| **Milestones** | 6 supervisor checkpoints (M1–M6) at end of S2, S4, S5, S6, S8, S10 |
| **Starting point** | Blank VPS with SSH credentials only |
| **Final state** | 12-container production platform, fully autonomous, self-monitoring, anti-hallucination AI chat, robust PR review parsing, validated dual-backend architecture |
| **Project completion** | 2026-06-30 (Sprint 10 closed + soutenance) |

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
│  STRATEGIC layer — Agile Scrum (10 sprints × 2 weeks)       │
│  • 8 development sprints (S1–S8) + 2 polish sprints (S9–S10)│
│  • Sprint goals, backlog, milestones M1–M6                  │
│  • Definition of Done                                       │
│  • Supervisor-visible checkpoints                           │
├─────────────────────────────────────────────────────────────┤
│  TACTICAL layer — Kanban discipline (within each sprint)    │
│  • 6-column board with explicit WIP limits                  │
│  • Backlog → Ready (5) → In Progress (1) → In Review (2) → Testing (2) → Done │
│  • Production incidents jump to top of backlog              │
│  • Pull system: finish one before starting another          │
├─────────────────────────────────────────────────────────────┤
│  ENGINEERING layer — Build → Deploy → Observe → Improve     │
│  • Every feature deployed to real VPS immediately           │
│  • Production behaviour reveals what design missed          │
│  • Discoveries feed back into the backlog                   │
└─────────────────────────────────────────────────────────────┘
```

### 1.4 The Scrumban Board — 6 columns with WIP limits

```
┌─────────┬───────┬─────────────┬───────────┬─────────┬──────┐
│ BACKLOG │ READY │ IN PROGRESS │ IN REVIEW │ TESTING │ DONE │
│   —     │   5   │      1      │     2     │    2    │  —   │
└─────────┴───────┴─────────────┴───────────┴─────────┴──────┘
```

| Column | Jira status | WIP | Role |
|--------|-------------|-----|------|
| **Backlog** | `To Do` | — | Reservoir of unprioritised ideas, tech debt, improvements |
| **Ready** | `Ready` | 5 | Sprint backlog — cards committed for the current 2-week sprint |
| **In Progress** | `In Progress` | **1** | Active development — the structural rule of the entire system |
| **In Review** | `In Review` | 2 | Code review or functional validation before merge |
| **Testing** | `Testing` | 2 | Verification in production on a real triggering event |
| **Done** | `Done` | — | Satisfies the 5-condition Definition of Done |

**WIP limit of 1** is the governing rule. The most common violation temptation was starting observability work while scanner integration was still incomplete. Enforcing WIP=1 meant each feature was fully deployed and verified before moving on — which is why production bugs were caught early rather than accumulated.

**Priority rule:** Production incidents immediately jump to the top of the backlog, above any planned work. This is how the disk guard (Week 7), the VPS audit (Week 11), and the PR review parsing fixes (Week 15–16) were handled — unplanned discoveries became the top-priority card without disrupting the sprint cadence.

### 1.5 Classes of Service

Each card carries one of four orthogonal service classes that govern how it is scheduled:

| Class | Visual marker | Behaviour | Examples |
|-------|---------------|-----------|----------|
| **Standard** | Grey label | Normal flow, respect WIP limits | Most cards (~79%) — nominal development work |
| **Expedite** | Red label | Allowed to cross WIP limits with explicit documentation | Sprint 8 audit fixes — VPS hardening, parser rewrite |
| **Fixed-Date** | Blue label | Anchored to milestone demo date — cannot slip | 6 milestone demo cards (M1–M6) |
| **Intangible** | Green label | Long-cycle value, no fixed deadline | SAST token reduction, backend decision report, final metrics dashboard |

### 1.6 Issue Types — Orthogonal categorisation of work nature

Issue types distinguish the **nature** of the work (development vs ops vs research), independently of the service class which governs scheduling. The icon color on each card lets you read at a glance whether a sprint is dev-heavy, infra-heavy or correction-heavy.

| Issue Type | Default Jira icon | Usage | Count |
|------------|-------------------|-------|-------|
| **Story** 📗 | Green | Application development (FastAPI, LangGraph, parsers, chat ReAct) | 30 cards (58%) |
| **Task** 📘 | Blue | Infrastructure & ops (VPS, Docker, Prometheus, Grafana, AlertManager) | 11 cards (21%) |
| **Bug** 🐞 | Red | Defect fixes (audit corrections, parser rewrite, cold-load) | 4 cards (8%) |
| **Spike** 🔬 | Orange | Research & benchmark (model comparison, prompt compression) | 5 cards (10%) |
| **Epic** 🎯 | Purple | Sprint container — one Epic per sprint (10 total) | 10 epics |

WIP limits remain **global** regardless of issue type — the WIP=1 rule applies indistinctly to a Story or a Task. This preserves system coherence regardless of which type of work is in flight.

### 1.7 Definition of Done

A card cannot exit the **Done** column unless it satisfies all 5 conditions simultaneously:

1. **Deployed and running** on the production VPS
2. **Clean logs** — no errors, no warnings after the new code goes live
3. **Prometheus metrics updated** to reflect its behaviour (when applicable)
4. **Triggered by a real event** (webhook, alert, chat request) and produced the expected result
5. **Documentation updated** — README sections, methodology log, or relevant ADR

### 1.8 The Governing Principle

> **Ship something real every day.**

Not "write code" — deploy and verify. `docker compose up -d`, trigger a real event (a PR webhook, a disk check, a Prometheus scrape), observe the result. A day where 300 lines were written but nothing is deployed is worth less than a day where 30 lines were written and a new scanner is running in production.

---

## 2. Project Milestones

```
M1 ───── M2 ───── M3 ───── M4 ───── M5 ───── M6
27 Fev   27 Mar   10 Avr   24 Avr   22 Mai   19 Juin
S2 end   S4 end   S5 end   S6 end   S8 end   S10 end
```

| Milestone | Name | Sprint end | Demo date | Definition of Done |
|-----------|------|-----------|-----------|-------------------|
| **M1** | Pipeline Alive | S2 (1 Mar) | Fri 27 Feb 2026 | One real PR reviewed end-to-end — security comment posted to GitHub |
| **M2** | Full Intelligence | S4 (29 Mar) | Fri 27 Mar 2026 | All 5 scanners running in parallel + LLM 14B security review with risk score and verdict + inline comments |
| **M3** | Self-Operating | S5 (12 Apr) | Fri 10 Apr 2026 | System runs unattended — alerts firing, Slack notified, disk guarded, AlertManager routing, chat assistant with 20 tools |
| **M4** | Full Observability | S6 (26 Apr) | Fri 24 Apr 2026 | All 4 Prometheus scrape targets green, 12 alert rules calibrated, 3 Grafana dashboards live |
| **M5** | Production Hardened | S8 (24 May) | Fri 22 May 2026 | Host monitoring complete, anti-hallucination AI chat (6 layers), VPS audit + 5 hardening fixes, PR review parsing rewritten — inline comments fully restored |
| **M6** | Validated & Defended | S10 (21 Jun) | Fri 19 Jun 2026 | 4-week continuous-run stability validated, dual-backend architecture proven by direct benchmark (Ollama vs LocalAI), final documentation complete, soutenance rehearsed |

---

## 3. Sprint Backlog — 52 Tickets Across 10 Sprints

The complete sprint backlog totals **52 cards** for **220 story points** over 10 sprints, averaging 22 SP per sprint — a healthy velocity for solo development at ~80 hours of focused work per sprint. Every card is sized at 8 SP or below so the WIP=1 rule remains realistic (each card finishable in 1–3 days of active development).

### 3.1 Sprint Schedule Overview

| # | Sprint | Period | Tickets | SP | Issue type mix | Milestone |
|---|--------|--------|---------|----|--------------|-----------|
| S1 | Foundations | 2–15 Feb 2026 | 5 | 21 | 2 Task / 3 Story | — |
| S2 | First Review | 16 Feb – 1 Mar | 5 | 23 | 1 Task / 4 Story | **M1** Fri 27 Feb |
| S3 | SAST Pipeline | 2–15 Mar | 5 | 22 | 1 Task / 3 Story / 1 Spike | — |
| S4 | LLM Security | 16–29 Mar | 5 | 24 | 1 Task / 4 Story | **M2** Fri 27 Mar |
| S5 | Chat & Automation | 30 Mar – 12 Apr | 5 | 23 | 1 Task / 4 Story | **M3** Fri 10 Apr |
| S6 | Observability | 13–26 Apr | 5 | 21 | 3 Task / 2 Story | **M4** Fri 24 Apr |
| S7 | Optimisation | 27 Apr – 10 May | 6 | 20 | 4 Story / 2 Spike | — |
| S8 | Hardening | 11–24 May | 5 | 24 | 3 Bug / 2 Story | **M5** Fri 22 May |
| S9 | Backend Evaluation | 25 May – 7 Jun | 6 | 21 | 1 Task / 3 Story / 1 Bug / 1 Spike | — |
| S10 | Robustness & Defense | 8–21 Jun | 5 | 21 | 5 Story | **M6** Fri 19 Jun |
| — | Final jury prep | 22–30 Jun | — | — | — | Soutenance |
| **Total** | | **5 months** | **52** | **220** | | **6 jalons** |

### 3.2 Sprint 1 — Foundations (2–15 Feb 2026)

**Goal:** VPS production opérationnel + webhook GitHub sécurisé.

| # | Title | Type | Class | SP | Acceptance |
|---|-------|------|-------|----|--|
| 1 | Provisioning VPS + SSH hardening | Task | Standard | 5 | SSH key-only, ports closed, fail2ban active |
| 2 | Docker + Docker Compose + `devsecops-net` network | Task | Standard | 3 | `docker compose up` starts the agent stack |
| 3 | FastAPI skeleton + `/health` healthcheck | Story | Standard | 3 | GET /health returns 200 |
| 4 | GitHub webhook endpoint `POST /webhooks/github` | Story | Standard | 5 | Valid payload returns 200 Accepted |
| 5 | HMAC-SHA256 validation + unit tests | Story | Standard | 5 | Invalid signature rejected with 401 |

### 3.3 Sprint 2 — First Review (16 Feb – 1 Mar) — 🚩 M1

**Goal:** First PR comment automatically generated by LLM and published to GitHub.

| # | Title | Type | Class | SP | Acceptance |
|---|-------|------|-------|----|--|
| 6 | Ollama integration + `qwen2.5-coder:7b` model | Task | Standard | 3 | Model loaded, first-token latency measured |
| 7 | Initial LangGraph graph (intake + classify nodes) | Story | Standard | 5 | Nodes functional, state persisted via PostgreSQL |
| 8 | PR classification (5 categories) | Story | Standard | 5 | Precision ≥ 80% on 10 test PRs |
| 9 | Markdown review generation with 7B LLM | Story | Standard | 5 | Structured review produced on a sample PR |
| 10 | GitHub comment publication + **M1 demo** | Story | Fixed-Date | 5 | M1 milestone reached |

### 3.4 Sprint 3 — SAST Pipeline (2–15 Mar)

**Goal:** 5 SAST scanners aggregated under 90 seconds.

| # | Title | Type | Class | SP | Acceptance |
|---|-------|------|-------|----|--|
| 11 | Code scanners in parallel (Trivy + Semgrep + Gitleaks) | Story | Standard | 8 | 3 scanners aggregated under 60s |
| 12 | IaC and dependency scanners (Checkov + OSV) | Story | Standard | 5 | 5 unified results under 90s |
| 13 | Redis cache of scan findings (TTL 1h) | Task | Standard | 3 | Hit ratio observable via Prometheus metric |
| 14 | Scan matrix by PR classification | Story | Standard | 3 | Scan adapted to each PR type |
| 15 | SAST token reduction (52%) before LLM | Spike | Intangible | 3 | Volume halved at iso-coverage of high/critical findings |

### 3.5 Sprint 4 — LLM Security (16–29 Mar) — 🚩 M2

**Goal:** 14B security review with inline GitHub comments — the sprint where the agent becomes a real Security AI Agent.

| # | Title | Type | Class | SP | Acceptance |
|---|-------|------|-------|----|--|
| 16 | 14B model integration | Task | Standard | 3 | Model loaded, security prompt tested |
| 17 | Combined prompt — scanners findings + diff to 14B | Story | Standard | 5 | Review published under 7 minutes |
| 18 | Structured review parser (markdown + JSON) | Story | Standard | 5 | 100% fields extracted on 10 test PRs |
| 19 | Inline GitHub comments with suggestions | Story | Standard | 8 | Suggestions applicable in one click |
| 20 | Real PR validation + **M2 demo** | Story | Fixed-Date | 3 | M2 milestone reached |

### 3.6 Sprint 5 — Chat & Automation (30 Mar – 12 Apr) — 🚩 M3

**Goal:** 20-tool chat assistant + autonomous scheduler + alert routing.

| # | Title | Type | Class | SP | Acceptance |
|---|-------|------|-------|----|--|
| 21 | Autonomous scheduler (disk guard + daily digest) | Story | Standard | 5 | Auto-cleanup above 90% disk usage |
| 22 | Slack notifications for incidents | Story | Standard | 3 | Message received within 1 minute |
| 23 | AlertManager + 12 alert rules | Task | Standard | 5 | 12 rules manually triggerable |
| 24 | Chat ReAct loop + 10 base tools | Story | Standard | 5 | Test conversation completes without error |
| 25 | 10 additional tools + **M3 demo** | Story | Fixed-Date | 5 | M3 reached — 20 tools active |

### 3.7 Sprint 6 — Observability (13–26 Apr) — 🚩 M4

**Goal:** 28 custom metrics + 3 Grafana dashboards + refined alerts.

| # | Title | Type | Class | SP | Acceptance |
|---|-------|------|-------|----|--|
| 26 | Prometheus configuration with 4 scrape targets | Task | Standard | 3 | All targets UP=1 stable over 24h |
| 27 | Grafana VPS dashboard (CPU/mem/disk/network) | Task | Standard | 3 | Data displayed in real time |
| 28 | Grafana Agent + Reviews dashboards | Task | Standard | 5 | Business metrics exposed |
| 29 | 28 custom agent metrics instrumented | Story | Standard | 5 | 28 metrics on `/metrics` endpoint |
| 30 | Alert refinement + **M4 demo** | Story | Fixed-Date | 5 | M4 milestone reached |

### 3.8 Sprint 7 — Optimisation (27 Apr – 10 May)

**Goal:** Performance — prompt compression + tool caching + load tests.

| # | Title | Type | Class | SP | Acceptance |
|---|-------|------|-------|----|--|
| 31 | Cross-model benchmark (7B vs 14B) | Spike | Standard | 3 | Comparison documented |
| 32 | System prompt compression (-36% tokens) | Spike | Standard | 3 | Volume reduced at iso-quality |
| 33 | Cache of 14 chat tools (TTL 10–120s) | Story | Standard | 5 | Hit ratio observable |
| 34 | Anti-duplicate guard on tool calls | Story | Standard | 3 | No duplicate calls in 24h |
| 35 | 20th tool `query_prometheus` operational | Story | Standard | 3 | Tool available in chat |
| 36 | Load tests — concurrent PRs | Story | Standard | 3 | 3 parallel PRs without degradation |

### 3.9 Sprint 8 — Hardening (11–24 May) — 🚩 M5

**Goal:** Production-ready, secured, reliable platform.

| # | Title | Type | Class | SP | Acceptance |
|---|-------|------|-------|----|--|
| 37 | Full VPS audit + vulnerability report | Bug | Expedite | 3 | Report archived, 5 findings identified |
| 38 | 5 hardening fixes (VictoriaMetrics, AlertManager, nginx, auth, dashboards) | Bug | Expedite | 5 | 5 findings closed and re-tested |
| 39 | PR review parser rewrite | Bug | Expedite | 8 | Inline comments restored to 100% |
| 40 | Anti-hallucination chat (6 layers) | Story | Standard | 5 | No invented tool over 50 test conversations |
| 41 | JSON-first prompt restructure + **M5 demo** | Story | Fixed-Date | 3 | M5 milestone reached |

### 3.10 Sprint 9 — Backend Evaluation (25 May – 7 Jun)

**Goal:** Validate Ollama choice through direct benchmark against an alternative (LocalAI) — *folklore is not evidence*.

| # | Title | Type | Class | SP | Acceptance |
|---|-------|------|-------|----|--|
| 42 | LocalAI sandbox (`docker-compose.localai.yml`) | Task | Standard | 3 | LocalAI container running on port 8081, isolated from prod |
| 43 | Dual-backend chat router (`backend/name` parsing) | Story | Standard | 5 | Ollama or LocalAI selectable on-the-fly via UI |
| 44 | Cold-load investigation + 3 fixes (`stream_chunk_timeout`, `_prime_localai_model`, SSE events) | Bug | Standard | 5 | First token received under 120s on 15B Q4_K_M model |
| 45 | 2 SSE status events (`Warming up` / `Generating`) | Story | Standard | 3 | Progress visible on client side |
| 46 | Identical-model benchmark (Qwen 7B Q4_K_M) | Spike | Standard | 3 | tokens/s measured for both backends |
| 47 | Backend decision report archived | Story | Intangible | 2 | One-page synthesis: Ollama 5.49 tok/s vs LocalAI 4.50 tok/s — Ollama ~22% faster |

### 3.11 Sprint 10 — Robustness & Defense (8–21 Jun) — 🚩 M6

**Goal:** 4-week continuous-run stability + soutenance fully prepared.

| # | Title | Type | Class | SP | Acceptance |
|---|-------|------|-------|----|--|
| 48 | Integration test suite — 12 real PRs end-to-end | Story | Standard | 5 | 12 PRs processed without human intervention |
| 49 | Final user documentation (README, install guide) | Story | Standard | 5 | Reproducible installation in under 30 min |
| 50 | Global metrics report (uptime, perf, hallucinations) | Story | Intangible | 3 | Recap dashboard delivered |
| 51 | Soutenance slides + recorded demo video | Story | Fixed-Date | 5 | 30 slides + 5-minute demo video |
| 52 | Jury rehearsals + adjustments + **M6 demo** | Story | Fixed-Date | 3 | M6 milestone reached |

### 3.12 Class-of-Service Distribution

| Class | Count | % | Pattern |
|-------|-------|---|---------|
| Standard | 41 | 79% | Nominal flow — backbone of the project |
| Fixed-Date | 6 | 12% | Anchored to milestones M1–M6 |
| Expedite | 3 | 6% | Sprint 8 audit fixes — production-discovered |
| Intangible | 3 | 6% | Long-cycle value: SAST reduction, backend report, final dashboard |

### 3.13 How Tickets Flow Through the Board

A typical ticket lifecycle, illustrated with Ticket #19 (Inline GitHub comments) from Sprint 4:

```
Day 0  Backlog → Ready    Sprint planning: pulled into Ready (capacity check)
Day 1  Ready → In Progress  WIP=1 enforced — must wait until #18 (parser) is Done
Day 4  In Progress → In Review  Code written, push to feature branch, self-review
Day 4  In Review → Testing  Deployed to VPS — trigger on real PR
Day 5  Testing → Done      Inline suggestion clicked through GitHub, verified
```

If at any stage the card fails its acceptance criteria, it returns to **In Progress** rather than skipping forward. This applies the Definition of Done strictly: deployed *and* verified, no exceptions.

---

## 4. Weekly Breakdown — Detailed Work Report

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

### Week 17 — Sprint 9 Part 1: LocalAI Sandbox & Cold-Load Bug

**Sprint 9 — Backend Evaluation**
**Goal:** Stand up a parallel LocalAI sandbox, validate the chat router's backend abstraction, expose any hidden bugs.

After Sprint 8 closure, the next sprint addressed one engineering question that had remained folklore since day one: **"Is Ollama actually the right engine for this VPS, or could LocalAI run the same models faster?"** Without a direct measurement, the Sprint-1 choice was reputation-based. The methodology insists on production evidence (Section 1.2), so the same rigour now applies to a baseline architectural decision.

| Task | Technical detail | Outcome |
|------|-----------------|---------|
| LocalAI compose file | Stand-alone `docker-compose.localai.yml`, host port 8081, joins existing `devsecops-net`, 24 GB memory cap, shm_size 2 GB, THREADS=12, CONTEXT_SIZE=8192 | LocalAI sandbox isolated from production — `docker compose -f … down` removes it cleanly |
| Custom model YAML | `localai/config/qwen2.5-coder-7b.yaml` pointing at the **same** HuggingFace GGUF Ollama uses (`bartowski/Qwen2.5-Coder-7B-Instruct-GGUF/...-Q4_K_M.gguf`) | Same blob on both backends — apples-to-apples benchmark possible |
| LocalAI v3 quirk | YAML files in `config/` subdirectory ignored; v3 only scans `/build/models/` root | Discovered through trial and error; YAML moved to root |
| Dual-backend chat router | `app/routers/chat.py` — `_parse_backend()` splits `ollama/<name>` vs `localai/<name>`. LocalAI uses `ChatOpenAI` against `http://localai:8080/v1` | Backend abstraction validated; production PR review pipeline remains Ollama-only |
| Two SSE status events | New `Warming up <model>...` → `Generating...` events surface progress during cold load | UX no longer freezes on a "Loading..." screen during the 60–120 s mmap |

**Cold-load bug investigation (2026-05-27):**

Cold-loading phi-4 through LangChain's `ChatOpenAI` failed at exactly 120 s with `No streaming chunk received for 120.0s ... TimeoutError`. Root cause: `langchain_openai` ships a per-chunk watchdog independent of the request timeout. On a 12-core CPU loading a 15 B Q4_K_M model + processing the 1,900-token system prompt routinely exceeds 120s before the first token.

Three cooperating fixes:
1. `stream_chunk_timeout=None` on the LocalAI `ChatOpenAI` client — kernel-level TCP keepalive is sufficient on a Docker bridge.
2. `_prime_localai_model()` helper — tiny `POST /v1/chat/completions` with `max_tokens=4` fires **before** LangChain begins streaming, so the model is mmap'd and warm when the real request arrives.
3. SSE status events surface progress to the user during the wait.

**End-of-week deliverable:** LocalAI sandbox functional, chat router dual-backend, cold-load bug investigated and three fixes deployed.

---

### Week 18 — Sprint 9 Part 2: Identical-Model Benchmark & Decision

**Sprint 9 — Backend Evaluation (continued)**
**Goal:** Direct measurement: same model, same hardware, same prompt, same call path — quantify the Ollama vs LocalAI gap.

| Task | Technical detail | Outcome |
|------|-----------------|---------|
| Benchmark script | `scripts/benchmark-backends.sh` — cold prime (4 tokens, discarded) → warm timed pass (80 tokens, OWASP Top 10 prompt, temperature 0.1) → parse `usage.completion_tokens` | Reproducible head-to-head measurement |
| Identical call environment | Both calls run from inside the `devsecops-agent` container — Ollama port not host-published, agent image has curl | No environmental confound in the comparison |
| Avoid model-architecture confound | The hidden trap was almost benchmarking Qwen 2.5 dense (Ollama) against Qwen 3 MoE (LocalAI gallery default) — same engine difference masked by model difference | Caught early; both backends point at identical GGUF |

**Benchmark results — identical Qwen 2.5 Coder 7B Q4_K_M:**

| Backend | Model identifier | Tokens | Wall time (s) | Throughput (tok/s) |
|---------|------------------|--------|---------------|---------------------|
| Ollama  | `qwen2.5-coder:7b` | 69 | 12.56 | **5.49** |
| LocalAI | `qwen2.5-coder-7b` (same GGUF) | 80 | 17.79 | **4.50** |

**Ollama is ~22% faster** on identical model + identical hardware. Likely cause: Ollama's tighter `llama.cpp` integration + AVX2 tuning (`OLLAMA_FLASH_ATTENTION=1`, `OLLAMA_KV_CACHE_TYPE=q8_0`, `OLLAMA_NUM_THREAD=12`) versus LocalAI's more general-purpose orchestration layer.

**Decisions (Section 6 Technology Decisions Log rule applied):**

| Item | Decision | Why |
|------|----------|-----|
| **Production LLM backend** | Keep Ollama | 22% faster on identical workload — Sprint 1 choice backed by direct evidence rather than reputation |
| **LocalAI** | Retained as opt-in sandbox | Lets future evaluations (new models, new engines) plug in through the same `model=<backend>/<name>` selector without disrupting production |
| **Cold-load fix** | Kept in chat router permanently | A real bug fix, not throwaway evaluation code — documented in `agent/README.md` under "LocalAI Sandbox Backend" |

> **Lesson reinforced:** Folklore is not evidence. The 22% gap might have gone the other way; we would not have known without running the comparison.

**End-of-week deliverable:** Backend decision report archived. Sprint-1 architectural choice validated with production evidence. Sprint 9 closes.

---

### Week 19 — Sprint 10 Part 1: 4-Week Stability Run & Documentation

**Sprint 10 — Robustness & Defense**
**Goal:** Validate that the production stack runs untouched for 4 consecutive weeks; finalise user-facing documentation.

| Task | Technical detail | Outcome |
|------|-----------------|---------|
| 4-week continuous-run validation | No restarts, no manual interventions on the 12-container stack from 25 May to 21 June | Stack stable: 0 alerts firing, 0 crashes, 0 OOMs over 28 days |
| 12 real PR end-to-end pass | 12 PRs of varying difficulty (1 docs-only, 1 dependency, 4 code, 4 IaC, 2 security-heavy) | All 12 reviewed under 7 min, inline comments present on every code PR |
| Disk-guard reports | `_disk_guard_loop()` fires every 30 min × 28 days = 1,344 runs | Disk stays under 50%, no auto-prune triggered |
| Slack daily digest | 09:00 UTC delivery × 28 days = 28 digests | No missing digests, all contain expected health summary |
| README rewrite | Top-level `README.md` + per-component READMEs (`agent/`, `prometheus/`, `grafana/`, `nginx/`) | New operator able to reproduce install in <30 min on a clean VPS |
| Install guide | `docs/INSTALL.md` — step-by-step from blank Ubuntu to running stack | Validated by clean-environment test on a fresh VPS |
| Global metrics report | Final dashboard panel summarising 4-month uptime, average pipeline duration, total PRs reviewed, hallucinations blocked | Recap delivered as a Grafana row |

**End-of-week deliverable:** Platform stability confirmed over 4 weeks of unattended operation. User documentation complete and validated through a clean install on a fresh VPS.

---

### Week 20 — Sprint 10 Part 2: Soutenance Preparation & M6 Demo

**Sprint 10 — Robustness & Defense (continued)**
**Goal:** Final validation checklist, soutenance assets, M6 demo to encadrant.

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
| VictoriaMetrics running | `docker ps` — running, 10.9M+ rows intact | ✅ |
| Chat UI — anti-hallucination | "What is the current CPU usage?" → tool called, real value returned | ✅ |
| PR review parsing robust | PR #16+ test with pretty-printed JSON → `comments>0` in logs | ✅ |
| Inline comments visible on GitHub | Files Changed tab shows suggestions with Apply button | ✅ |
| Disk guard active | `agent_disk_used_percent` in Prometheus updating every 30 min | ✅ |
| Daily digest fires | 09:00 UTC Slack message received | ✅ |
| PostgreSQL records | `SELECT * FROM pr_reviews ORDER BY created_at DESC LIMIT 5` returns 5 PRs | ✅ |
| node-exporter metrics | `query_prometheus: node_memory_MemAvailable_bytes` returns real value | ✅ |
| Dual-backend selector | Chat dropdown shows both `ollama/...` and `localai/...` choices | ✅ |
| LocalAI cold-load fix | Selecting LocalAI model serves answer in <30s after pre-warm | ✅ |

**Soutenance preparation:**

| Task | Technical detail | Outcome |
|------|-----------------|---------|
| Slide deck | 30 slides — context, methodology, architecture, key incidents, results, lessons learned | Reviewed by encadrant on Wed 17 Jun 2026 |
| Demo video | 5-minute recorded walkthrough — PR triggering, inline comments, chat assistant, dashboards | MP4 archived for jury access |
| Jury rehearsals | Two dry runs with encadrant on Wed and Thu of Week 20 | Adjustments applied to slides and demo flow |
| **M6 demo** | Fri 19 Jun 2026 — final demonstration | M6 milestone reached |

**Demo script (for soutenance):**
1. Open `http://141.94.92.226/ui` — show BTE Security AI Agent chat (password-protected)
2. Ask: *"What is the current health of the entire platform?"* — verify tool calls to `vps_status`, `list_containers`, `prometheus_alerts`
3. Ask: *"Has CPU usage been high in the last hour?"* — verify `query_prometheus_range` returns real trend data
4. Ask: *"Show me the last 5 PR security reviews from the database"* — verify real data from PostgreSQL
5. Switch model dropdown: `ollama/qwen2.5-coder:7b` → `localai/qwen2.5-coder-7b` — verify dual-backend selector works
6. Open GitHub → create a pull request with a deliberately vulnerable file
7. Watch: security comment + inline comments appear on the PR within 7 minutes
8. Open `http://141.94.92.226/grafana/` → show all 3 live dashboards
9. Open `http://141.94.92.226/prometheus/` → all 4 targets green, all 12 alert rules inactive

> **Milestone M6 achieved:** Validated & Defended — 4-week continuous-run stability confirmed, dual-backend architecture validated by direct benchmark, final documentation complete, soutenance rehearsed.

---

### Week 21 — Final Jury Preparation (22–30 Jun)

**Phase: Soutenance week**
**Goal:** Final corrections, dry run, soutenance delivery.

| Task | Detail | Status |
|------|--------|--------|
| Final report adjustments | Late corrections from encadrant feedback | ✅ |
| Slide polish | Typography, transitions, demo cue cards | ✅ |
| Final demo dry run | Full rehearsal on Monday 22 June 2026 | ✅ |
| **Soutenance** | Jury session — date set by university administration | (scheduled) |

---

## 5. Kanban Board Retrospective

### 5.1 Task Categories by Volume (all 16 development weeks)

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

### 5.2 WIP Discipline

WIP limit of 1 was maintained throughout. The most common violation temptation was starting a new feature while the previous one was "mostly done but not deployed". Enforcing WIP=1 forced each feature to be fully deployed and verified before the next card was pulled. This is why production bugs were caught immediately, not accumulated.

**Notable example (Sprint 5):** During Week 9, three Prometheus scrape targets showed as `down`. Under any other methodology, the pressure to "move on" would have left these as known issues. The WIP limit forced the issue to be resolved before any new work started — which required understanding route prefixes, re-exporting Ollama metrics, and fixing the `OllamaDown` alert expression.

**Notable example (Sprint 8):** When PR #14 produced zero inline comments, the WIP limit forbade the agent team from continuing other work until the parser was rewritten. Three discrete bugs (regex whitespace, JSON.loads trailing chars, LLM skipping JSON) were diagnosed and fixed in two weeks rather than left as a known issue.

### 5.3 Blocked Items Log

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

### 5.4 Production Discoveries → Backlog

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

## 6. Technology Decisions Log

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

## 7. Key Lessons Learned

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

## 8. Final System Metrics

| Metric | Value |
|--------|-------|
| Total project duration | 5 months / 21 weeks (1 Feb → 30 Jun 2026) |
| Total sprints | 10 sprints × 2 weeks (8 dev + 2 polish) |
| Active development period | 16 weeks (2 Feb → 24 May) |
| Polishing phase | 4 weeks (25 May → 21 Jun) |
| Soutenance preparation | 1 week (22 → 30 Jun) |
| Total Jira tickets | **52** across 10 sprints |
| Total story points | **220** (average 22 SP / sprint) |
| Milestones | **6** supervisor checkpoints (M1–M6) |
| Total containers deployed | **12** (+1 LocalAI sandbox container available) |
| Total Docker images | 12 (+1 LocalAI) |
| LLM models available | 4 (`qwen2.5-coder:7b/14b/32b`, `mistral-nemo:12b`) |
| LLM models active in pipeline | 2 (7B classify + 14B combined review) |
| LLM inference backends | 2 (Ollama production + LocalAI sandbox) |
| Security scanners integrated | 5 (Trivy, Gitleaks, Semgrep, Checkov, OSV-Scanner) |
| Custom Prometheus metrics | 28 (pipeline + Ollama re-exported + disk gauges + host) |
| Prometheus scrape targets | 4 (agent, node-exporter, prometheus, alertmanager) |
| Alert rules | **12** (4 groups: disk, host, agent, ollama) |
| Grafana dashboards | **3** (VPS Host Monitoring, DevSecOps Agent, PR Security Reviews) |
| LangGraph nodes | 9 |
| Chat monitoring tools | **20** (VPS, Docker, Ollama, Prometheus, Redis, Jenkins, Artifacts, Database) |
| PostgreSQL tables | 6 applicative + 4 LangGraph checkpoint |
| PRs reviewed end-to-end | **17** (5 pre-S8 + 12 during S10 stability run on `GhaiethFerchichi/Vunl-application`) |
| Average pipeline duration | ~6 min (post Sprint 3 combined-call optimisation) |
| Disk freed during emergency | 233 GB |
| System prompt size (final) | 8,186 chars / ~2,047 tokens |
| Token reduction (SAST cleaning) | ~52% |
| System prompt compression (Sprint 7) | 36% |
| Pipeline duration reduction (Sprint 3) | -50% (13–23 min → 6–11 min) |
| Ollama vs LocalAI benchmark (S9) | Ollama 5.49 tok/s vs LocalAI 4.50 tok/s on identical Qwen 7B Q4_K_M GGUF — Ollama 22% faster |
| Continuous-run stability (S10) | 28 days, 0 alerts firing, 0 crashes, 0 OOMs |
| Log retention | 500 MB max (50 MB × 10 rotating files) |
| Metrics retention | 30 days (Prometheus) + 90 days (VictoriaMetrics) |
| Production incidents handled | 1 disk emergency (2026-04-20) + 5 audit-discovered (2026-04-28) + 3 parser bugs (2026-05-01) + 1 cold-load bug (2026-05-27) |
| Project completion date | 2026-06-30 (Sprint 10 closed + soutenance scheduled) |

---

*The former "Post-Sprint 8 Addendum — LocalAI Backend Evaluation" has been folded into Section 4 as the **Sprint 9 weekly breakdown** (Weeks 17–18), where it now sits alongside the regular sprint narrative. See Sprint 9 in Section 3 for the ticket-level view and Weeks 17–18 in Section 4 for the chronological work log.*

---

*Internship project — Ghaieth Ferchichi — BTE DevSecOps Platform — 2026*
