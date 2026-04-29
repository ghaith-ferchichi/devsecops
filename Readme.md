# BTE Security AI Agent — Full System Report

> **Status as of 2026-04-28 (Sprint 7)** — All 12 containers running. VictoriaMetrics restarted after 9-day crash. AlertManager 404 fixed — alerts now correctly reach the agent. nginx hardened: root redirect, Grafana WebSocket, chat UI password-protected (Basic Auth). 3 Grafana dashboards live (VPS Host Monitoring added). Chat agent anti-hallucination: temperature=0.0, num_ctx=6144, num_predict=800, no-tool guard, ANTI-HALLUCINATION system prompt block. Security gaps remain: Redis/Prometheus/AlertManager/VictoriaMetrics host-exposed without auth. Disk at 16% (245 GB free).

An event-driven security automation platform that intercepts GitHub Pull Requests, runs a parallel security scanning pipeline powered by local LLM inference, and posts an AI-generated security + code quality review directly on the PR — with optional human approval gates via Slack. Includes a real-time ops assistant chat interface for live infrastructure monitoring, an autonomous background scheduler, and full AlertManager integration.

---

## Table of Contents

1. [VPS Environment](#1-vps-environment)
2. [Architecture Overview](#2-architecture-overview)
3. [Container Inventory](#3-container-inventory)
4. [Docker Images & Models](#4-docker-images--models)
5. [Agent Codebase Structure](#5-agent-codebase-structure)
6. [LangGraph Workflow — Node Reference](#6-langgraph-workflow--node-reference)
7. [Scan Matrix](#7-scan-matrix)
8. [Configuration Reference](#8-configuration-reference)
9. [Nginx Reverse Proxy](#9-nginx-reverse-proxy)
10. [Database Schema](#10-database-schema)
11. [Observability Stack](#11-observability-stack)
12. [Autonomous Operations](#12-autonomous-operations)
13. [Chat Ops Assistant UI — BTE Security AI Agent](#13-chat-ops-assistant-ui--bte-security-ai-agent)
14. [Artifacts Volume](#14-artifacts-volume)
15. [Known Bugs & Fixes](#15-known-bugs--fixes)
16. [Live Pipeline Results](#16-live-pipeline-results)
17. [Quick Start](#17-quick-start)
18. [Work Methodology Recommendation](#18-work-methodology-recommendation)
19. [Latest Improvements — Sprint 5](#19-latest-improvements--sprint-5)
20. [Latest Improvements — Sprint 6](#20-latest-improvements--sprint-6)
21. [Latest Improvements — Sprint 7](#21-latest-improvements--sprint-7)

---

## 1. VPS Environment

| Property | Value |
|----------|-------|
| **Host IP** | `141.94.92.226` |
| **OS** | Ubuntu Linux (kernel 6.14.0-37-generic) |
| **CPU** | 12 cores — Intel Core (Haswell/AVX2, no TSX, no GPU) |
| **RAM** | 45 GB total / ~41 GB available |
| **Disk** | 290 GB total / ~41 GB used / ~249 GB free |
| **GPU** | None — all LLM inference runs on CPU |
| **Docker** | 29.4.0 |
| **Working directory** | `/opt/devsecops` |

> **CPU-only inference:** All Ollama models run entirely on CPU with AVX2 acceleration. The `libggml-cpu-haswell.so` backend is auto-selected. Flash Attention reduces KV cache memory from O(n²) to O(n). The 14B model runs at ~3–6 tok/s.

> **Disk emergency (2026-04-20):** A 242 GB partial model download (`sha256-c430a9b9...`) had no manifest and was unusable. Deleted it + `llama3.2:3b` + Docker build cache → freed 233 GB (92% → 14% disk usage). No running services were affected.

---

## 2. Architecture Overview

```
GitHub Pull Request (opened / synchronize)
         │
         ▼  POST /webhooks/github
    [ Nginx :80 ]  ←── single external entry point
         │                     │
         │                     ├── GET  /ui           → Chat UI HTML (BTE Security AI Agent)
         │                     ├── GET  /chat/models   → Ollama model list
         │                     └── POST /chat/stream   → SSE streaming chat
         ▼
  [ FastAPI Agent :8000 ]
         │  HMAC-SHA256 validated
         │  async background task
         ▼
  LangGraph StateGraph ─────────────────────────────────────────────┐
                                                                     │
  intake ──► classify ──► route_scans                               │
                              │                                      │
              ┌───────────────┼───────────────┐                     │
              ▼               ▼               ▼                     │
          scan_full        scan_fs        skip_scan                 │
              └───────────────┴───────────────┘                     │
                              │                                      │
                              ▼                                      │
                       analyze_review   ← single 14B call:          │
                              │           security + code quality    │
                         route_risk      + posts GitHub inline review│
                         ┌────┴────┐                                 │
                         ▼         ▼                                 │
                      escalate*  report                              │
                         └────┬────┘                                 │
                              ▼                                      │
                  error_node (fallback)                              │
                              ▼                                      │
                             END                                     │
  ───────────────────────────────────────────────────────────────────┘
         │                    │                │
         ▼                    ▼                ▼
  [ Ollama :11434 ]   [ PostgreSQL :5432 ]  [ Redis :6379 ]
  (internal only —    (knowledge base +    (dedup + cache +
   not host-exposed)   LangGraph ckpts)     rate limiting)

  [ node-exporter :9100 ] ──────────────────────────────┐
  (host PID+net namespace)                             │
  CPU/RAM/disk I/O/network/load                        │
                                                       │
  [ Prometheus :9090 ] ──alerts──► [ AlertManager :9093 ]
         │ scrape 4 targets:                │
         │  agent + node-exporter           ▼  POST /webhooks/alertmanager
         │  prometheus + alertmanager  [ FastAPI Agent :8000 ]
         ▼                                  │ auto-clean + Slack notify
  [ VictoriaMetrics :8428 ]                 ▼
         │                          [ Slack #security-channel ]
         ▼
  [ Grafana :3000 dashboards ]

  Artifacts: ./artifacts/ ──bind_mount──► /opt/devsecops/artifacts/
         ├── scans/{owner}-{repo}/pr-{n}/*.json   ← raw SAST outputs
         └── logs/agent.log.*                     ← structured JSON logs

  [ Open WebUI :3001 ] ──► Ollama :11434  ← direct model interaction UI

  Background Scheduler (asyncio tasks inside agent):
    ├── disk_guard   — every 30 min: update metrics, Slack alert at >80%/>90%
    └── health_digest — daily 09:00 UTC: full VPS health report to Slack

* escalate only runs when SLACK_ESCALATION_ENABLED=true
```

---

## 3. Container Inventory

| Container | Image | Ports | Status | Memory |
|-----------|-------|-------|--------|--------|
| `devsecops-agent` | `devsecops-agent:latest` | `8000` (host) | healthy | ~120 MB |
| `ollama` | `ollama/ollama:latest` | internal only | healthy | ~1.3 GB idle / ~10 GB with 14B loaded |
| `postgres` | `postgres:16-alpine` | internal only | healthy | ~33 MB |
| `redis` | `redis:7-alpine` | **`6379` (host ⚠️ no auth)** | healthy | ~5 MB |
| `nginx` | `nginx:alpine` | `80`, `443` | running | ~3 MB |
| `jenkins` | `devsecops-jenkins:latest` | `8080`, `50000` (host) | running | ~1 GB |
| `prometheus` | `prom/prometheus:latest` | **`9090` (host ⚠️ no auth)** | running | ~26 MB |
| `alertmanager` | `prom/alertmanager:latest` | **`9093` (host ⚠️ no auth)** | running | ~10 MB |
| `grafana` | `grafana/grafana:latest` | `3000` (host, has auth) | running | ~96 MB |
| `victoriametrics` | `victoriametrics/victoria-metrics:latest` | **`8428` (host ⚠️ no auth)** | running | ~97 MB |
| `open-webui` | `ghcr.io/open-webui/open-webui:main` | `3001` (host) | healthy | ~300 MB |
| `node-exporter` | `prom/node-exporter:latest` | `9100` (host network) | running | ~10 MB |

---

### 3.1 `devsecops-agent` — Core AI Orchestration Engine

**Built from:** `./agent/Dockerfile` (Python 3.12-slim)
**Port:** `8000` (host-exposed)
**Image size:** ~1.55 GB

The brain of the system. Receives GitHub webhooks, runs the LangGraph security workflow, calls Ollama LLMs, executes all security scanners, posts results back to GitHub, runs the autonomous background scheduler, handles AlertManager webhooks, and serves the interactive BTE Security AI Agent chat interface.

**Python runtime versions:**
| Library | Version |
|---------|---------|
| FastAPI | 0.135+ |
| LangGraph | 1.1+ |
| LangChain-Ollama | 0.3.x |
| httpx | 0.28.1 |
| structlog | 25.5+ |
| prometheus-client | 0.24+ |
| semgrep | 1.157+ |
| checkov | 3.2.517+ |
| psycopg3 | 3.3 (binary) |
| redis | 7.4 (hiredis) |

**Security tools baked into the image:**
| Tool | Version | Install method |
|------|---------|---------------|
| Trivy | 0.69+ | Official install script |
| Semgrep | 1.157+ | pip |
| Gitleaks | 8.30+ | GitHub Releases tar.gz |
| Checkov | 3.2.517+ | pip |
| OSV-Scanner | 2.3+ | GitHub Releases binary |
| Docker CLI | 29.4.0 | Docker apt repo |

**Volume mounts:**
| Host path | Container path | Purpose |
|-----------|---------------|---------|
| `./agent/app` | `/app/app` | Hot-reload of source code |
| `/var/run/docker.sock` | `/var/run/docker.sock` | Docker-in-Docker for container scanning |
| `agent_workspace` (named) | `/tmp/agent-workspace` | Ephemeral PR clone directory |
| `./artifacts` (bind) | `/opt/devsecops/artifacts` | Persistent SAST output + agent logs |

**Log rotation (docker json-file driver):**
```yaml
logging:
  driver: "json-file"
  options:
    max-size: "50m"
    max-file: "10"
```
Agent also writes structured JSON logs to `./artifacts/logs/agent.log` (rotating, 50 MB × 10 = 500 MB max).

**Registered routers:**
| Router | Module | Endpoints |
|--------|--------|-----------|
| Webhooks | `app.routers.webhooks` | `POST /webhooks/github`, `POST /webhooks/alertmanager` |
| Callbacks | `app.routers.callbacks` | `POST /callbacks/slack` |
| Health | `app.routers.health` | `GET /health`, `GET /metrics` |
| Chat | `app.routers.chat` | `GET /ui`, `GET /chat/models`, `POST /chat/stream` |

---

### 3.2 `ollama` — Local LLM Inference Server

**Image:** `ollama/ollama:latest`
**Port:** `11434` — **internal Docker network only** (not host-exposed, removed for security)
**Memory limit:** 42 GB

Serves local LLM models entirely on-premise — no code or diffs leave the VPS.

**Performance tuning (docker-compose.yml environment):**
| Variable | Value | Effect |
|----------|-------|--------|
| `OLLAMA_FLASH_ATTENTION` | `1` | Reduces KV cache from O(n²) to O(n) — critical at 16K context |
| `OLLAMA_KV_CACHE_TYPE` | `q8_0` | 8-bit KV cache: halves KV RAM (~650 MB saved at 16K ctx) |
| `OLLAMA_NUM_THREAD` | `12` | Pins all 12 Haswell cores; auto-selects `libggml-cpu-haswell.so` |
| `OLLAMA_MAX_LOADED_MODELS` | `1` | One model at a time — all RAM to active model |
| `OLLAMA_NUM_PARALLEL` | `1` | All 12 cores dedicated to single inference |
| `OLLAMA_KEEP_ALIVE` | `20m` | Keep model hot 20 min after last call |
| `shm_size` | `2gb` | Shared memory for thread sync buffers |
| `ulimits.nofile` | `65536` | Raised open file descriptor limit |

**Three-model pipeline assignment:**
| Model | Size | CPU speed (est.) | num_ctx | Pipeline role |
|-------|------|-----------------|---------|---------------|
| `qwen2.5-coder:7b` | 4.7 GB | ~8–12 tok/s | 4096 | `classify_node` — fast JSON classification |
| `qwen2.5-coder:14b` | 9.0 GB | ~3–6 tok/s | 12288 | `analyze_review_node` — security + quality (single call) |
| `qwen2.5-coder:32b` | 19 GB | ~1–2.5 tok/s | — | Available on disk — not in active pipeline |
| `mistral-nemo:12b` | 7.1 GB | ~4–7 tok/s | — | Available for Chat UI |

> **Why 14B for combined analysis:** On 12 CPU cores with no GPU, the 32B model takes 14–34 min for 2048 tokens. The 14B runs in 6–11 min with no quality degradation for code pattern recognition. Merging the two former 14B calls (analyze + code_review) into a single `analyze_review_node` cuts total pipeline time from ~13–23 min to ~6–11 min.

---

### 3.3 `postgres` — Knowledge Base + Workflow Checkpointing

**Image:** `postgres:16-alpine` | **Port:** `5432` (internal only)

Dual purpose:
1. Stores all security knowledge (reviews, scan results, repo profiles)
2. LangGraph workflow checkpointing — pipelines survive container restarts

**LangGraph checkpoint tables** (auto-created): `checkpoints`, `checkpoint_blobs`, `checkpoint_writes`, `checkpoint_migrations`

**Application tables** (see Section 10 for full schema):
`repo_profiles`, `scan_results`, `pr_reviews`, `sbom_cache`, `security_policies`, `incidents`

---

### 3.4 `redis` — Cache + Deduplication + Rate Limiting

**Image:** `redis:7-alpine` | **Memory cap:** 256 MB (`allkeys-lru`)
**⚠️ Security gap:** Port `6379` is bound to `0.0.0.0` (host interface) in docker-compose.yml — Redis has no authentication. Should be internal-only (remove `ports:` entry).

| Role | Key pattern | TTL |
|------|------------|-----|
| Webhook deduplication | `dedup:{repo}:{pr}:{sha}` | 1 hour |
| Rate limiting | `rate:{repo_full_name}` | per window |
| Scan result caching | `scan:{scanner}:{repo_path}` | 1 hour |

---

### 3.5 `nginx` — Reverse Proxy + API Gateway

**Image:** `nginx:alpine` | **Ports:** `80`, `443` | Config: `nginx/nginx.conf`

Full routing table in [Section 9](#9-nginx-reverse-proxy). Critical: `/chat/` has 1800s timeout for large model cold-start.

---

### 3.6 `prometheus` — Metrics Scraping + Alerting

**Image:** `prom/prometheus:latest` | **Port:** `9090`
Config: `prometheus/prometheus.yml` + `prometheus/alerts.rules.yml`
Retention: 30 days local + remote_write to VictoriaMetrics (90 days)

**Alert rules** (`prometheus/alerts.rules.yml`) — 12 active rules across 4 groups:

*Group: disk*
| Alert | Condition | For | Severity |
|-------|-----------|-----|----------|
| `DiskWarning` | `(size - free) / size > 0.80` (node-exporter filesystem) | 5m | warning |
| `DiskCritical` | `(size - free) / size > 0.90` (node-exporter filesystem) | 2m | critical |
| `AgentDiskWarning` | `agent_disk_used_percent > 80` (agent gauge, no node-exporter needed) | 5m | warning |
| `AgentDiskCritical` | `agent_disk_used_percent > 90` (agent gauge, no node-exporter needed) | 2m | critical |

*Group: host (node-exporter — NEW)*
| Alert | Condition | For | Severity |
|-------|-----------|-----|----------|
| `HostHighCPU` | `100 - avg(rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100 > 85` | 5m | warning |
| `HostHighMemory` | `(1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes) * 100 > 88` | 3m | critical |
| `HostDiskIOHigh` | `rate(node_disk_io_time_seconds_total[5m]) > 0.9` | 5m | warning |

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

> **Dual disk coverage:** `DiskWarning/DiskCritical` use node-exporter filesystem metrics; `AgentDiskWarning/AgentDiskCritical` use the agent's own gauge — both fire independently. `HostHighMemory` (critical at 88%) is the most important host alert: at 45 GB total RAM, an OOM kill of the Ollama process would terminate an in-progress PR review. `OllamaDown` uses `ollama_reachable` Gauge so idle Ollama (no model loaded, fully normal between reviews) never triggers it.

---

### 3.7 `alertmanager` — Alert Routing + Deduplication

**Image:** `prom/alertmanager:latest` | **Port:** `9093`
Config: `alertmanager/alertmanager.yml`

Routes Prometheus alerts to the agent's `/webhooks/alertmanager` endpoint, which:
- Sends Slack Block Kit notifications (🔴 critical / 🟡 warning / 🔵 resolved)
- Auto-runs `docker builder prune -f` on `DiskCritical` alerts
- Groups by `alertname` with inhibition rules (critical suppresses warning for same alert)

Repeat intervals: critical alerts repeat every 1h, warning/info every 24h.

---

### 3.8 `grafana` — Dashboards

**Image:** `grafana/grafana:latest` | **Port:** `3000` | Path: `/grafana/`

**Provisioned datasources** (`grafana/provisioning/datasources/`):
| Name | Type | URL | Default |
|------|------|-----|---------|
| `Prometheus` | prometheus | `http://prometheus:9090/prometheus` | ✅ |
| `VictoriaMetrics` | prometheus | `http://victoriametrics:8428` | — |
| `PostgreSQL` | postgres | `postgres:5432` | — |

**Provisioned dashboards** (`grafana/provisioning/dashboards/`):
| File | Dashboard | Datasource | Sections |
|------|-----------|-----------|---------|
| `vps_host.json` | **VPS Host Monitoring** (NEW) | Prometheus | CPU %, RAM %, Disk %, Load, Uptime stats · CPU & IO Wait time series · Memory breakdown · Load averages · Network I/O · Disk I/O |
| `devsecops_agent.json` | **DevSecOps AI Agent** (updated) | Prometheus | VPS Health row · PR Pipeline row · Chat Ops Activity row · Ollama LLM row · Network & Disk I/O row |
| `pr_reviews.json` | **PR Security Reviews** | PostgreSQL | Review volume · Risk distribution · Verdict breakdown · Pipeline duration · Recent PRs table |

**Dashboard URLs:**
| Dashboard | URL |
|-----------|-----|
| VPS Host Monitoring | `http://141.94.92.226/grafana/d/vps-host-monitoring/` |
| DevSecOps AI Agent | `http://141.94.92.226/grafana/d/devsecops-agent/` |
| PR Security Reviews | `http://141.94.92.226/grafana/d/pr-reviews-01/` |

---

### 3.9 `victoriametrics` — Long-term Metrics Storage

**Image:** `victoriametrics/victoria-metrics:latest` | **Port:** `8428` (host-exposed, no auth)
Retention: 90 days. Receives remote_write from Prometheus.

> **Crash incident (2026-04-19 → 2026-04-28):** VictoriaMetrics panicked when disk hit 0 bytes free (`FATAL: cannot create directory: no space left on device`). Exited with code 2 and was not restarted automatically (disk was still full when Docker tried to restart it). After disk was cleaned (233 GB freed on 2026-04-20), the container remained `exited` and was missed during recovery. It was down for 9 days before being detected by this audit. Restarted 2026-04-28 — 10.9M stored rows recovered from storage volume intact. **Prevention:** lower disk alert threshold to 70% and ensure VictoriaMetrics uses `restart: always` policy.

---

### 3.10 `jenkins` — CI/CD

**Image:** Built from `./jenkins/Dockerfile` (Jenkins LTS JDK17)
**Ports:** `8080` (UI), `50000` (agent) | Path: `/jenkins/`
Plugins: `git`, `docker-workflow`, `github`, `blueocean`, `slack`.

---

### 3.11 `open-webui` — Ollama Web Interface

**Image:** `ghcr.io/open-webui/open-webui:main` | **Port:** `3001`
Connects directly to `http://ollama:11434`. Allows direct interactive model access without the PR pipeline. Sign-up enabled for first admin account creation.

---

### 3.12 `node-exporter` — Host Metrics Exporter

**Image:** `prom/node-exporter:latest` | **Port:** `9100` (host network)

Runs with `pid: host` and `network_mode: host` — it is the only container that operates outside the Docker bridge network. This gives it full visibility into the **real host OS**: all processes, all network interfaces, all disk I/O, not just the container's namespaced view.

**What it exposes (~1000+ metrics):**
| Metric family | Examples |
|--------------|---------|
| CPU | Per-core usage %, idle time, iowait, steal |
| Memory | Available/total/cached/buffered bytes, swap usage |
| Disk I/O | Read/write bytes/s per device, I/O utilization % |
| Filesystem | Free/used bytes per mountpoint |
| Network | RX/TX bytes/s per interface, errors, drops |
| System | Load averages (1/5/15m), boot time, open file descriptors |
| OS | Kernel version (`node_uname_info`) |

**Access from Prometheus:** node-exporter runs on the host at `0.0.0.0:9100`. Prometheus reaches it via the Docker bridge gateway `172.20.0.1:9100`. An `iptables` rule allows this: `-A INPUT -s 172.20.0.0/16 -p tcp --dport 9100 -j ACCEPT` (persisted via `iptables-persistent`).

**Chat agent integration:** The system prompt includes ready-to-use PromQL patterns for common host queries. The existing `query_prometheus` tool can query any node-exporter metric.

```
# Ask the chat agent:
"What is the current CPU usage?"
→ query_prometheus: 100 - (avg(rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)

"How much RAM is free on the VPS?"
→ query_prometheus: node_memory_MemAvailable_bytes / 1024 / 1024 / 1024

"Is the disk I/O high?"
→ query_prometheus: rate(node_disk_io_time_seconds_total[5m])
```

---

## 4. Docker Images & Models

| Image | Size | Notes |
|-------|------|-------|
| `devsecops-agent:latest` | ~1.55 GB | Python 3.12 + all scanners + Docker CLI |
| `devsecops-jenkins:latest` | ~1.59 GB | Jenkins LTS + plugins |
| `ollama/ollama:latest` | ~9.89 GB | LLM inference server |
| `grafana/grafana:latest` | ~1.01 GB | — |
| `prom/prometheus:latest` | ~578 MB | — |
| `prom/alertmanager:latest` | ~150 MB | — |
| `postgres:16-alpine` | ~395 MB | — |
| `nginx:alpine` | ~93 MB | — |
| `victoriametrics/victoria-metrics:latest` | ~53 MB | — |
| `redis:7-alpine` | ~61 MB | — |
| `ghcr.io/open-webui/open-webui:main` | ~1.2 GB | — |
| `prom/node-exporter:latest` | ~25 MB | Host metrics — CPU/RAM/disk/network |

**Ollama model data (benchmarked on 12-core Haswell CPU-only):**
| Model | Size | Speed (warm) | Tool Accuracy | Role | UI Tag |
|-------|------|-------------|---------------|------|--------|
| `qwen2.5-coder:7b` | 4.7 GB | ~5 tok/s | **80%** | `classify_node` + **chat default** | ✅ Recommended |
| `qwen2.5-coder:14b` | 9.0 GB | ~3.2 tok/s | 80% | `analyze_review_node` (security + quality) | Deep analysis |
| `llama3.2:3b` | 2.0 GB | ~8 tok/s | 0% (full prompt) | Chat — experimental only | ❌ Experimental |
| `granite3.1-dense:2b` | 1.6 GB | ~8.5 tok/s | 0% | Chat — incompatible format | ❌ Incompatible |

> **Benchmark findings:** `llama3.2:3b` is the fastest but collapses under the full 7,577-char system prompt — its 4096-token context saturates leaving no room for reasoning. `granite3.1-dense:2b` uses IBM's proprietary tool-call schema, incompatible with our `{"name":…,"arguments":…}` format. `qwen2.5-coder:7b` is the confirmed best balance: same accuracy as 14b (80%), 43% faster, 100% correct args format.

---

## 5. Agent Codebase Structure

```
agent/
├── Dockerfile
├── requirements.txt
└── app/
    ├── main.py                      # FastAPI app, lifespan, structlog (console+file), Ollama poller,
    │                                # scheduler startup
    ├── config.py                    # Pydantic settings (env vars incl. artifacts_path)
    ├── engine/
    │   ├── checkpointer.py          # AsyncPostgresSaver init/close
    │   ├── dispatcher.py            # Routes webhook events to workflows
    │   └── registry.py             # Registers all LangGraph workflow graphs
    ├── llm/
    │   └── ollama.py               # get_fast_llm() (7b, 4096 ctx)
    │                               # get_deep_llm() (14b, 8192 ctx)
    │                               # get_review_llm() (14b, 8192 ctx, format=json)
    │                               # get_combined_llm() (14b, 12288 ctx) ← NEW
    │                               # + circuit breaker + check_ollama_health()
    ├── metrics/
    │   └── custom.py               # Custom Prometheus counters/histograms/gauges
    │                               # incl. agent_disk_used_percent, agent_disk_free_gb ← NEW
    ├── models/
    │   ├── db.py
    │   ├── github_webhooks.py      # PullRequestWebhookPayload.to_initial_state()
    │   │                           # now includes base_branch field ← UPDATED
    │   └── state.py
    ├── prompts/
    │   ├── classifier.py           # Fast 7B classification prompt
    │   ├── security_review.py      # Deep 14B security analysis prompt (OWASP Top 10)
    │   ├── code_review.py          # Code quality prompt → {summary, comments[]}
    │   ├── combined_review.py      # Combined security+quality prompt for single LLM call ← NEW
    │   └── templates.py            # SAST output formatters — Checkov guideline removed,
    │                               # Semgrep INFO collapsed to count only ← UPDATED
    ├── routers/
    │   ├── webhooks.py             # POST /webhooks/github
    │   │                           # POST /webhooks/alertmanager ← NEW
    │   ├── callbacks.py            # POST /callbacks/slack — LangGraph resume
    │   ├── health.py               # GET /health, GET /metrics
    │   └── chat.py                 # BTE Security AI Agent chat — ReAct loop + SSE streaming
    │                               # num_ctx=16384 for 16K context window ← UPDATED
    ├── services/
    │   ├── artifact_store.py       # Saves raw SAST JSONs per PR + final summary
    │   ├── cache.py                # Redis: init/close, dedup, rate limit, scan cache
    │   ├── checkov_service.py      # Checkov subprocess + parser
    │   ├── diff_parser.py          # Unified diff parser — line number mapping
    │   ├── docker_service.py       # build_image(), remove_image(), check_dockerfile()
    │   ├── git_service.py          # clone_repo(), get_local_diff() ← NEW (-U15)
    │   │                           # get_pr_diff() (fallback), truncate_diff()
    │   ├── github_api.py           # post_pr_comment, set_commit_status, post_pr_review
    │   ├── gitleaks_service.py     # Gitleaks subprocess + parser (Match field omitted)
    │   ├── knowledge.py            # PostgreSQL pool: get_repo_history, save_pr_review, etc.
    │   ├── osv_service.py          # OSV-Scanner subprocess + parser
    │   ├── scheduler.py            # Autonomous background scheduler ← NEW
    │   │                           # disk_guard (30 min) + health_digest (09:00 UTC daily)
    │   ├── semgrep_service.py      # Semgrep subprocess — pinned to p/security-audit
    │   │                           # + p/owasp-top-ten ← UPDATED (was --config auto)
    │   ├── slack_api.py            # send_notification(), request_approval()
    │   └── trivy_service.py        # Trivy subprocess + parser
    ├── static/
    │   └── index.html              # BTE Security AI Agent chat UI
    └── workflows/
        ├── pr_review/
        │   ├── graph.py            # LangGraph StateGraph — 9 nodes (was 10)
        │   │                       # analyze_review replaces analyze + code_review ← UPDATED
        │   ├── nodes.py            # analyze_review_node() — combined single LLM call ← NEW
        │   │                       # analyze_node(), code_review_node() — kept for reference
        │   ├── edges.py            # route_scans(), route_risk()
        │   └── state.py            # PRReviewState — added base_branch field ← UPDATED
        └── ops_assistant/
            ├── graph.py            # BTE system prompt (7,577 chars / ~1,894 tokens) + TOOL_MAP (20 tools)
            └── tools.py            # 20 infrastructure monitoring tools (read-only)
                                    # includes query_prometheus_range() for trend/history queries
```

---

## 6. LangGraph Workflow — Node Reference

### Graph Topology

```
START
  │
  ▼
intake_node
  │  Redis dedup + rate limit, clone repo, local git diff -U15, get history
  ▼
classify_node           ← LLM call #1: 7B fast, JSON-forced, num_ctx=4096
  │  circuit breaker fallback → _fallback_classify() (regex)
  ▼
route_scans()
  ├── "docs"        ──► skip_scan_node
  ├── has_dockerfile ──► scan_full_node    (build + full scanner suite)
  └── default       ──► scan_fs_node      (filesystem scanner suite)
         │
         └─── (all branches converge)
                │
                ▼
          [parallel asyncio.gather()]
          Trivy FS + Gitleaks + Semgrep|Checkov|OSV (by matrix)
          + save raw JSON to ./artifacts/
                │
                ▼
          analyze_review_node    ← LLM call #2: 14B combined, num_ctx=12288
                │  single call for:
                │  • full security review (OWASP, risk_score, verdict)
                │  • code quality review (summary + inline comments JSON)
                │  posts GitHub PR Review with inline suggestion blocks
                │  saves to PostgreSQL
                ▼
          route_risk()
                ├── CRITICAL|HIGH ──► escalate_node  (PAUSED — Slack gate)
                │                         │
                │                 POST /callbacks/slack resumes
                │                         │
                └── MEDIUM|LOW|INFO ──► report_node
                                           │  PR comment, commit status, Slack notify
                                           │  saves summary.json to ./artifacts/
                                           ▼
                                          END

  Any node sets state["error"] ──► error_node ──► END
```

### `intake_node`

```python
async def intake_node(state: PRReviewState) -> dict:
```

1. Redis dedup: `SET NX dedup:{repo}:{pr}:{sha}` — returns early if duplicate
2. Rate limit: max 3 concurrent pipelines per repo
3. Posts `"Security review in progress..."` placeholder comment to PR
4. Clones PR branch: `git clone --depth 1 --branch {head_branch} {url}`
5. Fetches diff using **local git diff** — `git fetch --depth=1 origin {base_branch}` then `git diff -U15 FETCH_HEAD..HEAD` (15 lines of context vs GitHub API's fixed -U3). Falls back to GitHub API diff on fetch failure.
6. `git_service.truncate_diff()` — caps at 30,000 chars
7. Detects Dockerfile: `check_dockerfile(repo_path)`
8. Extracts changed files from diff headers
9. `knowledge.get_repo_history()` — last 10 PR reviews for context injection

### `classify_node`

Calls `get_fast_llm()` (7B, `format="json"`, `num_predict=512`, `num_ctx=4096`, `temperature=0.0`).

Output: `{"classification": "feature|dependency|infrastructure|docs|config", "risk_hint": "..."}`
Fallback: `_fallback_classify()` — regex on file extensions and names.

### `scan_full_node` / `scan_fs_node` / `skip_scan_node`

Central scan runner (`_run_scan()`) with Redis caching, Prometheus timing, and error isolation. All applicable scanners run concurrently via `asyncio.gather()`. Raw outputs saved to `./artifacts/scans/{repo}/pr-{n}/{scanner}.json`.

**Semgrep uses pinned rulesets** (changed from non-deterministic `--config auto`):
```bash
semgrep scan --config p/security-audit --config p/owasp-top-ten --json --quiet
```

### `analyze_review_node` ← **Replaces `analyze_node` + `code_review_node`**

```python
async def analyze_review_node(state: PRReviewState) -> dict:
```

Single 14B call using `get_combined_llm()` (`num_ctx=12288`, `num_predict=2500`, `temperature=0.1`).

**Input to the LLM:**
- PR metadata + repository history
- Full diff (plain, for security review)
- Annotated diff with line numbers (for inline comment line validation)
- All scanner output (Trivy, Semgrep, Gitleaks, Checkov, OSV) — SAST-cleaned
- Combined review prompt (from `prompts/combined_review.py`)

**Output parsing:**
- Security review markdown extracted as everything before the final JSON block
- JSON block at end: `{"risk_score": "...", "verdict": "...", "code_review_summary": "...", "comments": [...]}`
- Every comment line validated against the actual diff (hallucinated lines dropped)
- Posts formal GitHub PR Review with inline `suggestion` blocks
- Saves to PostgreSQL knowledge base

**Circuit breaker fallback:** On LLM unavailability, produces a scan-only degraded review with risk score derived from scanner counts — no inline comments posted.

### `escalate_node`

Only runs when `SLACK_ESCALATION_ENABLED=true`. Posts Slack Block Kit message with Approve/Reject buttons. Graph checkpoints to PostgreSQL and **pauses** until `POST /callbacks/slack` resumes it.

### `report_node`

1. Formats final PR comment: security review + code quality summary + inline comment count
2. `github_api.post_pr_comment()` — updates placeholder
3. `github_api.set_commit_status()` — `success` (APPROVE) or `failure` (REQUEST_CHANGES/BLOCK)
4. `slack_api.send_notification()` — summary to security channel
5. `artifact_store.save_pr_summary()` — saves `summary.json`
6. `docker_service.remove_image()` + `shutil.rmtree(repo_path)` — cleanup
7. `cache.release_rate_limit()` — decrements concurrent counter
8. Emits `agent_reviews_total`, `agent_pipeline_duration_seconds`

### `error_node`

Posts failure comment to PR, sends Slack error notification, increments `agent_errors_total{stage=...}`, releases Redis rate limit.

---

## 7. Scan Matrix

| Classification | Trivy FS | Gitleaks | Semgrep | Checkov | OSV-Scanner |
|----------------|----------|----------|---------|---------|-------------|
| `feature` | ✅ | ✅ | ✅ | — | — |
| `dependency` | ✅ | ✅ | — | — | ✅ |
| `infrastructure` | ✅ | ✅ | — | ✅ | — |
| `config` | ✅ | ✅ | — | — | — |
| `docs` | — | — | — | — | — |

When a Dockerfile is detected → `scan_full_node`: Docker image is built and Trivy also scans the container image.

**SAST token cleaning applied before LLM input:**
| Section | Before | After | Reduction |
|---------|--------|-------|-----------|
| Trivy (30 vulns) | ~6,000 chars | ~2,500 chars | ~58% |
| Gitleaks (Match field omitted) | ~400 chars | ~200 chars | 50% |
| Semgrep (INFO collapsed to count) | ~2,000 chars | ~1,200 chars | 40% |
| Checkov (guideline URL removed) | ~1,500 chars | ~800 chars | 47% |
| **Total SAST** | **~9,900 chars** | **~4,700 chars** | **~52%** |

---

## 8. Configuration Reference

### `.env` file

| Variable | Value | Description |
|----------|-------|-------------|
| `GITHUB_TOKEN` | `github_pat_...` | PAT for PR comments, commit statuses, diff fetch |
| `GITHUB_WEBHOOK_SECRET` | `2f015f4b...` | HMAC-SHA256 secret shared with GitHub webhook |
| `OLLAMA_BASE_URL` | `http://ollama:11434` | Ollama internal URL |
| `OLLAMA_MODEL_FAST` | `qwen2.5-coder:7b` | classify_node |
| `OLLAMA_MODEL_DEEP` | `qwen2.5-coder:14b` | analyze_review_node (security portion) |
| `OLLAMA_MODEL_REVIEW` | `qwen2.5-coder:14b` | kept for reference (merged into combined) |
| `OLLAMA_TIMEOUT` | `900` | max seconds per LLM call (15 min) |
| `SLACK_BOT_TOKEN` | `xoxb-...` | Slack bot token |
| `SLACK_CHANNEL_ID` | `C0ARJD4H1K5` | Security channel for notifications |
| `SLACK_SIGNING_SECRET` | `fac8cfd3...` | Slack request signing |
| `SLACK_ESCALATION_ENABLED` | `false` | Set `true` to enable Slack approval gate |
| `POSTGRES_HOST` | `postgres` | — |
| `POSTGRES_PORT` | `5432` | — |
| `POSTGRES_USER` | `devsecops` | — |
| `POSTGRES_PASSWORD` | `CHANGE_ME_STRONG_PASSWORD` | **⚠ Change in production** |
| `POSTGRES_DB` | `devsecops_db` | — |
| `REDIS_URL` | `redis://redis:6379/0` | — |
| `GRAFANA_PASSWORD` | `CHANGE_ME_GRAFANA_ADMIN` | **⚠ Change in production** |
| `WEBUI_SECRET_KEY` | `323a02...` | Open WebUI JWT secret |
| `AGENT_LOG_LEVEL` | `INFO` | — |
| `AGENT_WORKSPACE` | `/tmp/agent-workspace` | PR clone directory |
| `TRIVY_SEVERITY` | `CRITICAL,HIGH,MEDIUM` | Scanner threshold |
| `JENKINS_URL` | `http://jenkins:8080` | — |
| `JENKINS_USER` | `admin` | — |
| `JENKINS_API_TOKEN` | _(empty)_ | Set for `jenkins_status` tool |

### `docker-compose.yml` highlights

- **Ollama** port `11434` removed from host — internal Docker network only (security hardening)
- **Ollama** memory limit `42g`, `shm_size: 2gb`, 6 performance env vars, file descriptor ulimits
- **Agent** mounts `./artifacts` as bind mount → persists SAST outputs and logs to host
- **Agent** uses `json-file` log driver with 50 MB × 10 rotation
- **AlertManager** service added (`prom/alertmanager:latest`, port `9093`)
- **Prometheus** mounts `alerts.rules.yml`, depends_on `alertmanager`
- **Grafana** receives `POSTGRES_*` env vars for PostgreSQL datasource provisioning
- **Open WebUI** added (`ghcr.io/open-webui/open-webui:main`, port `3001:8080`)
- **VictoriaMetrics** retains metrics for 90 days
- **Prometheus** uses `--web.route-prefix=/prometheus/` — all API paths prefixed

**⚠️ Known port exposure issues (not yet fixed in docker-compose.yml):**

| Service | Current | Should be |
|---------|---------|-----------|
| `redis` | `"6379:6379"` — host-exposed, no auth | Remove `ports:` entry — internal only |
| `prometheus` | `"9090:9090"` — host-exposed, no auth | Remove `ports:` — access via nginx `/prometheus/` |
| `alertmanager` | `"9093:9093"` — host-exposed, no auth | Remove `ports:` — access via nginx or internal |
| `victoriametrics` | `"8428:8428"` — host-exposed, no auth | Remove `ports:` — Prometheus writes internally |
| `grafana` | `"3000:3000"` — host-exposed (has auth) | Optional: remove, access only via nginx `/grafana/` |

---

## 9. Nginx Reverse Proxy

Config: `nginx/nginx.conf`

| Location | Upstream | Timeout | Auth | Notes |
|----------|---------|---------|------|-------|
| `GET /` | redirect → `/ui` | — | — | Root redirect added 2026-04-28 |
| `GET /ui` | `devsecops-agent:8000/ui` | default | **Basic Auth** | Password-protected — credentials in `/etc/nginx/.htpasswd` |
| `GET/POST /chat/` | `devsecops-agent:8000/chat/` | **1800s** | **Basic Auth** | SSE stream — no buffering; same credentials as `/ui` |
| `POST /webhooks/github` | `devsecops-agent:8000` | 30s | HMAC | GitHub signature validated by agent |
| `POST /callbacks/slack` | `devsecops-agent:8000` | 10s | — | Approval gate callback |
| `/api/` | `devsecops-agent:8000/` | 600s | — | General API (strips `/api/` prefix) |
| `/health` | `devsecops-agent:8000` | default | — | Health passthrough |
| `/grafana/` | `grafana:3000` | default | Grafana auth | WebSocket headers forwarded (Upgrade/Connection) |
| `/prometheus/` | `prometheus:9090` | default | — | No rewrite — full path forwarded |
| `/jenkins/` | `jenkins:8080/` | default | Jenkins auth | Strips `/jenkins/` prefix |

**Chat UI credentials:** User: `bte` · Password stored as bcrypt hash in `./nginx/.htpasswd` (bind-mounted into container). To change: `docker exec nginx htpasswd -bB /etc/nginx/.htpasswd bte NEW_PASSWORD`

**Upstreams defined:** `agent`, `jenkins`, `grafana`, `prometheus`

**Port 443:** Exposed in docker-compose but nginx has no SSL certificate configured. Stub server block returns 444 (silent close). HTTPS not functional — requires Let's Encrypt or self-signed cert.

**Note:** AlertManager sends webhooks directly to `devsecops-agent:8000` via Docker network — bypasses nginx. No nginx location needed.

**nginx audit (2026-04-28):** (1) Added `GET /` → `/ui` redirect · (2) Added WebSocket headers to `/grafana/` (live dashboards were silently broken) · (3) Removed unused `open-webui` upstream · (4) Added stub 443 server block · (5) Added HTTP Basic Auth on `/ui` and `/chat/` · (6) Added `.htpasswd` volume mount to docker-compose. Container restart required to pick up new bind-mount inode.

---

## 10. Database Schema

### `pr_reviews`
| Column | Type | Description |
|--------|------|-------------|
| `id` | serial PK | — |
| `repo_full_name` | text | `owner/repo` |
| `pr_number` | integer | — |
| `pr_title` | text | — |
| `pr_author` | text | GitHub username |
| `classification` | text | `feature` / `infrastructure` / etc. |
| `risk_score` | text | `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` |
| `verdict` | text | `APPROVE` / `REQUEST_CHANGES` / `BLOCK` |
| `review_markdown` | text | Full LLM security review |
| `scan_summary` | jsonb | Structured scanner findings |
| `files_changed` | jsonb | List of changed files |
| `approval_status` | text | `auto` / `pending` / `approved` / `rejected` |
| `duration_ms` | integer | Total pipeline duration |
| `created_at` | timestamptz | — |

### `scan_results`
| Column | Type | Description |
|--------|------|-------------|
| `id` | serial PK | — |
| `repo_full_name` | text | — |
| `scan_type` | text | Scanner name |
| `trigger_type` | text | `pr_review` / `manual` |
| `trigger_ref` | text | Branch or PR ref |
| `summary` | jsonb | `{"CRITICAL": 2, "HIGH": 5, ...}` |
| `raw_output` | jsonb | Full scanner output |
| `created_at` | timestamptz | — |

### `repo_profiles`
Rolling risk score average and total review count per repo. Updated after every `analyze_review_node` run.

### `security_policies`
Three default policies seeded at startup:
- `block_critical_vulns` — max 0 critical, max 5 high CVEs
- `require_secret_scan` — block on any Gitleaks finding
- `base_image_age` — base images must be < 90 days old

---

## 11. Observability Stack

```
node-exporter:9100 (host)           devsecops-agent:8000/metrics
  CPU/RAM/disk I/O/network               agent + Ollama metrics
         │                                       │
         └──────────────┬────────────────────────┘
                        ▼ scrape every 15s (4 targets)
               prom/prometheus:9090
                        │
                        ├──► TSDB (30d local retention)
                        ├──► remote_write ──► victoriametrics:8428 (90d)
                        │                              │
                        │                              ▼
                        │           grafana (Prometheus + VictoriaMetrics + PostgreSQL)
                        │
                        └──► alertmanager:9093
                                    │
                                    ▼ POST /webhooks/alertmanager
                             devsecops-agent:8000
                                    │
                                    ├── Slack Block Kit alert (🔴/🟡/🔵)
                                    └── docker builder prune -f (on DiskCritical)
```

### Custom Prometheus Metrics

All metrics are exposed by the agent at `/metrics` and scraped by Prometheus. Ollama metrics are re-exported by the agent — no direct Ollama scrape job needed.

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

### Prometheus Scrape Configuration

Four active scrape jobs — all targets `up`:

| Job | Target | Metrics path | Purpose |
|-----|--------|-------------|---------|
| `devsecops-agent` | `devsecops-agent:8000` | `/metrics` | All agent + Ollama re-exported metrics |
| `node-exporter` | `172.20.0.1:9100` | `/metrics` | Full host metrics (CPU/RAM/disk/network) |
| `prometheus` | `localhost:9090` | `/prometheus/metrics` | Prometheus self-metrics (route prefix!) |
| `alertmanager` | `alertmanager:9093` | `/alertmanager/metrics` | AlertManager self-metrics (route prefix!) |

> **Route prefix gotcha:** Prometheus runs with `--web.route-prefix=/prometheus/` and AlertManager with `--web.route-prefix=/alertmanager/`. Both services prefix ALL their HTTP paths including `/metrics`. Scrape configs must set `metrics_path` accordingly.

> **node-exporter network path:** node-exporter uses `network_mode: host` so it's not on the Docker bridge. Prometheus reaches it via the Docker bridge gateway IP (`172.20.0.1:9100`). An `iptables` rule allows this traffic: `-A INPUT -s 172.20.0.0/16 -p tcp --dport 9100 -j ACCEPT` (persisted in `/etc/iptables/rules.v4`).

### Access URLs

| Service | URL |
|---------|-----|
| BTE Security AI Agent Chat | `http://141.94.92.226/ui` |
| Open WebUI (direct Ollama access) | `http://141.94.92.226:3001` |
| Grafana — Agent dashboard | `http://141.94.92.226/grafana/d/devsecops-agent` |
| Grafana — PR Reviews dashboard | `http://141.94.92.226/grafana/d/pr-reviews-01` |
| Prometheus UI | `http://141.94.92.226/prometheus/` |
| AlertManager UI | `http://141.94.92.226:9093` |
| Agent health | `http://141.94.92.226/health` |
| Jenkins | `http://141.94.92.226/jenkins/` |

---

## 12. Autonomous Operations

The agent runs two autonomous background tasks (asyncio, started at lifespan):

### Disk Guard (every 30 minutes)

```
_disk_guard_loop() → _check_disk()
    ├── Updates agent_disk_used_percent + agent_disk_free_gb Prometheus gauges
    ├── pct >= 90% → log warning + _prune_build_cache() + Slack 🔴 alert
    └── pct >= 80% → log warning + Slack 🟡 alert
```

`_prune_build_cache()`: runs `docker builder prune -f` (recoverable, no running containers affected). Returns human-readable result to Slack.

### Daily Health Digest (09:00 UTC every day)

Posts a comprehensive Slack Block Kit digest including:
- Disk usage (% used, GB free) with 🟢/🟡/🔴 icon
- All container states (`docker ps` output)
- Ollama status (model loaded or idle)
- Active Prometheus firing alerts

### AlertManager Webhook (`POST /webhooks/alertmanager`)

Receives Prometheus alert payloads from AlertManager. For each alert group:
- Separates `firing` vs `resolved` alerts
- On `DiskCritical` firing: auto-runs `docker builder prune -f`
- Posts Slack Block Kit with alert name, severity, description, labels
- Resolved alerts show 🔵 resolution notification

---

## 13. Chat Ops Assistant UI — BTE Security AI Agent

### Identity

The chat interface at `http://141.94.92.226/ui` is the **BTE Security AI Agent** — an AI-powered security and infrastructure operations assistant. When asked who it is, it responds:

> *"BTE Security AI Agent — your DevSecOps operations assistant."*

Tone: professional, security-first, data-driven. Complex reports end with a **"BTE Agent Assessment"** conclusion block.

### ReAct Loop Architecture

`qwen2.5-coder` models output tool calls as plain text JSON. The custom ReAct loop in `app/routers/chat.py`:
1. Streams LLM response token-by-token
2. Buffers tokens and detects tool-call shape
3. Parses JSON using a 4-pass extractor
4. Invokes tool via `asyncio.run_in_executor`
5. Injects result as `[OBSERVATION: tool_name]...[/OBSERVATION]` + verbatim directive
6. Loops back (max 8 tool calls per response)

**Chat LLM configuration (Sprint 7 — anti-hallucination tuned):**
| Parameter | Value | Reason |
|-----------|-------|--------|
| Default model | `qwen2.5-coder:7b` | Benchmarked: 80% tool accuracy, 100% args format, ~5 tok/s warm |
| `num_ctx` | `6144` (7b/14b) / `16384` (32b) | Prompt ~2,047 tokens → 4,100 tokens free. More context = less forgetting = fewer hallucinations |
| `num_predict` | `800` | Room for complete multi-container/metric answers. Cut-off answers caused model to fill the rest from training memory |
| `temperature` | `0.0` | Fully deterministic — eliminates creative "filling in" of metric values |
| `keep_alive` | `10m` | Model stays warm — subsequent questions get first token in ~2s |

**Anti-hallucination design (Sprint 7):**
- **No-tool guard (code-level):** If step 0 produces a final answer without any tool call AND the question contains live-data keywords (cpu, disk, container, alerts, logs, status, current, now, etc.) → blocked, model forced to call a tool first
- **Strengthened observation injection:** After every tool result: `"Every number, percentage, status, name, and timestamp MUST appear verbatim in an [OBSERVATION] block. NEVER invent values."`
- **ANTI-HALLUCINATION system prompt block:** 5 hard rules — (1) never answer from training data (2) live-state questions always require a tool (3) only quote values from observations (4) "approximately/typically" forbidden for live metrics (5) if you answered without a tool, stop and call one
- **temperature=0.0:** Deterministic token selection — no probabilistic "creative" values

**Tool result caching** — 14 tools, per-tool TTLs (10–120s). Cache key: `tool_name:sorted_args_json`. Repeated calls within TTL return instantly.

**Anti-loop dedup guard** — tracks `{tool}:{args}` per response. Repeated call → blocked, hard-stop injected.

> **Why Open WebUI feels faster:** Open WebUI calls Ollama directly (1 generation per message). The chat agent runs 2–3 generations per response (tool detection + execution + synthesis).

### 20 Monitoring Tools + node-exporter via Prometheus

**VPS / Host (5):** `vps_status`, `disk_usage`, `top_processes`, `network_stats`, `system_net_io`

**Full host metrics via `query_prometheus`** — node-exporter exposes 1000+ host metrics:
- CPU: `100 - (avg(rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)`
- RAM: `(1 - node_memory_MemAvailable_bytes/node_memory_MemTotal_bytes) * 100`
- Disk I/O: `rate(node_disk_io_time_seconds_total[5m])`
- Network: `rate(node_network_receive_bytes_total{device!="lo"}[5m])`

**Docker (6):** `list_containers`, `container_logs`, `container_stats`, `inspect_container`, `list_images`, `restart_service`

**Ollama / LLM (1):** `ollama_status`

**Prometheus / Alerting (3):** `query_prometheus`, `query_prometheus_range`, `prometheus_alerts`

> `query_prometheus_range(promql, duration, step)` — range query returning min/max/avg/latest + trend sparkline. Use for *"has CPU been high recently?"* or *"show RAM trend over 6 hours"* — the instant `query_prometheus` cannot answer these.

**Redis (1):** `redis_info`

**Jenkins (1):** `jenkins_status`

**Scan Artifacts (2):** `list_scan_artifacts`, `read_scan_artifact`

**Database (1):** `query_database` (read-only SELECT, up to 50 rows)

### SSE Event Protocol

| Event | Fields | Description |
|-------|--------|-------------|
| `status` | `content` | First event — "Loading model…" during cold-start |
| `thinking_start` | `step` | Model is building a tool call |
| `thinking_token` | `content` | Raw token in tool call JSON |
| `thinking_end` | — | Tool call JSON complete |
| `tool_start` | `name`, `args`, `step` | Tool about to be invoked |
| `tool_end` | `name`, `content` | Tool result returned |
| `token` | `content` | Final answer text token |
| `replace_text` | `content` | Flush pre-call explanatory text |
| `error` | `content` | Exception message |
| `done` | — | Stream complete |

---

## 14. Artifacts Volume

```
./artifacts/                              ← bind mount on host, always accessible
├── scans/
│   └── {owner}-{repo}/
│       └── pr-{number}/
│           ├── trivy_image.json          ← full raw Trivy image scan output
│           ├── trivy_fs.json             ← full raw Trivy filesystem output
│           ├── gitleaks.json             ← full raw Gitleaks findings
│           ├── semgrep.json              ← full raw Semgrep SAST output
│           ├── checkov.json              ← full raw Checkov IaC output
│           ├── osv.json                  ← full raw OSV-Scanner output
│           └── summary.json             ← final verdict, risk, files, duration
└── logs/
    ├── agent.log                         ← structured JSON lines (rotating)
    ├── agent.log.1
    └── ...                               ← up to 10 × 50 MB = 500 MB max
```

---

## 15. Known Bugs & Fixes

| Bug | Root cause | Fix applied |
|-----|-----------|-------------|
| `ModuleNotFoundError: langgraph.graph.graph` | Import path changed in LangGraph 1.x | Changed to `from langgraph.graph.state import CompiledStateGraph` |
| `AttributeError: '_AsyncGeneratorContextManager' has no attribute 'setup'` | `AsyncPostgresSaver.from_conn_string()` became async context manager | Rewrote `checkpointer.py` to use `__aenter__`/`__aexit__` |
| `AttributeError: module 'psycopg' has no attribute 'AsyncConnectionPool'` | Pool moved to `psycopg_pool` package | Changed import to `from psycopg_pool import AsyncConnectionPool` |
| `500 Internal Server Error` on webhook | nginx HTTP/1.0 mangled chunked body | Added `proxy_http_version 1.1; proxy_set_header Connection "";` |
| `ERR_TOO_MANY_REDIRECTS` on Grafana | nginx rewrite stripped `/grafana/` prefix | Removed rewrite; used `proxy_pass http://grafana;` (no trailing slash) |
| `404 page not found` in Grafana panels | Datasource URL missing Prometheus prefix | Updated datasource URL to `http://prometheus:9090/prometheus` |
| Grafana panels show no data | Dashboard JSON used plain name string | Replaced all panel datasources with `{"type": "prometheus", "uid": "..."}` |
| LLM hanging indefinitely | `request_timeout` never passed to `ChatOllama` | Added `request_timeout=float(settings.ollama_timeout)` |
| Pipeline stuck on HIGH/CRITICAL PRs | `interrupt_before=["escalate"]` paused graph waiting for Slack | Added `SLACK_ESCALATION_ENABLED=false` default |
| Chat tool calls never execute | `qwen2.5-coder` outputs tool calls as plain text | Custom ReAct loop with 4-pass JSON extractor |
| Wrong DB column name (`pr_id`) | Model hallucinated column name | Injected full PostgreSQL schema into system prompt |
| Log hallucination — model fabricates log lines | Model paraphrased tool output | `[OBSERVATION]...[/OBSERVATION]` format + CRITICAL verbatim rule |
| Chat UI blank for 60–120s | Model cold-start with no early feedback | `status` SSE event fired immediately before LLM call |
| `model requires more system memory (8.7 GiB)` | 32B model consumed too much RAM | Raised Ollama container limit from `32g` to `42g` |
| Large model requests silently dropped | `request_timeout=120s` killed 14B calls | Raised to `900s` in chat router and nginx |
| Inline review comments on wrong lines | Model hallucinated line numbers | `diff_parser.py` validates every line against actual diff |
| LLM no response (chat) | Default 4096 context too small for BTE system prompt (~3K tokens) | Added `num_ctx=16384` to `ChatOllama` in chat router |
| Disk at 92% — 242 GB consumed by orphaned blob | Partial `qwen2.5-coder:32b` pull with no manifest | Deleted orphaned blob `sha256-c430a9b9...` + `llama3.2:3b` + build cache → freed 233 GB |
| Port 11434 accessible on public host interface | `ports: - "11434:11434"` in docker-compose | Removed host binding — Ollama now internal-only |
| Semgrep non-deterministic results | `--config auto` uses unpredictable remote ruleset | Pinned to `p/security-audit` + `p/owasp-top-ten` |
| Diff context only 3 lines | GitHub API always returns `-U3` unified diff | `get_local_diff()`: `git fetch origin {base}` then `git diff -U15 FETCH_HEAD..HEAD` |
| Two sequential 14B LLM calls per PR (~23 min worst case) | Separate `analyze_node` + `code_review_node` | Merged into single `analyze_review_node` with `num_ctx=12288` — cuts to ~6–11 min |
| Checkov output bloated with guideline URLs | `guideline` field included per finding (~150 chars each) | Removed `guideline` field from `format_checkov_findings()` |
| Semgrep INFO findings consuming LLM context | All 15 findings listed including low-value INFO entries | INFO severity collapsed to count only; only ERROR + WARNING listed |
| No disk monitoring without node-exporter | Agent had no Prometheus disk metrics | Added `agent_disk_used_percent` + `agent_disk_free_gb` gauges + autonomous disk guard |
| Ollama scrape target showing `down` | `OLLAMA_METRICS=true` doesn't expose `/metrics` in the installed Ollama version | Removed direct Ollama scrape job entirely. Agent re-exports all Ollama metrics (`ollama_reachable`, `ollama_model_*`, `ollama_models_loaded_total`) via its own `/metrics` endpoint — no data lost |
| AlertManager scrape target showing `down` | AlertManager runs with `--web.route-prefix=/alertmanager/` — all paths prefixed, metrics at `/alertmanager/metrics` not `/metrics` | Added `metrics_path: /alertmanager/metrics` to the scrape config |
| Prometheus self-scrape showing `down` | Prometheus runs with `--web.route-prefix=/prometheus/` — its own metrics are at `/prometheus/metrics` | Added `metrics_path: /prometheus/metrics` to the prometheus scrape config |
| `OllamaDown` alert misfiring (stuck `pending`) | Expression `absent(ollama_models_loaded_total) or (ollama_models_loaded_total == 0 ...)` fires when Ollama is idle (no model loaded = normal state between PR reviews) | Added `ollama_reachable` Gauge to the agent, set to 1/0 by the 30s Ollama poller. Alert uses `ollama_reachable == 0` — true only when Ollama is genuinely unreachable, not just idle. Severity upgraded to critical |
| `OllamaNoModelLoaded` alert firing too aggressively | `for: 10m` is too short — Ollama is idle between PR reviews for longer than 10 min routinely | Extended `for:` to `60m` — only sustained inactivity (e.g., Ollama crashed but process still running) triggers the informational alert |
| Chat agent slower than Open WebUI | Two extra LLM round-trips per response (tool call + answer) with `num_ctx=16384` (huge KV cache) and `num_predict=4096` (allowed 4K token answers) | Reduced `num_ctx` to `8192` for 7b/14b — halves KV cache compute. Capped `num_predict` to `1500` — stops runaway generation. Result: faster first token, faster total response |
| Chat agent picking wrong tool, retrying | Default model was `qwen2.5-coder:7b` — insufficient reasoning for 19-tool routing | Changed default to `qwen2.5-coder:14b` + added explicit tool-selection rules to system prompt (`vps_status` vs `query_prometheus`, `disk_usage` vs `vps_status`, etc.) |
| Host metrics invisible (CPU/RAM/disk I/O/network) | All agent tools read from container namespace — only Docker-level visibility | Added `node-exporter` (`prom/node-exporter:latest`) with `pid: host` + `network_mode: host` — full host OS visibility. PromQL patterns injected into system prompt |
| node-exporter scrape target `down` (context deadline exceeded) | Host firewall blocked Docker bridge network (`172.20.0.0/16`) from reaching host port `9100` | Added `iptables` rule: `-A INPUT -s 172.20.0.0/16 -p tcp --dport 9100 -j ACCEPT`. Persisted via `iptables-persistent` to `/etc/iptables/rules.v4` |
| Grafana 502 Bad Gateway after container recreation | nginx caches upstream DNS at startup — Grafana's Docker IP changed after recreation (`172.20.0.6` → `172.20.0.4`) | Added `resolver 127.0.0.11 valid=10s` to nginx config — Docker's internal DNS, re-resolves upstreams dynamically on each connection |
| Chat agent loops between `list_images` and `disk_usage` forever | Observation injection said *"MUST quote exact lines from the [OBSERVATION] block above"* — after calling `list_images`, model was told to quote those lines. But needing `disk_usage` next, it called it. After `disk_usage`, same message appeared. Model wanted to quote `list_images` too → re-called it. Infinite alternation. No code-level repeat guard existed | (1) Changed observation message to *"Tools used this turn: X, Y. Steps remaining: N. Write final answer or call one more tool."* (2) Added dedup guard: tracks `tool:args` hash per response. Repeat call → blocked, model receives hard stop |
| Chat agent default 14b was slower than 7b with no accuracy gain | Live benchmark on this VPS: 14b = 0.76 tok/s (6144 ctx), 7b = 1.09 tok/s. Both achieve 80% tool accuracy with the explicit system prompt. 14b provides 0 benefit for monitoring queries | Reverted default to `qwen2.5-coder:7b`. 14b retained for PR review pipeline (deep security analysis) |
| No trend/history queries possible | `query_prometheus` only supported instant queries — impossible to answer *"has CPU been high in the last hour?"* | Added `query_prometheus_range(promql, duration, step)` tool: queries `/api/v1/query_range`, returns min/max/avg/latest + trend sparkline across up to 12 sampled datapoints |
| `network_stats` / `system_net_io` used for host bandwidth — returned wrong data | Both tools run inside the container network namespace, not the host. Model had no routing rule distinguishing them from `query_prometheus` | Added explicit tool selection rule: *"NEVER network_stats for host — it shows container internals only"*. Host bandwidth always → `query_prometheus` with `node_network_receive_bytes_total` |
| System prompt too large (2,948 tokens) — slowed every token | Every generated token attends to all prior context. 2,948 prompt tokens were the fixed overhead on every call | Compressed system prompt to 1,894 tokens (36% reduction) — removed verbose decorations, condensed sections, preserved all functional rules. `num_ctx` reduced 6144 → 4096 |
| Repeated tool calls re-execute expensive subprocess/network ops | `container_stats`, `query_prometheus`, etc. re-ran on every identical tool call — even within the same conversation turn | Added in-memory tool result cache with per-tool TTLs (10–120s). Cache key: `tool_name:sorted_args_json`. Eliminates 0.5–3s execution overhead on repeated calls |
| `llama3.2:3b` benchmarked as 0% accurate with full system prompt | 7,577-char prompt ≈ 2,950 tokens fills most of its 4,096-token context — no room to reason. Showed 60% accuracy with short prompt (500 tokens) but all PARSE_FAIL under real prompt | Model kept installed but tagged *Experimental* in UI. Not recommended for tool-calling chat |
| `granite3.1-dense:2b` benchmarked as 0% accurate | Uses IBM's proprietary tool-call schema — outputs `{"tool_name": …}` instead of our `{"name":…,"arguments":…}` format. Format mismatch is fundamental, not fixable via prompt | Tagged *Incompatible* in UI. `_extract_tool_call` parser cannot handle its output |
| **VictoriaMetrics silently crashed — down 9 days** (2026-04-19 to 2026-04-28) | Disk full (92%) caused a storage panic: `FATAL: cannot create directory: no space left on device`. Container exited with code 2. Docker's restart policy tried to restart but failed because disk was still full at that point. After disk was freed (233 GB reclaimed), the container remained in `exited` state and was never brought back up. Prometheus continued attempting `remote_write` to the dead endpoint. | Restarted with `docker compose restart victoriametrics`. Storage opened cleanly (10.9M rows recovered). Prometheus remote_write resumed. Grafana long-term dashboards restored. **Prevention**: add disk alert at 70% (currently at 80%/90%) to catch issues earlier. VictoriaMetrics should have `restart: always` not `unless-stopped`. |
| **Redis publicly exposed on `0.0.0.0:6379` with no auth** | `docker-compose.yml` has `ports: - "6379:6379"` which Docker binds to all host interfaces. Redis runs with default `requirepass ""` (no password). README incorrectly stated Redis was "internal only". | **Not yet fixed.** To fix: remove `ports:` from redis service in docker-compose.yml (containers communicate via Docker network, no host port needed). Or add `--requirepass` to the redis command. Until fixed, any internet host can connect to port 6379 and read/write cached scan results, dedup keys, and rate limit counters. |
| **Prometheus (9090), AlertManager (9093), VictoriaMetrics (8428) publicly exposed** | All three have `ports:` entries in docker-compose.yml binding to 0.0.0.0. None have authentication on direct port access. VictoriaMetrics logs show external bots scanning it (e.g. `139.162.173.209`, `147.185.133.56`). | **Not yet fixed.** Workaround: access all three via nginx proxy (e.g., `/prometheus/`). Full fix: remove host port bindings for internal services. Only `nginx:80/443` needs public exposure for these. |
| **AlertManager never received any alerts** — Prometheus 404 on every send | AlertManager runs with `--web.route-prefix=/alertmanager/` so its API is at `/alertmanager/api/v2/alerts`. Prometheus config had no `path_prefix` setting, so it sent every alert to `/api/v2/alerts` → 404. This was broken since deployment — `OllamaNoModelLoaded` was firing but the agent webhook never received it. | Added `path_prefix: /alertmanager/` to `alerting.alertmanagers` in `prometheus.yml`. Prometheus container restart required (bind-mount inode issue — hot-reload applied config but container kept old file). Verified: Prometheus now sends to `http://alertmanager:9093/alertmanager/api/v2/alerts`. |
| **nginx `GET /` returned 404** | No default location block in nginx.conf — unmatched paths fell to nginx's default static file handler, which found no `index.html`. | Added `location = / { return 301 /ui; }` — anyone hitting the server root is redirected to the chat UI. |
| **Grafana live-streaming dashboards silently broken** | nginx `/grafana/` location was missing `proxy_http_version 1.1`, `Upgrade`, and `Connection: upgrade` headers. WebSocket connections for Grafana's live panel updates were refused. | Added `proxy_http_version 1.1; proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection "upgrade";` to the grafana location block. |
| **Chat UI publicly accessible — anyone could use it** | `/ui` and `/chat/` had no authentication. Anyone with the IP could open the chat and run tool calls against the VPS. | Added HTTP Basic Auth via nginx: `auth_basic "BTE Security AI Agent"; auth_basic_user_file /etc/nginx/.htpasswd;`. bcrypt hash stored in `./nginx/.htpasswd`, bind-mounted to container. User: `bte`. |
| **Chat agent hallucinated live metrics** (CPU %, disk space, container counts) | Three compounding causes: (1) `temperature=0.1` allowed probabilistic token sampling — model could "create" plausible metric values. (2) `num_ctx=4096` overflowed with 2+ large tool observations — model forgot earlier data and filled in from training memory. (3) No code-level enforcement prevented model from answering live-data questions without calling any tool. | (1) `temperature` → `0.0` — fully deterministic. (2) `num_ctx` → `6144` — 4,100 tokens free for observations. (3) `num_predict` → `800` — complete answers don't get cut off. (4) No-tool guard: step-0 intercept forces tool call for live-data questions. (5) Strengthened observation injection: every value must appear verbatim in an `[OBSERVATION]`. (6) ANTI-HALLUCINATION block in system prompt with 5 hard rules. |
| **No VPS Host Monitoring dashboard** | node-exporter collecting 1000+ host metrics (CPU/RAM/disk/network) but no Grafana dashboard existed for them. Both existing dashboards used agent pipeline metrics only. | Created `vps_host.json` provisioned dashboard with 13 panels: 6 stat panels (CPU %, RAM %, Disk %, Disk Free, Load 1m, Uptime) + CPU & IO time series + Memory breakdown + Load averages + Network I/O + Disk I/O. Auto-refreshes every 15s. |
| **DevSecOps Agent dashboard had no host metrics** | Dashboard only showed PR pipeline stats. VPS health was invisible from Grafana. | Rebuilt `devsecops_agent.json` with 33 panels across 5 rows: VPS Health, PR Review Pipeline, Chat Ops Activity, Ollama LLM, Network & Disk I/O. |

---

## 16. Live Pipeline Results

**2 PRs reviewed end-to-end on `GhaiethFerchichi/Vunl-application`:**

| PR | Risk | Verdict | Classification | Duration |
|----|------|---------|----------------|----------|
| #11 | HIGH | REQUEST_CHANGES | infrastructure | ~6 min |
| #12 | HIGH | REQUEST_CHANGES | infrastructure | ~5.6 min |

**Pipeline timing breakdown (14B model, CPU-only, post-merge optimization):**
| Stage | Duration |
|-------|----------|
| `intake_node` (clone + local diff) | ~5–10s |
| `classify_node` (7B) | ~30s |
| `scan_fs_node` (parallel) | ~5–7s (cached) |
| `analyze_review_node` (14B combined) | ~6–11 min |
| `report_node` | ~1s |
| **Total** | **~7–12 min** |

> **Before merge optimization:** Two sequential 14B calls totalled ~13–23 min. Single combined call cuts wall time roughly in half.

---

## 17. Quick Start

### Prerequisites
- Docker + Docker Compose v2
- GitHub repository with webhook configured
- 45 GB RAM (host) — Ollama limited to 42 GB

### Setup

```bash
# 1. Enter the project directory
cd /opt/devsecops

# 2. Fill in secrets
cp .env.example .env
# Edit: GITHUB_TOKEN, GITHUB_WEBHOOK_SECRET, POSTGRES_PASSWORD, GRAFANA_PASSWORD

# 3. Start all services
docker compose up -d

# 4. Pull LLM models
docker exec ollama ollama pull qwen2.5-coder:7b       # 4.7 GB — classify
docker exec ollama ollama pull qwen2.5-coder:14b      # 9.0 GB — analyze + code review (combined)
docker exec ollama ollama pull mistral-nemo:12b       # 7.1 GB — chat UI option

# 5. Verify agent health
curl http://localhost:8000/health
# Expected: {"status":"healthy","agent":"SECURITY AI AGENT"}

# 6. Open the BTE Security AI Agent chat
open http://141.94.92.226/ui

# 7. Open Ollama Web UI
open http://141.94.92.226:3001

# 8. Rebuild agent image (after Dockerfile changes)
docker compose build agent && docker compose up -d agent

# 9. Reload env vars (compose restart does NOT re-read .env)
docker compose up -d --force-recreate agent
```

### GitHub Webhook Configuration

Repo → Settings → Webhooks → Add webhook:
- **Payload URL:** `http://141.94.92.226/webhooks/github`
- **Content type:** `application/json`
- **Secret:** value of `GITHUB_WEBHOOK_SECRET`
- **Events:** `Pull requests`

### Database Inspection

```bash
docker exec -it postgres psql -U devsecops -d devsecops_db

-- View all PR reviews
SELECT repo_full_name, pr_number, risk_score, verdict, duration_ms, created_at
FROM pr_reviews ORDER BY created_at DESC;

-- View scan results
SELECT repo_full_name, scan_type, created_at FROM scan_results ORDER BY created_at DESC;
```

### Monitoring

```bash
# Check all containers
docker compose ps

# View agent logs (docker driver)
docker compose logs -f agent

# Check Prometheus scrape targets
curl -s http://141.94.92.226/prometheus/api/v1/targets | python3 -m json.tool

# Check active alerts
curl -s http://141.94.92.226/prometheus/api/v1/alerts | python3 -m json.tool

# Disk usage
df -h /

# Watch agent logs in real time
tail -f ./artifacts/logs/agent.log
```

### BTE Agent Chat — Example Queries

```
# Platform overview
"What is the overall health of the platform?"
"Are there any active Prometheus alerts?"

# Host resources (answered via node-exporter + query_prometheus)
"What is the current CPU usage across all cores?"
"How much RAM is being used on the VPS right now?"
"Is the disk I/O high? What is the read/write rate?"
"What is the network bandwidth usage?"
"Show me the load averages"

# Container-level
"How much RAM are all containers using?"
"Show me the last 50 lines of the agent logs for errors"
"What models does Ollama have loaded right now?"

# Security data
"Show me the last 5 PR security reviews from the database"
"What are the Redis cache hit rates?"
"List all saved scan artifacts"
"Show me the Trivy results for owner/repo PR 3"
"What is the Jenkins build status?"
"How much disk space is free?"
```

---

## 18. Work Methodology Recommendation

### Recommended: Agile Scrum (2-Week Sprints)

This project is a strong fit for **Agile Scrum** — specifically 2-week sprints with a focused backlog and a small team (1–3 engineers). Here is why, and how the work done in this session maps directly to the Agile model.

---

### Why Agile Scrum — Not Waterfall or Kanban

| Methodology | Verdict | Reason |
|-------------|---------|--------|
| **Waterfall** | ❌ Poor fit | Requirements are not fully known upfront — the project evolved iteratively (disk guard was added after a real 242 GB emergency, AlertManager after observing alert gaps). Waterfall's fixed design phase would have locked in the wrong architecture. |
| **Kanban** | ⚠ Acceptable for pure ops | Kanban works well for ongoing maintenance (disk cleanups, config tweaks) but lacks the structure needed to ship features like the combined LLM pipeline or the Grafana dashboard. No sprint goals → scope creep. |
| **Agile Scrum** | ✅ Best fit | Short cycles match infrastructure/AI work where each sprint produces a working, testable increment. Retrospectives expose gaps (e.g., Prometheus monitoring was discovered broken only after deployment). The backlog is always a living list of improvements. |
| **SAFe / Scaled Agile** | ❌ Overkill | Designed for 50+ person programs. This is a 1–3 person DevSecOps platform. SAFe overhead would slow delivery without adding value. |

---

### How This Project Maps to Scrum

**Sprint 1 — Foundation**
- FastAPI + LangGraph skeleton
- PostgreSQL checkpointing
- Basic GitHub webhook intake
- Trivy + Gitleaks scanner integration

**Sprint 2 — Intelligence Layer**
- Ollama integration (7B classify + 14B security review)
- Semgrep + Checkov + OSV-Scanner
- Scan matrix routing
- GitHub PR comments + commit statuses

**Sprint 3 — Operations & Reliability**
- Redis dedup + rate limiting
- Circuit breaker + graceful degradation
- AlertManager + Prometheus alert rules
- Disk guard scheduler + daily health digest

**Sprint 4 — Quality & Performance (this session)**
- Combined `analyze_review_node` (two 14B calls → one): -U15 local diff, SAST token reduction
- `ollama_reachable` metric + monitoring fixes (Prometheus scrape targets, alert expressions)
- Grafana PostgreSQL datasource + PR review dashboard
- Open WebUI
- README full-system reports

Each sprint delivered a **working, deployed increment** — validated by real PR reviews running through the pipeline.

---

### Scrum Ceremonies for This Scale

| Ceremony | Frequency | Duration | Value |
|----------|-----------|----------|-------|
| **Sprint Planning** | Every 2 weeks | 1 hour | Pick top-priority backlog items, define sprint goal |
| **Daily Standup** | Daily (solo: async log) | 10 min | For a team of 1–2, a written status log is sufficient |
| **Sprint Review** | End of sprint | 30 min | Demo the running system — real PR review, live Grafana dashboard |
| **Retrospective** | End of sprint | 30 min | What gaps were found? (e.g., Prometheus targets down) What to improve? |
| **Backlog Refinement** | Mid-sprint | 30 min | Groom next sprint's stories — break down large items |

---

### Backlog Prioritization (MoSCoW for this project)

| Priority | Examples |
|----------|---------|
| **Must Have** | GitHub webhook integration, LLM review, security scanners, PR comments |
| **Should Have** | Slack escalation, AlertManager, Grafana dashboards, disk guard |
| **Could Have** | Open WebUI, Jenkins integration, SBOM caching, custom Semgrep rules |
| **Won't Have (now)** | Multi-VPS support, Kubernetes deployment, GPU inference, multi-tenant |

---

### Definition of Done for This Project

A story is **done** when:
1. Feature is deployed and running in the Docker Compose stack
2. Agent logs show no errors for the new code path
3. Prometheus metrics reflect the new behavior (if applicable)
4. Relevant section of `Readme.md` or `agent/README.md` is updated
5. A real PR review or real alert has been processed through the new code

---

### Continuous Improvement Loop (Kaizen within Scrum)

```
Deploy sprint increment
        │
        ▼
Monitor in production (Grafana + Prometheus alerts + agent logs)
        │
        ▼
Observe gap (e.g., Prometheus targets down, alert misfiring)
        │
        ▼
Add to backlog → prioritize → next sprint
        │
        ▼
Fix deployed + retrospective note added
```

This is exactly the loop followed in this session: monitoring was deployed (Sprint 3), gaps were observed (OllamaDown misfiring, scrape targets down), and corrected as a focused Sprint 4 item — a textbook Agile improvement cycle.

---

---

## 19. Latest Improvements — Sprint 5

*Completed 2026-04-23*

### Full Host Monitoring via node-exporter

| Before | After |
|--------|-------|
| Agent tools read from container namespace only | node-exporter reads from host PID + network namespace |
| No CPU per-core metrics | `node_cpu_seconds_total` per core in Prometheus |
| No disk I/O metrics | `node_disk_io_time_seconds_total` per device |
| No network bandwidth history | `node_network_receive/transmit_bytes_total` per interface |
| 9 alert rules (3 groups) | 12 alert rules (4 groups) — new `host` group: CPU/RAM/disk I/O |

node-exporter added to `docker-compose.yml` with `pid: host` + `network_mode: host`. Prometheus scrapes it via Docker bridge gateway `172.20.0.1:9100`. `iptables` rule persisted.

### Chat Agent Speed + Precision (Sprint 5)

| Parameter | Before | After | Impact |
|-----------|--------|-------|--------|
| Default model | `qwen2.5-coder:7b` | `qwen2.5-coder:14b` | Better tool selection, fewer retries |
| `num_ctx` | `16384` | `8192` (7b/14b) | Halves KV cache — faster per-token compute on CPU |
| `num_predict` | `4096` | `1500` | Stops runaway generation — faster total response |
| Tool selection rules | Generic system prompt | Explicit `tool → use-case` mapping | Model picks correct tool first time |
| node-exporter PromQL | Not in prompt | 4 ready-to-use PromQL patterns | Model can query host metrics without guessing |

### Nginx DNS Fix

Added `resolver 127.0.0.11 valid=10s` to nginx config — Docker's internal DNS. Upstream IPs now re-resolved dynamically on each connection, preventing 502 errors after container recreation.

---

## 20. Latest Improvements — Sprint 6

*Completed 2026-04-27*

### Model Benchmarking — Confirmed Best Model

Pulled `llama3.2:3b` and `granite3.1-dense:2b`, ran a 5-query benchmark against the full system prompt on this VPS:

| Model | Size | Speed (warm) | Tool Accuracy | Args Format | Result |
|-------|------|-------------|---------------|-------------|--------|
| `qwen2.5-coder:7b` | 4.7 GB | ~5 tok/s | **80%** | **100%** | ✅ Default |
| `qwen2.5-coder:14b` | 9.0 GB | ~3.2 tok/s | 80% | 100% | PR review only |
| `llama3.2:3b` | 2.0 GB | ~8 tok/s | 0% full prompt | — | ❌ Experimental |
| `granite3.1-dense:2b` | 1.6 GB | ~8.5 tok/s | 0% | — | ❌ Incompatible |

**Decision:** reverted default from 14b → 7b. Both achieve 80% tool accuracy with the explicit system prompt, but 7b is 43% faster per token.

### Chat Agent Speed Improvements

| What | Before | After | Impact |
|------|--------|-------|--------|
| Default model | `qwen2.5-coder:14b` | `qwen2.5-coder:7b` | 43% faster per token, same accuracy |
| System prompt | 11,794 chars / 2,948 tokens | 7,577 chars / 1,894 tokens | 36% smaller → smaller KV cache |
| `num_ctx` | 6144 | **4096** | Lower KV cache allocation |
| `num_predict` | 1500 | **600** | Caps runaway generation |
| Tool result cache | None | 14 tools, TTL 10–120s | Tool execution cost eliminated on repeats |

### Bug Fixes

| Bug | Fix |
|-----|-----|
| Infinite loop: `list_images ↔ disk_usage` | (1) Dedup guard (code-level): blocks repeated `tool:args`, injects hard stop message. (2) Observation message redesigned: tells model exactly which tools already called + steps remaining |
| No trend/history tool | Added `query_prometheus_range(promql, duration, step)` — 20th tool. Returns min/max/avg/latest + trend sparkline. Enables *"has CPU been high in the last hour?"* |
| `network_stats` called for host bandwidth | Added routing rule: *"NEVER network_stats for host — container internals only"* |

### UI Enhancements

| Feature | Description |
|---------|-------------|
| Copy buttons | Hover any code block → `Copy` button appears top-right. Click → copies to clipboard, shows `Copied!` for 1.8s |
| Response timing | Each completed response shows `⏱ Xs` at the bottom |
| Model tag badges | Dropdown shows `[Recommended]` / `[Deep analysis]` / `[Experimental]` / `[Incompatible]` with colour-coded badges. Model metadata shows accuracy %, speed tok/s |
| Model auto-sort | Recommended first, then Deep, Experimental, Incompatible |

---

## 21. Latest Improvements — Sprint 7

*Completed 2026-04-28*

### VPS Audit & Critical Fixes

| Fix | Root cause | Impact |
|-----|-----------|--------|
| **VictoriaMetrics restarted** | Crashed 2026-04-19 on disk-full panic, silently down 9 days | 10.9M historical rows recovered; Prometheus remote_write resumed |
| **AlertManager 404 fixed** | `path_prefix` missing → every alert sent to wrong URL | Alerts now correctly POST to agent webhook; `OllamaNoModelLoaded` reaches agent |
| **nginx root redirect** | `GET /` returned 404 | `GET /` now 301 → `/ui` |
| **Grafana WebSocket fixed** | Upgrade headers not forwarded by nginx | Live-streaming dashboards now functional |
| **Chat UI Basic Auth** | `/ui` and `/chat/` publicly accessible | Password-protected (user: `bte`, bcrypt htpasswd) |

### Anti-Hallucination — Chat Agent

| What | Before | After |
|------|--------|-------|
| `temperature` | 0.1 (probabilistic) | **0.0** (deterministic — no creative metric invention) |
| `num_ctx` | 4096 | **6144** (4,100 tokens free — 6–8 observations without overflow) |
| `num_predict` | 600 | **800** (complete answers; cut-off answers caused memory fill-in) |
| No-tool guard | None | **Code-level intercept**: step-0 final answer for live-data question → forced tool call |
| Observation injection | "write final answer now" | **"Every value MUST appear verbatim in an [OBSERVATION]. NEVER invent."** |
| System prompt | No hallucination rules | **ANTI-HALLUCINATION block**: 5 hard rules enforced in every generation |

### Grafana Dashboards

| Dashboard | Status | Panels | Datasource |
|-----------|--------|--------|-----------|
| VPS Host Monitoring | **NEW** | 13 | Prometheus (node-exporter) |
| DevSecOps AI Agent | **Rebuilt** — 5 sections | 33 | Prometheus |
| PR Security Reviews | Unchanged | 5 | PostgreSQL |

All 3 datasources confirmed healthy: Prometheus ✅ · VictoriaMetrics ✅ · PostgreSQL ✅

---

*BTE Security AI Agent — built for the BTE DevSecOps platform.*
