# OMNISCIENT DEVSECOPS AI AGENT — FULL BUILD SPECIFICATION

## YOUR ROLE

You are an Elite DevSecOps Architect. You will build a **full-spectrum DevSecOps AI Agent** with a scalable multi-workflow architecture. The system is designed to eventually run six independent security workflows (PR review, pipeline gate, scheduled audit, CVE watch, incident triage, compliance drift). **For this build, you will fully implement the PR Security Review workflow** while scaffolding the architecture so every future workflow plugs in without structural changes.

Every file you produce must be **complete, production-ready, and runnable** — no pseudo-code, no placeholders, no `TODO` comments. Use `async/await` everywhere. Never hardcode secrets.

---

## 1. ENVIRONMENT

### 1.1 Hardware
- **VPS:** OVH — 12 vCores, 48 GB RAM, 300 GB NVMe, Ubuntu 24.04
- **IP:** 141.94.92.226

### 1.2 Networking
- **UFW ports:** 22, 80, 443, 8080 (Jenkins), 9000 (SonarQube), 11434 (Ollama), 8000 (Agent)
- **Docker network:** `devsecops-net` (bridge, `172.20.0.0/16`)
- All inter-service calls use **Docker DNS hostnames** (`http://ollama:11434`, `http://postgres:5432`). NEVER use `localhost` or hard IPs from inside containers.

### 1.3 Complete Directory Tree

```
/opt/devsecops/
├── docker-compose.yml
├── .env
├── .env.example
├── nginx/
│   └── nginx.conf
├── jenkins/
│   └── Dockerfile
├── agent/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── alembic.ini                        # DB migration config (optional, can use raw SQL init)
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                        # FastAPI app + lifespan (startup/shutdown)
│   │   ├── config.py                      # Pydantic Settings — all env vars, cached singleton
│   │   │
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── github_webhooks.py         # Pydantic models for GitHub PR webhook payload
│   │   │   ├── state.py                   # AgentState TypedDict for LangGraph
│   │   │   └── db.py                      # SQLAlchemy / raw SQL table definitions
│   │   │
│   │   ├── routers/
│   │   │   ├── __init__.py
│   │   │   ├── webhooks.py                # POST /webhooks/github — validates HMAC, dispatches
│   │   │   ├── callbacks.py               # POST /callbacks/slack — resumes paused graphs
│   │   │   └── health.py                  # GET /health, GET /readiness
│   │   │
│   │   ├── engine/
│   │   │   ├── __init__.py
│   │   │   ├── registry.py                # Workflow registry — maps event types to graphs
│   │   │   ├── dispatcher.py              # Event dispatcher — receives events, invokes correct graph
│   │   │   └── checkpointer.py            # PostgreSQL AsyncCheckpointSaver setup
│   │   │
│   │   ├── workflows/
│   │   │   ├── __init__.py
│   │   │   ├── pr_review/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── graph.py               # StateGraph builder + compiler for PR review
│   │   │   │   ├── nodes.py               # All node functions: intake, classify, scan, analyze, report, escalate, error
│   │   │   │   ├── edges.py               # Conditional edge functions: route_scans, route_risk
│   │   │   │   └── state.py               # PRReviewState(AgentState) — PR-specific state fields
│   │   │   ├── pipeline_gate/             # SCAFFOLD ONLY — __init__.py + empty graph.py with docstring
│   │   │   ├── scheduled_audit/           # SCAFFOLD ONLY
│   │   │   ├── cve_watch/                 # SCAFFOLD ONLY
│   │   │   ├── incident_triage/           # SCAFFOLD ONLY
│   │   │   └── compliance_drift/          # SCAFFOLD ONLY
│   │   │
│   │   ├── services/
│   │   │   ├── __init__.py
│   │   │   ├── git_service.py             # clone_repo, get_pr_diff (async subprocess + httpx)
│   │   │   ├── trivy_service.py           # scan_image, scan_filesystem, parse results (async subprocess)
│   │   │   ├── gitleaks_service.py        # scan_repo for secrets (async subprocess)
│   │   │   ├── docker_service.py          # build_image, remove_image, check_dockerfile (async subprocess)
│   │   │   ├── github_api.py              # post_pr_comment, set_commit_status, create_check_run (httpx)
│   │   │   ├── slack_api.py               # send_notification, request_approval (slack-sdk async)
│   │   │   └── knowledge.py               # Read/write to PostgreSQL knowledge base tables
│   │   │
│   │   ├── llm/
│   │   │   ├── __init__.py
│   │   │   └── ollama.py                  # ChatOllama factory, get_llm() singleton
│   │   │
│   │   └── prompts/
│   │       ├── __init__.py
│   │       ├── classifier.py              # System prompt for PR classification
│   │       ├── security_review.py         # System prompt for deep security analysis
│   │       └── templates.py               # Shared prompt fragments (OWASP checklist, output format)
│   │
│   └── tests/
│       ├── __init__.py
│       ├── conftest.py                    # Fixtures: test client, mock payloads, mock trivy output
│       ├── test_webhook_handler.py        # HMAC validation, event filtering, 202 response
│       ├── test_pr_review_graph.py        # Full graph flow with mocked services
│       ├── test_trivy_parsing.py          # Parse real + empty Trivy JSON
│       └── test_knowledge_service.py      # DB read/write for scan results
│
├── db/
│   └── init.sql                           # PostgreSQL schema — ALL tables for full architecture
│
└── scripts/
    └── start.sh                           # Full startup: sysctl, docker compose, ollama pull
```

---

## 2. CORE ARCHITECTURAL PRINCIPLES

### 2.1 Event-Driven Multi-Workflow Engine

The agent is NOT a single pipeline. It is an **event-driven workflow engine**. Events arrive (webhooks, cron, callbacks), get classified, and dispatched to the correct LangGraph workflow.

```
Event (webhook/cron/callback)
    │
    ▼
FastAPI Router → validates + extracts event type
    │
    ▼
Dispatcher → looks up workflow in Registry
    │
    ▼
LangGraph StateGraph → runs nodes, checkpoints to Postgres
    │
    ▼
Services → execute actions (scan, API calls, LLM inference)
    │
    ▼
Knowledge Base → stores results for cross-workflow intelligence
```

**The Registry** (`engine/registry.py`) maps event types to compiled graphs:
```python
WORKFLOW_REGISTRY: dict[str, CompiledGraph] = {
    "pull_request": pr_review_graph,
    # Future:
    # "build_completed": pipeline_gate_graph,
    # "scheduled_audit": audit_graph,
    # "cve_alert": cve_watch_graph,
    # "runtime_alert": incident_triage_graph,
    # "compliance_check": compliance_drift_graph,
}
```

**The Dispatcher** (`engine/dispatcher.py`) is a single async function:
```python
async def dispatch_event(event_type: str, payload: dict) -> str:
    graph = WORKFLOW_REGISTRY.get(event_type)
    if not graph:
        log.warning("unknown_event_type", event_type=event_type)
        return "ignored"
    config = {"configurable": {"thread_id": f"{event_type}-{payload['id']}"}}
    await graph.ainvoke(initial_state_from_payload(payload), config=config)
    return "dispatched"
```

This means adding a new workflow is: (1) build a new `StateGraph` in `workflows/<name>/graph.py`, (2) register it in the registry. No changes to FastAPI routers, no changes to dispatcher.

### 2.2 LLM as Analyst, Not Orchestrator

The LLM (Qwen2.5-Coder:32B via Ollama) is called at **exactly two points** in the PR review workflow:

1. **Classify** — reads PR title + file list → outputs JSON classification (fast, ~15s)
2. **Analyze** — reads diff + scan results + repo history → outputs markdown security review (deep, ~60-120s)

The LLM NEVER selects tools, NEVER decides execution order, NEVER calls functions. All routing is deterministic Python code in conditional edge functions. This is a deliberate design decision: Qwen 32B is excellent at code analysis and reasoning but unreliable at structured tool calling.

### 2.3 Shared Knowledge Base

Every workflow reads from and writes to PostgreSQL. The schema is defined ONCE in `db/init.sql` and covers ALL future workflows. The `services/knowledge.py` module provides typed async functions for reading/writing.

### 2.4 LangGraph + PostgreSQL Checkpointer

Every graph uses `AsyncPostgresSaver` for checkpointing. This enables:
- **Slack approval gate**: graph pauses, state persists, resumes when callback arrives
- **Crash recovery**: if the agent container restarts mid-pipeline, the graph resumes from last checkpoint
- **Audit trail**: every state transition is recorded

---

## 3. TECHNOLOGY STACK

### 3.1 `requirements.txt`

```
fastapi>=0.115.0
uvicorn[standard]>=0.30.0
httpx>=0.27.0
pydantic>=2.8.0
pydantic-settings>=2.4.0
langgraph>=0.4.0
langchain-core>=0.3.0
langchain-ollama>=0.3.0
langgraph-checkpoint-postgres>=2.0.0
psycopg[binary]>=3.2.0
structlog>=24.4.0
tenacity>=8.5.0
slack-sdk>=3.31.0
```

### 3.2 Container Images

| Service     | Image                          | RAM   |
|-------------|--------------------------------|-------|
| Ollama      | `ollama/ollama:latest`         | ~24GB |
| Agent       | Custom (Python 3.12-slim)      | ~512MB|
| PostgreSQL  | `postgres:16-alpine`           | ~1GB  |
| Jenkins     | Custom (`jenkins/jenkins:lts-jdk17`) | ~2GB |
| SonarQube   | `sonarqube:lts-community`      | ~4GB  |
| Nginx       | `nginx:alpine`                 | ~32MB |

---

## 4. ENVIRONMENT VARIABLES (`.env`)

```env
# === GitHub ===
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
GITHUB_WEBHOOK_SECRET=your-webhook-secret-here

# === Ollama ===
OLLAMA_BASE_URL=http://ollama:11434
OLLAMA_MODEL=qwen2.5-coder:32b
OLLAMA_TIMEOUT=300

# === Slack ===
SLACK_BOT_TOKEN=xoxb-xxxxxxxxxxxx-xxxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxx
SLACK_CHANNEL_ID=C0XXXXXXXXX
SLACK_SIGNING_SECRET=your-slack-signing-secret

# === Jenkins ===
JENKINS_URL=http://jenkins:8080
JENKINS_USER=admin
JENKINS_API_TOKEN=your-jenkins-api-token

# === SonarQube ===
SONARQUBE_URL=http://sonarqube:9000
SONARQUBE_TOKEN=squ_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# === PostgreSQL ===
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
POSTGRES_USER=devsecops
POSTGRES_PASSWORD=change-me-to-a-strong-password
POSTGRES_DB=devsecops_db

# === Agent ===
AGENT_LOG_LEVEL=INFO
AGENT_WORKSPACE=/tmp/agent-workspace
TRIVY_SEVERITY=CRITICAL,HIGH,MEDIUM
```

Produce both `.env` (with these placeholder values) and `.env.example` (identical but with empty values).

---

## 5. DOCKER COMPOSE — FULL SPECIFICATION

### Services

**ollama:**
- Image: `ollama/ollama:latest`, container name `ollama`
- Ports: `11434:11434`
- Volumes: `ollama_data:/root/.ollama`
- Deploy: `resources.limits.memory: 28g`
- Healthcheck: `curl -f http://localhost:11434/api/tags || exit 1` (interval 30s, timeout 10s, retries 5)
- Restart: `unless-stopped`, network: `devsecops-net`

**agent:**
- Build: `./agent`, container name `devsecops-agent`
- Ports: `8000:8000`
- Depends on: `ollama` (healthy), `postgres` (healthy)
- Env file: `.env`
- Volumes: `./agent/app:/app/app` (dev hot-reload), `/var/run/docker.sock:/var/run/docker.sock`, `agent_workspace:/tmp/agent-workspace`
- Healthcheck: `curl -f http://localhost:8000/health || exit 1`
- Restart: `unless-stopped`, network: `devsecops-net`

**postgres:**
- Image: `postgres:16-alpine`, container name `postgres`
- Environment: `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB` from `.env`
- Volumes: `postgres_data:/var/lib/postgresql/data`, `./db/init.sql:/docker-entrypoint-initdb.d/init.sql:ro`
- Healthcheck: `pg_isready -U ${POSTGRES_USER}` (interval 10s, retries 5)
- Restart: `unless-stopped`, network: `devsecops-net`

**jenkins:**
- Build: `./jenkins`, container name `jenkins`
- Ports: `8080:8080`, `50000:50000`
- Volumes: `jenkins_data:/var/jenkins_home`, `/var/run/docker.sock:/var/run/docker.sock`
- Restart: `unless-stopped`, network: `devsecops-net`

**sonarqube:**
- Image: `sonarqube:lts-community`, container name `sonarqube`
- Ports: `9000:9000`
- Environment: `SONAR_JDBC_URL=jdbc:postgresql://postgres:5432/${POSTGRES_DB}`, `SONAR_JDBC_USERNAME=${POSTGRES_USER}`, `SONAR_JDBC_PASSWORD=${POSTGRES_PASSWORD}`
- Depends on: `postgres` (healthy)
- Volumes: `sonarqube_data:/opt/sonarqube/data`, `sonarqube_extensions:/opt/sonarqube/extensions`, `sonarqube_logs:/opt/sonarqube/logs`
- Ulimits: `nofile: soft=131072, hard=131072`
- Restart: `unless-stopped`, network: `devsecops-net`

**nginx:**
- Image: `nginx:alpine`, container name `nginx`
- Ports: `80:80`, `443:443`
- Volumes: `./nginx/nginx.conf:/etc/nginx/nginx.conf:ro`
- Depends on: `agent`, `jenkins`, `sonarqube`
- Restart: `unless-stopped`, network: `devsecops-net`

**Network:** `devsecops-net`, bridge, subnet `172.20.0.0/16`

**Volumes:** `ollama_data`, `postgres_data`, `jenkins_data`, `sonarqube_data`, `sonarqube_extensions`, `sonarqube_logs`, `agent_workspace`

---

## 6. DATABASE SCHEMA (`db/init.sql`)

This schema covers the FULL architecture — all six workflows. Create ALL tables now so the schema is stable.

```sql
-- === Knowledge Base ===

CREATE TABLE IF NOT EXISTS repo_profiles (
    id              SERIAL PRIMARY KEY,
    repo_full_name  TEXT UNIQUE NOT NULL,
    default_branch  TEXT DEFAULT 'main',
    primary_language TEXT,
    framework       TEXT,
    has_dockerfile  BOOLEAN DEFAULT FALSE,
    risk_score_avg  REAL DEFAULT 0.0,
    total_reviews   INTEGER DEFAULT 0,
    last_scan_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scan_results (
    id              SERIAL PRIMARY KEY,
    repo_full_name  TEXT NOT NULL,
    scan_type       TEXT NOT NULL,          -- 'trivy_image', 'trivy_fs', 'gitleaks', 'sonarqube', 'zap'
    trigger_type    TEXT NOT NULL,          -- 'pr_review', 'pipeline_gate', 'scheduled_audit', 'cve_watch'
    trigger_ref     TEXT,                   -- PR number, build ID, etc.
    summary         JSONB NOT NULL,         -- {"CRITICAL": 2, "HIGH": 5, ...}
    raw_output      JSONB,                  -- Full scan JSON (can be large)
    created_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_scan_results_repo ON scan_results(repo_full_name, created_at DESC);

CREATE TABLE IF NOT EXISTS pr_reviews (
    id              SERIAL PRIMARY KEY,
    repo_full_name  TEXT NOT NULL,
    pr_number       INTEGER NOT NULL,
    pr_title        TEXT,
    pr_author       TEXT,
    classification  TEXT,                   -- 'feature', 'dependency', 'infrastructure', 'docs', 'config'
    risk_score      TEXT,                   -- 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'
    verdict         TEXT,                   -- 'APPROVE', 'REQUEST_CHANGES', 'BLOCK'
    review_markdown TEXT,                   -- Full LLM analysis
    scan_summary    JSONB,                  -- Combined scan results summary
    files_changed   JSONB,                  -- List of changed file paths
    approval_status TEXT DEFAULT 'auto',    -- 'auto', 'pending', 'approved', 'rejected'
    duration_ms     INTEGER,               -- Total pipeline duration
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(repo_full_name, pr_number)
);
CREATE INDEX idx_pr_reviews_repo ON pr_reviews(repo_full_name, created_at DESC);

CREATE TABLE IF NOT EXISTS sbom_cache (
    id              SERIAL PRIMARY KEY,
    repo_full_name  TEXT NOT NULL,
    package_name    TEXT NOT NULL,
    package_version TEXT NOT NULL,
    package_type    TEXT,                   -- 'npm', 'pip', 'go', 'maven', 'cargo'
    scan_source     TEXT,                   -- 'trivy_fs', 'trivy_image'
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_sbom_repo ON sbom_cache(repo_full_name);
CREATE INDEX idx_sbom_package ON sbom_cache(package_name, package_version);

CREATE TABLE IF NOT EXISTS security_policies (
    id              SERIAL PRIMARY KEY,
    policy_name     TEXT UNIQUE NOT NULL,
    policy_type     TEXT NOT NULL,          -- 'vuln_threshold', 'branch_protection', 'secret_scan', 'image_age'
    config          JSONB NOT NULL,         -- Policy-specific config
    enabled         BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS incidents (
    id              SERIAL PRIMARY KEY,
    source          TEXT NOT NULL,          -- 'prometheus', 'grafana', 'manual'
    severity        TEXT NOT NULL,
    title           TEXT NOT NULL,
    description     TEXT,
    related_repo    TEXT,
    related_pr      INTEGER,
    triage_result   TEXT,                   -- LLM triage analysis
    status          TEXT DEFAULT 'open',    -- 'open', 'investigating', 'resolved'
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- === Insert default security policies ===
INSERT INTO security_policies (policy_name, policy_type, config) VALUES
    ('block_critical_vulns', 'vuln_threshold', '{"max_critical": 0, "max_high": 5}'),
    ('require_secret_scan', 'secret_scan', '{"enabled": true, "block_on_finding": true}'),
    ('base_image_age', 'image_age', '{"max_days": 90}')
ON CONFLICT (policy_name) DO NOTHING;
```

**IMPORTANT:** The LangGraph checkpoint tables are created automatically by `AsyncPostgresSaver.setup()` at startup. Do NOT define them manually.

---

## 7. AGENT DOCKERFILE (`agent/Dockerfile`)

```dockerfile
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl ca-certificates gnupg lsb-release \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list \
    && apt-get update && apt-get install -y --no-install-recommends docker-ce-cli \
    && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin \
    && curl -sfL https://raw.githubusercontent.com/gitleaks/gitleaks/main/scripts/install.sh | sh -s -- -b /usr/local/bin \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ ./app/
RUN mkdir -p /tmp/agent-workspace
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
```

---

## 8. LLM INTERFACE (`app/llm/ollama.py`)

Use `ChatOllama` from `langchain-ollama`. Create a cached factory function:

```python
from functools import lru_cache
from langchain_ollama import ChatOllama
from app.config import get_settings

@lru_cache
def get_llm() -> ChatOllama:
    settings = get_settings()
    return ChatOllama(
        base_url=settings.ollama_base_url,
        model=settings.ollama_model,
        temperature=0.1,
        num_predict=4096,
        keep_alive="10m",
    )

def get_classifier_llm() -> ChatOllama:
    """Faster config for classification — shorter output."""
    settings = get_settings()
    return ChatOllama(
        base_url=settings.ollama_base_url,
        model=settings.ollama_model,
        temperature=0.0,
        num_predict=512,
        format="json",      # Forces valid JSON output at Ollama level
        keep_alive="10m",
    )
```

**CRITICAL:** The classifier LLM uses `format="json"` — this forces Ollama to produce valid JSON at the grammar level. The analyzer LLM does NOT use `format="json"` because it produces mixed markdown + JSON, where only the metadata block at the end is JSON.

---

## 9. LANGGRAPH STATE

### 9.1 Base State (`app/models/state.py`)

```python
from typing import TypedDict, Annotated
from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages

class AgentState(TypedDict):
    """Base state shared by all workflows."""
    workflow_type: str
    repo_full_name: str
    trigger_ref: str
    current_stage: str
    error: str
    messages: Annotated[list[BaseMessage], add_messages]
```

### 9.2 PR Review State (`app/workflows/pr_review/state.py`)

```python
from typing import Literal
from app.models.state import AgentState

class PRReviewState(AgentState):
    """Extended state for the PR review workflow."""
    # Input
    pr_number: int
    clone_url: str
    head_branch: str
    head_sha: str
    pr_title: str
    pr_body: str
    pr_url: str
    sender: str

    # Populated by nodes
    repo_path: str
    diff: str
    has_dockerfile: bool
    docker_image_tag: str
    pr_classification: str                  # "feature" | "dependency" | "infrastructure" | "docs" | "config"
    files_changed: list[str]
    scan_results: dict                      # {"trivy_image": {...}, "trivy_fs": {...}, "gitleaks": {...}}
    security_review: str                    # Full markdown review from LLM
    risk_score: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    verdict: Literal["APPROVE", "REQUEST_CHANGES", "BLOCK"]
    approval_status: str                    # "auto" | "pending" | "approved" | "rejected"
    repo_history: list[dict]                # Past reviews for context injection
    started_at: str                         # ISO timestamp
```

---

## 10. PR REVIEW WORKFLOW — FULL SPECIFICATION

### 10.1 Graph Builder (`app/workflows/pr_review/graph.py`)

Build a `StateGraph(PRReviewState)` with these nodes and edges:

```
START → intake → classify → route_scans (conditional)
                                ├── scan_full (has Dockerfile)
                                ├── scan_fs (no Dockerfile, not docs)
                                └── skip_scan (docs only)
           scan_full ──┐
           scan_fs  ───┤──→ analyze → route_risk (conditional)
           skip_scan ──┘                  ├── report (LOW/MEDIUM/INFO)
                                          └── escalate (HIGH/CRITICAL) → report
                                                (interrupt_before for Slack gate)
           report → END

Any node that sets state["error"] → error_node → END
```

Compile with: `graph = builder.compile(checkpointer=checkpointer, interrupt_before=["escalate"])`

### 10.2 Node Specifications (`app/workflows/pr_review/nodes.py`)

Each node is `async def node_name(state: PRReviewState) -> dict:` and returns a partial state update.

#### `intake_node`
1. Set `current_stage = "intake"`, `started_at = datetime.utcnow().isoformat()`
2. Post "in progress" comment to PR via `github_api.post_pr_comment()`
3. Clone repo via `git_service.clone_repo(clone_url, head_branch, workspace)` — inject GitHub token into URL for private repos: `https://{token}@github.com/owner/repo.git`
4. Fetch diff via `git_service.get_pr_diff(repo_full_name, pr_number)` — uses GitHub API with `Accept: application/vnd.github.v3.diff`
5. If diff > 30,000 chars, truncate with: `\n\n... [DIFF TRUNCATED — {original_len} chars, showing first 30000] ...`
6. Check `docker_service.check_dockerfile(repo_path)`
7. Extract changed files: parse `diff --git a/... b/...` lines from the diff
8. Query `knowledge.get_repo_history(repo_full_name, limit=10)` for past reviews
9. Return: `repo_path`, `diff`, `has_dockerfile`, `files_changed`, `repo_history`

**Error handling:** If clone fails → set `error` field, return immediately. The graph routes to `error_node`.

#### `classify_node`
1. Set `current_stage = "classify"`
2. Invoke `get_classifier_llm()` with system prompt from `prompts/classifier.py` and user message containing: PR title, PR body, list of changed file paths (NOT full diff)
3. Parse JSON response: `{"classification": "feature", "reasoning": "...", "risk_hint": "medium", "focus_areas": ["api", "auth"]}`
4. Use `tenacity` retry (2 retries, exponential backoff) for Ollama connection issues
5. Return: `pr_classification`, appended `messages`

**The classifier system prompt must instruct:**
```
You are a DevSecOps triage specialist. Given a PR title, description, and list of changed files,
classify the PR into exactly one category and assess initial risk.

Respond with ONLY valid JSON:
{
  "classification": "<feature|dependency|infrastructure|docs|config>",
  "reasoning": "<one sentence explaining why>",
  "risk_hint": "<low|medium|high>",
  "focus_areas": ["<area1>", "<area2>"]
}

Classification rules:
- "docs": only .md, .txt, .rst, documentation files changed
- "dependency": only lock files, requirements.txt, package.json, go.sum changed
- "infrastructure": Dockerfile, docker-compose, CI/CD configs, terraform, k8s manifests
- "config": .env.example, settings files, feature flags
- "feature": any source code changes (.py, .js, .ts, .go, .java, .rs, etc.)
```

#### `scan_full_node`
1. Set `current_stage = "scan"`
2. Run `docker_service.build_image(repo_path, image_tag)` — tag: `{repo_name}-pr-{pr_number}:scan`
   - Timeout: 300s. If build fails, log warning, skip image scan, continue with fs scan.
3. Run `trivy_service.scan_image(image_tag, severity)` → parse into `TrivyScanResult`
4. Run `trivy_service.scan_filesystem(repo_path, severity)` → parse into `TrivyScanResult`
5. Run `gitleaks_service.scan_repo(repo_path)` → parse findings
6. Combine into `scan_results = {"trivy_image": {...}, "trivy_fs": {...}, "gitleaks": {...}}`
7. Store via `knowledge.save_scan_result(repo, scan_type, trigger, summary)`
8. Return: `scan_results`, `docker_image_tag`

#### `scan_fs_node`
Same as above but SKIP docker build + image scan. Only run trivy fs + gitleaks.

#### `skip_scan_node`
Set `scan_results = {}`, return immediately.

#### `analyze_node` — THE CORE
1. Set `current_stage = "analyze"`
2. Build prompt using `prompts/security_review.py` containing:
   - PR metadata (title, body, author, classification)
   - The diff (or truncated version)
   - Formatted scan results: vuln summary table + top 15 individual vulns + gitleaks findings
   - Repo history context: "This repo has had X reviews, average risk Y, most common vulns: Z"
3. Invoke `get_llm()` (the full-context analyzer, NOT the classifier)
4. Parse response:
   - Main body → `security_review` (full markdown)
   - Extract JSON metadata from end of response (regex for `{"risk_score": "...", "verdict": "..."}`)
   - If JSON extraction fails, default to `risk_score = "MEDIUM"`, `verdict = "REQUEST_CHANGES"`
5. Store via `knowledge.save_pr_review(repo, pr_number, classification, risk_score, verdict, review, scan_summary, files)`
6. Update repo profile via `knowledge.update_repo_profile(repo, risk_score)`
7. Return: `security_review`, `risk_score`, `verdict`, appended `messages`

**The security review system prompt** (in `prompts/security_review.py`) MUST follow this structure:

```
You are a senior Application Security Engineer performing a security code review.

## CONTEXT
- **PR:** #{pr_number} — {pr_title}
- **Author:** {sender}
- **Classification:** {classification}
- **Description:** {pr_body or "No description provided."}

## REPOSITORY HISTORY
{repo_history_summary}

## YOUR TASK
Analyze the code diff and vulnerability scan results. Produce a thorough security review.
Focus especially on: {focus_areas from classification}

## CODE DIFF
```diff
{diff}
```

## SCAN RESULTS
{formatted_trivy_summary}
{formatted_gitleaks_findings}

## OUTPUT FORMAT
Produce the following markdown structure. Be specific — cite file names and line numbers.

### Security review — PR #{pr_number}

**Risk score:** [CRITICAL / HIGH / MEDIUM / LOW / INFO]
**Verdict:** [APPROVE / REQUEST_CHANGES / BLOCK]

#### Code analysis
(Check for: hardcoded secrets, injection flaws, XSS, SSRF, path traversal, command injection,
insecure deserialization, broken auth, sensitive data exposure, insecure crypto.
For each finding: file, line, severity, description, fix suggestion.)

#### Dependency and container analysis
(Summarize Trivy findings. Highlight CRITICAL/HIGH. Specific remediation: exact package versions to upgrade.)

#### Secrets scan
(Summarize Gitleaks findings if any. Flag specific files and patterns.)

#### Recommendations
(Numbered list of actionable items, ordered by severity.)

After your markdown review, output EXACTLY this JSON block on its own line:
```json
{"risk_score": "<CRITICAL|HIGH|MEDIUM|LOW|INFO>", "verdict": "<APPROVE|REQUEST_CHANGES|BLOCK>"}
```
```

#### `escalate_node`
1. Set `current_stage = "escalate"`, `approval_status = "pending"`
2. Call `slack_api.request_approval()` — posts Block Kit message with:
   - PR title, author, URL, risk score
   - Top 3 critical findings from the review
   - "Approve" and "Reject" buttons with action IDs
3. **This node has `interrupt_before`** — after execution, the graph pauses.
4. When `/callbacks/slack` receives the button click, it resumes the graph with `approval_status = "approved"` or `"rejected"`
5. Return: `approval_status`

#### `report_node`
1. Set `current_stage = "report"`
2. Format the `security_review` markdown with a header:
   ```
   ## 🤖 Omniscient Agent — Security Review

   **Risk:** {risk_score} | **Verdict:** {verdict} | **Classification:** {classification}

   ---

   {security_review}
   ```
3. Call `github_api.post_pr_comment(repo, pr_number, formatted_review)`
4. Call `github_api.set_commit_status(repo, head_sha, state, description)`:
   - APPROVE → state="success", description="Security review passed"
   - REQUEST_CHANGES → state="failure", description="Security issues found"
   - BLOCK → state="error", description="Critical security vulnerabilities — blocked"
5. Call `slack_api.send_notification(summary)` — brief summary to Slack channel
6. Cleanup: `docker_service.remove_image(docker_image_tag)`, remove cloned repo dir
7. Calculate duration, update PR review record with `duration_ms`

#### `error_node`
1. Log full error with structlog
2. Post PR comment: "❌ **Omniscient Agent** — Review failed at stage: `{current_stage}`. Error: `{error}`"
3. Send Slack notification about the failure

### 10.3 Conditional Edges (`app/workflows/pr_review/edges.py`)

```python
def route_scans(state: PRReviewState) -> str:
    if state.get("error"):
        return "error_node"
    classification = state.get("pr_classification", "feature")
    if classification == "docs":
        return "skip_scan"
    if state.get("has_dockerfile", False):
        return "scan_full"
    return "scan_fs"

def route_risk(state: PRReviewState) -> str:
    if state.get("error"):
        return "error_node"
    risk = state.get("risk_score", "MEDIUM")
    if risk in ("CRITICAL", "HIGH"):
        return "escalate"
    return "report"
```

---

## 11. SERVICE SPECIFICATIONS

### 11.1 `services/git_service.py`
- `async def clone_repo(clone_url: str, branch: str, workspace: str) -> Path` — `git clone --depth 1 --branch {branch}` via `asyncio.create_subprocess_exec`
- `async def get_pr_diff(repo_full_name: str, pr_number: int) -> str` — GET GitHub API with `Accept: application/vnd.github.v3.diff` via `httpx.AsyncClient`

### 11.2 `services/trivy_service.py`
- `async def scan_image(image_tag: str, severity: str) -> dict` — runs `trivy image --format json --severity {severity} --timeout 5m0s {image_tag}` via `asyncio.create_subprocess_exec`, parses JSON stdout
- `async def scan_filesystem(path: str, severity: str) -> dict` — runs `trivy fs --format json`
- **Parsing logic:** Trivy JSON has `Results[]`, each with `Vulnerabilities[]` (can be `null`). Flatten all vulns, build summary `{"CRITICAL": N, "HIGH": N, ...}`, extract top 15 by severity.

### 11.3 `services/gitleaks_service.py`
- `async def scan_repo(repo_path: str) -> dict` — runs `gitleaks detect --source {repo_path} --report-format json --report-path /dev/stdout --no-banner` via `asyncio.create_subprocess_exec`
- Returns `{"findings": [...], "count": N}`

### 11.4 `services/docker_service.py`
- `async def build_image(context_path: Path, image_tag: str) -> tuple[bool, str]` — 300s timeout
- `async def remove_image(image_tag: str) -> None` — fire-and-forget
- `async def check_dockerfile(repo_path: Path) -> bool` — checks for Dockerfile in repo root

### 11.5 `services/github_api.py`
All calls use `httpx.AsyncClient` with `Authorization: Bearer {GITHUB_TOKEN}` header.
- `async def post_pr_comment(repo: str, pr_number: int, body: str) -> None` — POST `/repos/{repo}/issues/{pr_number}/comments`
- `async def set_commit_status(repo: str, sha: str, state: str, description: str) -> None` — POST `/repos/{repo}/statuses/{sha}`
- `async def validate_webhook_signature(body: bytes, signature: str, secret: str) -> bool` — HMAC-SHA256

### 11.6 `services/slack_api.py`
- `async def send_notification(channel: str, text: str, blocks: list | None) -> None` — uses `AsyncWebClient`
- `async def request_approval(channel: str, pr_info: dict, findings: list) -> None` — posts Block Kit with action buttons
- If `SLACK_BOT_TOKEN` is empty, all functions log a warning and return silently (Slack is optional).

### 11.7 `services/knowledge.py`
All functions use `psycopg` async connection from a pool created at startup.
- `async def get_repo_history(repo: str, limit: int = 10) -> list[dict]` — last N reviews for this repo
- `async def save_scan_result(repo, scan_type, trigger_type, trigger_ref, summary, raw_output) -> None`
- `async def save_pr_review(repo, pr_number, ...) -> None` — INSERT ON CONFLICT UPDATE
- `async def update_repo_profile(repo, risk_score) -> None` — upsert, recalculate averages
- `async def get_repo_profile(repo) -> dict | None`

---

## 12. FASTAPI APP (`app/main.py`)

```python
from contextlib import asynccontextmanager
from fastapi import FastAPI
import structlog
from app.config import get_settings
from app.engine.checkpointer import get_checkpointer
from app.llm.ollama import get_llm
from app.routers import webhooks, callbacks, health

@asynccontextmanager
async def lifespan(app: FastAPI):
    log = structlog.get_logger()
    settings = get_settings()

    # Initialize PostgreSQL checkpointer
    checkpointer = await get_checkpointer()
    await checkpointer.setup()
    app.state.checkpointer = checkpointer
    log.info("checkpointer_ready")

    # Initialize DB connection pool for knowledge service
    from app.services.knowledge import init_pool, close_pool
    await init_pool()
    log.info("knowledge_pool_ready")

    # Verify Ollama connectivity
    try:
        llm = get_llm()
        log.info("ollama_connected", model=settings.ollama_model)
    except Exception as e:
        log.warning("ollama_not_reachable", error=str(e))

    # Register workflows
    from app.engine.registry import register_all_workflows
    register_all_workflows(checkpointer)
    log.info("workflows_registered")

    yield

    await close_pool()
    log.info("agent_shutdown")

app = FastAPI(title="Omniscient DevSecOps AI Agent", version="0.1.0", lifespan=lifespan)
app.include_router(webhooks.router)
app.include_router(callbacks.router)
app.include_router(health.router)
```

---

## 13. WEBHOOK ROUTER (`app/routers/webhooks.py`)

```python
@router.post("/webhooks/github", status_code=202)
async def github_webhook(request: Request, background_tasks: BackgroundTasks):
    body = await request.body()
    signature = request.headers.get("X-Hub-Signature-256", "")

    # 1. Validate HMAC
    if not await validate_webhook_signature(body, signature, settings.github_webhook_secret):
        raise HTTPException(403, "Invalid signature")

    payload = await request.json()
    event_type = request.headers.get("X-GitHub-Event", "")

    # 2. Filter — only handle pull_request opened/synchronize
    if event_type != "pull_request":
        return {"message": "event ignored", "event": event_type}
    action = payload.get("action", "")
    if action not in ("opened", "synchronize"):
        return {"message": "action ignored", "action": action}

    # 3. Dispatch to workflow engine
    task_id = str(uuid4())
    background_tasks.add_task(dispatch_event, "pull_request", payload, task_id)
    return {"message": "processing", "task_id": task_id}
```

---

## 14. LOGGING

Use `structlog` everywhere. Configure in `app/main.py`:
```python
structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.dev.set_exc_info,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
    cache_logger_on_first_use=True,
)
```

Every service function: `log = structlog.get_logger().bind(service="trivy")` and log at start, success, failure.

---

## 15. NGINX (`nginx/nginx.conf`)

Route `/webhooks/github` and `/callbacks/slack` to agent. Route `/jenkins/` and `/sonarqube/` to respective services. Set `proxy_read_timeout 600s` on agent routes (LLM calls are slow). Forward `X-Hub-Signature-256` header.

---

## 16. TESTS

### `tests/conftest.py`
- Fixture: `async_client` — `httpx.AsyncClient` with `ASGITransport(app)`
- Fixture: `sample_pr_webhook` — complete GitHub PR webhook payload dict
- Fixture: `sample_trivy_output` — realistic Trivy JSON with 3 CRITICAL, 5 HIGH vulns
- Fixture: `sample_trivy_empty` — Trivy JSON with `Vulnerabilities: null`
- Fixture: `sample_gitleaks_output` — Gitleaks JSON with 2 findings

### `tests/test_webhook_handler.py`
- Test invalid HMAC → 403
- Test non-pull_request event → 200 "event ignored"
- Test pull_request with action="closed" → 200 "action ignored"
- Test valid pull_request opened → 202 with task_id

### `tests/test_pr_review_graph.py`
- Test full graph with all services mocked → reaches report node
- Test docs-only classification → skips scan
- Test error in clone → reaches error node, posts failure comment

### `tests/test_trivy_parsing.py`
- Test parsing realistic Trivy JSON → correct summary counts
- Test parsing empty Trivy output (no vulns) → summary all zeros
- Test top-N extraction ordered by severity

---

## 17. SCAFFOLD FILES FOR FUTURE WORKFLOWS

For each of `pipeline_gate`, `scheduled_audit`, `cve_watch`, `incident_triage`, `compliance_drift`:

Create `__init__.py` and `graph.py` containing ONLY:
```python
"""
{Workflow Name} Workflow

Trigger: {description}
Status: SCAFFOLD — not yet implemented.
"""

# from langgraph.graph import StateGraph
# Implementation in Phase {N}
```

Do NOT implement any logic. These are placeholders that show the architecture is ready.

---

## 18. STARTUP SCRIPT (`scripts/start.sh`)

```bash
#!/usr/bin/env bash
set -euo pipefail

echo "=== Omniscient DevSecOps AI Agent — Startup ==="

[ ! -f /opt/devsecops/.env ] && echo "ERROR: .env not found" && exit 1

sudo sysctl -w vm.max_map_count=524288
sudo sysctl -w fs.file-max=131072

cd /opt/devsecops
docker compose pull
docker compose build --no-cache agent jenkins
docker compose up -d

echo "Waiting for Ollama..."
sleep 10
docker exec ollama ollama pull qwen2.5-coder:32b

echo ""
echo "=== Services ==="
echo "Agent:     http://141.94.92.226:8000/health"
echo "Jenkins:   http://141.94.92.226:8080"
echo "SonarQube: http://141.94.92.226:9000"
echo "Ollama:    http://141.94.92.226:11434"
```

---

## 19. WHAT NOT TO DO

- **No LangChain chains, agents, or `@tool` decorators.** LangGraph replaces chains. Services are plain async functions called by graph nodes.
- **No ReAct loops.** The LLM never picks tools. Graph nodes call services directly.
- **No `subprocess.run()` or `os.system()`.** Use `asyncio.create_subprocess_exec()` everywhere.
- **No synchronous `requests` library.** Use `httpx.AsyncClient` for all HTTP.
- **No hardcoded secrets.** Everything from `.env` via `pydantic-settings`.
- **No external LLM APIs.** All calls to `http://ollama:11434`.
- **No `with_structured_output()` or tool binding on ChatOllama.** Qwen 32B is unreliable with these. Use `format="json"` for classifier, regex JSON extraction for analyzer.
- **No partial files.** Every file must be complete and runnable.
- **No CrewAI.** Multi-workflow is handled by the registry + dispatcher pattern.

---

## 20. FILE GENERATION ORDER

Generate ALL files in this order:

1. `/opt/devsecops/.env.example`
2. `/opt/devsecops/.env`
3. `/opt/devsecops/docker-compose.yml`
4. `/opt/devsecops/db/init.sql`
5. `/opt/devsecops/nginx/nginx.conf`
6. `/opt/devsecops/jenkins/Dockerfile`
7. `/opt/devsecops/agent/Dockerfile`
8. `/opt/devsecops/agent/requirements.txt`
9. `/opt/devsecops/agent/app/__init__.py`
10. `/opt/devsecops/agent/app/config.py`
11. `/opt/devsecops/agent/app/main.py`
12. `/opt/devsecops/agent/app/models/__init__.py`
13. `/opt/devsecops/agent/app/models/state.py`
14. `/opt/devsecops/agent/app/models/github_webhooks.py`
15. `/opt/devsecops/agent/app/models/db.py`
16. `/opt/devsecops/agent/app/llm/__init__.py`
17. `/opt/devsecops/agent/app/llm/ollama.py`
18. `/opt/devsecops/agent/app/engine/__init__.py`
19. `/opt/devsecops/agent/app/engine/checkpointer.py`
20. `/opt/devsecops/agent/app/engine/registry.py`
21. `/opt/devsecops/agent/app/engine/dispatcher.py`
22. `/opt/devsecops/agent/app/services/__init__.py`
23. `/opt/devsecops/agent/app/services/git_service.py`
24. `/opt/devsecops/agent/app/services/trivy_service.py`
25. `/opt/devsecops/agent/app/services/gitleaks_service.py`
26. `/opt/devsecops/agent/app/services/docker_service.py`
27. `/opt/devsecops/agent/app/services/github_api.py`
28. `/opt/devsecops/agent/app/services/slack_api.py`
29. `/opt/devsecops/agent/app/services/knowledge.py`
30. `/opt/devsecops/agent/app/prompts/__init__.py`
31. `/opt/devsecops/agent/app/prompts/classifier.py`
32. `/opt/devsecops/agent/app/prompts/security_review.py`
33. `/opt/devsecops/agent/app/prompts/templates.py`
34. `/opt/devsecops/agent/app/routers/__init__.py`
35. `/opt/devsecops/agent/app/routers/webhooks.py`
36. `/opt/devsecops/agent/app/routers/callbacks.py`
37. `/opt/devsecops/agent/app/routers/health.py`
38. `/opt/devsecops/agent/app/workflows/__init__.py`
39. `/opt/devsecops/agent/app/workflows/pr_review/__init__.py`
40. `/opt/devsecops/agent/app/workflows/pr_review/state.py`
41. `/opt/devsecops/agent/app/workflows/pr_review/nodes.py`
42. `/opt/devsecops/agent/app/workflows/pr_review/edges.py`
43. `/opt/devsecops/agent/app/workflows/pr_review/graph.py`
44-48. Scaffold `__init__.py` + `graph.py` for pipeline_gate, scheduled_audit, cve_watch, incident_triage, compliance_drift
49. `/opt/devsecops/agent/tests/__init__.py`
50. `/opt/devsecops/agent/tests/conftest.py`
51. `/opt/devsecops/agent/tests/test_webhook_handler.py`
52. `/opt/devsecops/agent/tests/test_pr_review_graph.py`
53. `/opt/devsecops/agent/tests/test_trivy_parsing.py`
54. `/opt/devsecops/agent/tests/test_knowledge_service.py`
55. `/opt/devsecops/scripts/start.sh`

---

## 21. VALIDATION CHECKLIST

After generating all files, verify:
- [ ] `docker compose config` passes (valid YAML, all env vars referenced)
- [ ] `python -m pytest agent/tests/` discovers all tests
- [ ] HMAC-SHA256 webhook validation is correct
- [ ] Ollama calls use `/api/chat` endpoint (ChatOllama handles this) at `http://ollama:11434`
- [ ] Trivy JSON parsing handles both "vulns found" and "null vulns" cases
- [ ] Gitleaks JSON parsing handles both "findings" and "no findings" cases
- [ ] Diff truncation caps at 30,000 chars
- [ ] Classifier uses `format="json"`, analyzer does NOT
- [ ] Error in any node → error_node → PR failure comment posted
- [ ] structlog used in every service module with `.bind(service="name")`
- [ ] Knowledge base writes happen in scan_node and analyze_node
- [ ] Repo history is injected into the analyzer prompt
- [ ] All five scaffold workflow directories exist with docstring-only graph.py
- [ ] The registry only registers `pull_request` → pr_review_graph (others commented out)
- [ ] PostgreSQL `init.sql` creates ALL tables (full schema for future workflows)
- [ ] `interrupt_before=["escalate"]` is set on graph compilation
- [ ] All subprocess calls use `asyncio.create_subprocess_exec`, never `subprocess.run`

**BEGIN. Generate all 55 files now.**
