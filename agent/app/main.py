import asyncio
import logging
import logging.handlers
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import structlog
from fastapi import FastAPI
from prometheus_fastapi_instrumentator import Instrumentator

from app.config import get_settings
from app.routers import callbacks, chat, health, webhooks

# Ensure artifacts/logs directory exists before configuring logging
_settings = get_settings()
_log_dir = Path(_settings.artifacts_path) / "logs"
_log_dir.mkdir(parents=True, exist_ok=True)

# Shared processor chain used by both handlers
_shared_processors = [
    structlog.contextvars.merge_contextvars,
    structlog.processors.add_log_level,
    structlog.processors.StackInfoRenderer(),
    structlog.dev.set_exc_info,
    structlog.processors.TimeStamper(fmt="iso"),
]

# Configure structlog to use stdlib so both handlers receive every log line
structlog.configure(
    processors=_shared_processors + [
        structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
    ],
    wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

# Console handler — human-readable (same as before)
_console_handler = logging.StreamHandler()
_console_handler.setFormatter(
    structlog.stdlib.ProcessorFormatter(
        processor=structlog.dev.ConsoleRenderer(),
        foreign_pre_chain=_shared_processors,
    )
)

# Rotating file handler — JSON lines, 50 MB × 10 files = 500 MB max
_file_handler = logging.handlers.RotatingFileHandler(
    str(_log_dir / "agent.log"),
    maxBytes=50 * 1024 * 1024,
    backupCount=10,
    encoding="utf-8",
)
_file_handler.setFormatter(
    structlog.stdlib.ProcessorFormatter(
        processor=structlog.processors.JSONRenderer(),
        foreign_pre_chain=_shared_processors,
    )
)

_root_logger = logging.getLogger()
_root_logger.addHandler(_console_handler)
_root_logger.addHandler(_file_handler)
_root_logger.setLevel(logging.INFO)


async def _poll_docker_stats():
    """Poll docker socket every 30s and update per-container Prometheus gauges.

    Replaces cAdvisor — incompatible with this host's Docker (containerd
    snapshotter). Reads the Docker Engine API over /var/run/docker.sock:
      GET /containers/json
      GET /containers/{id}/stats?stream=false
    """
    from app.metrics.custom import (
        container_running, container_memory_bytes, container_memory_limit_bytes,
        container_cpu_percent, container_network_rx_bytes, container_network_tx_bytes,
    )
    log = structlog.get_logger().bind(service="docker_stats")

    transport = httpx.AsyncHTTPTransport(uds="/var/run/docker.sock")
    seen_names: set[str] = set()

    while True:
        try:
            async with httpx.AsyncClient(transport=transport, base_url="http://docker",
                                        timeout=10.0) as client:
                resp = await client.get("/containers/json")
                if resp.status_code != 200:
                    log.warning("docker_list_failed", status=resp.status_code)
                    await asyncio.sleep(30)
                    continue
                containers = resp.json()
                current_names: set[str] = set()
                for c in containers:
                    cid = c["Id"]
                    name = (c.get("Names") or ["?"])[0].lstrip("/")
                    image = c.get("Image", "?")
                    current_names.add(name)
                    container_running.labels(name=name, image=image).set(1)

                    try:
                        s = await client.get(f"/containers/{cid}/stats", params={"stream": "false"})
                        if s.status_code != 200:
                            continue
                        st = s.json()

                        # ── Memory ──────────────────────────────────────
                        mem = st.get("memory_stats", {}) or {}
                        # cgroup v2: usage already excludes inactive_file/cache when present
                        usage = mem.get("usage", 0) or 0
                        limit = mem.get("limit", 0) or 0
                        container_memory_bytes.labels(name=name, image=image).set(usage)
                        container_memory_limit_bytes.labels(name=name, image=image).set(limit)

                        # ── CPU % ───────────────────────────────────────
                        cpu = st.get("cpu_stats", {}) or {}
                        precpu = st.get("precpu_stats", {}) or {}
                        cpu_total = (cpu.get("cpu_usage") or {}).get("total_usage", 0)
                        pre_total = (precpu.get("cpu_usage") or {}).get("total_usage", 0)
                        sys_now = cpu.get("system_cpu_usage", 0) or 0
                        sys_pre = precpu.get("system_cpu_usage", 0) or 0
                        online = cpu.get("online_cpus") or len((cpu.get("cpu_usage") or {}).get("percpu_usage", []) or [1])
                        cpu_delta = cpu_total - pre_total
                        sys_delta = sys_now - sys_pre
                        cpu_pct = (cpu_delta / sys_delta) * online * 100.0 if sys_delta > 0 else 0.0
                        container_cpu_percent.labels(name=name, image=image).set(max(0.0, cpu_pct))

                        # ── Network ─────────────────────────────────────
                        nets = st.get("networks") or {}
                        rx = sum(int(n.get("rx_bytes", 0)) for n in nets.values())
                        tx = sum(int(n.get("tx_bytes", 0)) for n in nets.values())
                        container_network_rx_bytes.labels(name=name).set(rx)
                        container_network_tx_bytes.labels(name=name).set(tx)
                    except Exception as exc:
                        log.debug("container_stats_failed", name=name, error=str(exc))

                # Zero out gauges for containers that disappeared since last poll
                for stale in seen_names - current_names:
                    try:
                        container_running.labels(name=stale, image="").set(0)
                    except Exception:
                        pass
                seen_names = current_names
        except Exception as exc:
            log.warning("docker_stats_poll_failed", error=str(exc))
        await asyncio.sleep(30)


async def _poll_localai_metrics():
    """Poll LocalAI /readyz + /v1/models every 30s.

    LocalAI is an optional sandbox backend (docker-compose.localai.yml).
    The poller silently sets the gauges to 0 if the service is absent —
    operators see this in Grafana / Prometheus without any error spam in logs.

    Also publishes per-model presence (localai_model_installed{model}) and
    on-disk size (localai_model_size_gb{model}) from the static catalog in
    app.routers.chat — keeps Grafana's "Installed Models" table populated.
    """
    import time as _time
    from app.metrics.custom import (
        localai_reachable, localai_models_total,
        localai_health_check_latency_seconds,
        localai_model_installed, localai_model_size_gb,
    )
    log = structlog.get_logger().bind(service="localai_metrics")
    settings = get_settings()

    # Imported lazily — chat module pulls in langchain on import (slow).
    try:
        from app.routers.chat import LOCALAI_MODEL_META as _META
    except Exception:
        _META = {}

    while True:
        try:
            start = _time.perf_counter()
            async with httpx.AsyncClient(timeout=3) as client:
                ready = await client.get(f"{settings.localai_base_url}/readyz")
                latency = _time.perf_counter() - start
                localai_health_check_latency_seconds.set(latency)
                if ready.status_code == 200:
                    localai_reachable.set(1)
                    models = await client.get(f"{settings.localai_base_url}/v1/models")
                    if models.status_code == 200:
                        data = models.json().get("data", [])
                        # Filter vision projectors + raw GGUF files (not chat models)
                        chat_ids = {
                            m["id"] for m in data
                            if m.get("id")
                            and "mmproj" not in m["id"].lower()
                            and not m["id"].endswith(".gguf")
                        }
                        localai_models_total.set(len(chat_ids))
                        for mid in chat_ids:
                            localai_model_installed.labels(model=mid).set(1)
                            size = (_META.get(mid) or {}).get("size_gb", 0)
                            localai_model_size_gb.labels(model=mid).set(size)
                        # Zero out labels that disappeared since last poll
                        for metric_key in list(localai_model_installed._metrics.keys()):
                            label_name = metric_key[0] if metric_key else None
                            if label_name and label_name not in chat_ids:
                                localai_model_installed.labels(model=label_name).set(0)
                                localai_model_size_gb.labels(model=label_name).set(0)
                else:
                    localai_reachable.set(0)
                    localai_models_total.set(0)
        except Exception:
            localai_reachable.set(0)
            localai_models_total.set(0)
            localai_health_check_latency_seconds.set(0)
        await asyncio.sleep(30)


async def _poll_ollama_metrics():
    """Poll Ollama /api/ps every 30s and update Prometheus gauges."""
    from app.metrics.custom import (
        ollama_model_loaded, ollama_model_size_bytes,
        ollama_model_vram_bytes, ollama_models_loaded_total,
        ollama_reachable,
    )
    log = structlog.get_logger().bind(service="ollama_metrics")
    settings = get_settings()

    while True:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(f"{settings.ollama_base_url}/api/ps")
                if resp.status_code == 200:
                    ollama_reachable.set(1)
                    models = resp.json().get("models", [])
                    active_names = set()
                    for m in models:
                        name = m.get("name", "unknown")
                        active_names.add(name)
                        ollama_model_loaded.labels(model=name).set(1)
                        ollama_model_size_bytes.labels(model=name).set(m.get("size", 0))
                        ollama_model_vram_bytes.labels(model=name).set(m.get("size_vram", 0))
                    ollama_models_loaded_total.set(len(models))
                    # Zero out models no longer loaded
                    for metric in list(ollama_model_loaded._metrics.keys()):
                        label_name = metric[0] if metric else None
                        if label_name and label_name not in active_names:
                            ollama_model_loaded.labels(model=label_name).set(0)
                            ollama_model_size_bytes.labels(model=label_name).set(0)
                            ollama_model_vram_bytes.labels(model=label_name).set(0)
                else:
                    ollama_reachable.set(0)
        except Exception:
            ollama_reachable.set(0)
        await asyncio.sleep(30)


@asynccontextmanager
async def lifespan(app: FastAPI):
    log = structlog.get_logger()
    settings = get_settings()

    # Initialize Redis (graceful — pipeline works without it)
    from app.services.cache import init_redis, close_redis
    await init_redis()

    # Initialize PostgreSQL checkpointer
    from app.engine.checkpointer import init_checkpointer
    checkpointer = await init_checkpointer()
    await checkpointer.setup()
    app.state.checkpointer = checkpointer
    log.info("checkpointer_ready")

    # Initialize DB connection pool for knowledge service
    from app.services.knowledge import init_pool, close_pool
    await init_pool()
    log.info("knowledge_pool_ready")

    # Verify Ollama connectivity (dual model)
    from app.llm.ollama import check_ollama_health
    if await check_ollama_health():
        log.info(
            "ollama_connected",
            fast_model=settings.ollama_model_fast,
            deep_model=settings.ollama_model_deep,
        )
    else:
        log.warning("ollama_not_reachable")

    # Register workflows
    from app.engine.registry import register_all_workflows
    register_all_workflows(checkpointer)
    log.info("workflows_registered")

    # Start Ollama metrics poller
    ollama_poller = asyncio.create_task(_poll_ollama_metrics())
    log.info("ollama_metrics_poller_started")

    # Start LocalAI metrics poller (silent if sandbox is not running)
    localai_poller = asyncio.create_task(_poll_localai_metrics())
    log.info("localai_metrics_poller_started")

    # Start docker-stats poller (per-container CPU/RAM/Net, replaces cAdvisor)
    docker_poller = asyncio.create_task(_poll_docker_stats())
    log.info("docker_stats_poller_started")

    # Start autonomous scheduler (disk guard every 30min + daily Slack digest)
    from app.services.scheduler import start_scheduler
    scheduler_tasks = start_scheduler()

    yield

    ollama_poller.cancel()
    localai_poller.cancel()
    docker_poller.cancel()
    for t in scheduler_tasks:
        t.cancel()

    await close_redis()
    await close_pool()
    from app.engine.checkpointer import close_checkpointer
    await close_checkpointer()
    log.info("agent_shutdown")


app = FastAPI(
    title="SECURITY AI AGENT",
    description="DevSecOps AI Agent — Event-driven security workflow engine",
    version="0.2.0",
    lifespan=lifespan,
)

# Prometheus HTTP metrics (request count, latency, in-progress)
Instrumentator().instrument(app).expose(app, endpoint="/metrics")

app.include_router(webhooks.router)
app.include_router(callbacks.router)
app.include_router(health.router)
app.include_router(chat.router)
