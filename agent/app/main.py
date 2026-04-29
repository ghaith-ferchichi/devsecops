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

    # Start autonomous scheduler (disk guard every 30min + daily Slack digest)
    from app.services.scheduler import start_scheduler
    scheduler_tasks = start_scheduler()

    yield

    ollama_poller.cancel()
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
