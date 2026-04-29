import structlog
from fastapi import APIRouter

from app.config import get_settings

log = structlog.get_logger().bind(service="health")
router = APIRouter(tags=["health"])


@router.get("/health")
async def health():
    """Basic liveness probe."""
    return {"status": "healthy", "agent": "SECURITY AI AGENT"}


@router.get("/readiness")
async def readiness():
    """Readiness probe — checks dependencies are available."""
    settings = get_settings()

    # Check Redis connectivity
    redis_ok = False
    try:
        from app.services.cache import _get_redis
        r = _get_redis()
        if r:
            await r.ping()
            redis_ok = True
    except Exception:
        redis_ok = False

    # Check Ollama connectivity
    ollama_ok = False
    try:
        from app.llm.ollama import check_ollama_health
        ollama_ok = await check_ollama_health()
    except Exception:
        ollama_ok = False

    checks = {
        "agent": "ready",
        "ollama": ollama_ok,
        "redis": redis_ok,
        "postgres_configured": bool(settings.postgres_host),
        "github_configured": bool(settings.github_token),
    }

    all_ready = all(checks.values())
    return {
        "status": "ready" if all_ready else "degraded",
        "checks": checks,
    }
