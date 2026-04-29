import json

import structlog

from app.config import get_settings

log = structlog.get_logger().bind(service="cache")

_redis = None


async def init_redis() -> None:
    """Initialize the Redis async connection."""
    global _redis
    settings = get_settings()
    try:
        import redis.asyncio as aioredis
        _redis = aioredis.from_url(
            settings.redis_url,
            decode_responses=True,
            socket_connect_timeout=5,
        )
        await _redis.ping()
        log.info("redis_connected", url=settings.redis_url)
    except Exception as e:
        log.warning("redis_connection_failed", error=str(e))
        _redis = None


async def close_redis() -> None:
    """Close the Redis connection."""
    global _redis
    if _redis:
        await _redis.aclose()
        _redis = None
        log.info("redis_closed")


def _get_redis():
    return _redis


async def is_duplicate(key: str) -> bool:
    """Check if a webhook event is a duplicate. Sets key with 1-hour TTL."""
    r = _get_redis()
    if not r:
        return False
    try:
        result = await r.set(key, "1", nx=True, ex=3600)
        return result is None  # None means key already existed
    except Exception as e:
        log.warning("redis_dedup_error", error=str(e))
        return False


async def check_rate_limit(repo: str, max_concurrent: int = 3) -> bool:
    """Check if repo is at its concurrent processing limit. Returns True if over limit."""
    r = _get_redis()
    if not r:
        return False
    try:
        key = f"rate:{repo}"
        count = await r.incr(key)
        if count == 1:
            await r.expire(key, 600)  # 10 min window
        return count > max_concurrent
    except Exception as e:
        log.warning("redis_rate_limit_error", error=str(e))
        return False


async def release_rate_limit(repo: str) -> None:
    """Decrement the rate limit counter for a repo."""
    r = _get_redis()
    if not r:
        return
    try:
        key = f"rate:{repo}"
        await r.decr(key)
    except Exception as e:
        log.warning("redis_rate_release_error", error=str(e))


async def get_scan(key: str) -> dict | None:
    """Get a cached scan result."""
    r = _get_redis()
    if not r:
        return None
    try:
        data = await r.get(key)
        if data:
            return json.loads(data)
        return None
    except Exception as e:
        log.warning("redis_get_error", error=str(e))
        return None


async def set_scan(key: str, result: dict, ttl: int = 3600) -> None:
    """Cache a scan result with TTL (default 1 hour)."""
    r = _get_redis()
    if not r:
        return
    try:
        await r.set(key, json.dumps(result, default=str), ex=ttl)
    except Exception as e:
        log.warning("redis_set_error", error=str(e))
