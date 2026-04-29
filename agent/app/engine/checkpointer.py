from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

from app.config import get_settings

_checkpointer: AsyncPostgresSaver | None = None
_cm = None  # context manager kept alive for the app's lifetime


async def init_checkpointer() -> AsyncPostgresSaver:
    """Enter the AsyncPostgresSaver context manager and return the live saver."""
    global _checkpointer, _cm
    settings = get_settings()
    _cm = AsyncPostgresSaver.from_conn_string(settings.postgres_dsn)
    _checkpointer = await _cm.__aenter__()
    return _checkpointer


async def close_checkpointer() -> None:
    """Exit the checkpointer context manager on shutdown."""
    global _cm
    if _cm is not None:
        await _cm.__aexit__(None, None, None)
        _cm = None


async def get_checkpointer() -> AsyncPostgresSaver:
    return _checkpointer
