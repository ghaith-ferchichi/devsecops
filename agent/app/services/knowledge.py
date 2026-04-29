import json

import psycopg
import structlog
from psycopg_pool import AsyncConnectionPool

from app.config import get_settings

log = structlog.get_logger().bind(service="knowledge")

_pool: AsyncConnectionPool | None = None


async def init_pool() -> None:
    """Initialize the async connection pool."""
    global _pool
    settings = get_settings()
    _pool = AsyncConnectionPool(
        conninfo=(
            f"host={settings.postgres_host} port={settings.postgres_port} "
            f"dbname={settings.postgres_db} user={settings.postgres_user} "
            f"password={settings.postgres_password}"
        ),
        min_size=2,
        max_size=10,
        open=False,
    )
    await _pool.open()
    log.info("knowledge_pool_opened")


async def close_pool() -> None:
    """Close the connection pool."""
    global _pool
    if _pool:
        await _pool.close()
        _pool = None
        log.info("knowledge_pool_closed")


def _get_pool() -> AsyncConnectionPool:
    if _pool is None:
        raise RuntimeError("Knowledge DB pool not initialized. Call init_pool() first.")
    return _pool


async def get_repo_history(repo: str, limit: int = 10) -> list[dict]:
    """Fetch the last N PR reviews for a repo."""
    pool = _get_pool()
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                SELECT pr_number, pr_title, classification, risk_score, verdict,
                       scan_summary, created_at
                FROM pr_reviews
                WHERE repo_full_name = %s
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (repo, limit),
            )
            rows = await cur.fetchall()
            columns = [desc[0] for desc in cur.description]
            return [
                {col: (str(val) if not isinstance(val, (str, int, float, bool, type(None), dict, list)) else val)
                 for col, val in zip(columns, row)}
                for row in rows
            ]


async def save_scan_result(
    repo: str,
    scan_type: str,
    trigger_type: str,
    trigger_ref: str,
    summary: dict,
    raw_output: dict | None = None,
) -> None:
    """Insert a scan result into the database."""
    pool = _get_pool()
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                INSERT INTO scan_results
                    (repo_full_name, scan_type, trigger_type, trigger_ref, summary, raw_output)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (
                    repo,
                    scan_type,
                    trigger_type,
                    trigger_ref,
                    json.dumps(summary),
                    json.dumps(raw_output) if raw_output else None,
                ),
            )
        await conn.commit()
    log.info("scan_result_saved", repo=repo, scan_type=scan_type)


async def save_pr_review(
    repo: str,
    pr_number: int,
    pr_title: str,
    pr_author: str,
    classification: str,
    risk_score: str,
    verdict: str,
    review_markdown: str,
    scan_summary: dict,
    files_changed: list[str],
    approval_status: str = "auto",
    duration_ms: int | None = None,
) -> None:
    """Upsert a PR review record."""
    pool = _get_pool()
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                INSERT INTO pr_reviews
                    (repo_full_name, pr_number, pr_title, pr_author, classification,
                     risk_score, verdict, review_markdown, scan_summary, files_changed,
                     approval_status, duration_ms)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (repo_full_name, pr_number)
                DO UPDATE SET
                    pr_title = EXCLUDED.pr_title,
                    pr_author = EXCLUDED.pr_author,
                    classification = EXCLUDED.classification,
                    risk_score = EXCLUDED.risk_score,
                    verdict = EXCLUDED.verdict,
                    review_markdown = EXCLUDED.review_markdown,
                    scan_summary = EXCLUDED.scan_summary,
                    files_changed = EXCLUDED.files_changed,
                    approval_status = EXCLUDED.approval_status,
                    duration_ms = EXCLUDED.duration_ms
                """,
                (
                    repo,
                    pr_number,
                    pr_title,
                    pr_author,
                    classification,
                    risk_score,
                    verdict,
                    review_markdown,
                    json.dumps(scan_summary),
                    json.dumps(files_changed),
                    approval_status,
                    duration_ms,
                ),
            )
        await conn.commit()
    log.info("pr_review_saved", repo=repo, pr=pr_number)


async def update_repo_profile(repo: str, risk_score: str) -> None:
    """Upsert the repo profile and recalculate averages."""
    score_map = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
    numeric_score = score_map.get(risk_score, 3)

    pool = _get_pool()
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                """
                INSERT INTO repo_profiles (repo_full_name, risk_score_avg, total_reviews, last_scan_at, updated_at)
                VALUES (%s, %s, 1, NOW(), NOW())
                ON CONFLICT (repo_full_name)
                DO UPDATE SET
                    risk_score_avg = (
                        repo_profiles.risk_score_avg * repo_profiles.total_reviews + %s
                    ) / (repo_profiles.total_reviews + 1),
                    total_reviews = repo_profiles.total_reviews + 1,
                    last_scan_at = NOW(),
                    updated_at = NOW()
                """,
                (repo, numeric_score, numeric_score),
            )
        await conn.commit()
    log.info("repo_profile_updated", repo=repo, risk_score=risk_score)


async def get_repo_profile(repo: str) -> dict | None:
    """Fetch the repo profile."""
    pool = _get_pool()
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "SELECT * FROM repo_profiles WHERE repo_full_name = %s",
                (repo,),
            )
            row = await cur.fetchone()
            if not row:
                return None
            columns = [desc[0] for desc in cur.description]
            return {
                col: (str(val) if not isinstance(val, (str, int, float, bool, type(None), dict, list)) else val)
                for col, val in zip(columns, row)
            }
