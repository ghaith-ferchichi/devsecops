"""
Database table definitions as raw SQL constants.

Tables are created by db/init.sql at PostgreSQL startup.
These constants are kept here for reference and for any
dynamic query building in the knowledge service.
"""

TABLES = {
    "repo_profiles": """
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
        )
    """,
    "scan_results": """
        CREATE TABLE IF NOT EXISTS scan_results (
            id              SERIAL PRIMARY KEY,
            repo_full_name  TEXT NOT NULL,
            scan_type       TEXT NOT NULL,
            trigger_type    TEXT NOT NULL,
            trigger_ref     TEXT,
            summary         JSONB NOT NULL,
            raw_output      JSONB,
            created_at      TIMESTAMPTZ DEFAULT NOW()
        )
    """,
    "pr_reviews": """
        CREATE TABLE IF NOT EXISTS pr_reviews (
            id              SERIAL PRIMARY KEY,
            repo_full_name  TEXT NOT NULL,
            pr_number       INTEGER NOT NULL,
            pr_title        TEXT,
            pr_author       TEXT,
            classification  TEXT,
            risk_score      TEXT,
            verdict         TEXT,
            review_markdown TEXT,
            scan_summary    JSONB,
            files_changed   JSONB,
            approval_status TEXT DEFAULT 'auto',
            duration_ms     INTEGER,
            created_at      TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE(repo_full_name, pr_number)
        )
    """,
    "sbom_cache": """
        CREATE TABLE IF NOT EXISTS sbom_cache (
            id              SERIAL PRIMARY KEY,
            repo_full_name  TEXT NOT NULL,
            package_name    TEXT NOT NULL,
            package_version TEXT NOT NULL,
            package_type    TEXT,
            scan_source     TEXT,
            updated_at      TIMESTAMPTZ DEFAULT NOW()
        )
    """,
    "security_policies": """
        CREATE TABLE IF NOT EXISTS security_policies (
            id              SERIAL PRIMARY KEY,
            policy_name     TEXT UNIQUE NOT NULL,
            policy_type     TEXT NOT NULL,
            config          JSONB NOT NULL,
            enabled         BOOLEAN DEFAULT TRUE,
            created_at      TIMESTAMPTZ DEFAULT NOW()
        )
    """,
    "incidents": """
        CREATE TABLE IF NOT EXISTS incidents (
            id              SERIAL PRIMARY KEY,
            source          TEXT NOT NULL,
            severity        TEXT NOT NULL,
            title           TEXT NOT NULL,
            description     TEXT,
            related_repo    TEXT,
            related_pr      INTEGER,
            triage_result   TEXT,
            status          TEXT DEFAULT 'open',
            created_at      TIMESTAMPTZ DEFAULT NOW()
        )
    """,
}
