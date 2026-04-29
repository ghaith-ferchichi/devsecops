-- ============================================
-- OMNISCIENT DEVSECOPS AI AGENT — DB SCHEMA
-- Covers all 6 workflows (full architecture)
-- ============================================

-- Repository security profiles
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

-- Scan results from all scanners
CREATE TABLE IF NOT EXISTS scan_results (
    id              SERIAL PRIMARY KEY,
    repo_full_name  TEXT NOT NULL,
    scan_type       TEXT NOT NULL,
    trigger_type    TEXT NOT NULL,
    trigger_ref     TEXT,
    summary         JSONB NOT NULL,
    raw_output      JSONB,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_scan_results_repo ON scan_results(repo_full_name, created_at DESC);

-- PR review history
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
);
CREATE INDEX idx_pr_reviews_repo ON pr_reviews(repo_full_name, created_at DESC);

-- Software bill of materials cache
CREATE TABLE IF NOT EXISTS sbom_cache (
    id              SERIAL PRIMARY KEY,
    repo_full_name  TEXT NOT NULL,
    package_name    TEXT NOT NULL,
    package_version TEXT NOT NULL,
    package_type    TEXT,
    scan_source     TEXT,
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_sbom_repo ON sbom_cache(repo_full_name);
CREATE INDEX idx_sbom_package ON sbom_cache(package_name, package_version);

-- Organization security policies
CREATE TABLE IF NOT EXISTS security_policies (
    id              SERIAL PRIMARY KEY,
    policy_name     TEXT UNIQUE NOT NULL,
    policy_type     TEXT NOT NULL,
    config          JSONB NOT NULL,
    enabled         BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- Runtime incidents
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
);

-- Default security policies
INSERT INTO security_policies (policy_name, policy_type, config) VALUES
    ('block_critical_vulns', 'vuln_threshold', '{"max_critical": 0, "max_high": 5}'),
    ('require_secret_scan', 'secret_scan', '{"enabled": true, "block_on_finding": true}'),
    ('base_image_age', 'image_age', '{"max_days": 90}')
ON CONFLICT (policy_name) DO NOTHING;
