import asyncio
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path

import structlog
from langchain_core.messages import HumanMessage, SystemMessage
from tenacity import retry, stop_after_attempt, wait_exponential

from app.config import get_settings
from app.llm.ollama import (
    get_combined_llm,
    get_deep_llm,
    get_fast_llm,
    get_review_llm,
    is_circuit_open,
    record_llm_failure,
    record_llm_success,
)
from app.metrics.custom import (
    agent_cache_hits,
    agent_errors_total,
    agent_llm_duration,
    agent_pipeline_duration,
    agent_reviews_total,
    agent_scan_duration,
)
from app.prompts.classifier import CLASSIFIER_SYSTEM_PROMPT, build_classifier_prompt
from app.prompts.code_review import _SYSTEM as CODE_REVIEW_SYSTEM, build_code_review_prompt
from app.prompts.combined_review import build_combined_review_prompt
from app.prompts.security_review import build_security_review_prompt
from app.services.diff_parser import diff_lines_for_file, format_diff_with_line_numbers, parse_diff
from app.prompts.templates import (
    format_checkov_findings,
    format_gitleaks_findings,
    format_osv_findings,
    format_repo_history,
    format_semgrep_findings,
    format_trivy_summary,
)
from app.services import (
    cache,
    checkov_service,
    docker_service,
    git_service,
    github_api,
    gitleaks_service,
    knowledge,
    osv_service,
    semgrep_service,
    slack_api,
    trivy_service,
)
from app.services import artifact_store
from app.workflows.pr_review.state import PRReviewState

log = structlog.get_logger().bind(service="pr_review_nodes")


# === SCAN SELECTION MATRIX ===
# classification → set of scanners to run (beyond trivy_fs + gitleaks which always run)
SCAN_MATRIX = {
    "feature":        {"semgrep"},
    "dependency":     {"osv"},
    "infrastructure": {"checkov"},
    "config":         set(),
    "docs":           set(),
}


async def intake_node(state: PRReviewState) -> dict:
    """Clone repo, fetch diff, gather metadata."""
    log.info("intake_start", pr=state["pr_number"], repo=state["repo_full_name"])
    settings = get_settings()

    try:
        # Redis dedup check
        dedup_key = f"pr:{state['repo_full_name']}:{state['pr_number']}:{state.get('head_sha', '')}"
        if await cache.is_duplicate(dedup_key):
            log.info("duplicate_webhook", key=dedup_key)
            return {"current_stage": "intake", "error": "duplicate webhook"}

        # Redis rate limit
        if await cache.check_rate_limit(state["repo_full_name"], max_concurrent=3):
            log.warning("rate_limit_exceeded", repo=state["repo_full_name"])
            return {"current_stage": "intake", "error": "rate limit exceeded"}

        # Post "in progress" comment
        await github_api.post_pr_comment(
            state["repo_full_name"],
            state["pr_number"],
            "**SECURITY AI AGENT** — Security review in progress...",
        )

        # Clone repo
        repo_path = await git_service.clone_repo(
            state["clone_url"],
            state["head_branch"],
            settings.agent_workspace,
        )

        # Generate -U15 diff using local git operations (more context than GitHub API -U3)
        try:
            diff = await git_service.get_local_diff(
                repo_path,
                state.get("base_branch", "main"),
            )
        except Exception as diff_err:
            log.warning("local_diff_failed_fallback", error=str(diff_err))
            diff = await git_service.get_pr_diff(
                state["repo_full_name"],
                state["pr_number"],
            )
        diff = git_service.truncate_diff(diff)

        # Check for Dockerfile
        has_dockerfile = await docker_service.check_dockerfile(repo_path)

        # Extract changed files
        files_changed = git_service.extract_changed_files(diff)

        # Get repo history
        try:
            repo_history = await knowledge.get_repo_history(
                state["repo_full_name"], limit=10
            )
        except Exception as e:
            log.warning("repo_history_fetch_failed", error=str(e))
            repo_history = []

        log.info(
            "intake_complete",
            pr=state["pr_number"],
            files=len(files_changed),
            diff_len=len(diff),
            has_dockerfile=has_dockerfile,
        )

        return {
            "current_stage": "intake",
            "started_at": datetime.now(timezone.utc).isoformat(),
            "repo_path": str(repo_path),
            "diff": diff,
            "has_dockerfile": has_dockerfile,
            "files_changed": files_changed,
            "repo_history": repo_history,
        }
    except Exception as e:
        log.error("intake_failed", error=str(e), pr=state["pr_number"])
        return {"current_stage": "intake", "error": str(e)}


def _fallback_classify(files: list[str]) -> str:
    """Regex-based classification fallback when LLM is unavailable."""
    doc_exts = {".md", ".txt", ".rst", ".adoc"}
    dep_files = {"requirements.txt", "package.json", "go.sum", "Cargo.lock", "poetry.lock", "Pipfile.lock", "yarn.lock", "pnpm-lock.yaml"}
    iac_files = {"Dockerfile", "docker-compose.yml", "docker-compose.yaml", ".github", "Jenkinsfile", "terraform", ".tf"}
    config_files = {".env.example", ".env.sample"}

    categories = {"docs": 0, "dependency": 0, "infrastructure": 0, "config": 0, "feature": 0}
    for f in files:
        name = Path(f).name
        ext = Path(f).suffix.lower()
        if ext in doc_exts:
            categories["docs"] += 1
        elif name in dep_files or name.endswith(".lock"):
            categories["dependency"] += 1
        elif name in iac_files or any(k in f for k in ("terraform", ".tf", "k8s", "helm")):
            categories["infrastructure"] += 1
        elif name in config_files:
            categories["config"] += 1
        else:
            categories["feature"] += 1

    return max(categories, key=categories.get)


@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
async def _invoke_classifier(messages: list) -> str:
    """Invoke the classifier LLM with retry logic."""
    llm = get_fast_llm()
    response = await llm.ainvoke(messages)
    return response.content


async def classify_node(state: PRReviewState) -> dict:
    """Classify the PR using the 7B fast LLM."""
    log.info("classify_start", pr=state["pr_number"])

    # Circuit breaker — fall back to regex classification
    if is_circuit_open():
        log.warning("circuit_breaker_active_classify", pr=state["pr_number"])
        classification = _fallback_classify(state.get("files_changed", []))
        return {
            "current_stage": "classify",
            "pr_classification": classification,
            "messages": [],
        }

    try:
        user_msg = build_classifier_prompt(
            state["pr_title"],
            state["pr_body"],
            state["files_changed"],
        )

        messages = [
            SystemMessage(content=CLASSIFIER_SYSTEM_PROMPT),
            HumanMessage(content=user_msg),
        ]

        start = time.time()
        response_text = await _invoke_classifier(messages)
        duration = time.time() - start
        agent_llm_duration.labels(model="7b", node="classify").observe(duration)

        result = json.loads(response_text)
        record_llm_success()

        classification = result.get("classification", "feature")
        valid_classifications = {"feature", "dependency", "infrastructure", "docs", "config"}
        if classification not in valid_classifications:
            classification = "feature"

        log.info(
            "classify_complete",
            pr=state["pr_number"],
            classification=classification,
            risk_hint=result.get("risk_hint"),
            duration=f"{duration:.1f}s",
        )

        return {
            "current_stage": "classify",
            "pr_classification": classification,
            "messages": [
                HumanMessage(content=user_msg),
                SystemMessage(content=response_text),
            ],
        }
    except Exception as e:
        record_llm_failure()
        log.error("classify_failed", error=str(e), pr=state["pr_number"])
        classification = _fallback_classify(state.get("files_changed", []))
        return {
            "current_stage": "classify",
            "pr_classification": classification,
            "messages": [],
        }


async def _run_scan(name: str, coro, repo_path: str) -> tuple[str, dict]:
    """Run a single scanner with error handling, caching, and metrics."""
    cache_key = f"scan:{name}:{repo_path}"

    # Check Redis cache
    cached = await cache.get_scan(cache_key)
    if cached:
        agent_cache_hits.inc()
        log.info("scan_cache_hit", scanner=name)
        coro.close()  # discard unawaited coroutine cleanly
        return name, cached

    start = time.time()
    try:
        result = await coro
        duration = time.time() - start
        agent_scan_duration.labels(scanner=name).observe(duration)
        log.info("scan_complete", scanner=name, duration=f"{duration:.1f}s")

        # Cache result (skip raw output to save Redis memory)
        cache_result = {k: v for k, v in result.items() if k != "raw"}
        await cache.set_scan(cache_key, cache_result, ttl=3600)

        return name, result
    except Exception as e:
        duration = time.time() - start
        agent_scan_duration.labels(scanner=name).observe(duration)
        log.error("scan_failed", scanner=name, error=str(e), duration=f"{duration:.1f}s")
        return name, {"scan_type": name, "error": str(e)}


async def scan_full_node(state: PRReviewState) -> dict:
    """Full scan: Docker build + all applicable scanners in parallel."""
    log.info("scan_full_start", pr=state["pr_number"])
    settings = get_settings()
    repo_path = state["repo_path"]
    classification = state.get("pr_classification", "feature")
    repo_name = state["repo_full_name"].replace("/", "-")
    image_tag = f"{repo_name}-pr-{state['pr_number']}:scan"

    # Docker build (sequential — needed before image scan)
    build_ok, build_msg = await docker_service.build_image(Path(repo_path), image_tag)
    if not build_ok:
        log.warning("docker_build_skipped", reason=build_msg)

    # Determine which scans to run based on classification matrix
    extra_scanners = SCAN_MATRIX.get(classification, set())
    tasks = []

    # Always: Trivy fs + Gitleaks
    tasks.append(_run_scan("trivy_fs", trivy_service.scan_filesystem(repo_path), repo_path))
    tasks.append(_run_scan("gitleaks", gitleaks_service.scan_repo(repo_path), repo_path))

    # Trivy image — only if Docker build succeeded
    if build_ok:
        tasks.append(_run_scan("trivy_image", trivy_service.scan_image(image_tag), repo_path))

    # Conditional scanners
    if "semgrep" in extra_scanners:
        tasks.append(_run_scan("semgrep", semgrep_service.scan_directory(repo_path), repo_path))
    if "checkov" in extra_scanners:
        tasks.append(_run_scan("checkov", checkov_service.scan_iac(repo_path), repo_path))
    if "osv" in extra_scanners:
        tasks.append(_run_scan("osv", osv_service.scan_lockfiles(repo_path), repo_path))

    # Run all scans in parallel
    results = await asyncio.gather(*tasks, return_exceptions=True)

    scan_results = {}
    for item in results:
        if isinstance(item, Exception):
            log.error("scan_gather_exception", error=str(item))
            continue
        name, result = item
        scan_results[name] = result

    # Persist scan results
    for scan_type, result in scan_results.items():
        summary = result.get("summary", {})
        if summary:
            try:
                await knowledge.save_scan_result(
                    state["repo_full_name"], scan_type, "pr_review",
                    str(state["pr_number"]), summary,
                )
            except Exception as e:
                log.warning("scan_result_save_failed", scan_type=scan_type, error=str(e))

    # Save raw scanner artifacts to disk
    settings = get_settings()
    for scan_type, result in scan_results.items():
        artifact_store.save_scan_artifact(
            settings.artifacts_path,
            state["repo_full_name"],
            state["pr_number"],
            scan_type,
            result.get("raw") or {k: v for k, v in result.items() if k != "raw"},
        )

    log.info("scan_full_complete", pr=state["pr_number"], scanners=list(scan_results.keys()))
    return {
        "current_stage": "scan",
        "scan_results": scan_results,
        "docker_image_tag": image_tag if build_ok else "",
    }


async def scan_fs_node(state: PRReviewState) -> dict:
    """Filesystem-only scan: no Docker build. All applicable scanners in parallel."""
    log.info("scan_fs_start", pr=state["pr_number"])
    repo_path = state["repo_path"]
    classification = state.get("pr_classification", "feature")

    extra_scanners = SCAN_MATRIX.get(classification, set())
    tasks = []

    # Always: Trivy fs + Gitleaks
    tasks.append(_run_scan("trivy_fs", trivy_service.scan_filesystem(repo_path), repo_path))
    tasks.append(_run_scan("gitleaks", gitleaks_service.scan_repo(repo_path), repo_path))

    # Conditional scanners
    if "semgrep" in extra_scanners:
        tasks.append(_run_scan("semgrep", semgrep_service.scan_directory(repo_path), repo_path))
    if "checkov" in extra_scanners:
        tasks.append(_run_scan("checkov", checkov_service.scan_iac(repo_path), repo_path))
    if "osv" in extra_scanners:
        tasks.append(_run_scan("osv", osv_service.scan_lockfiles(repo_path), repo_path))

    # Run all scans in parallel
    results = await asyncio.gather(*tasks, return_exceptions=True)

    scan_results = {}
    for item in results:
        if isinstance(item, Exception):
            log.error("scan_gather_exception", error=str(item))
            continue
        name, result = item
        scan_results[name] = result

    # Persist scan results
    for scan_type, result in scan_results.items():
        summary = result.get("summary", {})
        if summary:
            try:
                await knowledge.save_scan_result(
                    state["repo_full_name"], scan_type, "pr_review",
                    str(state["pr_number"]), summary,
                )
            except Exception as e:
                log.warning("scan_result_save_failed", scan_type=scan_type, error=str(e))

    # Save raw scanner artifacts to disk
    settings = get_settings()
    for scan_type, result in scan_results.items():
        artifact_store.save_scan_artifact(
            settings.artifacts_path,
            state["repo_full_name"],
            state["pr_number"],
            scan_type,
            result.get("raw") or {k: v for k, v in result.items() if k != "raw"},
        )

    log.info("scan_fs_complete", pr=state["pr_number"], scanners=list(scan_results.keys()))
    return {
        "current_stage": "scan",
        "scan_results": scan_results,
        "docker_image_tag": "",
    }


async def skip_scan_node(state: PRReviewState) -> dict:
    """Skip scanning for docs-only PRs."""
    log.info("scan_skipped", pr=state["pr_number"], classification=state.get("pr_classification"))
    return {
        "current_stage": "scan",
        "scan_results": {},
        "docker_image_tag": "",
    }


def _build_degraded_review(state: PRReviewState) -> tuple[str, str, str]:
    """Build a scan-only review when the LLM is unavailable (circuit breaker open)."""
    scan_results = state.get("scan_results", {})
    total_critical = 0
    total_high = 0

    for result in scan_results.values():
        summary = result.get("summary", {})
        total_critical += summary.get("CRITICAL", 0) + summary.get("ERROR", 0)
        total_high += summary.get("HIGH", 0) + summary.get("WARNING", 0)

        # Count checkov/osv
        total_critical += len([c for c in result.get("failed_checks", []) if c.get("severity") == "CRITICAL"])
        total_high += result.get("count", 0) if result.get("scan_type") == "osv" else 0

    # Determine risk score from scan counts
    if total_critical > 0:
        risk_score = "CRITICAL"
        verdict = "BLOCK"
    elif total_high > 3:
        risk_score = "HIGH"
        verdict = "REQUEST_CHANGES"
    elif total_high > 0:
        risk_score = "MEDIUM"
        verdict = "REQUEST_CHANGES"
    else:
        risk_score = "LOW"
        verdict = "APPROVE"

    review = (
        f"### Security Review — PR #{state['pr_number']} (Degraded Mode)\n\n"
        f"**Risk Score:** {risk_score}\n"
        f"**Verdict:** {verdict}\n\n"
        f"*AI analysis unavailable — review based on scan results only.*\n\n"
        f"{format_trivy_summary(scan_results)}\n\n"
        f"{format_semgrep_findings(scan_results)}\n\n"
        f"{format_gitleaks_findings(scan_results)}\n\n"
        f"{format_checkov_findings(scan_results)}\n\n"
        f"{format_osv_findings(scan_results)}"
    )

    return review, risk_score, verdict


async def analyze_node(state: PRReviewState) -> dict:
    """Deep security analysis using the 32B LLM."""
    log.info("analyze_start", pr=state["pr_number"])

    scan_results = state.get("scan_results", {})

    # Circuit breaker — degraded review from scan results only
    if is_circuit_open():
        log.warning("circuit_breaker_active_analyze", pr=state["pr_number"])
        review, risk_score, verdict = _build_degraded_review(state)

        try:
            scan_summary = {k: v.get("summary", {}) for k, v in scan_results.items()}
            await knowledge.save_pr_review(
                repo=state["repo_full_name"], pr_number=state["pr_number"],
                pr_title=state["pr_title"], pr_author=state["sender"],
                classification=state.get("pr_classification", "feature"),
                risk_score=risk_score, verdict=verdict,
                review_markdown=review, scan_summary=scan_summary,
                files_changed=state.get("files_changed", []),
            )
            await knowledge.update_repo_profile(state["repo_full_name"], risk_score)
        except Exception as e:
            log.warning("knowledge_save_failed", error=str(e))

        return {
            "current_stage": "analyze",
            "security_review": review,
            "risk_score": risk_score,
            "verdict": verdict,
            "messages": [],
        }

    try:
        trivy_summary = format_trivy_summary(scan_results)
        semgrep_findings = format_semgrep_findings(scan_results)
        gitleaks_findings = format_gitleaks_findings(scan_results)
        checkov_findings = format_checkov_findings(scan_results)
        osv_findings = format_osv_findings(scan_results)
        repo_history_summary = format_repo_history(state.get("repo_history", []))

        prompt = build_security_review_prompt(
            pr_number=state["pr_number"],
            pr_title=state["pr_title"],
            pr_body=state["pr_body"],
            sender=state["sender"],
            classification=state.get("pr_classification", "feature"),
            diff=state["diff"],
            trivy_summary=trivy_summary,
            semgrep_findings=semgrep_findings,
            gitleaks_findings=gitleaks_findings,
            checkov_findings=checkov_findings,
            osv_findings=osv_findings,
            repo_history_summary=repo_history_summary,
        )

        llm = get_deep_llm()
        start = time.time()
        response = await llm.ainvoke([HumanMessage(content=prompt)])
        duration = time.time() - start
        agent_llm_duration.labels(model="32b", node="analyze").observe(duration)
        record_llm_success()

        review_text = response.content

        # Extract JSON metadata from end of response
        risk_score = "MEDIUM"
        verdict = "REQUEST_CHANGES"

        json_match = re.search(
            r'\{"risk_score"\s*:\s*"(CRITICAL|HIGH|MEDIUM|LOW|INFO)"\s*,\s*"verdict"\s*:\s*"(APPROVE|REQUEST_CHANGES|BLOCK)"\}',
            review_text,
        )
        if json_match:
            risk_score = json_match.group(1)
            verdict = json_match.group(2)
        else:
            log.warning("json_extraction_failed", pr=state["pr_number"])

        # Build combined scan summary for DB
        scan_summary = {k: v.get("summary", {}) for k, v in scan_results.items()}

        # Persist to knowledge base
        try:
            await knowledge.save_pr_review(
                repo=state["repo_full_name"], pr_number=state["pr_number"],
                pr_title=state["pr_title"], pr_author=state["sender"],
                classification=state.get("pr_classification", "feature"),
                risk_score=risk_score, verdict=verdict,
                review_markdown=review_text, scan_summary=scan_summary,
                files_changed=state.get("files_changed", []),
            )
            await knowledge.update_repo_profile(state["repo_full_name"], risk_score)
        except Exception as e:
            log.warning("knowledge_save_failed", error=str(e))

        log.info(
            "analyze_complete",
            pr=state["pr_number"],
            risk_score=risk_score,
            verdict=verdict,
            duration=f"{duration:.1f}s",
        )

        return {
            "current_stage": "analyze",
            "security_review": review_text,
            "risk_score": risk_score,
            "verdict": verdict,
            "messages": [HumanMessage(content=prompt)],
        }
    except Exception as e:
        record_llm_failure()
        log.error("analyze_failed", error=str(e), pr=state["pr_number"])

        # Degraded fallback on LLM failure
        review, risk_score, verdict = _build_degraded_review(state)
        return {
            "current_stage": "analyze",
            "security_review": review,
            "risk_score": risk_score,
            "verdict": verdict,
            "messages": [],
        }


async def analyze_review_node(state: PRReviewState) -> dict:
    """Combined security analysis + code quality review — single 14B LLM call."""
    log.info("analyze_review_start", pr=state["pr_number"])

    scan_results = state.get("scan_results", {})
    diff = state.get("diff", "")

    # Circuit breaker fallback — degraded review, no inline comments
    if is_circuit_open():
        log.warning("circuit_breaker_active_analyze_review", pr=state["pr_number"])
        review, risk_score, verdict = _build_degraded_review(state)
        try:
            scan_summary = {k: v.get("summary", {}) for k, v in scan_results.items()}
            await knowledge.save_pr_review(
                repo=state["repo_full_name"], pr_number=state["pr_number"],
                pr_title=state["pr_title"], pr_author=state["sender"],
                classification=state.get("pr_classification", "feature"),
                risk_score=risk_score, verdict=verdict,
                review_markdown=review, scan_summary=scan_summary,
                files_changed=state.get("files_changed", []),
            )
            await knowledge.update_repo_profile(state["repo_full_name"], risk_score)
        except Exception as e:
            log.warning("knowledge_save_failed", error=str(e))
        return {
            "current_stage": "analyze",
            "security_review": review,
            "risk_score": risk_score,
            "verdict": verdict,
            "code_review_summary": "",
            "code_review_comments": [],
            "messages": [],
        }

    # Prepare scan context
    trivy_summary = format_trivy_summary(scan_results)
    semgrep_findings = format_semgrep_findings(scan_results)
    gitleaks_findings = format_gitleaks_findings(scan_results)
    checkov_findings = format_checkov_findings(scan_results)
    osv_findings = format_osv_findings(scan_results)
    repo_history_summary = format_repo_history(state.get("repo_history", []))

    # Annotated diff for inline comment line-number validation
    annotated_diff = format_diff_with_line_numbers(diff) if diff else ""
    parsed_diff = parse_diff(diff) if diff else {}

    try:
        prompt = build_combined_review_prompt(
            pr_number=state["pr_number"],
            pr_title=state["pr_title"],
            pr_body=state["pr_body"],
            sender=state["sender"],
            classification=state.get("pr_classification", "feature"),
            diff=diff,
            annotated_diff=annotated_diff,
            trivy_summary=trivy_summary,
            semgrep_findings=semgrep_findings,
            gitleaks_findings=gitleaks_findings,
            checkov_findings=checkov_findings,
            osv_findings=osv_findings,
            repo_history_summary=repo_history_summary,
        )

        llm = get_combined_llm()
        start = time.time()
        response = await llm.ainvoke([HumanMessage(content=prompt)])
        duration = time.time() - start
        agent_llm_duration.labels(model="14b", node="analyze_review").observe(duration)
        record_llm_success()

        raw = response.content

        # Extract JSON metadata — last occurrence of the metadata object
        risk_score = "MEDIUM"
        verdict = "REQUEST_CHANGES"
        code_review_summary = ""
        raw_comments: list[dict] = []

        json_match = re.search(
            r'\{"risk_score"\s*:\s*"(?P<rs>CRITICAL|HIGH|MEDIUM|LOW|INFO)"\s*,'
            r'\s*"verdict"\s*:\s*"(?P<v>APPROVE|REQUEST_CHANGES|BLOCK)"'
            r'.*?\}',
            raw,
            re.DOTALL,
        )
        if json_match:
            try:
                # Find the full JSON object starting at the match
                json_start = json_match.start()
                data = json.loads(raw[json_start:])
                risk_score = data.get("risk_score", "MEDIUM")
                verdict = data.get("verdict", "REQUEST_CHANGES")
                code_review_summary = data.get("code_review_summary", "")
                raw_comments = data.get("comments", [])
            except json.JSONDecodeError:
                risk_score = json_match.group("rs")
                verdict = json_match.group("v")

        review_text = raw[:json_match.start()].strip() if json_match else raw

        # Validate inline comment line numbers against actual diff
        valid_comments: list[dict] = []
        if diff:
            for c in raw_comments:
                file_path = str(c.get("file", "")).strip()
                line = c.get("line")
                if not file_path or not isinstance(line, int):
                    continue
                valid_lines = diff_lines_for_file(parsed_diff, file_path)
                if line not in valid_lines:
                    log.warning("analyze_review_invalid_line", file=file_path, line=line)
                    continue
                valid_comments.append(c)

        log.info(
            "analyze_review_complete",
            pr=state["pr_number"],
            risk_score=risk_score,
            verdict=verdict,
            comments=len(valid_comments),
            duration=f"{duration:.1f}s",
        )

        # Post GitHub inline code review (same as former code_review_node)
        if valid_comments or code_review_summary:
            github_comments: list[dict] = []
            for c in valid_comments:
                severity_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}.get(
                    c.get("severity", "medium").lower(), "🟡"
                )
                suggestion = c.get("suggestion", "").strip()
                suggestion_block = f"\n\n```suggestion\n{suggestion}\n```" if suggestion else ""
                body = (
                    f"{severity_emoji} **[{c.get('severity', 'medium').upper()}] {c.get('title', '')}**\n\n"
                    f"{c.get('description', '')}"
                    f"{suggestion_block}"
                )
                github_comments.append({
                    "path": c["file"],
                    "line": c["line"],
                    "side": "RIGHT",
                    "body": body,
                })
            review_body = (
                f"## Code Quality Review\n\n{code_review_summary}" if code_review_summary
                else "## Code Quality Review"
            )
            try:
                await github_api.post_pr_review(
                    repo=state["repo_full_name"],
                    pr_number=state["pr_number"],
                    body=review_body,
                    comments=github_comments,
                    event="COMMENT",
                )
            except Exception as exc:
                log.error("analyze_review_post_failed", pr=state["pr_number"], error=str(exc))

        # Persist to knowledge base
        scan_summary = {k: v.get("summary", {}) for k, v in scan_results.items()}
        try:
            await knowledge.save_pr_review(
                repo=state["repo_full_name"], pr_number=state["pr_number"],
                pr_title=state["pr_title"], pr_author=state["sender"],
                classification=state.get("pr_classification", "feature"),
                risk_score=risk_score, verdict=verdict,
                review_markdown=review_text, scan_summary=scan_summary,
                files_changed=state.get("files_changed", []),
            )
            await knowledge.update_repo_profile(state["repo_full_name"], risk_score)
        except Exception as e:
            log.warning("knowledge_save_failed", error=str(e))

        return {
            "current_stage": "analyze",
            "security_review": review_text,
            "risk_score": risk_score,
            "verdict": verdict,
            "code_review_summary": code_review_summary,
            "code_review_comments": valid_comments,
            "messages": [HumanMessage(content=prompt)],
        }

    except Exception as e:
        record_llm_failure()
        log.error("analyze_review_failed", error=str(e), pr=state["pr_number"])
        review, risk_score, verdict = _build_degraded_review(state)
        return {
            "current_stage": "analyze",
            "security_review": review,
            "risk_score": risk_score,
            "verdict": verdict,
            "code_review_summary": "",
            "code_review_comments": [],
            "messages": [],
        }


async def escalate_node(state: PRReviewState) -> dict:
    """Escalate HIGH/CRITICAL findings to Slack for approval."""
    log.info("escalate_start", pr=state["pr_number"], risk_score=state.get("risk_score"))

    # Extract top findings for Slack message
    findings = []
    review = state.get("security_review", "")
    for line in review.split("\n"):
        stripped = line.strip()
        if stripped.startswith("- **") or stripped.startswith("1.") or stripped.startswith("2.") or stripped.startswith("3."):
            findings.append(stripped[:120])
            if len(findings) >= 3:
                break

    await slack_api.request_approval(
        pr_info={
            "title": state["pr_title"],
            "author": state["sender"],
            "risk_score": state.get("risk_score", "HIGH"),
            "url": state.get("pr_url", ""),
            "pr_number": state["pr_number"],
        },
        findings=findings,
    )

    log.info("escalate_complete", pr=state["pr_number"])
    return {
        "current_stage": "escalate",
        "approval_status": "pending",
    }


async def code_review_node(state: PRReviewState) -> dict:
    """Code-quality review using the 14B model.

    Parses the PR diff, asks the LLM for structured JSON suggestions, validates
    line numbers against the diff, then posts a formal GitHub PR review with
    inline comments (each containing a ```suggestion``` block where applicable).
    """
    log.info("code_review_start", pr=state["pr_number"])

    diff = state.get("diff", "")
    if not diff:
        log.warning("code_review_skipped_no_diff", pr=state["pr_number"])
        return {"current_stage": "code_review", "code_review_summary": "", "code_review_comments": []}

    # Skip docs-only PRs — nothing actionable to review
    if state.get("pr_classification") == "docs":
        return {"current_stage": "code_review", "code_review_summary": "", "code_review_comments": []}

    # Build compact security findings context to avoid duplicates
    scan_results = state.get("scan_results", {})
    security_lines: list[str] = []
    for scanner, result in scan_results.items():
        summary = result.get("summary", {})
        if summary:
            counts = ", ".join(f"{k}: {v}" for k, v in summary.items() if v)
            if counts:
                security_lines.append(f"- {scanner}: {counts}")
    security_findings = "\n".join(security_lines)

    # Annotate diff with line numbers for the model
    annotated_diff = format_diff_with_line_numbers(diff)
    parsed_diff = parse_diff(diff)

    try:
        prompt = build_code_review_prompt(
            pr_number=state["pr_number"],
            pr_title=state["pr_title"],
            classification=state.get("pr_classification", "feature"),
            annotated_diff=annotated_diff,
            security_findings=security_findings,
        )

        llm = get_review_llm()
        start = time.time()
        response = await llm.ainvoke([
            SystemMessage(content=CODE_REVIEW_SYSTEM),
            HumanMessage(content=prompt),
        ])
        duration = time.time() - start
        agent_llm_duration.labels(model="14b", node="code_review").observe(duration)

        raw = response.content.strip()
        data = json.loads(raw)

        summary: str = data.get("summary", "")
        raw_comments: list[dict] = data.get("comments", [])

        log.info(
            "code_review_llm_done",
            pr=state["pr_number"],
            comments=len(raw_comments),
            duration=f"{duration:.1f}s",
        )

    except Exception as exc:
        log.error("code_review_llm_failed", pr=state["pr_number"], error=str(exc))
        return {"current_stage": "code_review", "code_review_summary": "", "code_review_comments": []}

    # Validate each comment's line against the actual diff
    valid_comments: list[dict] = []
    for c in raw_comments:
        file_path = str(c.get("file", "")).strip()
        line = c.get("line")
        if not file_path or not isinstance(line, int):
            continue
        valid_lines = diff_lines_for_file(parsed_diff, file_path)
        if line not in valid_lines:
            log.warning(
                "code_review_invalid_line",
                file=file_path,
                line=line,
                pr=state["pr_number"],
            )
            continue
        valid_comments.append(c)

    log.info(
        "code_review_validation",
        pr=state["pr_number"],
        raw=len(raw_comments),
        valid=len(valid_comments),
    )

    # Build GitHub inline review comment bodies
    github_comments: list[dict] = []
    for c in valid_comments:
        severity_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}.get(
            c.get("severity", "medium").lower(), "🟡"
        )
        suggestion = c.get("suggestion", "").strip()
        suggestion_block = (
            f"\n\n```suggestion\n{suggestion}\n```" if suggestion else ""
        )
        body = (
            f"{severity_emoji} **[{c.get('severity', 'medium').upper()}] {c.get('title', '')}**\n\n"
            f"{c.get('description', '')}"
            f"{suggestion_block}"
        )
        github_comments.append({
            "path": c["file"],
            "line": c["line"],
            "side": "RIGHT",
            "body": body,
        })

    # Post the GitHub PR review (inline comments appear on Files Changed tab)
    if github_comments or summary:
        review_body = (
            f"## Code Quality Review\n\n{summary}" if summary
            else "## Code Quality Review"
        )
        try:
            await github_api.post_pr_review(
                repo=state["repo_full_name"],
                pr_number=state["pr_number"],
                body=review_body,
                comments=github_comments,
                event="COMMENT",
            )
        except Exception as exc:
            log.error("code_review_post_failed", pr=state["pr_number"], error=str(exc))

    return {
        "current_stage": "code_review",
        "code_review_summary": summary,
        "code_review_comments": valid_comments,
    }


async def report_node(state: PRReviewState) -> dict:
    """Post the security review to GitHub and send Slack notification."""
    log.info("report_start", pr=state["pr_number"])

    review = state.get("security_review", "No review generated.")
    risk_score = state.get("risk_score", "INFO")
    verdict = state.get("verdict", "APPROVE")
    classification = state.get("pr_classification", "unknown")

    # Append code review summary if available
    code_review_summary = state.get("code_review_summary", "")
    code_review_comments = state.get("code_review_comments", [])
    code_review_section = ""
    if code_review_summary or code_review_comments:
        inline_note = (
            f"\n\n> 💬 **{len(code_review_comments)} inline suggestion(s)** posted on the Files Changed tab."
            if code_review_comments else ""
        )
        code_review_section = (
            f"\n\n---\n\n## Code Quality Review\n\n"
            f"{code_review_summary}"
            f"{inline_note}"
        )

    # Format the review with header
    formatted_review = (
        f"## SECURITY AI AGENT — Security Review\n\n"
        f"**Risk:** {risk_score} | **Verdict:** {verdict} | **Classification:** {classification}\n\n"
        f"---\n\n"
        f"{review}"
        f"{code_review_section}"
    )

    # Post PR comment
    try:
        await github_api.post_pr_comment(
            state["repo_full_name"], state["pr_number"], formatted_review,
        )
    except Exception as e:
        log.error("pr_comment_failed", error=str(e))

    # Set commit status
    status_map = {
        "APPROVE": ("success", "Security review passed"),
        "REQUEST_CHANGES": ("failure", "Security issues found"),
        "BLOCK": ("error", "Critical security vulnerabilities — blocked"),
    }
    gh_state, description = status_map.get(verdict, ("failure", "Security issues found"))

    try:
        await github_api.set_commit_status(
            state["repo_full_name"], state["head_sha"], gh_state, description,
        )
    except Exception as e:
        log.error("commit_status_failed", error=str(e))

    # Slack notification
    summary = (
        f"*SECURITY AI AGENT* — PR #{state['pr_number']} review complete\n"
        f"*Repo:* {state['repo_full_name']}\n"
        f"*Risk:* {risk_score} | *Verdict:* {verdict}"
    )
    await slack_api.send_notification(text=summary)

    # Cleanup
    docker_image = state.get("docker_image_tag", "")
    if docker_image:
        await docker_service.remove_image(docker_image)

    import shutil
    repo_path = state.get("repo_path", "")
    if repo_path and Path(repo_path).exists():
        try:
            shutil.rmtree(repo_path)
        except Exception as e:
            log.warning("cleanup_failed", path=repo_path, error=str(e))

    # Release rate limit
    await cache.release_rate_limit(state["repo_full_name"])

    # Calculate duration + record metrics
    duration_ms = None
    started = state.get("started_at", "")
    if started:
        try:
            start_time = datetime.fromisoformat(started)
            duration_ms = int((datetime.now(timezone.utc) - start_time).total_seconds() * 1000)
            agent_pipeline_duration.observe(duration_ms / 1000)
        except ValueError:
            pass

    agent_reviews_total.labels(risk_score=risk_score, verdict=verdict).inc()

    if duration_ms:
        try:
            await knowledge.save_pr_review(
                repo=state["repo_full_name"], pr_number=state["pr_number"],
                pr_title=state["pr_title"], pr_author=state["sender"],
                classification=classification, risk_score=risk_score,
                verdict=verdict, review_markdown=review,
                scan_summary={}, files_changed=state.get("files_changed", []),
                duration_ms=duration_ms,
            )
        except Exception as e:
            log.warning("duration_update_failed", error=str(e))

    # Save final PR summary to artifacts
    try:
        artifact_store.save_pr_summary(
            get_settings().artifacts_path,
            state["repo_full_name"],
            state["pr_number"],
            {
                "pr_number": state["pr_number"],
                "pr_title": state["pr_title"],
                "repo": state["repo_full_name"],
                "sender": state.get("sender", ""),
                "classification": classification,
                "risk_score": risk_score,
                "verdict": verdict,
                "files_changed": state.get("files_changed", []),
                "head_sha": state.get("head_sha", ""),
                "pr_url": state.get("pr_url", ""),
                "started_at": state.get("started_at", ""),
                "duration_ms": duration_ms,
                "inline_comments": len(state.get("code_review_comments", [])),
            },
        )
    except Exception as e:
        log.warning("artifact_summary_failed", error=str(e))

    log.info(
        "report_complete", pr=state["pr_number"],
        risk_score=risk_score, verdict=verdict, duration_ms=duration_ms,
    )
    return {"current_stage": "report"}


async def error_node(state: PRReviewState) -> dict:
    """Handle errors — post failure comment and notify Slack."""
    error = state.get("error", "Unknown error")
    stage = state.get("current_stage", "unknown")
    log.error("workflow_error", pr=state.get("pr_number"), stage=stage, error=error)

    agent_errors_total.labels(stage=stage).inc()

    # Release rate limit on error too
    await cache.release_rate_limit(state.get("repo_full_name", ""))

    # Post error comment to PR
    error_comment = (
        f"**SECURITY AI AGENT** — Review failed at stage: `{stage}`.\n\n"
        f"Error: `{error}`\n\n"
        f"Please check the agent logs for details."
    )

    try:
        await github_api.post_pr_comment(
            state["repo_full_name"], state.get("pr_number", 0), error_comment,
        )
    except Exception as e:
        log.error("error_comment_failed", error=str(e))

    # Slack notification
    await slack_api.send_notification(
        text=(
            f"*SECURITY AI AGENT* — Review FAILED\n"
            f"*Repo:* {state.get('repo_full_name', 'unknown')}\n"
            f"*PR:* #{state.get('pr_number', '?')}\n"
            f"*Stage:* {stage}\n"
            f"*Error:* {error}"
        ),
    )

    return {"current_stage": "error"}
