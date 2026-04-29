"""
BTE Security AI Agent — Ops Assistant tools.

All tools are read-only (no mutations to state, data, or running containers
except the explicitly allowed restart_service whitelist).
All tools are synchronous (subprocess / sync psycopg / sync httpx / sync redis).
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import httpx
import psycopg
import redis as redis_lib
from langchain_core.tools import tool

from app.config import get_settings


# ───────────────────────────────────────────────────────────
# VPS / HOST TOOLS
# ───────────────────────────────────────────────────────────

@tool
def vps_status() -> str:
    """Return a full VPS health snapshot: CPU cores & model, total/used RAM,
    disk usage, system uptime, and 1/5/15-minute load averages."""
    parts = {}

    # CPU
    try:
        nproc = subprocess.run(["nproc"], capture_output=True, text=True, timeout=3)
        parts["cpu_cores"] = nproc.stdout.strip()
        cpuinfo = Path("/proc/cpuinfo").read_text()
        for line in cpuinfo.splitlines():
            if line.startswith("model name"):
                parts["cpu_model"] = line.split(":", 1)[1].strip()
                break
    except Exception as e:
        parts["cpu_error"] = str(e)

    # Memory
    try:
        mem = Path("/proc/meminfo").read_text()
        memmap = {}
        for line in mem.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                memmap[k.strip()] = v.strip()
        total_kb = int(memmap.get("MemTotal",     "0 kB").split()[0])
        avail_kb = int(memmap.get("MemAvailable", "0 kB").split()[0])
        used_kb  = total_kb - avail_kb
        parts["ram_total_gb"] = round(total_kb / 1_048_576, 1)
        parts["ram_used_gb"]  = round(used_kb  / 1_048_576, 1)
        parts["ram_free_gb"]  = round(avail_kb / 1_048_576, 1)
        parts["ram_used_pct"] = f"{used_kb / total_kb * 100:.1f}%"
    except Exception as e:
        parts["ram_error"] = str(e)

    # Disk
    try:
        df = subprocess.run(
            ["df", "-h", "--output=source,size,used,avail,pcent,target", "/"],
            capture_output=True, text=True, timeout=5,
        )
        parts["disk"] = df.stdout.strip()
    except Exception as e:
        parts["disk_error"] = str(e)

    # Uptime + load
    try:
        load_raw = Path("/proc/loadavg").read_text().split()
        parts["load_avg_1_5_15"] = f"{load_raw[0]}  {load_raw[1]}  {load_raw[2]}"
        uptime_s = int(Path("/proc/uptime").read_text().split()[0].split(".")[0])
        days, rem = divmod(uptime_s, 86400)
        hours, rem = divmod(rem, 3600)
        mins = rem // 60
        parts["uptime"] = f"{days}d {hours}h {mins}m"
    except Exception as e:
        parts["uptime_error"] = str(e)

    # Swap
    try:
        swap_lines = [l for l in Path("/proc/meminfo").read_text().splitlines() if l.startswith("Swap")]
        swap_info  = {l.split(":")[0].strip(): l.split(":")[1].strip() for l in swap_lines}
        parts["swap_total"] = swap_info.get("SwapTotal", "0 kB")
        parts["swap_free"]  = swap_info.get("SwapFree",  "0 kB")
    except Exception:
        pass

    return json.dumps(parts, indent=2)


@tool
def disk_usage() -> str:
    """Show disk space for all mounted filesystems (df -h)."""
    result = subprocess.run(["df", "-h"], capture_output=True, text=True, timeout=5)
    return result.stdout.strip() or result.stderr.strip()


@tool
def top_processes(sort_by: str = "cpu") -> str:
    """List the top 20 processes by CPU or memory usage.

    Args:
        sort_by: 'cpu' to sort by CPU usage, 'memory' to sort by RAM usage
    """
    sort_flag = "--sort=-%cpu" if sort_by == "cpu" else "--sort=-%mem"
    result = subprocess.run(
        ["ps", "aux", sort_flag],
        capture_output=True, text=True, timeout=10,
    )
    lines = result.stdout.strip().splitlines()
    return "\n".join(lines[:21])  # header + top 20


@tool
def network_stats() -> str:
    """Show listening ports and active TCP connections inside this container."""
    out = []
    try:
        ss = subprocess.run(["ss", "-tlnp"], capture_output=True, text=True, timeout=5)
        out.append("=== Listening sockets ===")
        out.append(ss.stdout.strip())
    except Exception as e:
        out.append(f"ss error: {e}")
    try:
        conn = subprocess.run(
            ["ss", "-tnp", "state", "established"],
            capture_output=True, text=True, timeout=5,
        )
        out.append("\n=== Established connections ===")
        out.append("\n".join(conn.stdout.strip().splitlines()[:30]))
    except Exception as e:
        out.append(f"connections error: {e}")
    return "\n".join(out)


@tool
def system_net_io() -> str:
    """Show cumulative network I/O (MB received / transmitted) per interface from /proc/net/dev.
    Useful for spotting unusually active interfaces or unexpected traffic."""
    try:
        raw   = Path("/proc/net/dev").read_text()
        lines = raw.strip().splitlines()[2:]  # skip 2 header lines
        result: dict = {}
        for line in lines:
            parts = line.split()
            if len(parts) < 10:
                continue
            iface    = parts[0].rstrip(":")
            rx_bytes = int(parts[1])
            tx_bytes = int(parts[9])
            if rx_bytes == 0 and tx_bytes == 0:
                continue
            result[iface] = {
                "rx_mb": round(rx_bytes / 1_048_576, 1),
                "tx_mb": round(tx_bytes / 1_048_576, 1),
            }
        return json.dumps(result, indent=2)
    except Exception as exc:
        return f"Error reading /proc/net/dev: {exc}"


# ───────────────────────────────────────────────────────────
# DOCKER TOOLS
# ───────────────────────────────────────────────────────────

@tool
def list_containers() -> str:
    """List all Docker containers with name, status, image, and ports."""
    result = subprocess.run(
        [
            "docker", "ps", "-a",
            "--format", "table {{.Names}}\t{{.Status}}\t{{.Image}}\t{{.Ports}}",
        ],
        capture_output=True, text=True, timeout=10,
    )
    return result.stdout.strip() or f"Error: {result.stderr.strip()}"


@tool
def container_logs(container: str, tail: int = 100, since: str = "") -> str:
    """Fetch recent logs from a Docker container.

    Args:
        container: Container name. Available: devsecops-agent, ollama, postgres,
                   redis, nginx, jenkins, prometheus, grafana, victoriametrics
        tail: Number of lines from the end (default 100, max 500)
        since: Only logs newer than this — e.g. '30m', '2h', '1d'. Empty = no filter.
    """
    tail = min(int(tail), 500)
    cmd  = ["docker", "logs", "--tail", str(tail), container]
    if since:
        cmd += ["--since", since]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        output = (result.stdout + result.stderr).strip()
        if not output:
            return f"No logs found for '{container}'."
        if len(output) > 4_000:
            lines = output.splitlines()
            kept  = []
            chars = 0
            for line in reversed(lines):
                chars += len(line) + 1
                if chars > 4_000:
                    break
                kept.append(line)
            output  = "\n".join(reversed(kept))
            output += f"\n\n[... output truncated — {len(lines)} total lines, showing last {len(kept)}]"
        return output
    except subprocess.TimeoutExpired:
        return "Timed out fetching logs."
    except Exception as exc:
        return f"Error: {exc}"


@tool
def container_stats() -> str:
    """Get live CPU %, memory usage, and network I/O for all running containers."""
    result = subprocess.run(
        [
            "docker", "stats", "--no-stream",
            "--format",
            "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}",
        ],
        capture_output=True, text=True, timeout=15,
    )
    return result.stdout.strip() or f"Error: {result.stderr.strip()}"


@tool
def inspect_container(container: str) -> str:
    """Detailed state, health checks, restart policy, and mounts for a container.

    Args:
        container: Container name to inspect
    """
    result = subprocess.run(
        ["docker", "inspect", container],
        capture_output=True, text=True, timeout=10,
    )
    if result.returncode != 0:
        return f"Error: {result.stderr.strip()}"
    try:
        data = json.loads(result.stdout)
        if not data:
            return f"Container '{container}' not found."
        d      = data[0]
        state  = d.get("State", {})
        health = state.get("Health") or {}
        return json.dumps({
            "name":           d.get("Name", "").lstrip("/"),
            "status":         state.get("Status"),
            "running":        state.get("Running"),
            "health":         health.get("Status", "no healthcheck"),
            "exit_code":      state.get("ExitCode"),
            "started_at":     state.get("StartedAt"),
            "image":          d.get("Config", {}).get("Image"),
            "restart_policy": d.get("HostConfig", {}).get("RestartPolicy", {}).get("Name"),
            "restart_count":  d.get("RestartCount", 0),
            "mounts":         [m.get("Destination") for m in d.get("Mounts", [])],
            "recent_health":  [
                {"exit": h.get("ExitCode"), "out": (h.get("Output") or "")[:300]}
                for h in (health.get("Log") or [])[-5:]
            ],
        }, indent=2, default=str)
    except Exception:
        return result.stdout[:5_000]


@tool
def list_images() -> str:
    """List all Docker images with repository:tag, size, and creation date."""
    result = subprocess.run(
        [
            "docker", "images",
            "--format", "table {{.Repository}}:{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}",
        ],
        capture_output=True, text=True, timeout=10,
    )
    return result.stdout.strip() or f"Error: {result.stderr.strip()}"


@tool
def restart_service(service: str) -> str:
    """Restart a Docker Compose service. Only stateless services are allowed.

    Args:
        service: One of: agent, grafana, prometheus, nginx, victoriametrics
    """
    safe = {"agent", "grafana", "prometheus", "nginx", "victoriametrics"}
    if service not in safe:
        return (
            f"'{service}' is not restartable via this tool "
            f"(data-loss risk). Allowed: {', '.join(sorted(safe))}"
        )
    result = subprocess.run(
        ["docker", "compose", "-f", "/opt/devsecops/docker-compose.yml",
         "restart", service],
        capture_output=True, text=True, timeout=60, cwd="/opt/devsecops",
    )
    if result.returncode == 0:
        return f"✓ '{service}' restarted successfully."
    return f"Error restarting '{service}': {result.stderr.strip()}"


# ───────────────────────────────────────────────────────────
# OLLAMA / LLM TOOLS
# ───────────────────────────────────────────────────────────

@tool
def ollama_status() -> str:
    """Show which Ollama LLM models are currently loaded in RAM and all installed models.
    Reports RAM consumed per model and when each loaded model will be evicted."""
    try:
        with httpx.Client(timeout=10) as client:
            ps_resp   = client.get("http://ollama:11434/api/ps")
            tags_resp = client.get("http://ollama:11434/api/tags")

        loaded    = ps_resp.json().get("models", [])
        installed = tags_resp.json().get("models", [])

        total_loaded_gb = sum(m.get("size", 0) for m in loaded) / 1_073_741_824

        return json.dumps({
            "loaded_model_count": len(loaded),
            "total_ram_used_gb": round(total_loaded_gb, 1),
            "loaded_models": [
                {
                    "name":       m.get("name"),
                    "size_gb":    round(m.get("size", 0) / 1_073_741_824, 1),
                    "expires_at": m.get("expires_at", "unknown"),
                }
                for m in loaded
            ],
            "installed_models": [
                {
                    "name":        m.get("name"),
                    "size_gb":     round(m.get("size", 0) / 1_073_741_824, 1),
                    "modified_at": m.get("modified_at", ""),
                }
                for m in installed
            ],
        }, indent=2)
    except Exception as exc:
        return f"Ollama unreachable: {exc}"


# ───────────────────────────────────────────────────────────
# PROMETHEUS / ALERTING
# ───────────────────────────────────────────────────────────

@tool
def query_prometheus(promql: str) -> str:
    """Query Prometheus using PromQL.

    Args:
        promql: PromQL expression. Examples:
                'up'
                'http_requests_total'
                'rate(agent_errors_total[5m])'
                'ollama_models_loaded_total'
                'rate(agent_pipeline_duration_seconds_sum[1h]) / rate(agent_pipeline_duration_seconds_count[1h])'
    """
    try:
        with httpx.Client(timeout=10) as client:
            resp = client.get(
                "http://prometheus:9090/prometheus/api/v1/query",
                params={"query": promql},
            )
            data = resp.json()
            if data.get("status") != "success":
                return f"Prometheus error: {data}"
            results = data["data"]["result"]
            if not results:
                return f"No data for query: {promql}"
            lines = []
            for r in results[:30]:
                metric = r["metric"]
                name   = metric.get("__name__", promql)
                labels = ", ".join(
                    f'{k}="{v}"' for k, v in metric.items() if k != "__name__"
                )
                value  = r.get("value", [None, "N/A"])[1]
                lines.append(f"{name}{{{labels}}} = {value}")
            return "\n".join(lines)
    except Exception as exc:
        return f"Error: {exc}"


@tool
def query_prometheus_range(promql: str, duration: str = "1h", step: str = "5m") -> str:
    """Query Prometheus for a metric over a time window and return a statistical summary.
    Use this for trend questions: "has CPU been high?", "RAM over the last 6 hours", etc.

    Args:
        promql:   PromQL expression (same as query_prometheus)
        duration: How far back to look — e.g. '30m', '1h', '6h', '24h'  (default: '1h')
        step:     Sample resolution — e.g. '1m', '5m', '15m'            (default: '5m')

    Returns min / max / avg / latest value plus up to 12 evenly-spaced samples.
    """
    import time as _time
    now    = int(_time.time())
    # Parse duration to seconds
    _units = {"m": 60, "h": 3600, "d": 86400}
    try:
        dur_s = int(duration[:-1]) * _units[duration[-1]]
    except Exception:
        return f"Invalid duration '{duration}'. Use e.g. '30m', '1h', '6h', '24h'."

    start = now - dur_s
    try:
        with httpx.Client(timeout=15) as client:
            resp = client.get(
                "http://prometheus:9090/prometheus/api/v1/query_range",
                params={"query": promql, "start": start, "end": now, "step": step},
            )
            data = resp.json()
        if data.get("status") != "success":
            return f"Prometheus error: {data}"
        results = data["data"]["result"]
        if not results:
            return f"No data for '{promql}' over the last {duration}."

        out = []
        for series in results[:5]:   # cap at 5 series
            labels = series.get("metric", {})
            label_str = ", ".join(f'{k}="{v}"' for k, v in labels.items() if k != "__name__")
            values = [float(v) for _, v in series.get("values", []) if v != "NaN"]
            if not values:
                continue
            mn, mx, avg = min(values), max(values), sum(values) / len(values)
            latest = values[-1]
            # Pick up to 12 evenly-spaced samples for a readable sparkline
            stride = max(1, len(values) // 12)
            samples = [f"{v:.2f}" for v in values[::stride][-12:]]
            out.append(
                f"Series: {label_str or promql}\n"
                f"  Range:   {duration} · {len(values)} samples\n"
                f"  Min:     {mn:.2f}\n"
                f"  Max:     {mx:.2f}\n"
                f"  Avg:     {avg:.2f}\n"
                f"  Latest:  {latest:.2f}\n"
                f"  Trend:   [{' → '.join(samples)}]"
            )
        return "\n\n".join(out) if out else "All series contained only NaN values."
    except Exception as exc:
        return f"Error: {exc}"


@tool
def prometheus_alerts() -> str:
    """List all active (firing or pending) Prometheus alerts with severity and summary.
    Returns a clean status if no alerts are active."""
    try:
        with httpx.Client(timeout=10) as client:
            resp = client.get("http://prometheus:9090/prometheus/api/v1/alerts")
            data = resp.json()

        alerts  = data.get("data", {}).get("alerts", [])
        firing  = [a for a in alerts if a.get("state") == "firing"]
        pending = [a for a in alerts if a.get("state") == "pending"]

        if not alerts:
            return "✓ No active alerts. All Prometheus rules are within normal thresholds."

        return json.dumps({
            "firing_count":  len(firing),
            "pending_count": len(pending),
            "alerts": [
                {
                    "name":         a.get("labels", {}).get("alertname", "unknown"),
                    "state":        a.get("state"),
                    "severity":     a.get("labels", {}).get("severity", "unknown"),
                    "summary":      a.get("annotations", {}).get("summary", ""),
                    "active_since": a.get("activeAt", ""),
                }
                for a in alerts
            ],
        }, indent=2)
    except Exception as exc:
        return f"Error reaching Prometheus: {exc}"


# ───────────────────────────────────────────────────────────
# REDIS
# ───────────────────────────────────────────────────────────

@tool
def redis_info() -> str:
    """Show Redis server health: memory usage, connected clients, cache hit rate,
    keyspace size, and last persistence status."""
    settings = get_settings()
    try:
        r    = redis_lib.Redis.from_url(settings.redis_url, socket_timeout=5)
        info = r.info()

        hits   = info.get("keyspace_hits", 0)
        misses = info.get("keyspace_misses", 0)
        total  = hits + misses
        hit_rate = f"{hits / total * 100:.1f}%" if total > 0 else "n/a (no requests yet)"

        return json.dumps({
            "redis_version":       info.get("redis_version"),
            "uptime_days":         info.get("uptime_in_days"),
            "connected_clients":   info.get("connected_clients"),
            "used_memory":         info.get("used_memory_human"),
            "maxmemory":           info.get("maxmemory_human", "no limit"),
            "mem_fragmentation":   info.get("mem_fragmentation_ratio"),
            "cache_hit_rate":      hit_rate,
            "keyspace_hits":       hits,
            "keyspace_misses":     misses,
            "total_commands":      info.get("total_commands_processed"),
            "keyspace":            info.get("db0", "empty"),
            "persistence_status":  info.get("rdb_last_bgsave_status", "unknown"),
            "aof_enabled":         info.get("aof_enabled", 0),
        }, indent=2)
    except Exception as exc:
        return f"Redis error: {exc}"


# ───────────────────────────────────────────────────────────
# JENKINS
# ───────────────────────────────────────────────────────────

@tool
def jenkins_status() -> str:
    """Show Jenkins job health and the result of the most recent build per job."""
    settings = get_settings()
    if not settings.jenkins_api_token:
        return "Jenkins API token not configured (JENKINS_API_TOKEN env var is empty)."
    try:
        with httpx.Client(
            timeout=10,
            auth=(settings.jenkins_user, settings.jenkins_api_token),
        ) as client:
            resp = client.get(
                "http://jenkins:8080/api/json",
                params={
                    "tree": "jobs[name,color,lastBuild[number,result,timestamp,duration,url]]"
                },
            )
        if resp.status_code == 401:
            return "Jenkins authentication failed — check JENKINS_API_TOKEN."
        if resp.status_code != 200:
            return f"Jenkins returned HTTP {resp.status_code}."

        jobs = resp.json().get("jobs", [])
        if not jobs:
            return "No Jenkins jobs found."

        result = []
        for job in jobs:
            last = job.get("lastBuild") or {}
            result.append({
                "job":        job.get("name"),
                "health":     job.get("color", "unknown"),
                "last_build": last.get("number", "none"),
                "result":     last.get("result", "N/A"),
                "duration_s": round((last.get("duration") or 0) / 1000),
            })

        return json.dumps(result, indent=2)
    except Exception as exc:
        return f"Jenkins error: {exc}"


# ───────────────────────────────────────────────────────────
# SCAN ARTIFACTS
# ───────────────────────────────────────────────────────────

@tool
def list_scan_artifacts(repo: str = "", pr_number: int = 0) -> str:
    """Browse saved SAST scan artifact files. Lists recent PRs or files for a specific PR.

    Args:
        repo: Repository in 'owner/repo' format. Leave empty to list all repos.
        pr_number: PR number. Leave 0 to list all PRs for the given repo.
    """
    settings = get_settings()
    base     = Path(settings.artifacts_path) / "scans"

    if not base.exists() or not any(base.iterdir()):
        return "No scan artifacts saved yet. Artifacts are created after the first PR review."

    if repo and pr_number:
        pr_dir = base / repo.replace("/", "-") / f"pr-{pr_number}"
        if not pr_dir.exists():
            return f"No artifacts found for {repo} PR #{pr_number}."
        files = sorted(pr_dir.glob("*.json"))
        if not files:
            return f"Directory exists but is empty: {pr_dir}"
        return "\n".join(
            f"  {f.name:30s}  {f.stat().st_size / 1024:.1f} KB" for f in files
        )

    if repo:
        repo_dir = base / repo.replace("/", "-")
        if not repo_dir.exists():
            return f"No artifacts found for {repo}."
        prs = sorted(repo_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)
        return "\n".join(
            f"  {p.name}  ({len(list(p.glob('*.json')))} files)" for p in prs[:20]
        )

    # List all repos + their latest PRs
    repos = sorted(base.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)
    lines = []
    for repo_dir in repos[:10]:
        prs = sorted(repo_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)
        for pr in prs[:3]:
            files = list(pr.glob("*.json"))
            lines.append(f"  {repo_dir.name}/{pr.name}  ({len(files)} files)")
    return "\n".join(lines) if lines else "No artifacts found."


@tool
def read_scan_artifact(repo: str, pr_number: int, scanner: str) -> str:
    """Read the raw JSON output from a SAST tool for a specific PR review.

    Args:
        repo: Repository in 'owner/repo' format
        pr_number: PR number
        scanner: File to read — one of: trivy_image, trivy_fs, gitleaks,
                 semgrep, checkov, osv, summary
    """
    settings = get_settings()
    path = (
        Path(settings.artifacts_path)
        / "scans"
        / repo.replace("/", "-")
        / f"pr-{pr_number}"
        / f"{scanner}.json"
    )

    if not path.exists():
        return (
            f"Artifact not found: {scanner}.json for {repo} PR #{pr_number}.\n"
            f"Use list_scan_artifacts to see what is available."
        )

    try:
        content = path.read_text(encoding="utf-8")
        # For large trivy outputs, surface a compact summary instead
        if len(content) > 6_000 and scanner.startswith("trivy"):
            data = json.loads(content)
            return json.dumps({
                "note":            f"File is large ({len(content)//1024} KB) — showing summary only",
                "summary":         data.get("summary", {}),
                "total_count":     data.get("total_count", 0),
                "top_10_vulns":    data.get("vulnerabilities", [])[:10],
            }, indent=2)
        if len(content) > 6_000:
            return content[:6_000] + f"\n\n[... truncated — full file is {len(content)//1024} KB]"
        return content
    except Exception as exc:
        return f"Error reading artifact: {exc}"


# ───────────────────────────────────────────────────────────
# DATABASE
# ───────────────────────────────────────────────────────────

@tool
def query_database(sql: str) -> str:
    """Run a read-only SELECT on PostgreSQL.

    Tables: pr_reviews, scan_results, repo_profiles, incidents,
            security_policies, sbom_cache

    Args:
        sql: A SELECT statement. Example:
             'SELECT repo_full_name, risk_score, verdict, duration_ms, created_at
              FROM pr_reviews ORDER BY created_at DESC LIMIT 10'
    """
    if not sql.strip().upper().startswith("SELECT"):
        return "Error: only SELECT queries are permitted."
    settings = get_settings()
    try:
        with psycopg.connect(settings.postgres_dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(sql)
                rows = cur.fetchmany(50)
                if not rows:
                    return "Query returned no rows."
                cols = [d.name for d in cur.description]
                return json.dumps(
                    [dict(zip(cols, row)) for row in rows],
                    indent=2, default=str,
                )
    except Exception as exc:
        return f"Database error: {exc}"


# ───────────────────────────────────────────────────────────
# TOOL REGISTRY
# ───────────────────────────────────────────────────────────

ALL_TOOLS = [
    # VPS / Host
    vps_status,
    disk_usage,
    top_processes,
    network_stats,
    system_net_io,
    # Docker
    list_containers,
    container_logs,
    container_stats,
    inspect_container,
    list_images,
    restart_service,
    # Ollama / LLM
    ollama_status,
    # Prometheus / Alerting
    query_prometheus,
    query_prometheus_range,
    prometheus_alerts,
    # Redis
    redis_info,
    # Jenkins
    jenkins_status,
    # Scan Artifacts
    list_scan_artifacts,
    read_scan_artifact,
    # Database
    query_database,
]
