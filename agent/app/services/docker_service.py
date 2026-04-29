import asyncio
from pathlib import Path

import structlog

log = structlog.get_logger().bind(service="docker")


async def check_dockerfile(repo_path: Path) -> bool:
    """Check if a Dockerfile exists in the repo root."""
    dockerfile = repo_path / "Dockerfile"
    exists = dockerfile.is_file()
    log.info("dockerfile_check", path=str(repo_path), exists=exists)
    return exists


async def build_image(context_path: Path, image_tag: str) -> tuple[bool, str]:
    """Build a Docker image from the repo context. Returns (success, message)."""
    log.info("building_image", context=str(context_path), tag=image_tag)

    try:
        proc = await asyncio.wait_for(
            asyncio.create_subprocess_exec(
                "docker", "build", "-t", image_tag, str(context_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            ),
            timeout=10,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
    except asyncio.TimeoutError:
        log.error("docker_build_timeout", tag=image_tag)
        return False, "Docker build timed out after 300s"

    if proc.returncode != 0:
        error_msg = stderr.decode().strip()[-500:]
        log.error("docker_build_failed", returncode=proc.returncode, stderr=error_msg)
        return False, f"Build failed: {error_msg}"

    log.info("docker_build_success", tag=image_tag)
    return True, "Build successful"


async def remove_image(image_tag: str) -> None:
    """Remove a Docker image. Fire-and-forget, errors are logged but not raised."""
    if not image_tag:
        return

    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "rmi", "-f", image_tag,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()
        log.info("image_removed", tag=image_tag)
    except Exception as e:
        log.warning("image_removal_failed", tag=image_tag, error=str(e))
