import hashlib
import hmac
import json

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient


@pytest.fixture
def sample_pr_webhook():
    """Complete GitHub PR webhook payload."""
    return {
        "action": "opened",
        "number": 42,
        "pull_request": {
            "number": 42,
            "title": "Add user authentication endpoint",
            "body": "Implements JWT-based auth with login/register endpoints.",
            "html_url": "https://github.com/testorg/testrepo/pull/42",
            "state": "open",
            "user": {"login": "devuser", "id": 12345},
            "head": {
                "ref": "feature/auth",
                "sha": "abc123def456789",
                "label": "testorg:feature/auth",
            },
            "base": {
                "ref": "main",
                "sha": "000111222333444",
                "label": "testorg:main",
            },
        },
        "repository": {
            "full_name": "testorg/testrepo",
            "clone_url": "https://github.com/testorg/testrepo.git",
            "html_url": "https://github.com/testorg/testrepo",
            "default_branch": "main",
            "private": False,
        },
        "sender": {"login": "devuser", "id": 12345},
    }


@pytest.fixture
def sample_trivy_output():
    """Realistic Trivy JSON output with vulnerabilities."""
    return {
        "SchemaVersion": 2,
        "ArtifactName": "testorg/testrepo:scan",
        "Results": [
            {
                "Target": "python-pkg (requirements.txt)",
                "Class": "lang-pkgs",
                "Type": "pip",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-0001",
                        "PkgName": "requests",
                        "InstalledVersion": "2.28.0",
                        "FixedVersion": "2.31.0",
                        "Severity": "CRITICAL",
                        "Title": "SSRF vulnerability in requests",
                        "Description": "Server-Side Request Forgery via crafted URL.",
                    },
                    {
                        "VulnerabilityID": "CVE-2024-0002",
                        "PkgName": "flask",
                        "InstalledVersion": "2.2.0",
                        "FixedVersion": "2.3.3",
                        "Severity": "CRITICAL",
                        "Title": "Path traversal in Flask",
                        "Description": "Arbitrary file read via path traversal.",
                    },
                    {
                        "VulnerabilityID": "CVE-2024-0003",
                        "PkgName": "pyjwt",
                        "InstalledVersion": "2.4.0",
                        "FixedVersion": "2.8.0",
                        "Severity": "CRITICAL",
                        "Title": "JWT signature bypass",
                        "Description": "Algorithm confusion allows signature bypass.",
                    },
                    {
                        "VulnerabilityID": "CVE-2024-0010",
                        "PkgName": "pillow",
                        "InstalledVersion": "9.0.0",
                        "FixedVersion": "10.0.0",
                        "Severity": "HIGH",
                        "Title": "Buffer overflow in Pillow",
                        "Description": "Heap-based buffer overflow via crafted image.",
                    },
                    {
                        "VulnerabilityID": "CVE-2024-0011",
                        "PkgName": "cryptography",
                        "InstalledVersion": "39.0.0",
                        "FixedVersion": "41.0.0",
                        "Severity": "HIGH",
                        "Title": "RSA key recovery",
                        "Description": "Timing side channel allows RSA key recovery.",
                    },
                    {
                        "VulnerabilityID": "CVE-2024-0012",
                        "PkgName": "urllib3",
                        "InstalledVersion": "1.26.0",
                        "FixedVersion": "1.26.18",
                        "Severity": "HIGH",
                        "Title": "Request smuggling in urllib3",
                        "Description": "HTTP request smuggling via Transfer-Encoding.",
                    },
                    {
                        "VulnerabilityID": "CVE-2024-0013",
                        "PkgName": "jinja2",
                        "InstalledVersion": "3.1.0",
                        "FixedVersion": "3.1.3",
                        "Severity": "HIGH",
                        "Title": "XSS in Jinja2 templates",
                        "Description": "Cross-site scripting via sandbox escape.",
                    },
                    {
                        "VulnerabilityID": "CVE-2024-0014",
                        "PkgName": "setuptools",
                        "InstalledVersion": "65.0.0",
                        "FixedVersion": "70.0.0",
                        "Severity": "HIGH",
                        "Title": "Code execution in setuptools",
                        "Description": "Arbitrary code execution via crafted package.",
                    },
                ],
            },
        ],
    }


@pytest.fixture
def sample_trivy_empty():
    """Trivy JSON output with no vulnerabilities."""
    return {
        "SchemaVersion": 2,
        "ArtifactName": "testorg/testrepo:scan",
        "Results": [
            {
                "Target": "python-pkg (requirements.txt)",
                "Class": "lang-pkgs",
                "Type": "pip",
                "Vulnerabilities": None,
            },
        ],
    }


@pytest.fixture
def sample_gitleaks_output():
    """Gitleaks JSON output with findings."""
    return [
        {
            "RuleID": "generic-api-key",
            "Description": "Generic API Key",
            "File": "config/settings.py",
            "StartLine": 15,
            "EndLine": 15,
            "Match": "API_KEY = 'sk-proj-abc123def456...'",
        },
        {
            "RuleID": "aws-access-key-id",
            "Description": "AWS Access Key ID",
            "File": ".env.production",
            "StartLine": 3,
            "EndLine": 3,
            "Match": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
        },
    ]


@pytest.fixture
def sample_semgrep_output():
    """Realistic Semgrep JSON output with findings."""
    return {
        "version": "1.90.0",
        "results": [
            {
                "check_id": "python.lang.security.audit.dangerous-system-call",
                "path": "app/utils/deploy.py",
                "start": {"line": 42, "col": 5},
                "end": {"line": 42, "col": 55},
                "extra": {
                    "message": "Detected use of os.system(). Use subprocess.run() instead.",
                    "severity": "ERROR",
                    "metadata": {
                        "category": "security",
                        "confidence": "HIGH",
                        "cwe": ["CWE-89"],
                        "owasp": ["A03:2021"],
                    },
                },
            },
            {
                "check_id": "python.lang.security.audit.eval-detected",
                "path": "app/services/parser.py",
                "start": {"line": 18, "col": 12},
                "end": {"line": 18, "col": 40},
                "extra": {
                    "message": "Detected the use of eval(). Consider safer alternatives.",
                    "severity": "WARNING",
                    "metadata": {
                        "category": "security",
                        "confidence": "MEDIUM",
                        "cwe": ["CWE-95"],
                        "owasp": ["A03:2021"],
                    },
                },
            },
            {
                "check_id": "python.lang.best-practice.open-never-closed",
                "path": "app/utils/logger.py",
                "start": {"line": 7, "col": 1},
                "end": {"line": 7, "col": 30},
                "extra": {
                    "message": "File opened but never closed. Use a with statement.",
                    "severity": "INFO",
                    "metadata": {
                        "category": "best-practice",
                        "confidence": "HIGH",
                        "cwe": [],
                        "owasp": [],
                    },
                },
            },
        ],
        "errors": [],
    }


@pytest.fixture
def sample_checkov_output():
    """Realistic Checkov JSON output with failed checks (single framework)."""
    return {
        "check_type": "dockerfile",
        "summary": {"passed": 5, "failed": 2, "skipped": 0, "parsing_errors": 0},
        "results": {
            "passed_checks": [],
            "failed_checks": [
                {
                    "check_id": "CKV_DOCKER_2",
                    "check_type": "dockerfile",
                    "resource": "Dockerfile",
                    "file_path": "/Dockerfile",
                    "guideline": "Ensure that HEALTHCHECK instructions have been added to container images",
                    "severity": "HIGH",
                },
                {
                    "check_id": "CKV_DOCKER_3",
                    "check_type": "dockerfile",
                    "resource": "Dockerfile",
                    "file_path": "/Dockerfile",
                    "guideline": "Ensure that a user for the container has been created",
                    "severity": "MEDIUM",
                },
            ],
        },
    }


@pytest.fixture
def sample_checkov_multi_output(sample_checkov_output):
    """Checkov JSON output with multiple frameworks (returned as list)."""
    k8s_result = {
        "check_type": "kubernetes",
        "summary": {"passed": 3, "failed": 1, "skipped": 0, "parsing_errors": 0},
        "results": {
            "passed_checks": [],
            "failed_checks": [
                {
                    "check_id": "CKV_K8S_8",
                    "check_type": "kubernetes",
                    "resource": "Deployment.default.api",
                    "file_path": "/k8s/deployment.yaml",
                    "guideline": "Ensure liveness probe is configured",
                    "severity": "MEDIUM",
                },
            ],
        },
    }
    return [sample_checkov_output, k8s_result]


@pytest.fixture
def sample_osv_output():
    """Realistic OSV-Scanner JSON output with vulnerabilities."""
    return {
        "results": [
            {
                "source": {"path": "requirements.txt", "type": "lockfile"},
                "packages": [
                    {
                        "package": {
                            "name": "requests",
                            "version": "2.28.0",
                            "ecosystem": "PyPI",
                        },
                        "vulnerabilities": [
                            {
                                "id": "GHSA-j8r2-6x86-q33q",
                                "summary": "Requests has a vulnerability in certificate verification",
                                "aliases": ["CVE-2024-0001"],
                                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N"}],
                                "affected": [
                                    {
                                        "package": {"name": "requests", "ecosystem": "PyPI"},
                                        "ranges": [
                                            {
                                                "type": "ECOSYSTEM",
                                                "events": [
                                                    {"introduced": "0"},
                                                    {"fixed": "2.31.0"},
                                                ],
                                            }
                                        ],
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        ]
    }


@pytest.fixture
def webhook_secret():
    return "test-webhook-secret"


def make_signature(body: bytes, secret: str) -> str:
    """Generate a valid HMAC-SHA256 signature."""
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
