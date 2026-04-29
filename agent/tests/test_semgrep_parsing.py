import pytest

from app.services.semgrep_service import parse_semgrep_output


class TestSemgrepParsing:
    """Tests for Semgrep JSON output parsing."""

    def test_parse_realistic_output(self, sample_semgrep_output):
        """Test parsing Semgrep JSON with real findings."""
        result = parse_semgrep_output(sample_semgrep_output)

        assert result["scan_type"] == "semgrep"
        assert result["count"] == 3
        assert result["summary"]["ERROR"] == 1
        assert result["summary"]["WARNING"] == 1
        assert result["summary"]["INFO"] == 1

    def test_finding_fields_extracted(self, sample_semgrep_output):
        """Test that all expected fields are extracted from findings."""
        result = parse_semgrep_output(sample_semgrep_output)
        finding = result["findings"][0]

        assert "check_id" in finding
        assert "path" in finding
        assert "start_line" in finding
        assert "end_line" in finding
        assert "message" in finding
        assert "severity" in finding
        assert "metadata" in finding

    def test_metadata_extracted(self, sample_semgrep_output):
        """Test that CWE and OWASP metadata are extracted."""
        result = parse_semgrep_output(sample_semgrep_output)
        # First finding has CWE-89 (SQL injection)
        meta = result["findings"][0]["metadata"]
        assert "cwe" in meta
        assert len(meta["cwe"]) > 0
        assert "CWE-89" in meta["cwe"]

    def test_parse_empty_results(self):
        """Test parsing Semgrep output with empty results."""
        raw = {"results": [], "errors": [], "version": "1.90.0"}
        result = parse_semgrep_output(raw)

        assert result["scan_type"] == "semgrep"
        assert result["count"] == 0
        assert result["findings"] == []
        assert result["summary"] == {"ERROR": 0, "WARNING": 0, "INFO": 0}

    def test_parse_no_results_key(self):
        """Test parsing Semgrep output with missing results key."""
        raw = {"version": "1.90.0"}
        result = parse_semgrep_output(raw)

        assert result["count"] == 0
        assert result["findings"] == []

    def test_severity_summary_counts(self, sample_semgrep_output):
        """Test that severity summary counts match actual findings."""
        result = parse_semgrep_output(sample_semgrep_output)
        summary = result["summary"]
        findings = result["findings"]

        actual_counts = {"ERROR": 0, "WARNING": 0, "INFO": 0}
        for f in findings:
            if f["severity"] in actual_counts:
                actual_counts[f["severity"]] += 1

        assert summary == actual_counts


class TestCheckovParsing:
    """Tests for Checkov JSON output parsing."""

    def test_parse_single_framework(self, sample_checkov_output):
        from app.services.checkov_service import parse_checkov_output

        result = parse_checkov_output(sample_checkov_output)

        assert result["scan_type"] == "checkov"
        assert result["passed"] == 5
        assert result["failed"] == 2
        assert len(result["failed_checks"]) == 2

    def test_failed_check_fields(self, sample_checkov_output):
        from app.services.checkov_service import parse_checkov_output

        result = parse_checkov_output(sample_checkov_output)
        check = result["failed_checks"][0]

        assert "check_id" in check
        assert "check_type" in check
        assert "resource" in check
        assert "file_path" in check
        assert "guideline" in check

    def test_parse_multi_framework(self, sample_checkov_multi_output):
        from app.services.checkov_service import parse_checkov_output

        result = parse_checkov_output(sample_checkov_multi_output)

        assert result["passed"] == 8  # 5 + 3
        assert result["failed"] == 3  # 2 + 1

    def test_parse_empty_results(self):
        from app.services.checkov_service import parse_checkov_output

        raw = {"summary": {"passed": 10, "failed": 0}, "results": {"failed_checks": []}}
        result = parse_checkov_output(raw)

        assert result["failed"] == 0
        assert result["failed_checks"] == []


class TestOsvParsing:
    """Tests for OSV-Scanner JSON output parsing."""

    def test_parse_realistic_output(self, sample_osv_output):
        from app.services.osv_service import parse_osv_output

        result = parse_osv_output(sample_osv_output)

        assert result["scan_type"] == "osv"
        assert result["count"] >= 1

    def test_vulnerability_fields(self, sample_osv_output):
        from app.services.osv_service import parse_osv_output

        result = parse_osv_output(sample_osv_output)
        vuln = result["vulnerabilities"][0]

        assert "id" in vuln
        assert "summary" in vuln
        assert "severity" in vuln
        assert "package_name" in vuln
        assert "package_version" in vuln
        assert "ecosystem" in vuln

    def test_parse_empty_results(self):
        from app.services.osv_service import parse_osv_output

        raw = {"results": []}
        result = parse_osv_output(raw)

        assert result["count"] == 0
        assert result["vulnerabilities"] == []

    def test_parse_no_results_key(self):
        from app.services.osv_service import parse_osv_output

        raw = {}
        result = parse_osv_output(raw)

        assert result["count"] == 0

    def test_fixed_version_extracted(self, sample_osv_output):
        from app.services.osv_service import parse_osv_output

        result = parse_osv_output(sample_osv_output)
        vuln = result["vulnerabilities"][0]

        assert vuln["fixed_version"] == "2.31.0"
