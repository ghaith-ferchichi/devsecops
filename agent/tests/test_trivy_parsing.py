import pytest

from app.services.trivy_service import parse_trivy_output


class TestTrivyParsing:
    """Tests for Trivy JSON output parsing."""

    def test_parse_realistic_output(self, sample_trivy_output):
        """Test parsing Trivy JSON with real vulnerabilities."""
        result = parse_trivy_output(sample_trivy_output, "trivy_image")

        assert result["scan_type"] == "trivy_image"
        assert result["summary"]["CRITICAL"] == 3
        assert result["summary"]["HIGH"] == 5
        assert result["summary"]["MEDIUM"] == 0
        assert result["summary"]["LOW"] == 0
        assert result["total_count"] == 8
        assert len(result["vulnerabilities"]) == 8  # all 8, less than top 15

    def test_parse_empty_output(self, sample_trivy_empty):
        """Test parsing Trivy JSON with no vulnerabilities (null)."""
        result = parse_trivy_output(sample_trivy_empty, "trivy_fs")

        assert result["scan_type"] == "trivy_fs"
        assert result["summary"]["CRITICAL"] == 0
        assert result["summary"]["HIGH"] == 0
        assert result["summary"]["MEDIUM"] == 0
        assert result["summary"]["LOW"] == 0
        assert result["total_count"] == 0
        assert result["vulnerabilities"] == []

    def test_top_n_sorted_by_severity(self, sample_trivy_output):
        """Test that vulnerabilities are sorted by severity (CRITICAL first)."""
        result = parse_trivy_output(sample_trivy_output, "trivy_image")

        severities = [v["Severity"] for v in result["vulnerabilities"]]
        # All CRITICAL should come before HIGH
        critical_indices = [i for i, s in enumerate(severities) if s == "CRITICAL"]
        high_indices = [i for i, s in enumerate(severities) if s == "HIGH"]

        if critical_indices and high_indices:
            assert max(critical_indices) < min(high_indices)

    def test_parse_empty_results_array(self):
        """Test parsing with empty Results array."""
        raw = {"SchemaVersion": 2, "Results": []}
        result = parse_trivy_output(raw, "trivy_fs")

        assert result["total_count"] == 0
        assert result["summary"]["CRITICAL"] == 0

    def test_parse_no_results_key(self):
        """Test parsing with missing Results key."""
        raw = {"SchemaVersion": 2}
        result = parse_trivy_output(raw, "trivy_fs")

        assert result["total_count"] == 0
        assert result["vulnerabilities"] == []

    def test_vulnerability_fields_extracted(self, sample_trivy_output):
        """Test that all expected fields are extracted from vulnerabilities."""
        result = parse_trivy_output(sample_trivy_output, "trivy_image")
        vuln = result["vulnerabilities"][0]

        assert "VulnerabilityID" in vuln
        assert "PkgName" in vuln
        assert "InstalledVersion" in vuln
        assert "FixedVersion" in vuln
        assert "Severity" in vuln
        assert "Title" in vuln
        assert "Target" in vuln

    def test_description_truncated(self):
        """Test that long descriptions are truncated to 200 chars."""
        raw = {
            "Results": [
                {
                    "Target": "test",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-9999",
                            "PkgName": "testpkg",
                            "InstalledVersion": "1.0",
                            "Severity": "HIGH",
                            "Description": "A" * 500,
                        },
                    ],
                },
            ],
        }
        result = parse_trivy_output(raw, "trivy_fs")
        assert len(result["vulnerabilities"][0]["Description"]) == 200
