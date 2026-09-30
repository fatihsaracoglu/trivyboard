package parser

import (
        "encoding/json"
        "testing"

        "trivyboard-backend/internal/domain"
)

// TestParseMinimalReport verifies the parser correctly handles a minimal
// Trivy report structure with a single vulnerability.
func TestParseMinimalReport(t *testing.T) {
        // A minimal valid Trivy v2 report with one vulnerability.
        rawJSON := `{
                "SchemaVersion": 2,
                "ArtifactName": "alpine:3.19",
                "ArtifactType": "container_image",
                "Metadata": {
                        "OS": {"Family": "alpine", "Name": "3.19.1"},
                        "ImageID": "sha256:abcd1234",
                        "RepoTags": ["alpine:3.19"],
                        "ScanStartedAt": "2025-01-15T10:30:00.000Z",
                        "ScanEndedAt": "2025-01-15T10:30:05.000Z"
                },
                "Results": [
                        {
                                "Target": "alpine:3.19 (alpine 3.19.1)",
                                "Class": "os-pkgs",
                                "Type": "alpine",
                                "Vulnerabilities": [
                                        {
                                                "VulnerabilityID": "CVE-2024-2961",
                                                "PkgName": "libcrypto3",
                                                "InstalledVersion": "3.1.4-r4",
                                                "FixedVersion": "3.1.4-r5",
                                                "Status": "fixed",
                                                "Severity": "HIGH",
                                                "Title": "libcrypto3: buffer overflow",
                                                "Description": "A vulnerability was found in OpenSSL.",
                                                "CVSS": {
                                                        "nvd": {"V3Score": 7.5, "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}
                                                },
                                                "CweIDs": ["CWE-122"],
                                                "References": ["https://nvd.nist.gov/vuln/detail/CVE-2024-2961"]
                                        }
                                ]
                        }
                ]
        }`
        var input interface{}
        if err := json.Unmarshal([]byte(rawJSON), &input); err != nil {
                t.Fatalf("failed to parse test JSON: %v", err)
        }
        scan, err := ParseTrivyReport(input, ParseOptions{Filename: "minimal.json"})
        if err != nil {
                t.Fatalf("ParseTrivyReport failed: %v", err)
        }
        if scan.ArtifactName != "alpine:3.19" {
                t.Errorf("expected artifactName 'alpine:3.19', got %q", scan.ArtifactName)
        }
        if *scan.ArtifactType != "container_image" {
                t.Errorf("expected artifactType 'container_image', got %q", *scan.ArtifactType)
        }
        if len(scan.Vulnerabilities) != 1 {
                t.Fatalf("expected 1 vulnerability, got %d", len(scan.Vulnerabilities))
        }
        v := scan.Vulnerabilities[0]
        if v.VulnerabilityID != "CVE-2024-2961" {
                t.Errorf("expected CVE-2024-2961, got %q", v.VulnerabilityID)
        }
        if v.Severity != domain.SeverityHigh {
                t.Errorf("expected HIGH severity, got %q", v.Severity)
        }
        if v.PkgName != "libcrypto3" {
                t.Errorf("expected pkgName 'libcrypto3', got %q", v.PkgName)
        }
        if *v.InstalledVersion != "3.1.4-r4" {
                t.Errorf("expected installedVersion '3.1.4-r4', got %q", *v.InstalledVersion)
        }
        if v.FixedVersion == nil || *v.FixedVersion != "3.1.4-r5" {
                t.Errorf("expected fixedVersion '3.1.4-r5', got %v", v.FixedVersion)
        }
        if !v.Fixable {
                t.Error("expected fixable=true when FixedVersion is present")
        }
        if scan.FixableCount != 1 {
                t.Errorf("expected fixableCount=1, got %d", scan.FixableCount)
        }
}

// TestParseInvalidInput verifies the parser rejects non-Trivy input.
func TestParseInvalidInput(t *testing.T) {
        inputs := []interface{}{
                nil,
                "not an object",
                123,
                []string{"array"},
                map[string]interface{}{"foo": "bar"},
        }
        for _, input := range inputs {
                _, err := ParseTrivyReport(input, ParseOptions{Filename: "test.json"})
                if err == nil {
                        t.Errorf("expected error for input %v, got nil", input)
                }
        }
}

// TestParseEmptyResults verifies the parser handles a report with no results.
func TestParseEmptyResults(t *testing.T) {
        rawJSON := `{
                "SchemaVersion": 2,
                "ArtifactName": "empty:test",
                "ArtifactType": "container_image",
                "Results": []
        }`
        var input interface{}
        if err := json.Unmarshal([]byte(rawJSON), &input); err != nil {
                t.Fatalf("failed to parse test JSON: %v", err)
        }
        scan, err := ParseTrivyReport(input, ParseOptions{Filename: "empty.json"})
        if err != nil {
                t.Fatalf("ParseTrivyReport failed: %v", err)
        }
        if len(scan.Vulnerabilities) != 0 {
                t.Errorf("expected 0 vulnerabilities, got %d", len(scan.Vulnerabilities))
        }
}

// TestParseMultipleTargets verifies occurrences across targets are not merged.
func TestParseMultipleTargets(t *testing.T) {
        rawJSON := `{
                "SchemaVersion": 2,
                "ArtifactName": "multi:test",
                "ArtifactType": "container_image",
                "Results": [
                        {
                                "Target": "target-a",
                                "Class": "os-pkgs",
                                "Type": "debian",
                                "Vulnerabilities": [
                                        {"VulnerabilityID": "CVE-2024-0001", "PkgName": "openssl", "InstalledVersion": "1.0", "Severity": "HIGH"}
                                ]
                        },
                        {
                                "Target": "target-b",
                                "Class": "os-pkgs",
                                "Type": "debian",
                                "Vulnerabilities": [
                                        {"VulnerabilityID": "CVE-2024-0001", "PkgName": "openssl", "InstalledVersion": "1.0", "Severity": "HIGH"}
                                ]
                        }
                ]
        }`
        var input interface{}
        if err := json.Unmarshal([]byte(rawJSON), &input); err != nil {
                t.Fatalf("failed to parse test JSON: %v", err)
        }
        scan, err := ParseTrivyReport(input, ParseOptions{Filename: "multi.json"})
        if err != nil {
                t.Fatalf("ParseTrivyReport failed: %v", err)
        }
        if len(scan.Vulnerabilities) != 2 {
                t.Fatalf("expected 2 vulnerability occurrences (one per target), got %d", len(scan.Vulnerabilities))
        }
        // Verify they have different IDs (different targets → different composite keys).
        if scan.Vulnerabilities[0].ID == scan.Vulnerabilities[1].ID {
                t.Error("expected different IDs for the same CVE in different targets")
        }
}

// TestSeverityNormalization verifies severity strings are normalized correctly.
func TestSeverityNormalization(t *testing.T) {
        cases := []struct {
                input    interface{}
                expected domain.Severity
        }{
                {"CRITICAL", domain.SeverityCritical},
                {"critical", domain.SeverityCritical},
                {"SEVERE", domain.SeverityCritical},
                {"HIGH", domain.SeverityHigh},
                {"MEDIUM", domain.SeverityMedium},
                {"MODERATE", domain.SeverityMedium},
                {"IMPORTANT", domain.SeverityMedium},
                {"LOW", domain.SeverityLow},
                {"MINOR", domain.SeverityLow},
                {"UNKNOWN", domain.SeverityUnknown},
                {"", domain.SeverityUnknown},
                {"garbage", domain.SeverityUnknown},
                {nil, domain.SeverityUnknown},
                {123, domain.SeverityUnknown},
        }
        for _, c := range cases {
                got := domain.NormalizeSeverity(c.input)
                if got != c.expected {
                        t.Errorf("NormalizeSeverity(%v) = %q, want %q", c.input, got, c.expected)
                }
        }
}
