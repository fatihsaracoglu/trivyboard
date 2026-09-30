package domain

import "strings"

// VulnerabilityStatus represents the lifecycle status of a vuln as reported
// by Trivy. Empty string means the source report did not provide one.
type VulnerabilityStatus string

const (
        StatusFixed              VulnerabilityStatus = "fixed"
        StatusAffected           VulnerabilityStatus = "affected"
        StatusWillNotFix         VulnerabilityStatus = "will_not_fix"
        StatusNotAffected        VulnerabilityStatus = "not_affected"
        StatusUnderInvestigation VulnerabilityStatus = "under_investigation"
)

var vulnerabilityStatuses = []VulnerabilityStatus{
        StatusFixed, StatusAffected, StatusWillNotFix, StatusNotAffected, StatusUnderInvestigation,
}

// IsVulnerabilityStatus reports whether value is a known status string.
func IsVulnerabilityStatus(value string) bool {
        for _, s := range vulnerabilityStatuses {
                if string(s) == value {
                        return true
                }
        }
        return false
}

// NormalizeVulnerabilityStatus returns a known status string or "" if value
// is missing/unrecognized. The lookup is case-insensitive.
func NormalizeVulnerabilityStatus(value interface{}) string {
        str, ok := value.(string)
        if !ok {
                return ""
        }
        if IsVulnerabilityStatus(str) {
                return str
        }
        lower := strings.ToLower(strings.TrimSpace(str))
        if IsVulnerabilityStatus(lower) {
                return lower
        }
        return ""
}

// ScanResultClass values emitted by Trivy in the per-result "Class" field.
type ScanResultClass string

const (
        ClassOSPkg  ScanResultClass = "os-pkgs"
        ClassLangP  ScanResultClass = "lang-pkgs"
        ClassConfig ScanResultClass = "config"
        ClassSecret ScanResultClass = "secret"
        ClassLicense ScanResultClass = "license"
)

// FindingKind enumerates the non-vulnerability finding types Trivy reports.
type FindingKind string

const (
        FindingMisconfiguration FindingKind = "misconfiguration"
        FindingSecret           FindingKind = "secret"
        FindingLicense          FindingKind = "license"
)

// PriorityLevel is one of the dashboard-calculated remediation priority levels.
type PriorityLevel string

const (
        PriorityP0 PriorityLevel = "P0"
        PriorityP1 PriorityLevel = "P1"
        PriorityP2 PriorityLevel = "P2"
        PriorityP3 PriorityLevel = "P3"
        PriorityP4 PriorityLevel = "P4"
)

// PriorityLevels lists the priority levels in descending order of urgency.
var PriorityLevels = []PriorityLevel{
        PriorityP0, PriorityP1, PriorityP2, PriorityP3, PriorityP4,
}

// PriorityOrder ranks priority levels for sorting (higher = more urgent).
var PriorityOrder = map[PriorityLevel]int{
        PriorityP0: 5,
        PriorityP1: 4,
        PriorityP2: 3,
        PriorityP3: 2,
        PriorityP4: 1,
}

// PriorityRank returns the 0-based index of a level in PriorityLevels.
func PriorityRank(level PriorityLevel) int {
        for i, l := range PriorityLevels {
                if l == level {
                        return i
                }
        }
        return len(PriorityLevels)
}
