// Package priority computes the dashboard-calculated remediation priority
// (P0-P4) for a vulnerability. The function lives in a dedicated package to
// avoid an import cycle: parser depends on priority, and service depends on
// parser (via scanprocessor). Both parser and service can therefore import
// priority without circular dependencies.
package priority

import (
	"trivyboard-backend/internal/domain"
)

// Result is the calculated priority score for a single vulnerability.
type Result struct {
	Score   int
	Level   domain.PriorityLevel
	Reasons []string
}

type threshold struct {
	level    domain.PriorityLevel
	minScore int
}

var levelThresholds = []threshold{
	{domain.PriorityP0, 120},
	{domain.PriorityP1, 95},
	{domain.PriorityP2, 70},
	{domain.PriorityP3, 45},
	{domain.PriorityP4, 0},
}

// Calculate implements the dashboard-calculated remediation priority.
//
//   base severity weight          (CRITICAL=100, HIGH=80, ...)
//   + CVSS score band             (>=9.0 → +15, >=7.0 → +8, >=4.0 → +3)
//   + fixed version is known      (+12, only counts toward unfixed findings)
//   + exploit metadata available  (+20)
//   + status adjustments          (will_not_fix +5, under_investigation +3,
//                                  not_affected -20)
func Calculate(
	severity domain.Severity,
	cvssMaxScore *float64,
	fixedVersion *string,
	status string,
	exploit *domain.ExploitDetails,
) Result {
	reasons := []string{}
	score := domain.SeverityWeight[severity]
	reasons = append(reasons, "Severity "+string(severity))

	if cvssMaxScore != nil {
		if *cvssMaxScore >= 9.0 {
			score += 15
			reasons = append(reasons, "CVSS >= 9.0")
		} else if *cvssMaxScore >= 7.0 {
			score += 8
			reasons = append(reasons, "CVSS >= 7.0")
		} else if *cvssMaxScore >= 4.0 {
			score += 3
			reasons = append(reasons, "CVSS >= 4.0")
		} else {
			reasons = append(reasons, "CVSS < 4.0")
		}
	}

	hasFix := fixedVersion != nil && *fixedVersion != ""
	if hasFix && status != string(domain.StatusFixed) {
		score += 12
		reasons = append(reasons, "Fixed version available")
	}

	if exploit != nil && exploit.Available {
		score += 20
		reasons = append(reasons, "Exploit metadata present")
	}

	switch status {
	case string(domain.StatusWillNotFix):
		score += 5
		reasons = append(reasons, "Will not fix upstream")
	case string(domain.StatusUnderInvestigation):
		score += 3
		reasons = append(reasons, "Under investigation")
	case string(domain.StatusNotAffected):
		score -= 20
		reasons = append(reasons, "Status not affected")
	}

	if score > 150 {
		score = 150
	}
	if score < 0 {
		score = 0
	}

	level := domain.PriorityP4
	for _, t := range levelThresholds {
		if score >= t.minScore {
			level = t.level
			break
		}
	}
	return Result{Score: score, Level: level, Reasons: reasons}
}
