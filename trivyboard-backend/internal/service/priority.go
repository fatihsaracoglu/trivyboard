package service

import (
	"trivyboard-backend/internal/domain"
	"trivyboard-backend/internal/priority"
)

// PriorityResult is the calculated priority score for a single vulnerability.
// Aliased here for ergonomic access from the rest of the service layer.
type PriorityResult = priority.Result

// CalculatePriority is a thin wrapper around priority.Calculate so callers
// can stay within the service package. The implementation lives in the
// dedicated priority package to avoid an import cycle (parser → priority,
// service → parser).
func CalculatePriority(
	severity domain.Severity,
	cvssMaxScore *float64,
	fixedVersion *string,
	status string,
	exploit *domain.ExploitDetails,
) PriorityResult {
	return priority.Calculate(severity, cvssMaxScore, fixedVersion, status, exploit)
}

// HasPriorityFor returns true when a vulnerability should be considered
// high-priority (P0 or P1 by score).
func HasPriorityFor(priorityScore int) bool {
	return priorityScore >= 95
}
