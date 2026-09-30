package domain

import (
	"strings"
)

// Severity is one of the five normalized severity levels used by the dashboard.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityUnknown  Severity = "UNKNOWN"
)

// Severities lists the normalized severities in canonical order.
var Severities = []Severity{
	SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityUnknown,
}

// SeverityOrder ranks severities for sorting (higher = more severe).
var SeverityOrder = map[Severity]int{
	SeverityCritical: 5,
	SeverityHigh:     4,
	SeverityMedium:   3,
	SeverityLow:      2,
	SeverityUnknown:  1,
}

// SeverityWeight is the base score contribution per severity.
var SeverityWeight = map[Severity]int{
	SeverityCritical: 100,
	SeverityHigh:     80,
	SeverityMedium:   60,
	SeverityLow:      40,
	SeverityUnknown:  30,
}

// SeverityKey returns the lowercase severity key used by SeverityCounts maps.
func SeverityKey(s Severity) string {
	return strings.ToLower(string(s))
}

// NormalizeSeverity maps arbitrary input strings into one of the five
// canonical Severity values. Various legacy/alternate spellings are tolerated.
func NormalizeSeverity(value interface{}) Severity {
	str, ok := value.(string)
	if !ok {
		return SeverityUnknown
	}
	upper := strings.ToUpper(strings.TrimSpace(str))
	switch upper {
	case "CRITICAL", "SEVERE":
		return SeverityCritical
	case "HIGH":
		return SeverityHigh
	case "MEDIUM", "MODERATE", "IMPORTANT":
		return SeverityMedium
	case "LOW", "MINOR":
		return SeverityLow
	}
	for _, s := range Severities {
		if string(s) == upper {
			return s
		}
	}
	return SeverityUnknown
}

// CompareSeverity returns a negative, zero or positive number depending on
// whether a is less than, equal to, or greater than b (by severity weight).
func CompareSeverity(a, b Severity) int {
	return SeverityOrder[a] - SeverityOrder[b]
}
