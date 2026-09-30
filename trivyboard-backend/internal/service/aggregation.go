package service

import (
        "sort"

        "trivyboard-backend/internal/domain"
)

// CountBySeverity returns per-severity counts across the given vulnerabilities.
func CountBySeverity(vulns []domain.Vulnerability) domain.SeverityCounts {
        counts := domain.EmptySeverityCounts()
        for _, v := range vulns {
                switch v.Severity {
                case domain.SeverityCritical:
                        counts.Critical++
                case domain.SeverityHigh:
                        counts.High++
                case domain.SeverityMedium:
                        counts.Medium++
                case domain.SeverityLow:
                        counts.Low++
                default:
                        counts.Unknown++
                }
        }
        return counts
}

// SummarizeScan computes the public, serializable summary payload for a scan.
func SummarizeScan(scan domain.NormalizedScan) domain.ScanSummary {
        severity := CountBySeverity(scan.Vulnerabilities)
        statusFixed := 0
        exploitableBySource := 0
        for _, v := range scan.Vulnerabilities {
                if v.Status == string(domain.StatusFixed) {
                        statusFixed++
                }
                if v.Exploit != nil && v.Exploit.Available &&
                        v.Severity != domain.SeverityLow && v.Severity != domain.SeverityUnknown {
                        exploitableBySource++
                }
        }
        topPackages := AggregatePackages(scan)
        if len(topPackages) > 10 {
                topPackages = topPackages[:10]
        }
        topEntries := make([]domain.TopPackageEntry, 0, len(topPackages))
        for _, p := range topPackages {
                topEntries = append(topEntries, domain.TopPackageEntry{
                        Package:       p.Package,
                        Occurrences:   p.Occurrences,
                        Severity:      p.Severity,
                        Fixable:       p.Fixable,
                        PriorityScore: p.PriorityScore,
                })
        }
        return domain.ScanSummary{
                ScanID:                   scan.ID,
                Filename:                 scan.Filename,
                ArtifactName:             scan.ArtifactName,
                ArtifactType:             scan.ArtifactType,
                SchemaVersion:            scan.SchemaVersion,
                UploadedAt:               scan.UploadedAt,
                Meta:                     scan.Metadata,
                ResultCount:              scan.ResultCount,
                ScannedAt:                scan.Metadata.ScanEndedAt,
                TargetCount:              scan.TargetCount,
                VulnerabilityOccurrences: scan.VulnerabilityCount,
                UniqueVulnerabilityIDs:   scan.UniqueVulnerabilityIDCount,
                Severity:                 severity,
                Fixable:                  scan.FixableCount,
                NoFixKnown:               scan.VulnerabilityCount - scan.FixableCount,
                StatusFixed:             statusFixed,
                ExploitableBySource:     exploitableBySource,
                Scanners:                scan.Scanners,
                Findings:                scan.Findings,
                Warnings:                scan.Warnings,
                TopPackages:             topEntries,
        }
}

// AggregatePackages groups vulnerabilities by package name.
func AggregatePackages(scan domain.NormalizedScan) []domain.PackageSummary {
        byPackage := map[string]*domain.PackageSummary{}
        order := []string{}
        for _, v := range scan.Vulnerabilities {
                summary, ok := byPackage[v.PkgName]
                if !ok {
                        summary = &domain.PackageSummary{
                                Package:  v.PkgName,
                                Severity: domain.EmptySeverityCounts(),
                                Targets:  []string{},
                        }
                        byPackage[v.PkgName] = summary
                        order = append(order, v.PkgName)
                }
                summary.Occurrences++
                incSeverity(&summary.Severity, v.Severity)
                if v.Fixable {
                        summary.Fixable++
                }
                if !containsStr(summary.Targets, v.Target) {
                        summary.Targets = append(summary.Targets, v.Target)
                }
                if v.PriorityScore > summary.PriorityScore {
                        summary.PriorityScore = v.PriorityScore
                }
        }
        // Sort by risk descending, then by package name (matches TS impl).
        out := make([]domain.PackageSummary, 0, len(order))
        for _, name := range order {
                out = append(out, *byPackage[name])
        }
        sort.SliceStable(out, func(i, j int) bool {
                ri, rj := PackageRiskSortValue(out[i]), PackageRiskSortValue(out[j])
                if ri != rj {
                        return ri > rj
                }
                return out[i].Package < out[j].Package
        })
        return out
}

// AggregateTargets groups vulnerabilities by target.
func AggregateTargets(scan domain.NormalizedScan) []domain.TargetSummary {
        byTarget := map[string]*domain.TargetSummary{}
        order := []string{}
        for _, v := range scan.Vulnerabilities {
                summary, ok := byTarget[v.Target]
                if !ok {
                        summary = &domain.TargetSummary{
                                Target:   v.Target,
                                Class:    strPtr(v.Class),
                                Type:     v.Type,
                                Severity: domain.EmptySeverityCounts(),
                        }
                        byTarget[v.Target] = summary
                        order = append(order, v.Target)
                }
                summary.Total++
                incSeverity(&summary.Severity, v.Severity)
                if v.Fixable {
                        summary.Fixable++
                }
        }
        out := make([]domain.TargetSummary, 0, len(order))
        for _, t := range order {
                out = append(out, *byTarget[t])
        }
        return out
}

// PackageRiskSortValue computes a comparable "risk score" for sorting package rows.
func PackageRiskSortValue(s domain.PackageSummary) int {
        return s.Severity.Critical*100 +
                s.Severity.High*40 +
                s.Severity.Medium*10 +
                s.Severity.Low*2 +
                s.PriorityScore
}

// FindingsTotal returns the total count of findings across all kinds.
func FindingsTotal(findings []domain.FindingSummary) int {
        total := 0
        for _, f := range findings {
                total += f.Count
        }
        return total
}

func incSeverity(sc *domain.SeverityCounts, s domain.Severity) {
        switch s {
        case domain.SeverityCritical:
                sc.Critical++
        case domain.SeverityHigh:
                sc.High++
        case domain.SeverityMedium:
                sc.Medium++
        case domain.SeverityLow:
                sc.Low++
        default:
                sc.Unknown++
        }
}

func containsStr(arr []string, s string) bool {
        for _, v := range arr {
                if v == s {
                        return true
                }
        }
        return false
}

func strPtr(s string) *string {
        if s == "" {
                return nil
        }
        t := s
        return &t
}
