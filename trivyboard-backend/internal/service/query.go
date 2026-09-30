package service

import (
        "sort"
        "strings"

        "trivyboard-backend/internal/domain"
)

// VulnerabilityQuery holds the filter / sort / paginate parameters for a
// vulnerability listing call.
type VulnerabilityQuery struct {
        Page          int
        PageSize      int
        Search        string
        Severities    []domain.Severity
        Statuses      []string
        Targets       []string
        Packages      []string
        Types         []string
        Fixability    string // "fixed" | "unfixed" | "all"
        SortBy        string
        SortOrder     string // "asc" | "desc"
        PriorityFilter string // "P0".."P4" — when set, restrict to that level
}

// VulnerabilityPage is one paginated slice of vulnerabilities.
type VulnerabilityPage struct {
        Rows       []domain.Vulnerability
        Total      int
        Page       int
        PageSize   int
        TotalPages int
}

// ValidSortFields enumerates the fields a client may sort by.
var ValidSortFields = []string{
        "severity", "vulnerabilityId", "pkgName", "installedVersion",
        "fixedVersion", "status", "target", "type", "cvssMaxScore",
        "publishedDate", "fixable", "priorityScore",
}

func matchesSearch(v domain.Vulnerability, search string) bool {
        needle := strings.ToLower(search)
        if strings.Contains(strings.ToLower(v.VulnerabilityID), needle) {
                return true
        }
        if strings.Contains(strings.ToLower(v.PkgName), needle) {
                return true
        }
        if v.Title != nil && strings.Contains(strings.ToLower(*v.Title), needle) {
                return true
        }
        if v.Description != nil && strings.Contains(strings.ToLower(*v.Description), needle) {
                return true
        }
        if strings.Contains(strings.ToLower(v.Target), needle) {
                return true
        }
        if v.InstalledVersion != nil && strings.Contains(strings.ToLower(*v.InstalledVersion), needle) {
                return true
        }
        if v.FixedVersion != nil && strings.Contains(strings.ToLower(*v.FixedVersion), needle) {
                return true
        }
        return false
}

// FilterVulnerabilities applies the structured overlay of filters to a list
// of occurrences and returns the matching subset.
func FilterVulnerabilities(rows []domain.Vulnerability, q VulnerabilityQuery) []domain.Vulnerability {
        fixability := q.Fixability
        if fixability == "" {
                fixability = "all"
        }
        search := strings.TrimSpace(q.Search)

        if len(q.Severities) == 0 && len(q.Statuses) == 0 && len(q.Targets) == 0 &&
                len(q.Packages) == 0 && len(q.Types) == 0 && fixability == "all" && search == "" &&
                q.PriorityFilter == "" {
                return rows
        }

        sevSet := toSet(q.SeveritiesAsStrings())
        statusSet := toSet(q.Statuses)
        targetSet := toSet(q.Targets)
        packageSet := toSet(q.Packages)
        typeSet := toSet(q.Types)
        priorityRange := priorityLevelRange(q.PriorityFilter)

        result := make([]domain.Vulnerability, 0, len(rows))
        for _, v := range rows {
                if len(sevSet) > 0 && !sevSet[string(v.Severity)] {
                        continue
                }
                if len(statusSet) > 0 && (v.Status == "" || !statusSet[v.Status]) {
                        continue
                }
                if len(targetSet) > 0 && !targetSet[v.Target] {
                        continue
                }
                if len(packageSet) > 0 && !packageSet[v.PkgName] {
                        continue
                }
                if len(typeSet) > 0 {
                        t := ""
                        if v.Type != nil {
                                t = *v.Type
                        }
                        if !typeSet[t] {
                                continue
                        }
                }
                if fixability == "fixed" && !v.Fixable {
                        continue
                }
                if fixability == "unfixed" && v.Fixable {
                        continue
                }
                if priorityRange != nil && (v.PriorityScore < priorityRange[0] || v.PriorityScore > priorityRange[1]) {
                        continue
                }
                if search != "" && !matchesSearch(v, search) {
                        continue
                }
                result = append(result, v)
        }
        return result
}

// priorityLevelRange returns the inclusive [min,max] score range for a P0..P4
// level string. Returns nil for empty/unknown values.
func priorityLevelRange(level string) []int {
        switch strings.ToUpper(strings.TrimSpace(level)) {
        case "P0":
                return []int{120, 9999}
        case "P1":
                return []int{95, 119}
        case "P2":
                return []int{70, 94}
        case "P3":
                return []int{45, 69}
        case "P4":
                return []int{0, 44}
        }
        return nil
}

// SeveritiesAsStrings renders the severities slice as plain strings for set
// lookup.
func (q VulnerabilityQuery) SeveritiesAsStrings() []string {
        out := make([]string, 0, len(q.Severities))
        for _, s := range q.Severities {
                out = append(out, string(s))
        }
        return out
}

// SortVulnerabilities returns a copy of rows sorted by the given field/order.
// Sort is stable for equal keys.
func SortVulnerabilities(rows []domain.Vulnerability, sortBy, sortOrder string) []domain.Vulnerability {
        if sortBy == "" {
                sortBy = "priorityScore"
        }
        if sortOrder == "" {
                sortOrder = "desc"
        }
        out := make([]domain.Vulnerability, len(rows))
        copy(out, rows)

        multiplier := -1
        if sortOrder == "asc" {
                multiplier = 1
        }

        sort.SliceStable(out, func(i, j int) bool {
                a, b := out[i], out[j]
                var cmp int
                switch sortBy {
                case "severity":
                        cmp = (domain.SeverityOrder[a.Severity]) - (domain.SeverityOrder[b.Severity])
                        cmp *= multiplier
                case "cvssMaxScore":
                        cmp = compareNumeric(a.CvssMaxScore, b.CvssMaxScore, sortOrder)
                case "publishedDate":
                        cmp = compareGeneric(a.PublishedDate, b.PublishedDate, sortOrder)
                case "fixable":
                        ai, bi := 0, 0
                        if a.Fixable {
                                ai = 1
                        }
                        if b.Fixable {
                                bi = 1
                        }
                        cmp = multiplier * (ai - bi)
                case "priorityScore":
                        cmp = multiplier * (a.PriorityScore - b.PriorityScore)
                case "status":
                        cmp = compareGeneric(strPtr(a.Status), strPtr(b.Status), sortOrder)
                case "installedVersion":
                        cmp = compareGeneric(a.InstalledVersion, b.InstalledVersion, sortOrder)
                case "fixedVersion":
                        cmp = compareGeneric(a.FixedVersion, b.FixedVersion, sortOrder)
                case "vulnerabilityId":
                        cmp = compareGeneric(strPtr(a.VulnerabilityID), strPtr(b.VulnerabilityID), sortOrder)
                case "pkgName":
                        cmp = compareGeneric(strPtr(a.PkgName), strPtr(b.PkgName), sortOrder)
                case "target":
                        cmp = compareGeneric(strPtr(a.Target), strPtr(b.Target), sortOrder)
                case "type":
                        cmp = compareGeneric(a.Type, b.Type, sortOrder)
                default:
                        cmp = multiplier * (a.PriorityScore - b.PriorityScore)
                }
                return cmp < 0
        })
        return out
}

func compareGeneric(a, b *string, order string) int {
        av := ""
        if a != nil {
                av = *a
        }
        bv := ""
        if b != nil {
                bv = *b
        }
        cmp := strings.Compare(av, bv)
        if order == "asc" {
                return cmp
        }
        return -cmp
}

func compareNumeric(a, b *float64, order string) int {
        av := negInf()
        if a != nil {
                av = *a
        }
        bv := negInf()
        if b != nil {
                bv = *b
        }
        if av < bv {
                if order == "asc" {
                        return -1
                }
                return 1
        }
        if av > bv {
                if order == "asc" {
                        return 1
                }
                return -1
        }
        return 0
}

func negInf() float64 { return -1e18 }

// Paginate slices rows into a single page.
func Paginate(rows []domain.Vulnerability, page, pageSize int) VulnerabilityPage {
        if pageSize < 1 {
                pageSize = 25
        }
        if page < 1 {
                page = 1
        }
        total := len(rows)
        totalPages := 1
        if total == 0 {
                totalPages = 1
        } else if pageSize > 0 {
                totalPages = (total + pageSize - 1) / pageSize
                if totalPages < 1 {
                        totalPages = 1
                }
        }
        if page > totalPages {
                page = totalPages
        }
        if page < 1 {
                page = 1
        }
        start := (page - 1) * pageSize
        if start > total {
                start = total
        }
        end := start + pageSize
        if end > total {
                end = total
        }
        return VulnerabilityPage{
                Rows:       rows[start:end],
                Total:      total,
                Page:       page,
                PageSize:   pageSize,
                TotalPages: totalPages,
        }
}

// QueryVulnerabilities applies filter → sort → paginate as a single pipeline.
func QueryVulnerabilities(rows []domain.Vulnerability, q VulnerabilityQuery) VulnerabilityPage {
        filtered := FilterVulnerabilities(rows, q)
        sorted := SortVulnerabilities(filtered, q.SortBy, q.SortOrder)
        return Paginate(sorted, q.Page, q.PageSize)
}

func toSet(items []string) map[string]bool {
        out := make(map[string]bool, len(items))
        for _, s := range items {
                if s != "" {
                        out[s] = true
                }
        }
        return out
}
