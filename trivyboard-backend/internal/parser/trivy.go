// Package parser implements defensive normalization of Trivy JSON reports.
//
// The input documents are heterogeneous across Trivy versions, so we always
// unmarshal into interface{} trees and walk them with helpers that tolerate
// missing/null/unexpected fields without crashing the parse. The output is
// a single, normalized domain.NormalizedScan that the rest of the service
// consumes.
package parser

import (
        "encoding/json"
        "fmt"
        "strings"
        "time"

        "trivyboard-backend/internal/domain"
        "trivyboard-backend/internal/priority"
        "trivyboard-backend/internal/util"
)

// ParseOptions tweaks the parser. Filename is the upload filename. SlotID,
// when non-empty, overrides the generated scan id (used by the scan runner
// when callers want a deterministic id).
type ParseOptions struct {
        Filename string
        SlotID   string
}

type cvssKeyPair struct {
        scoreKey string
        vectorKey string
        version string
}

// CVSS_SCORE_KEYS covers the per-vendor CVSS block shapes Trivy emits.
// Trivy v0.74 actually emits V40Score/V40Vector (not V4Score/V4Vector) so we
// probe both spellings to avoid losing score data.
var cvssScoreKeys = []cvssKeyPair{
        {"V2Score", "V2Vector", "2.0"},
        {"V3Score", "V3Vector", "3"},
        {"V4Score", "V4Vector", "4.0"},
        {"V40Score", "V40Vector", "4.0"},
}

type normalizeContext struct {
        seenKeys      map[string]struct{}
        warnings      []domain.ParserWarning
        vulnerabilities []domain.Vulnerability
        findingRows   []domain.Finding
}

// CanParseTrivyReport returns true when input looks like a Trivy JSON report:
// it must be an object containing a Results array AND either a numeric
// SchemaVersion or a string ArtifactName.
func CanParseTrivyReport(input interface{}) bool {
        root := toObj(input)
        if root == nil {
                return false
        }
        _, hasResults := root["Results"]
        _, resultsIsArray := asArray(root["Results"])
        if !hasResults || !resultsIsArray {
                return false
        }
        if _, ok := root["SchemaVersion"]; ok {
                if _, isNum := asFloat(root["SchemaVersion"]); isNum {
                        return true
                }
        }
        if s := asStr(root["ArtifactName"]); s != "" {
                return true
        }
        return false
}

// ValidateTrivyReportRoot raises an error when input is structurally not a
// Trivy report. The error code is returned as a string for the caller to wrap
// into an AppError.
func ValidateTrivyReportRoot(input interface{}) error {
        root := toObj(input)
        if root == nil {
                return fmt.Errorf("INVALID_TRIVY_RESULT:The uploaded file is not a valid Trivy scan result.")
        }
        results, ok := asArray(root["Results"])
        if !ok {
                return fmt.Errorf("INVALID_TRIVY_RESULT:The uploaded file is not a valid Trivy scan result: missing the 'Results' array.")
        }
        schemaVersion, _ := asFloat(root["SchemaVersion"])
        artifactName := asStr(root["ArtifactName"])
        hasMarkers := schemaVersion != 0 || artifactName != ""
        if !hasMarkers {
                return fmt.Errorf("INVALID_TRIVY_RESULT:The uploaded JSON does not look like a Trivy scan result (no SchemaVersion or ArtifactName found).")
        }
        // Schema versions 1 and 2 are accepted; nil is accepted (let it through).
        if schemaVersion != 0 && schemaVersion != 1 && schemaVersion != 2 {
                return fmt.Errorf("UNSUPPORTED_TRIVY_SCHEMA:Unsupported Trivy schema version %v. This dashboard accepts schema versions 1 and 2.", schemaVersion)
        }
        _ = results
        return nil
}

// ParseTrivyReport turns a parsed JSON tree into a NormalizedScan.
func ParseTrivyReport(input interface{}, options ParseOptions) (domain.NormalizedScan, error) {
        if err := ValidateTrivyReportRoot(input); err != nil {
                return domain.NormalizedScan{}, err
        }
        root := input.(map[string]interface{})

        ctx := &normalizeContext{
                seenKeys: make(map[string]struct{}),
                warnings: []domain.ParserWarning{},
        }

        results, _ := asArray(root["Results"])
        for rowIndex, raw := range results {
                result := toObj(raw)
                if result == nil {
                        ctx.warnings = append(ctx.warnings, domain.ParserWarning{
                                Code:    "MALFORMED_RESULT",
                                Message: fmt.Sprintf("Skipping malformed result at index %d.", rowIndex),
                        })
                        continue
                }
                normalizeResultRow(result, rowIndex, ctx)
        }

        findings := buildFindingSummaries(ctx.findingRows)

        uniqueVulnIDs := map[string]struct{}{}
        for _, v := range ctx.vulnerabilities {
                uniqueVulnIDs[v.VulnerabilityID] = struct{}{}
        }
        targetSet := map[string]struct{}{}
        for _, v := range ctx.vulnerabilities {
                targetSet[v.Target] = struct{}{}
        }

        schemaVersion, hasSchema := asFloat(root["SchemaVersion"])
        var schemaVersionPtr *int
        if hasSchema && schemaVersion == float64(int(schemaVersion)) {
                iv := int(schemaVersion)
                schemaVersionPtr = &iv
        }
        artifactName := asStr(root["ArtifactName"])
        artifactType := asStrOrNull(root["ArtifactType"])
        scanners := asStrArray(root["Scanners"])
        metadata := extractMetadata(root)

        fixableCount := 0
        for _, v := range ctx.vulnerabilities {
                if v.Fixable {
                        fixableCount++
                }
        }

        id := options.SlotID
        if id == "" {
                id = util.GenerateScanID(artifactName)
        }

        // Ensure warnings / scanners / findings are non-nil so they JSON-encode
        // as arrays rather than null.
        if ctx.warnings == nil {
                ctx.warnings = []domain.ParserWarning{}
        }
        if scanners == nil {
                scanners = []string{}
        }
        if findings == nil {
                findings = []domain.FindingSummary{}
        }
        if ctx.findingRows == nil {
                ctx.findingRows = []domain.Finding{}
        }
        if ctx.vulnerabilities == nil {
                ctx.vulnerabilities = []domain.Vulnerability{}
        }

        return domain.NormalizedScan{
                ID:                         id,
                Filename:                   options.Filename,
                ArtifactName:               artifactName,
                ArtifactType:               artifactType,
                SchemaVersion:              schemaVersionPtr,
                Scanners:                   scanners,
                Metadata:                   metadata,
                UploadedAt:                 nowMillis(),
                ResultCount:                len(results),
                TargetCount:                len(targetSet),
                Warnings:                   ctx.warnings,
                Vulnerabilities:            ctx.vulnerabilities,
                FindingRows:                ctx.findingRows,
                Findings:                   findings,
                VulnerabilityCount:         len(ctx.vulnerabilities),
                UniqueVulnerabilityIDCount: len(uniqueVulnIDs),
                FixableCount:               fixableCount,
        }, nil
}

// ParseBytes parses raw JSON bytes into a generic interface{} tree suitable
// for passing to ParseTrivyReport.
func ParseBytes(data []byte) (interface{}, error) {
        var v interface{}
        if err := json.Unmarshal(data, &v); err != nil {
                return nil, err
        }
        return v, nil
}

// ---------------------------------------------------------------------------
// Defensive accessor helpers (ports of toObj / asStr / asStrOrNull / asNum /
// asBool / asStrArray / asArray from the TS reference).
// ---------------------------------------------------------------------------

func toObj(value interface{}) map[string]interface{} {
        if m, ok := value.(map[string]interface{}); ok {
                return m
        }
        return nil
}

func asArray(value interface{}) ([]interface{}, bool) {
        if arr, ok := value.([]interface{}); ok {
                return arr, true
        }
        return nil, false
}

func asStr(value interface{}) string {
        if s, ok := value.(string); ok {
                return strings.TrimSpace(s)
        }
        return ""
}

func asStrOrNull(value interface{}) *string {
        s := asStr(value)
        if s == "" {
                return nil
        }
        return &s
}

func asFloat(value interface{}) (float64, bool) {
        switch v := value.(type) {
        case float64:
                return v, true
        case int:
                return float64(v), true
        case int64:
                return float64(v), true
        case string:
                s := strings.TrimSpace(v)
                if s == "" {
                        return 0, false
                }
                var f float64
                if _, err := fmt.Sscanf(s, "%g", &f); err != nil {
                        return 0, false
                }
                return f, true
        }
        return 0, false
}

func asNumPtr(value interface{}) *float64 {
        f, ok := asFloat(value)
        if !ok {
                return nil
        }
        return &f
}

func asIntPtr(value interface{}) *int {
        f, ok := asFloat(value)
        if !ok {
                return nil
        }
        i := int(f)
        return &i
}

func asBool(value interface{}) bool {
        switch v := value.(type) {
        case bool:
                return v
        case string:
                return len(v) > 0
        }
        return false
}

func asStrArray(value interface{}) []string {
        arr, ok := asArray(value)
        if !ok {
                return []string{}
        }
        results := make([]string, 0, len(arr))
        for _, item := range arr {
                if s, ok := item.(string); ok {
                        trimmed := strings.TrimSpace(s)
                        if trimmed != "" {
                                results = append(results, trimmed)
                        }
                }
        }
        return results
}

// nowMillis returns the current time as Unix milliseconds.
func nowMillis() int64 {
        return time.Now().UnixMilli()
}

// ---------------------------------------------------------------------------
// Per-row normalization.
// ---------------------------------------------------------------------------

func normalizeResultRow(result map[string]interface{}, rowIndex int, ctx *normalizeContext) {
        target := asStr(result["Target"])
        if target == "" {
                target = fmt.Sprintf("target-%d", rowIndex+1)
        }
        resultClass := asStrOrNull(result["Class"])
        resultType := asStrOrNull(result["Type"])

        if vulns, ok := asArray(result["Vulnerabilities"]); ok {
                for _, entry := range vulns {
                        raw := toObj(entry)
                        if raw == nil {
                                pkgStr := ""
                                ctx.warnings = append(ctx.warnings, domain.ParserWarning{
                                        Code:    "MALFORMED_VULNERABILITY",
                                        Message: fmt.Sprintf("Skipping malformed vulnerability in %s.", target),
                                        Target:  &target,
                                })
                                _ = pkgStr
                                continue
                        }
                        if v, ok := normalizeVulnerability(raw, target, resultClass, resultType, ctx); ok {
                                ctx.vulnerabilities = append(ctx.vulnerabilities, v)
                        }
                }
        }

        if mArr, ok := asArray(result["Misconfigurations"]); ok {
                for _, entry := range mArr {
                        if raw := toObj(entry); raw != nil {
                                ctx.findingRows = append(ctx.findingRows, normalizeMisconfiguration(raw, target, resultClass, resultType))
                        }
                }
        }
        if sArr, ok := asArray(result["Secrets"]); ok {
                for _, entry := range sArr {
                        if raw := toObj(entry); raw != nil {
                                ctx.findingRows = append(ctx.findingRows, normalizeSecret(raw, target, resultClass, resultType))
                        }
                }
        }
        if lArr, ok := asArray(result["Licenses"]); ok {
                for _, entry := range lArr {
                        if raw := toObj(entry); raw != nil {
                                ctx.findingRows = append(ctx.findingRows, normalizeLicense(raw, target, resultClass, resultType))
                        }
                }
        }
}

func normalizeVulnerability(
        raw map[string]interface{},
        target string,
        resultClass, resultType *string,
        ctx *normalizeContext,
) (domain.Vulnerability, bool) {
        vulnerabilityID := firstNonNilStr(asStrOrNull(raw["VulnerabilityID"]), asStrOrNull(raw["ID"]))
        pkgName := firstNonNilStr(asStrOrNull(raw["PkgName"]), asStrOrNull(raw["Package"]))

        if vulnerabilityID == nil {
                pkgStr := "unknown package"
                if pkgName != nil {
                        pkgStr = *pkgName
                }
                ctx.warnings = append(ctx.warnings, domain.ParserWarning{
                        Code:    "MISSING_VULNERABILITY_ID",
                        Message: fmt.Sprintf("Skipping vulnerability in %s without an identifier (%s).", target, pkgStr),
                        Target:  &target,
                })
                return domain.Vulnerability{}, false
        }

        installedVersion := firstNonNilStr(asStrOrNull(raw["InstalledVersion"]), asStrOrNull(raw["Version"]))
        fixedVersion := asStrOrNull(raw["FixedVersion"])
        severity := domain.NormalizeSeverity(raw["Severity"])
        status := domain.NormalizeVulnerabilityStatus(raw["Status"])
        cvss := extractCvss(raw)
        cvssMaxScore := maxCvss(cvss)
        exploit := extractExploit(raw)
        pkgIdentifier := normalizePkgIdentifier(raw)

        // fixable = a fixed version is known for this vulnerability, so the
        // user can remediate by upgrading. Trivy sets status="fixed" when a
        // fix exists — that does NOT mean the user has already applied it.
        // The installed version is still vulnerable (otherwise Trivy wouldn't
        // report it), so fixable should be true whenever FixedVersion is set.
        fixable := fixedVersion != nil && *fixedVersion != ""

        vulnClass := "os-pkgs"
        if resultClass != nil {
                switch *resultClass {
                case string(domain.ClassOSPkg):
                        vulnClass = "os-pkgs"
                case string(domain.ClassLangP):
                        vulnClass = "lang-pkgs"
                case "":
                        vulnClass = "os-pkgs"
                default:
                        vulnClass = "lang-pkgs"
                }
        }
        var language *string
        if resultClass != nil && *resultClass == string(domain.ClassLangP) {
                language = resultType
        }

        key := util.BuildVulnerabilityKey(target, *vulnerabilityID, strOrEmpty(pkgName), installedVersion)
        if _, seen := ctx.seenKeys[key]; seen {
                ctx.warnings = append(ctx.warnings, domain.ParserWarning{
                        Code:    "DUPLICATE_VULNERABILITY",
                        Message: fmt.Sprintf("Skipping duplicate vulnerability %s in %s (%s %s).", *vulnerabilityID, target, strOrEmpty(pkgName), strOrEmpty(installedVersion)),
                        Target:  &target,
                })
                return domain.Vulnerability{}, false
        }
        ctx.seenKeys[key] = struct{}{}

        p := priority.Calculate(severity, cvssMaxScore, fixedVersion, status, exploit)

        pkgNameStr := "(unknown)"
        if pkgName != nil {
                pkgNameStr = *pkgName
        }

        cweIDs := asStrArray(raw["CweIDs"])
        normalizedCwe := make([]string, 0, len(cweIDs))
        for _, c := range cweIDs {
                if strings.HasPrefix(c, "CWE") {
                        normalizedCwe = append(normalizedCwe, c)
                } else {
                        normalizedCwe = append(normalizedCwe, "CWE-"+c)
                }
        }

        publishedDate := firstNonNilStr(asStrOrNull(raw["PublishedDate"]), asStrOrNull(raw["Published"]))
        lastModifiedDate := firstNonNilStr(asStrOrNull(raw["LastModifiedDate"]), asStrOrNull(raw["LastModified"]))

        return domain.Vulnerability{
                ID:               util.EncodeID(key),
                Key:              key,
                VulnerabilityID:  *vulnerabilityID,
                Severity:         severity,
                PkgName:          pkgNameStr,
                PkgPath:          asStrOrNull(raw["PkgPath"]),
                InstalledVersion: installedVersion,
                FixedVersion:     fixedVersion,
                Status:           status,
                Target:           target,
                Type:             resultType,
                Class:            vulnClass,
                Language:         language,
                Cvss:             cvss,
                CvssMaxScore:     cvssMaxScore,
                SeveritySource:   asStrOrNull(raw["SeveritySource"]),
                Title:            asStrOrNull(raw["Title"]),
                Description:      asStrOrNull(raw["Description"]),
                References:       asStrArray(raw["References"]),
                CweIDs:           normalizedCwe,
                PublishedDate:    publishedDate,
                LastModifiedDate:  lastModifiedDate,
                PrimaryURL:       asStrOrNull(raw["PrimaryURL"]),
                Exploit:          exploit,
                Fixable:          fixable,
                PriorityScore:    p.Score,
                PriorityLevel:    p.Level,
                PriorityReasons:  p.Reasons,
                PkgIdentifier:    pkgIdentifier,
        }, true
}

func extractCvss(raw map[string]interface{}) []domain.CvssRecord {
        records := []domain.CvssRecord{}
        cvssValue := toObj(raw["CVSS"])

        if cvssValue != nil {
                // Preserve insertion order so output is deterministic per input.
                for source, blockValue := range cvssValue {
                        block := toObj(blockValue)
                        if block == nil {
                                if score, ok := asFloat(blockValue); ok {
                                        s := score
                                        records = append(records, domain.CvssRecord{
                                                Source:  source,
                                                Version: "",
                                                Score:   &s,
                                                Vector:  nil,
                                        })
                                }
                                continue
                        }
                        for _, item := range cvssScoreKeys {
                                score, scoreOk := asFloat(block[item.scoreKey])
                                vector := asStrOrNull(block[item.vectorKey])
                                if !scoreOk && vector == nil {
                                        continue
                                }
                                var scorePtr *float64
                                if scoreOk {
                                        s := score
                                        scorePtr = &s
                                }
                                records = append(records, domain.CvssRecord{
                                        Source:  source,
                                        Version: item.version,
                                        Score:   scorePtr,
                                        Vector:  vector,
                                })
                        }
                }
        } else {
                topLevel := []struct {
                        scoreKey string
                        vectorKey string
                        version string
                }{
                        {"CvssV3Score", "CvssV3Vector", "3"},
                        {"CvssV2Score", "CvssV2Vector", "2.0"},
                        {"CvssV4Score", "CvssV4Vector", "4.0"},
                        {"CvssV40Score", "CvssV40Vector", "4.0"},
                }
                for _, item := range topLevel {
                        score, scoreOk := asFloat(raw[item.scoreKey])
                        vector := asStrOrNull(raw[item.vectorKey])
                        if !scoreOk && vector == nil {
                                continue
                        }
                        var scorePtr *float64
                        if scoreOk {
                                s := score
                                scorePtr = &s
                        }
                        records = append(records, domain.CvssRecord{
                                Source:  "unspecified",
                                Version: item.version,
                                Score:   scorePtr,
                                Vector:  vector,
                        })
                }
        }
        return records
}

// maxCvss returns the best CVSS score across vendor blocks, preferring newer
// CVSS versions.
func maxCvss(records []domain.CvssRecord) *float64 {
        for _, prefix := range []string{"3", "4", "2"} {
                var best *float64
                for _, r := range records {
                        if !strings.HasPrefix(r.Version, prefix) {
                                continue
                        }
                        if r.Score == nil {
                                continue
                        }
                        if best == nil || *r.Score > *best {
                                s := *r.Score
                                best = &s
                        }
                }
                if best != nil {
                        return best
                }
        }
        return nil
}

func extractExploit(raw map[string]interface{}) *domain.ExploitDetails {
        sources := []string{}
        available := false

        probe := []struct {
                value interface{}
                label string
        }{
                {raw["Exploit"], "Exploit"},
                {raw["Exploitability"], "Exploitability"},
        }
        for _, p := range probe {
                obj := toObj(p.value)
                if obj != nil {
                        truthy := []string{}
                        for k, v := range obj {
                                if asBool(v) {
                                        truthy = append(truthy, k)
                                }
                        }
                        if len(truthy) > 0 {
                                available = true
                                sources = append(sources, p.label)
                                sources = append(sources, truthy...)
                        }
                } else if b, ok := p.value.(bool); ok && b {
                        available = true
                        sources = append(sources, p.label)
                } else if s, ok := p.value.(string); ok && strings.TrimSpace(s) != "" {
                        available = true
                        sources = append(sources, p.label+":"+strings.TrimSpace(s))
                }
        }

        if asBool(raw["Exploitable"]) {
                available = true
                sources = append(sources, "Exploitable")
        }
        if asBool(raw["ExploitAvailable"]) {
                available = true
                sources = append(sources, "ExploitAvailable")
        }

        if !available {
                return nil
        }
        // Dedupe sources preserving order.
        seen := map[string]struct{}{}
        unique := make([]string, 0, len(sources))
        for _, s := range sources {
                if _, ok := seen[s]; ok {
                        continue
                }
                seen[s] = struct{}{}
                unique = append(unique, s)
        }
        return &domain.ExploitDetails{Available: available, Sources: unique}
}

func normalizePkgIdentifier(raw map[string]interface{}) *domain.PkgIdentifier {
        obj := toObj(raw["PkgIdentifier"])
        if obj == nil {
                return nil
        }
        purl := asStrOrNull(obj["PURL"])
        uid := asStrOrNull(obj["UID"])
        if purl == nil && uid == nil {
                return nil
        }
        return &domain.PkgIdentifier{PURL: purl, UID: uid}
}

func normalizeMisconfiguration(entry map[string]interface{}, target string, resultClass, resultType *string) domain.Finding {
        id := firstNonNilStr(asStrOrNull(entry["ID"]), asStrOrNull(entry["Title"]))
        if id == nil {
                s := "Unknown"
                id = &s
        }
        cause := toObj(entry["CauseMetadata"])
        var file *string
        if cause != nil {
                file = firstNonNilStr(asStrOrNull(cause["Path"]), asStrOrNull(cause["Filename"]))
        }
        references := asStrArray(entry["References"])
        primaryURL := asStrOrNull(entry["PrimaryURL"])
        if primaryURL != nil {
                references = append([]string{*primaryURL}, references...)
        }
        severity := domain.NormalizeSeverity(entry["Severity"])
        return domain.Finding{
                ID:       util.BuildFindingID([]interface{}{"misconfiguration", target, *id, file}),
                Kind:     domain.FindingMisconfiguration,
                Target:   target,
                Severity: &severity,
                Title:    asStrOrNull(entry["Title"]),
                Message:  firstNonNilStr(asStrOrNull(entry["Message"]), asStrOrNull(entry["Description"])),
                SourceID:  id,
                ResultType: firstNonNilStr(asStrOrNull(entry["Type"]), resultType),
                File:       file,
                StartLine:  nilInt(cause, "StartLine"),
                EndLine:    nilInt(cause, "EndLine"),
                PackageName:      nil,
                InstalledVersion: nil,
                References: references,
                Details: map[string]interface{}{
                        "resolution":  asStrOrNull(entry["Resolution"]),
                        "resultClass": resultClass,
                },
        }
}

func normalizeSecret(entry map[string]interface{}, target string, resultClass, resultType *string) domain.Finding {
        id := asStrOrNull(entry["RuleID"])
        if id == nil {
                s := "secret"
                id = &s
        }
        startLine := nilInt(entry, "StartLine")
        endLine := nilInt(entry, "EndLine")
        severity := domain.NormalizeSeverity(entry["Severity"])
        return domain.Finding{
                ID:        util.BuildFindingID([]interface{}{"secret", target, *id, asStrOrNull(entry["Filename"]), startLine, endLine}),
                Kind:      domain.FindingSecret,
                Target:    target,
                Severity:  &severity,
                Title:     asStrOrNull(entry["Title"]),
                Message:   asStrOrNull(entry["Description"]),
                SourceID:   id,
                ResultType: resultType,
                File:       asStrOrNull(entry["Filename"]),
                StartLine:  startLine,
                EndLine:    endLine,
                PackageName:      nil,
                InstalledVersion: nil,
                References: []string{},
                Details: map[string]interface{}{
                        "category":    asStrOrNull(entry["Category"]),
                        "match":        asStrOrNull(entry["Match"]),
                        "resultClass":  resultClass,
                },
        }
}

func normalizeLicense(entry map[string]interface{}, target string, resultClass, resultType *string) domain.Finding {
        id := firstNonNilStr(asStrOrNull(entry["ID"]), asStrOrNull(entry["Name"]))
        if id == nil {
                s := "license"
                id = &s
        }
        pkg := asStrOrNull(entry["PkgName"])
        severity := domain.NormalizeSeverity(entry["Severity"])
        return domain.Finding{
                ID:        util.BuildFindingID([]interface{}{"license", target, *id, pkg}),
                Kind:      domain.FindingLicense,
                Target:    target,
                Severity:  &severity,
                Title:     firstNonNilStr(asStrOrNull(entry["Name"]), asStrOrNull(entry["ID"])),
                Message:   nil,
                SourceID:   id,
                ResultType: resultType,
                File:       nil,
                StartLine:  nil,
                EndLine:    nil,
                PackageName:      pkg,
                InstalledVersion: nil,
                References: []string{},
                Details: map[string]interface{}{
                        "category":    asStrOrNull(entry["Category"]),
                        "dependency":  asStrOrNull(entry["Dependency"]),
                        "resultClass": resultClass,
                },
        }
}

func nilInt(obj map[string]interface{}, key string) *int {
        if obj == nil {
                return nil
        }
        return asIntPtr(obj[key])
}

func buildFindingSummaries(rows []domain.Finding) []domain.FindingSummary {
        byKind := map[domain.FindingKind]*domain.FindingSummary{}
        order := []domain.FindingKind{}
        for _, row := range rows {
                summary, ok := byKind[row.Kind]
                if !ok {
                        summary = &domain.FindingSummary{
                                Kind:     row.Kind,
                                Count:    0,
                                Severity: domain.EmptySeverityCounts(),
                        }
                        byKind[row.Kind] = summary
                        order = append(order, row.Kind)
                }
                summary.Count++
                var key string
                if row.Severity != nil {
                        key = domain.SeverityKey(*row.Severity)
                } else {
                        key = "unknown"
                }
                switch key {
                case "critical":
                        summary.Severity.Critical++
                case "high":
                        summary.Severity.High++
                case "medium":
                        summary.Severity.Medium++
                case "low":
                        summary.Severity.Low++
                default:
                        summary.Severity.Unknown++
                }
        }
        out := make([]domain.FindingSummary, 0, len(order))
        for _, k := range order {
                out = append(out, *byKind[k])
        }
        return out
}

func extractMetadata(root map[string]interface{}) domain.ScanMetadata {
        metadata := toObj(root["Metadata"])
        var osObj, repoObj map[string]interface{}
        if metadata != nil {
                osObj = toObj(metadata["OS"])
                repoObj = toObj(metadata["Repo"])
        }

        var scanStartedAt, scanEndedAt *string
        if metadata != nil {
                scanStartedAt = firstNonNilStr(asStrOrNull(metadata["ScanStartedAt"]), asStrOrNull(metadata["ScanStartTime"]))
                scanEndedAt = firstNonNilStr(asStrOrNull(metadata["ScanEndedAt"]), asStrOrNull(metadata["ScanEndTime"]))
        }

        var osFamily, osName, repoName, imageID *string
        if osObj != nil {
                osFamily = asStrOrNull(osObj["Family"])
                osName = asStrOrNull(osObj["Name"])
        }
        if repoObj != nil {
                repoName = firstNonNilStr(asStrOrNull(repoObj["Name"]), asStrOrNull(repoObj["Ref"]))
        }
        var imageTags, imageDigests []string
        var artifactType *string
        if metadata != nil {
                imageID = asStrOrNull(metadata["ImageID"])
                imageTags = asStrArray(metadata["RepoTags"])
                imageDigests = asStrArray(metadata["RepoDigests"])
                artifactType = asStrOrNull(metadata["ArtifactType"])
        }

        return domain.ScanMetadata{
                ScanStartedAt: scanStartedAt,
                ScanEndedAt:   scanEndedAt,
                OSFamily:      osFamily,
                OSName:        osName,
                RepoName:      repoName,
                ImageID:       imageID,
                ImageTags:     imageTags,
                ImageDigests:  imageDigests,
                ArtifactType:  artifactType,
        }
}

// firstNonNilStr returns the first non-nil pointer in args, or nil.
func firstNonNilStr(args ...*string) *string {
        for _, a := range args {
                if a != nil {
                        return a
                }
        }
        return nil
}

func strOrEmpty(p *string) string {
        if p == nil {
                return ""
        }
        return *p
}
