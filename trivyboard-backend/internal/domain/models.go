package domain

// ScanSource describes how a scan was produced / ingested. It is exposed on
// every scan-list and scan-meta payload so the UI can distinguish uploaded
// JSON reports from live trivy scans of images, filesystems and git repos.
type ScanSource string

const (
        // SourceTrivyJSON is a Trivy JSON report uploaded through the API.
        SourceTrivyJSON ScanSource = "trivy-json"
        // SourceDockerImage is a live trivy scan of a local or remote image.
        SourceDockerImage ScanSource = "docker-image"
        // SourceFilesystem is a live trivy fs scan of a local directory.
        SourceFilesystem ScanSource = "filesystem"
        // SourceGitLocal is a live trivy repo scan of a local git working copy.
        SourceGitLocal ScanSource = "git-local"
        // SourceGitRemote is a live trivy repo scan of a remote HTTPS git URL.
        SourceGitRemote ScanSource = "git-remote"
)

// NormalizeScanSource returns the canonical ScanSource for a free-form input
// string. Unknown / empty values default to SourceTrivyJSON for backward
// compatibility with stored rows that predate the sourceType column.
func NormalizeScanSource(value string) ScanSource {
        switch ScanSource(value) {
        case SourceTrivyJSON, SourceDockerImage, SourceFilesystem, SourceGitLocal, SourceGitRemote:
                return ScanSource(value)
        }
        return SourceTrivyJSON
}

// CvssRecord captures one CVSS score / vector pair from a vendor block.
type CvssRecord struct {
        Source  string  `json:"source"`
        Version string  `json:"version"`
        Score   *float64 `json:"score"`
        Vector  *string  `json:"vector"`
}

// ExploitDetails summarizes the exploit-related metadata for a vulnerability.
type ExploitDetails struct {
        Available bool     `json:"available"`
        Sources   []string `json:"sources"`
}

// PkgIdentifier mirrors the PkgIdentifier block Trivy emits.
type PkgIdentifier struct {
        PURL *string `json:"purl"`
        UID  *string `json:"uid"`
}

// Vulnerability is a single, normalized vulnerability occurrence within one
// target/package/version tuple. The same CVE in two targets produces two
// distinct Vulnerability records.
type Vulnerability struct {
        ID                  string          `json:"id"`
        Key                 string          `json:"key"`
        VulnerabilityID     string          `json:"vulnerabilityId"`
        Severity            Severity        `json:"severity"`
        PkgName             string          `json:"pkgName"`
        PkgPath             *string         `json:"pkgPath"`
        InstalledVersion    *string         `json:"installedVersion"`
        FixedVersion        *string         `json:"fixedVersion"`
        Status              string          `json:"status"`
        Target              string          `json:"target"`
        Type                *string         `json:"type"`
        Class               string          `json:"class"`
        Language            *string         `json:"language"`
        Cvss                []CvssRecord    `json:"cvss"`
        CvssMaxScore        *float64        `json:"cvssMaxScore"`
        SeveritySource      *string         `json:"severitySource"`
        Title               *string         `json:"title"`
        Description         *string         `json:"description"`
        References          []string        `json:"references"`
        CweIDs              []string        `json:"cweIds"`
        PublishedDate       *string         `json:"publishedDate"`
        LastModifiedDate    *string         `json:"lastModifiedDate"`
        PrimaryURL          *string         `json:"primaryUrl"`
        Exploit             *ExploitDetails `json:"exploit"`
        Fixable             bool            `json:"fixable"`
        PriorityScore       int             `json:"priorityScore"`
        PriorityLevel       PriorityLevel  `json:"priorityLevel"`
        PriorityReasons     []string        `json:"priorityReasons"`
        PkgIdentifier       *PkgIdentifier  `json:"pkgIdentifier"`
}

// FindingKind field on the normalized Finding struct.
type Finding struct {
        ID               string                 `json:"id"`
        Kind             FindingKind            `json:"kind"`
        Target           string                 `json:"target"`
        Severity         *Severity              `json:"severity"`
        Title            *string                `json:"title"`
        Message          *string                `json:"message"`
        SourceID         *string                `json:"sourceId"`
        ResultType       *string                `json:"resultType"`
        File             *string                `json:"file"`
        StartLine        *int                   `json:"startLine"`
        EndLine          *int                   `json:"endLine"`
        PackageName      *string                `json:"packageName"`
        InstalledVersion *string                `json:"installedVersion"`
        References       []string               `json:"references"`
        Details          map[string]interface{} `json:"details"`
}

// FindingSummary groups findings by kind with a severity breakdown.
type FindingSummary struct {
        Kind     FindingKind      `json:"kind"`
        Count    int              `json:"count"`
        Severity SeverityCounts   `json:"severity"`
}

// SeverityCounts holds per-severity occurrence counts.
type SeverityCounts struct {
        Critical int `json:"critical"`
        High     int `json:"high"`
        Medium   int `json:"medium"`
        Low      int `json:"low"`
        Unknown  int `json:"unknown"`
}

// ParserWarning is surfaced when the parser defensively skips or alters data.
type ParserWarning struct {
        Code    string  `json:"code"`
        Message string  `json:"message"`
        Target  *string `json:"target,omitempty"`
}

// ScanMetadata captures the per-scan context block from the Trivy report.
type ScanMetadata struct {
        ScanStartedAt  *string  `json:"scanStartedAt"`
        ScanEndedAt    *string  `json:"scanEndedAt"`
        OSFamily       *string  `json:"osFamily"`
        OSName         *string  `json:"osName"`
        RepoName       *string  `json:"repoName"`
        ImageID        *string  `json:"imageId"`
        ImageTags      []string `json:"imageTags"`
        ImageDigests   []string `json:"imageDigests"`
        ArtifactType   *string  `json:"artifactType"`
}

// TargetSummary aggregates vulnerabilities per target.
type TargetSummary struct {
        Target   string        `json:"target"`
        Class    *string       `json:"class"`
        Type     *string       `json:"type"`
        Total    int           `json:"total"`
        Severity SeverityCounts `json:"severity"`
        Fixable  int           `json:"fixable"`
}

// PackageSummary aggregates vulnerabilities per package.
type PackageSummary struct {
        Package       string        `json:"package"`
        Occurrences   int           `json:"occurrences"`
        Severity      SeverityCounts `json:"severity"`
        Fixable       int           `json:"fixable"`
        Targets       []string      `json:"targets"`
        PriorityScore int           `json:"priorityScore"`
}

// ScanSummary is the public, serializable summary payload returned by
// GET /api/scans/:id/summary.
type ScanSummary struct {
        ScanID                   string            `json:"scanId"`
        Filename                 string            `json:"filename"`
        ArtifactName             string            `json:"artifactName"`
        ArtifactType             *string           `json:"artifactType"`
        SchemaVersion            *int              `json:"schemaVersion"`
        UploadedAt               int64             `json:"uploadedAt"`
        Meta                     ScanMetadata      `json:"meta"`
        ResultCount              int               `json:"resultCount"`
        ScannedAt                *string           `json:"scannedAt"`
        TargetCount              int               `json:"targetCount"`
        VulnerabilityOccurrences int               `json:"vulnerabilityOccurrences"`
        UniqueVulnerabilityIDs   int               `json:"uniqueVulnerabilityIds"`
        Severity                 SeverityCounts    `json:"severity"`
        Fixable                  int               `json:"fixable"`
        NoFixKnown               int               `json:"noFixKnown"`
        StatusFixed              int               `json:"statusFixed"`
        ExploitableBySource      int               `json:"exploitableBySource"`
        Scanners                 []string          `json:"scanners"`
        Findings                 []FindingSummary  `json:"findings"`
        Warnings                 []ParserWarning   `json:"warnings"`
        TopPackages              []TopPackageEntry `json:"topPackages"`
}

// TopPackageEntry is the trimmed PackageSummary shape used in ScanSummary.
type TopPackageEntry struct {
        Package       string        `json:"package"`
        Occurrences   int           `json:"occurrences"`
        Severity      SeverityCounts `json:"severity"`
        Fixable       int           `json:"fixable"`
        PriorityScore int           `json:"priorityScore"`
}

// NormalizedScan is the canonical, deduplicated representation of one Trivy
// report. The frontend and API layer only ever consume this shape.
type NormalizedScan struct {
        ID                          string           `json:"id"`
        Filename                    string           `json:"filename"`
        ArtifactName                string           `json:"artifactName"`
        ArtifactType                *string          `json:"artifactType"`
        SchemaVersion               *int             `json:"schemaVersion"`
        Scanners                    []string         `json:"scanners"`
        Metadata                    ScanMetadata     `json:"metadata"`
        UploadedAt                  int64            `json:"uploadedAt"`
        ResultCount                 int              `json:"resultCount"`
        TargetCount                 int              `json:"targetCount"`
        Warnings                    []ParserWarning  `json:"warnings"`
        Vulnerabilities             []Vulnerability  `json:"vulnerabilities"`
        FindingRows                 []Finding        `json:"findingRows"`
        Findings                    []FindingSummary `json:"findings"`
        VulnerabilityCount          int              `json:"vulnerabilityCount"`
        UniqueVulnerabilityIDCount  int              `json:"uniqueVulnerabilityIdCount"`
        FixableCount                int              `json:"fixableCount"`
        SourceType                  ScanSource       `json:"sourceType"`
}

// ScanListEntry is the trimmed record returned by GET /api/scans.
type ScanListEntry struct {
        ID                   string     `json:"id"`
        Filename             string     `json:"filename"`
        ArtifactName         string     `json:"artifactName"`
        ArtifactType         *string    `json:"artifactType"`
        UploadedAt           int64      `json:"uploadedAt"`
        TotalVulnerabilities int        `json:"totalVulnerabilities"`
        Critical             int        `json:"critical"`
        SourceType           ScanSource `json:"sourceType"`
}

// EmptySeverityCounts returns a fresh zeroed SeverityCounts.
func EmptySeverityCounts() SeverityCounts {
        return SeverityCounts{}
}
