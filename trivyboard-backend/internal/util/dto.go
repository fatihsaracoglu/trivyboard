package util

import (
        "trivyboard-backend/internal/domain"
)

// VulnerabilityListItem is the compact row shape returned by list endpoints.
type VulnerabilityListItem struct {
        ID                string             `json:"id"`
        VulnerabilityID   string             `json:"vulnerabilityId"`
        Severity          domain.Severity    `json:"severity"`
        PkgName           string             `json:"pkgName"`
        InstalledVersion  *string            `json:"installedVersion"`
        FixedVersion      *string            `json:"fixedVersion"`
        Status            string             `json:"status"`
        Target            string             `json:"target"`
        Type              *string            `json:"type"`
        CvssMaxScore      *float64           `json:"cvssMaxScore"`
        Fixable           bool               `json:"fixable"`
        PriorityScore     int                `json:"priorityScore"`
        PriorityLevel     domain.PriorityLevel `json:"priorityLevel"`
        Title             *string            `json:"title"`
        PublishedDate     *string            `json:"publishedDate"`
        LastModifiedDate  *string            `json:"lastModifiedDate"`
        ExploitAvailable  bool               `json:"exploitAvailable"`
}

// VulnerabilityDetail is the full record returned by the detail endpoint.
type VulnerabilityDetail struct {
        ID              string               `json:"id"`
        VulnerabilityID string               `json:"vulnerabilityId"`
        Severity        domain.Severity      `json:"severity"`
        SeveritySource  *string              `json:"severitySource"`
        Status          string              `json:"status"`
        PkgName         string               `json:"pkgName"`
        PkgPath         *string              `json:"pkgPath"`
        InstalledVersion *string             `json:"installedVersion"`
        FixedVersion    *string              `json:"fixedVersion"`
        Target          string               `json:"target"`
        Type            *string              `json:"type"`
        Class           string               `json:"class"`
        Language        *string              `json:"language"`
        Cvss            []domain.CvssRecord   `json:"cvss"`
        CvssMaxScore    *float64             `json:"cvssMaxScore"`
        Title           *string              `json:"title"`
        Description     *string              `json:"description"`
        References      []string             `json:"references"`
        CweIDs          []string             `json:"cweIds"`
        PublishedDate   *string              `json:"publishedDate"`
        LastModifiedDate *string             `json:"lastModifiedDate"`
        PrimaryURL      *string              `json:"primaryUrl"`
        Exploit         *domain.ExploitDetails `json:"exploit"`
        Fixable         bool                 `json:"fixable"`
        PriorityScore   int                  `json:"priorityScore"`
        PriorityLevel   domain.PriorityLevel `json:"priorityLevel"`
        PriorityReasons []string             `json:"priorityReasons"`
        PkgIdentifier   *domain.PkgIdentifier `json:"pkgIdentifier"`
}

// FindingListItem is the compact finding row returned by the findings endpoint.
type FindingListItem struct {
        ID               string                `json:"id"`
        Kind             domain.FindingKind   `json:"kind"`
        Target           string                `json:"target"`
        Severity         *domain.Severity      `json:"severity"`
        Title            *string               `json:"title"`
        Message          *string               `json:"message"`
        SourceID         *string               `json:"sourceId"`
        ResultType       *string               `json:"resultType"`
        File             *string               `json:"file"`
        StartLine        *int                  `json:"startLine"`
        EndLine          *int                  `json:"endLine"`
        PackageName      *string               `json:"packageName"`
        InstalledVersion *string               `json:"installedVersion"`
        References       []string              `json:"references"`
        Details          map[string]interface{} `json:"details"`
}

// ToVulnerabilityListItem projects a Vulnerability into its list DTO.
func ToVulnerabilityListItem(v domain.Vulnerability) VulnerabilityListItem {
        avail := false
        if v.Exploit != nil {
                avail = v.Exploit.Available
        }
        return VulnerabilityListItem{
                ID:                v.ID,
                VulnerabilityID:   v.VulnerabilityID,
                Severity:          v.Severity,
                PkgName:           v.PkgName,
                InstalledVersion:  v.InstalledVersion,
                FixedVersion:      v.FixedVersion,
                Status:            v.Status,
                Target:            v.Target,
                Type:              v.Type,
                CvssMaxScore:      v.CvssMaxScore,
                Fixable:           v.Fixable,
                PriorityScore:     v.PriorityScore,
                PriorityLevel:     v.PriorityLevel,
                Title:             v.Title,
                PublishedDate:     v.PublishedDate,
                LastModifiedDate:  v.LastModifiedDate,
                ExploitAvailable:  avail,
        }
}

// ToVulnerabilityDetail projects a Vulnerability into its full detail DTO.
func ToVulnerabilityDetail(v domain.Vulnerability) VulnerabilityDetail {
        return VulnerabilityDetail{
                ID:               v.ID,
                VulnerabilityID:  v.VulnerabilityID,
                Severity:         v.Severity,
                SeveritySource:   v.SeveritySource,
                Status:           v.Status,
                PkgName:          v.PkgName,
                PkgPath:          v.PkgPath,
                InstalledVersion: v.InstalledVersion,
                FixedVersion:     v.FixedVersion,
                Target:           v.Target,
                Type:             v.Type,
                Class:            v.Class,
                Language:         v.Language,
                Cvss:             v.Cvss,
                CvssMaxScore:     v.CvssMaxScore,
                Title:            v.Title,
                Description:      v.Description,
                References:       v.References,
                CweIDs:           v.CweIDs,
                PublishedDate:    v.PublishedDate,
                LastModifiedDate:  v.LastModifiedDate,
                PrimaryURL:       v.PrimaryURL,
                Exploit:          v.Exploit,
                Fixable:          v.Fixable,
                PriorityScore:    v.PriorityScore,
                PriorityLevel:    v.PriorityLevel,
                PriorityReasons:  v.PriorityReasons,
                PkgIdentifier:    v.PkgIdentifier,
        }
}

// ToFindingListItem projects a Finding into its list DTO.
func ToFindingListItem(f domain.Finding) FindingListItem {
        return FindingListItem{
                ID:               f.ID,
                Kind:             f.Kind,
                Target:           f.Target,
                Severity:         f.Severity,
                Title:            f.Title,
                Message:          f.Message,
                SourceID:         f.SourceID,
                ResultType:       f.ResultType,
                File:             f.File,
                StartLine:        f.StartLine,
                EndLine:          f.EndLine,
                PackageName:      f.PackageName,
                InstalledVersion: f.InstalledVersion,
                References:       f.References,
                Details:          f.Details,
        }
}
