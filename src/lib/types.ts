export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";

export type PriorityLevel = "P0" | "P1" | "P2" | "P3" | "P4";

export type VulnerabilityStatus =
  | "fixed"
  | "affected"
  | "will_not_fix"
  | "not_affected"
  | "under_investigation";

export type FindingKind = "misconfiguration" | "secret" | "license";

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
}

export interface ScanMetadata {
  scanStartedAt: string | null;
  scanEndedAt: string | null;
  osFamily: string | null;
  osName: string | null;
  repoName: string | null;
  imageId: string | null;
  imageTags: string[];
  imageDigests: string[];
  artifactType: string | null;
}

export interface ParserWarning {
  code: string;
  message: string;
  target?: string;
}

export interface FindingSummaryItem {
  kind: FindingKind;
  count: number;
  severity: SeverityCounts;
}

export interface CvssRecord {
  source: string;
  version: string;
  score: number | null;
  vector: string | null;
}

export interface ExploitDetails {
  available: boolean;
  sources: string[];
}

export interface PkgIdentifier {
  purl: string | null;
  uid: string | null;
}

export interface ScanMeta {
  id: string;
  filename: string;
  artifactName: string;
  artifactType: string | null;
  schemaVersion: number | null;
  uploadedAt: number;
  resultCount: number;
  targetCount: number;
  vulnerabilityOccurrences: number;
  uniqueVulnerabilityIds: number;
  severity: SeverityCounts;
  fixable: number;
  findings: FindingSummaryItem[];
  warnings: ParserWarning[];
  sourceType: ScanSource;
}

export interface UploadResponse {
  scan: ScanMeta;
}

export interface ScanListEntry {
  id: string;
  filename: string;
  artifactName: string;
  artifactType: string | null;
  uploadedAt: number;
  totalVulnerabilities: number;
  critical: number;
  sourceType: ScanSource;
}

export interface ScanSummary {
  scanId: string;
  filename: string;
  artifactName: string;
  artifactType: string | null;
  schemaVersion: number | null;
  uploadedAt: number;
  meta: ScanMetadata;
  resultCount: number;
  scannedAt: string | null;
  targetCount: number;
  vulnerabilityOccurrences: number;
  uniqueVulnerabilityIds: number;
  severity: SeverityCounts;
  fixable: number;
  noFixKnown: number;
  statusFixed: number;
  exploitableBySource: number;
  scanners: string[];
  findings: FindingSummaryItem[];
  warnings: ParserWarning[];
  topPackages: Array<{
    package: string;
    occurrences: number;
    severity: SeverityCounts;
    fixable: number;
    priorityScore: number;
  }>;
}

export interface VulnerabilityListItem {
  id: string;
  vulnerabilityId: string;
  severity: Severity;
  pkgName: string;
  installedVersion: string | null;
  fixedVersion: string | null;
  status: VulnerabilityStatus | null;
  target: string;
  type: string | null;
  class: string | null;
  fixable: boolean;
  cvssMaxScore: number | null;
  severitySource: string | null;
  title: string | null;
  priorityScore: number;
  priorityLevel: PriorityLevel;
  publishedDate: string | null;
  lastModifiedDate: string | null;
}

export interface VulnerabilityDetail extends VulnerabilityListItem {
  description: string | null;
  primaryUrl: string | null;
  references: string[];
  cweIds: string[];
  cvss: CvssRecord[];
  pkgPath: string | null;
  language: string | null;
  exploit: ExploitDetails | null;
  priorityReasons: string[];
  pkgIdentifier: PkgIdentifier | null;
}

export interface PackageSummary {
  package: string;
  occurrences: number;
  severity: SeverityCounts;
  fixable: number;
  targets: string[];
  priorityScore: number;
}

export interface TargetSummary {
  target: string;
  class: string | null;
  type: string | null;
  total: number;
  severity: SeverityCounts;
  fixable: number;
}

export interface FindingRow {
  id: string;
  kind: FindingKind;
  target: string;
  severity: Severity | null;
  title: string | null;
  message: string | null;
  sourceId: string | null;
  resultType: string | null;
  file: string | null;
  startLine: number | null;
  endLine: number | null;
  packageName: string | null;
  installedVersion: string | null;
  references: string[];
  details: Record<string, unknown>;
}

export interface Pagination {
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
}

export interface VulnerabilitiesResponse {
  data: VulnerabilityListItem[];
  pagination: Pagination;
  filteredSeverity: SeverityCounts;
}

export interface PackagesResponse {
  data: PackageSummary[];
  total: number;
}

export interface TargetsResponse {
  data: TargetSummary[];
}

export interface FindingsResponse {
  data: FindingRow[];
  pagination: Pagination;
  summary: FindingSummaryItem[];
}

export interface DockerImage {
  id: string;
  repoTags: string[];
  repoDigests: string[];
  created: number;
  size: number;
  digest: string;
  shortId: string;
  labels: Record<string, string>;
  os: string;
  arch: string;
}

export interface DockerImagesResponse {
  data: DockerImage[];
  source: "docker" | "unavailable" | "empty";
}

export type ScanTarget = "image" | "fs" | "repo";

export type ScanSource =
  | "trivy-json"
  | "docker-image"
  | "filesystem"
  | "git-local"
  | "git-remote";

export type JobStatus =
  | "queued"
  | "running"
  | "processing"
  | "completed"
  | "failed"
  | "cancelled";

export interface ScanRunRequest {
  target: ScanTarget;
  value: string;
  scanners?: string[];
}

export interface ScanRunResponse {
  scan: ScanMeta;
  source: "trivy";
}

export interface ScanJob {
  id: string;
  status: JobStatus;
  target: ScanTarget;
  value: string;
  scanners?: string[];
  sourceType: ScanSource;
  queuedAt: number;
  startedAt?: number;
  completedAt?: number;
  error?: string;
  scanId?: string;
}

export interface CreateScanJobResponse {
  job: ScanJob;
}

export interface ScanJobStatusResponse {
  job: ScanJob;
}

export interface CancelJobResponse {
  ok: boolean;
  error?: string;
}

export interface ApiError {
  error: {
    code: string;
    message: string;
    details?: unknown;
  };
}
