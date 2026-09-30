# trivyboard-backend

Go trivyboard-backend that powers the Trivy dashboard + scanning feature. Listens
on port **3030** (per gateway convention) and exposes a JSON REST API for
uploading Trivy reports, listing local Docker images, and running Trivy scans
(`image` / `fs` / `repo`).

The service uses defensive parsing, server-side validation, SQLite persistence,
and a restricted Docker API connection while preserving Trivy's report shape.

## Layout

```
trivyboard-backend/
  go.mod                 — module trivyboard-backend, Go 1.27
  package.json           — `dev`/`build`/`start` scripts (uses local Go install)
  main.go                — HTTP server entrypoint on :3030
  README.md              — this file
  internal/
    domain/
      severity.go        — Severity type, Severities, SeverityOrder, NormalizeSeverity
      enums.go           — VulnerabilityStatus, ScanResultClass, FindingKind, PriorityLevel
      models.go          — NormalizedScan, Vulnerability, Finding, ScanSummary, ...
    parser/
      trivy.go           — defensive Trivy JSON normalization (ports trivy-json-parser.ts)
      raw_types.go       — raw report shape (loose)
    service/
      aggregation.go     — CountBySeverity, AggregatePackages, AggregateTargets, SummarizeScan
      query.go           — FilterVulnerabilities, SortVulnerabilities, Paginate
      priority.go        — thin wrapper around internal/priority
      scanstore.go       — in-memory repository with TTL + cleanup goroutine
      scanprocessor.go   — ProcessRawScanPayload (byte → JSON → validate → normalize → save)
      docker.go          — ListDockerImages (unix socket with sample fallback)
      scanner.go         — RunScan (trivy subprocess: image/fs/repo)
    priority/
      priority.go        — P0–P4 calculation (lives here to avoid parser/service cycle)
    api/
      handler.go         — HTTP handlers + error envelope
      routes.go          — route registration + allow-listed CORS + logging
    util/
      ids.go             — encodeId (base64url), BuildVulnerabilityKey, BuildFindingId
      csv.go             — CSV export with spreadsheet-injection protection
      dto.go             — toVulnerabilityListItem / Detail / toFindingListItem
```

## Build & run

```bash
# Direct
cd trivyboard-backend
go run .

# Or from the project root
bun run backend:dev
```

The service binds `0.0.0.0:3030` and logs structured JSON to stdout.

## REST API

All responses are JSON. Errors use the envelope `{"error":{"code","message"}}`.

| Method | Path                                              | Description                                                       |
|--------|---------------------------------------------------|-------------------------------------------------------------------|
| GET    | `/api/health`                                     | `{status:"ok"}`                                                   |
| POST   | `/api/scans`                                      | multipart `file` upload → parse + store, returns scan meta (201) |
| GET    | `/api/scans`                                      | list recent scans (most recent first)                            |
| GET    | `/api/scans/:id`                                  | scan meta                                                         |
| GET    | `/api/scans/:id/summary`                          | full ScanSummary (KPIs, severity, topPackages, targets, ...)     |
| GET    | `/api/scans/:id/vulnerabilities`                  | filter / sort / paginate (server-side)                           |
| GET    | `/api/scans/:id/vulnerabilities/:vulnId`           | vulnerability detail DTO                                          |
| GET    | `/api/scans/:id/raw`                              | full NormalizedScan                                               |
| GET    | `/api/scans/:id/packages`                         | aggregated package summaries                                      |
| GET    | `/api/scans/:id/targets`                          | aggregated target summaries                                       |
| GET    | `/api/scans/:id/findings`                         | misconfig / secret / license rows with pagination                 |
| GET    | `/api/scans/:id/export?format=csv|json`           | file download                                                     |
| DELETE | `/api/scans/:id`                                  | remove a scan                                                     |
| GET    | `/api/docker/images`                              | docker daemon list, falls back to sample data                    |
| POST   | `/api/scans/run`                                  | run trivy image / fs / repo → returns scan meta                   |

### Vulnerability list query params

`page`, `pageSize`, `sortBy` (`severity`|`vulnerabilityId`|`pkgName`|
`installedVersion`|`fixedVersion`|`status`|`target`|`type`|`cvssMaxScore`|
`publishedDate`|`fixable`|`priorityScore`), `sortOrder` (`asc`|`desc`),
`severity` (repeatable, e.g. `?severity=CRITICAL&severity=HIGH`),
`search`, `target`, `package` (or `pkg`), `type`, `fixable` (`fixed`|`unfixed`|
`all`), `priority` (`P0`..`P4`).

### POST `/api/scans/run` body

```json
{ "target": "image"|"fs"|"repo", "value": "<image-or-path-or-url>",
  "scanners": ["vuln","misconfig","secret","license"] }
```

The handler invokes `trivy --cache-dir <configured-cache> <target> --format
json --quiet --scanners <list> <value>`, captures stdout, parses it through
the same NormalizedScan pipeline used for uploads, stores it, and returns
`{scan:<meta>, source:"trivy"}` (201). On trivy failure, returns 502 with
`SCAN_FAILED` and `details.stderr`.

## Implementation notes

- **Defensive parsing** — every Trivy report is unmarshalled into a generic
  `interface{}` tree and walked with helpers (`asStr`, `asStrOrNull`,
  `asFloat`, `asBool`, `asStrArray`, `toObj`) that tolerate missing/null/
  unexpected fields, mirroring the TS reference.
- **Severity normalization** — CRITICAL/SEVERE → CRITICAL, HIGH → HIGH,
  MEDIUM/MODERATE/IMPORTANT → MEDIUM, LOW/MINOR → LOW, anything else → UNKNOWN.
- **Vulnerability ID** — `base64url(target \u001f vulnerabilityId \u001f
  pkgName \u001f installedVersion)`. Occurrences are never merged across targets.
- **Deduplication** — exact duplicates by composite key are skipped; a
  `DUPLICATE_VULNERABILITY` parser warning is recorded.
- **Priority scoring** — base severity weight (CRITICAL=100, HIGH=80, MEDIUM=60,
  LOW=40, UNKNOWN=30) + CVSS band (≥9→+15, ≥7→+8, ≥4→+3) + fix available (+12,
  only when status ≠ fixed) + exploit metadata (+20) + status adjustments
  (will_not_fix +5, under_investigation +3, not_affected −20). Clamped to
  [0,150]. Levels: P0 ≥120, P1 ≥95, P2 ≥70, P3 ≥45, P4 ≥0.
- **CVSS** — handles both vendor blocks (`CVSS.{nvd,redhat,...}`) and legacy
  flat fields, plus `V40Score`/`V40Vector` (Trivy 0.74 spelling).
- **In-memory store** — `map[string]ScanRecord` guarded by a `sync.RWMutex`,
  TTL = 24h, cleanup goroutine every 60s.
- **Docker image listing** — dials the configured Unix socket via the Docker
  Engine API (`GET /v1.41/images/json`). When the daemon is unreachable
  it returns an empty result with `source:"unavailable"`.
- **CORS** — disabled by default; trusted browser origins can be listed in
  `CORS_ALLOWED_ORIGINS`.
- **SQLite** — implemented with `modernc.org/sqlite`, so the production binary
  remains CGO-free.
