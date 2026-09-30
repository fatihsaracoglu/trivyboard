import type {
  ApiError,
  CancelJobResponse,
  CreateScanJobResponse,
  DockerImagesResponse,
  FindingsResponse,
  PackagesResponse,
  ScanJobStatusResponse,
  ScanListEntry,
  ScanMeta,
  ScanRunRequest,
  ScanRunResponse,
  ScanSummary,
  TargetsResponse,
  UploadResponse,
  VulnerabilitiesResponse,
  VulnerabilityDetail,
} from "./types";

// Base URL: absolute if VITE_API_BASE_URL is set, otherwise relative "/api".
const VITE_API_BASE_URL = import.meta.env.VITE_API_BASE_URL?.replace(/\/+$/, "");
const PORT = "3030";
const BASE = VITE_API_BASE_URL ? `${VITE_API_BASE_URL}/api` : `/api`;

function withPort(path: string): string {
  const url = `${BASE}${path}`;
  // XTransformPort is only needed when behind the Caddy gateway.
  // When using VITE_API_BASE_URL (absolute URL), the gateway is bypassed.
  if (VITE_API_BASE_URL) {
    return url;
  }
  const separator = url.includes("?") ? "&" : "?";
  return `${url}${separator}XTransformPort=${PORT}`;
}

export class ApiRequestError extends Error {
  code: string;
  status: number;
  details?: unknown;
  constructor(code: string, message: string, status: number, details?: unknown) {
    super(message);
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

async function parseError(res: Response): Promise<ApiRequestError> {
  let payload: ApiError | null = null;
  try {
    payload = (await res.json()) as ApiError;
  } catch {
    /* ignore */
  }
  const code = payload?.error?.code ?? "HTTP_ERROR";
  const message = payload?.error?.message ?? `Request failed: ${res.status} ${res.statusText}`;
  return new ApiRequestError(code, message, res.status, payload?.error?.details);
}

export const api = {
  async getHealth(): Promise<{ status: string; uptime: number }> {
    const res = await fetch(withPort("/health"), { cache: "no-store" });
    if (!res.ok) throw await parseError(res);
    return res.json();
  },

  async listScans(): Promise<ScanListEntry[]> {
    const res = await fetch(withPort("/scans"), { cache: "no-store" });
    if (!res.ok) throw await parseError(res);
    const body = await res.json();
    return body.data ?? [];
  },

  async getScan(id: string): Promise<ScanMeta> {
    const res = await fetch(withPort(`/scans/${encodeURIComponent(id)}`), {
      cache: "no-store",
    });
    if (!res.ok) throw await parseError(res);
    const body = await res.json();
    return body.scan;
  },

  async getSummary(id: string): Promise<ScanSummary> {
    const res = await fetch(withPort(`/scans/${encodeURIComponent(id)}/summary`), {
      cache: "no-store",
    });
    if (!res.ok) throw await parseError(res);
    const body = await res.json();
    return body.summary;
  },

  async listVulnerabilities(
    id: string,
    params: {
      page?: number;
      pageSize?: number;
      sortBy?: string;
      sortOrder?: "asc" | "desc";
      severity?: string;
      search?: string;
      target?: string;
      package?: string;
      fixable?: boolean;
      priority?: string;
    } = {},
  ): Promise<VulnerabilitiesResponse> {
    const qs = new URLSearchParams();
    if (params.page != null) qs.set("page", String(params.page));
    if (params.pageSize != null) qs.set("pageSize", String(params.pageSize));
    if (params.sortBy) qs.set("sortBy", params.sortBy);
    if (params.sortOrder) qs.set("sortOrder", params.sortOrder);
    if (params.severity) qs.set("severity", params.severity);
    if (params.search) qs.set("search", params.search);
    if (params.target) qs.set("target", params.target);
    if (params.package) qs.set("package", params.package);
    if (params.fixable != null) qs.set("fixable", String(params.fixable));
    if (params.priority) qs.set("priority", params.priority);
    const res = await fetch(
      withPort(`/scans/${encodeURIComponent(id)}/vulnerabilities?${qs.toString()}`),
      { cache: "no-store" },
    );
    if (!res.ok) throw await parseError(res);
    return res.json();
  },

  async getVulnerability(id: string, vulnId: string): Promise<VulnerabilityDetail> {
    const res = await fetch(
      withPort(`/scans/${encodeURIComponent(id)}/vulnerabilities/${encodeURIComponent(vulnId)}`),
      { cache: "no-store" },
    );
    if (!res.ok) throw await parseError(res);
    const body = await res.json();
    return body.vulnerability;
  },

  async listPackages(
    id: string,
    params: { search?: string; sortBy?: string; sortOrder?: "asc" | "desc"; limit?: number } = {},
  ): Promise<PackagesResponse> {
    const qs = new URLSearchParams();
    if (params.search) qs.set("search", params.search);
    if (params.sortBy) qs.set("sortBy", params.sortBy);
    if (params.sortOrder) qs.set("sortOrder", params.sortOrder);
    if (params.limit != null) qs.set("limit", String(params.limit));
    const res = await fetch(
      withPort(`/scans/${encodeURIComponent(id)}/packages?${qs.toString()}`),
      { cache: "no-store" },
    );
    if (!res.ok) throw await parseError(res);
    return res.json();
  },

  async listTargets(id: string): Promise<TargetsResponse> {
    const res = await fetch(withPort(`/scans/${encodeURIComponent(id)}/targets`), {
      cache: "no-store",
    });
    if (!res.ok) throw await parseError(res);
    return res.json();
  },

  async listFindings(
    id: string,
    params: { page?: number; pageSize?: number; search?: string; type?: string } = {},
  ): Promise<FindingsResponse> {
    const qs = new URLSearchParams();
    if (params.page != null) qs.set("page", String(params.page));
    if (params.pageSize != null) qs.set("pageSize", String(params.pageSize));
    if (params.search) qs.set("search", params.search);
    if (params.type) qs.set("type", params.type);
    const res = await fetch(
      withPort(`/scans/${encodeURIComponent(id)}/findings?${qs.toString()}`),
      { cache: "no-store" },
    );
    if (!res.ok) throw await parseError(res);
    return res.json();
  },

  async uploadScan(file: File): Promise<UploadResponse> {
    const form = new FormData();
    form.append("file", file);
    const res = await fetch(withPort("/scans/upload"), {
      method: "POST",
      body: form,
    });
    if (!res.ok) throw await parseError(res);
    return res.json();
  },

  async deleteScan(id: string): Promise<void> {
    const res = await fetch(withPort(`/scans/${encodeURIComponent(id)}`), {
      method: "DELETE",
    });
    if (!res.ok) throw await parseError(res);
  },

  async listDockerImages(): Promise<DockerImagesResponse> {
    const res = await fetch(withPort("/docker/images"), { cache: "no-store" });
    if (!res.ok) throw await parseError(res);
    return res.json();
  },

  async runScan(req: ScanRunRequest): Promise<ScanRunResponse> {
    const res = await fetch(withPort("/scans/run"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(req),
    });
    if (!res.ok) throw await parseError(res);
    return res.json();
  },

  async createScanJob(req: ScanRunRequest): Promise<CreateScanJobResponse> {
    const res = await fetch(withPort("/scans"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(req),
    });
    if (!res.ok) throw await parseError(res);
    return res.json();
  },

  async getJobStatus(jobId: string): Promise<ScanJobStatusResponse> {
    const res = await fetch(withPort(`/scans/${encodeURIComponent(jobId)}/status`), {
      cache: "no-store",
    });
    if (!res.ok) throw await parseError(res);
    return res.json();
  },

  async cancelJob(jobId: string): Promise<CancelJobResponse> {
    const res = await fetch(withPort(`/scans/${encodeURIComponent(jobId)}/cancel`), {
      method: "POST",
    });
    if (!res.ok) throw await parseError(res);
    return res.json();
  },

  exportUrl(id: string, format: "csv" | "json"): string {
    const qs = new URLSearchParams({ format });
    return withPort(`/scans/${encodeURIComponent(id)}/export?${qs.toString()}`);
  },
};
