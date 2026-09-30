import type { PriorityLevel, Severity } from "./types";

export function formatNumber(n: number): string {
  return new Intl.NumberFormat("en-US").format(n);
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export function formatTimestamp(ms: number | string | null | undefined): string {
  if (ms == null || ms === "") return "—";
  const date = typeof ms === "string" ? new Date(ms) : new Date(ms);
  if (isNaN(date.getTime())) return "—";
  return date.toLocaleString("en-US", {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function formatRelativeTime(ms: number | null | undefined): string {
  if (ms == null) return "—";
  const now = Date.now();
  const diff = now - ms;
  if (diff < 0) return "just now";
  if (diff < 60_000) return `${Math.round(diff / 1000)}s ago`;
  if (diff < 3_600_000) return `${Math.round(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.round(diff / 3_600_000)}h ago`;
  return `${Math.round(diff / 86_400_000)}d ago`;
}

export const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];

export const SEVERITY_COLORS: Record<Severity, string> = {
  CRITICAL: "#dc2626", // red-600
  HIGH: "#ea580c", // orange-600
  MEDIUM: "#ca8a04", // yellow-600
  LOW: "#0284c7", // sky-600
  UNKNOWN: "#64748b", // slate-500
};

export const SEVERITY_BG: Record<Severity, string> = {
  CRITICAL: "bg-red-500/15 text-red-700 dark:text-red-300 border-red-500/30",
  HIGH: "bg-orange-500/15 text-orange-700 dark:text-orange-300 border-orange-500/30",
  MEDIUM: "bg-yellow-500/15 text-yellow-700 dark:text-yellow-300 border-yellow-500/30",
  LOW: "bg-sky-500/15 text-sky-700 dark:text-sky-300 border-sky-500/30",
  UNKNOWN: "bg-slate-500/15 text-slate-700 dark:text-slate-300 border-slate-500/30",
};

export const PRIORITY_COLORS: Record<PriorityLevel, string> = {
  P0: "bg-red-600 text-white",
  P1: "bg-red-500/80 text-white",
  P2: "bg-orange-500/80 text-white",
  P3: "bg-yellow-500/80 text-white",
  P4: "bg-emerald-500/80 text-white",
};

export const PRIORITY_DESCRIPTIONS: Record<PriorityLevel, string> = {
  P0: "Critical and exploitable — remediate immediately",
  P1: "Critical or high with available fix — remediate within 24h",
  P2: "High or medium with available fix — schedule this sprint",
  P3: "Medium severity — backlog item",
  P4: "Low or unknown severity — monitor only",
};

export function severityRank(s: Severity): number {
  return SEVERITY_ORDER.indexOf(s);
}

/**
 * Map a numeric priority score (0–150, calculated by the Go backend) to a
 * PriorityLevel using the exact same thresholds the backend uses:
 *   P0 >= 120, P1 >= 95, P2 >= 70, P3 >= 45, P4 >= 0
 * Used by the dashboard's "Top risky packages" badge so the displayed P-level
 * matches the per-vulnerability priority badge in the table below.
 */
export function priorityLevelFromScore(score: number): PriorityLevel {
  if (score >= 120) return "P0";
  if (score >= 95) return "P1";
  if (score >= 70) return "P2";
  if (score >= 45) return "P3";
  return "P4";
}

export function truncate(s: string | null, max: number): string {
  if (!s) return "—";
  if (s.length <= max) return s;
  return s.slice(0, max - 1) + "…";
}

export function safeUrl(url: string | null): string | null {
  if (!url) return null;
  try {
    const parsed = new URL(url);
    if (parsed.protocol === "http:" || parsed.protocol === "https:") return url;
    return null;
  } catch {
    return null;
  }
}

export const FINDING_KIND_LABELS: Record<string, string> = {
  misconfiguration: "Misconfiguration",
  secret: "Secret",
  license: "License",
};

export const FINDING_KIND_COLORS: Record<string, string> = {
  misconfiguration: "bg-purple-500/15 text-purple-700 dark:text-purple-300 border-purple-500/30",
  secret: "bg-pink-500/15 text-pink-700 dark:text-pink-300 border-pink-500/30",
  license: "bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border-cyan-500/30",
};

export const ARTIFACT_TYPE_LABELS: Record<string, string> = {
  container_image: "Container Image",
  filesystem: "Filesystem",
  repository: "Repository",
  vm: "VM",
  sbom: "SBOM",
};
