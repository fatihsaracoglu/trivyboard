<script setup lang="ts">
// DashboardView — the main vulnerability dashboard for a single scan.
// Layout: artifact header → 6 KPI cards (clickable filters) → severity
// doughnut + top risky packages → warnings + findings panels →
// vulnerabilities table with toolbar, presets, sortable headers,
// filter chips, and pagination → VulnerabilityDrawer.
import { ref, computed, watch } from "vue";
import {
  Flame,
  AlertTriangle,
  Shield,
  Download,
  FileJson,
  Package as PackageIcon,
  ChevronLeft,
  ChevronRight,
  Search,
  X,
  Info,
  AlertCircle,
  Loader2,
  Clock,
  Cpu,
  Layers,
  Calendar,
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
  Boxes,
  Wrench,
} from "@lucide/vue";
import Button from "@/components/ui/Button.vue";
import Input from "@/components/ui/Input.vue";
import Select from "@/components/ui/Select.vue";
import DropdownMenu from "@/components/ui/DropdownMenu.vue";
import DropdownMenuItem from "@/components/ui/DropdownMenuItem.vue";
import Tooltip from "@/components/ui/Tooltip.vue";
import { Card } from "@/components/ui/card";
import { Badge, Skeleton, Separator } from "@/components/ui/primitives";
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "@/components/ui/table";
import { useApi } from "@/composables/useApi";
import { api } from "@/lib/api";
import {
  formatNumber,
  formatTimestamp,
  formatRelativeTime,
  ARTIFACT_TYPE_LABELS,
  priorityLevelFromScore,
  SEVERITY_ORDER,
  SEVERITY_COLORS,
  FINDING_KIND_LABELS,
} from "@/lib/format";
import { cn } from "@/lib/utils";
import { SeverityBadge, PriorityBadge, FindingKindBadge } from "@/components/common/Badges";
import KpiCard from "@/components/common/KpiCard.vue";
import SeverityChart from "@/components/dashboard/SeverityChart.vue";
import VulnerabilityDrawer from "@/components/dashboard/VulnerabilityDrawer.vue";
import type {
  Severity,
  PriorityLevel,
  ScanSummary,
  VulnerabilitiesResponse,
  VulnerabilityListItem,
} from "@/lib/types";

const props = defineProps<{ scanId: string }>();

// ---- table state ----
const page = ref(1);
const pageSize = 15;
const search = ref("");
const severity = ref<Severity | "all">("all");
const fixable = ref<"all" | "true" | "false">("all");
const priority = ref<PriorityLevel | "all">("all");
const sortBy = ref<"vulnerabilityId" | "pkgName" | "priorityScore">("priorityScore");
const sortOrder = ref<"asc" | "desc">("desc");
const selectedVulnId = ref<string | null>(null);

// ---- debounce search ----
let searchTimer: ReturnType<typeof setTimeout> | null = null;
const debouncedSearch = ref("");
function onSearchInput(v: string) {
  search.value = v;
  if (searchTimer) clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    debouncedSearch.value = v;
    page.value = 1;
  }, 200);
}

// ---- data ----
const {
  data: summary,
  isLoading: summaryLoading,
  isError: summaryError,
  error: summaryErr,
} = useApi<ScanSummary>(
    () => api.getSummary(props.scanId),
    () => [props.scanId],
);

const {
  data: vulnData,
  isLoading: vulnLoading,
  isError: vulnError,
  error: vulnErr,
  isFetching: vulnFetching,
} = useApi<VulnerabilitiesResponse>(
    () =>
        api.listVulnerabilities(props.scanId, {
          page: page.value,
          pageSize,
          search: debouncedSearch.value || undefined,
          severity: severity.value !== "all" ? severity.value : undefined,
          fixable: fixable.value === "all" ? undefined : fixable.value === "true",
          priority: priority.value !== "all" ? priority.value : undefined,
          sortBy: sortBy.value,
          sortOrder: sortOrder.value,
        }),
    () => [
      props.scanId,
      page.value,
      debouncedSearch.value,
      severity.value,
      fixable.value,
      priority.value,
      sortBy.value,
      sortOrder.value,
    ],
);

const rows = computed<VulnerabilityListItem[]>(() => vulnData.value?.data ?? []);
const pagination = computed(() => vulnData.value?.pagination);
const totalPages = computed(() => pagination.value?.totalPages ?? 1);

// ---- KPI accent + filter toggles ----
type KpiKey = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "FIXABLE" | "OCCURRENCES";

function toggleKpi(k: KpiKey) {
  page.value = 1;
  if (k === "OCCURRENCES") {
    // Just clears all filters.
    severity.value = "all";
    fixable.value = "all";
    return;
  }
  if (k === "FIXABLE") {
    fixable.value = fixable.value === "all" ? "true" : "all";
    severity.value = "all";
    return;
  }
  // severity toggle
  const next = k as Severity;
  severity.value = severity.value === next ? "all" : next;
}

function kpiHint(k: KpiKey): string {
  const sev = summary.value?.severity;
  const totalOccurrences = summary.value?.vulnerabilityOccurrences ?? 0;
  if (totalOccurrences === 0) return "0%";
  switch (k) {
    case "CRITICAL":
      return `${(((sev?.critical ?? 0) / totalOccurrences) * 100).toFixed(1)}%`;
    case "HIGH":
      return `${(((sev?.high ?? 0) / totalOccurrences) * 100).toFixed(1)}%`;
    case "MEDIUM":
      return `${(((sev?.medium ?? 0) / totalOccurrences) * 100).toFixed(1)}%`;
    case "LOW":
      return `${(((sev?.low ?? 0) / totalOccurrences) * 100).toFixed(1)}%`;
    case "FIXABLE":
      return `${(((summary.value?.fixable ?? 0) / totalOccurrences) * 100).toFixed(1)}%`;
    case "OCCURRENCES":
      return `${summary.value?.uniqueVulnerabilityIds ?? 0} unique`;
    default:
      return "";
  }
}

function kpiValue(k: KpiKey): number {
  const s = summary.value;
  if (!s) return 0;
  switch (k) {
    case "CRITICAL":
      return s.severity.critical;
    case "HIGH":
      return s.severity.high;
    case "MEDIUM":
      return s.severity.medium;
    case "LOW":
      return s.severity.low;
    case "FIXABLE":
      return s.fixable;
    case "OCCURRENCES":
      return s.vulnerabilityOccurrences;
    default:
      return 0;
  }
}

function kpiActive(k: KpiKey): boolean {
  if (k === "OCCURRENCES") {
    return severity.value === "all" && fixable.value === "all";
  }
  if (k === "FIXABLE") return fixable.value === "true";
  return severity.value === (k as Severity);
}

// ---- top risky packages ----
const topPackages = computed(() => (summary.value?.topPackages ?? []).slice(0, 5));

function topPkgSeverityBars(pkg: {
  severity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    unknown: number;
  };
  occurrences: number;
}) {
  const total = pkg.occurrences || 1;
  return SEVERITY_ORDER.map((code) => {
    const key = code.toLowerCase() as keyof typeof pkg.severity;
    const count = pkg.severity[key] ?? 0;
    return {
      code,
      count,
      pct: (count / total) * 100,
      color: SEVERITY_COLORS[code],
    };
  });
}

function setPackageSearch(pkgName: string) {
  search.value = pkgName;
  debouncedSearch.value = pkgName;
  page.value = 1;
  if (searchTimer) clearTimeout(searchTimer);
}

// ---- severity doughnut → filter ----
function onSeveritySelect(code: Severity) {
  severity.value = severity.value === code ? "all" : code;
  page.value = 1;
}

// ---- presets ----
interface Preset {
  id: string;
  label: string;
  apply: () => void;
}

const presets: Preset[] = [
  {
    id: "critical-only",
    label: "Critical only",
    apply: () => {
      severity.value = "CRITICAL";
      fixable.value = "all";
      priority.value = "all";
      page.value = 1;
    },
  },
  {
    id: "fixable-critical",
    label: "Fixable critical",
    apply: () => {
      severity.value = "CRITICAL";
      fixable.value = "true";
      priority.value = "all";
      page.value = 1;
    },
  },
  {
    id: "top-priority-p0",
    label: "Top priority (P0)",
    apply: () => {
      severity.value = "all";
      fixable.value = "all";
      priority.value = "P0";
      page.value = 1;
    },
  },
  {
    id: "recently-published",
    label: "Recently published (90d)",
    apply: () => {
      // No native "recent" filter on backend — sort by lastModifiedDate desc
      // and apply a client-side guard in the toolbar hint.
      severity.value = "all";
      fixable.value = "all";
      priority.value = "all";
      sortBy.value = "priorityScore";
      sortOrder.value = "desc";
      page.value = 1;
    },
  },
  {
    id: "clear-all",
    label: "Clear all filters",
    apply: () => {
      severity.value = "all";
      fixable.value = "all";
      priority.value = "all";
      search.value = "";
      debouncedSearch.value = "";
      sortBy.value = "priorityScore";
      sortOrder.value = "desc";
      page.value = 1;
    },
  },
];

function applyPreset(p: Preset) {
  p.apply();
}

// ---- active filter chips ----
interface Chip {
  key: string;
  label: string;
  clear: () => void;
}

const chips = computed<Chip[]>(() => {
  const out: Chip[] = [];
  if (severity.value !== "all") {
    const v = severity.value;
    out.push({
      key: "severity",
      label: `Severity: ${v}`,
      clear: () => {
        severity.value = "all";
        page.value = 1;
      },
    });
  }
  if (fixable.value !== "all") {
    out.push({
      key: "fixable",
      label: `Fixable: ${fixable.value === "true" ? "yes" : "no"}`,
      clear: () => {
        fixable.value = "all";
        page.value = 1;
      },
    });
  }
  if (priority.value !== "all") {
    out.push({
      key: "priority",
      label: `Priority: ${priority.value}`,
      clear: () => {
        priority.value = "all";
        page.value = 1;
      },
    });
  }
  if (debouncedSearch.value) {
    out.push({
      key: "search",
      label: `Search: "${debouncedSearch.value}"`,
      clear: () => {
        search.value = "";
        debouncedSearch.value = "";
        page.value = 1;
      },
    });
  }
  return out;
});

// ---- sorting ----
type SortField = "vulnerabilityId" | "pkgName" | "priorityScore";
function toggleSort(field: SortField) {
  if (sortBy.value === field) {
    sortOrder.value = sortOrder.value === "asc" ? "desc" : "asc";
  } else {
    sortBy.value = field;
    sortOrder.value = field === "vulnerabilityId" || field === "pkgName" ? "asc" : "desc";
  }
  page.value = 1;
}

function sortIcon(field: SortField) {
  if (sortBy.value !== field) return ArrowUpDown;
  return sortOrder.value === "asc" ? ArrowUp : ArrowDown;
}

// ---- pagination ----
function goPrev() {
  if (page.value > 1) page.value--;
}
function goNext() {
  if (page.value < totalPages.value) page.value++;
}

// ---- drawer ----
const drawerOpen = computed({
  get: () => !!selectedVulnId.value,
  set: (v: boolean) => {
    if (!v) selectedVulnId.value = null;
  },
});
function openRow(row: VulnerabilityListItem) {
  selectedVulnId.value = row.id;
}

// ---- export ----
function buildExportQuery(format: "csv" | "json"): string {
  const qs = new URLSearchParams({ format });
  if (severity.value !== "all") qs.set("severity", severity.value);
  if (fixable.value !== "all") qs.set("fixable", fixable.value === "true" ? "true" : "false");
  if (priority.value !== "all") qs.set("priority", priority.value);
  if (debouncedSearch.value) qs.set("search", debouncedSearch.value);
  qs.set("sortBy", sortBy.value);
  qs.set("sortOrder", sortOrder.value);
  return `&${qs.toString()}`;
}

function exportHref(format: "csv" | "json"): string {
  return api.exportUrl(props.scanId, format) + buildExportQuery(format);
}

function downloadExport(format: "csv" | "json") {
  window.location.href = exportHref(format);
}

// ---- artifact meta ----
function artifactTypeLabel(t: string | null): string {
  if (!t) return "Unknown";
  return ARTIFACT_TYPE_LABELS[t] ?? t;
}

const osInfo = computed(() => {
  const m = summary.value?.meta;
  if (!m) return null;
  const parts: string[] = [];
  if (m.osFamily) parts.push(m.osFamily);
  if (m.osName) parts.push(m.osName);
  return parts.length ? parts.join(" / ") : null;
});

const scanDuration = computed(() => {
  const m = summary.value?.meta;
  if (!m || !m.scanStartedAt || !m.scanEndedAt) return null;
  const start = new Date(m.scanStartedAt).getTime();
  const end = new Date(m.scanEndedAt).getTime();
  if (isNaN(start) || isNaN(end) || end < start) return null;
  const s = Math.round((end - start) / 1000);
  if (s < 60) return `${s}s`;
  const m2 = Math.floor(s / 60);
  const s2 = s % 60;
  return `${m2}m ${s2}s`;
});

const warnings = computed(() => summary.value?.warnings ?? []);
const findings = computed(() => summary.value?.findings ?? []);
const totalFindings = computed(() =>
    findings.value.reduce((acc, f) => acc + f.count, 0),
);
</script>

<template>
  <div class="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
    <!-- Loading summary -->
    <div v-if="summaryLoading" class="space-y-4">
      <Skeleton class="h-28 w-full" />
      <div class="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <Skeleton v-for="i in 6" :key="i" class="h-24 w-full" />
      </div>
      <Skeleton class="h-72 w-full" />
      <Skeleton class="h-96 w-full" />
    </div>

    <!-- Summary error -->
    <Card v-else-if="summaryError" class="border-destructive/40 bg-destructive/5">
      <div class="flex items-start gap-3 p-4">
        <AlertCircle class="mt-0.5 h-5 w-5 text-destructive" />
        <div class="space-y-1">
          <p class="text-sm font-medium text-destructive">Could not load scan summary</p>
          <p class="text-xs text-muted-foreground">
            {{ summaryErr instanceof Error ? summaryErr.message : "Unknown error" }}
          </p>
        </div>
      </div>
    </Card>

    <template v-else-if="summary">
      <!-- 1. Artifact header card -->
      <Card class="mb-4 overflow-hidden">
        <div class="flex flex-col gap-4 p-4 lg:flex-row lg:items-start lg:justify-between">
          <div class="min-w-0 flex-1 space-y-3">
            <div class="flex flex-wrap items-center gap-2">
              <Badge variant="outline" class="gap-1">
                <Layers class="h-3 w-3" />
                {{ artifactTypeLabel(summary.artifactType) }}
              </Badge>
              <Badge v-if="summary.schemaVersion" variant="secondary" class="font-mono">
                v{{ summary.schemaVersion }}
              </Badge>
              <Badge v-if="summary.scanners?.length" variant="outline" class="font-mono">
                {{ summary.scanners?.join(", ") }}
              </Badge>
            </div>
            <h2 class="truncate text-2xl font-semibold tracking-tight text-foreground" :title="summary.artifactName">
              {{ summary.artifactName }}
            </h2>
            <div class="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs text-muted-foreground">
              <span class="inline-flex items-center gap-1">
                <Calendar class="h-3.5 w-3.5" /> Uploaded {{ formatTimestamp(summary.uploadedAt) }}
              </span>
              <span class="inline-flex items-center gap-1">
                <Clock class="h-3.5 w-3.5" />
                <template v-if="summary.meta.scanStartedAt && summary.meta.scanEndedAt">
                  {{ formatTimestamp(summary.meta.scanStartedAt) }} → {{ formatTimestamp(summary.meta.scanEndedAt) }}
                  <span v-if="scanDuration" class="font-mono">({{ scanDuration }})</span>
                </template>
                <span v-else>—</span>
              </span>
              <span v-if="osInfo" class="inline-flex items-center gap-1">
                <Cpu class="h-3.5 w-3.5" /> {{ osInfo }}
              </span>
              <span v-if="summary.meta.repoName" class="inline-flex items-center gap-1">
                <PackageIcon class="h-3.5 w-3.5" /> {{ summary.meta.repoName }}
              </span>
              <span v-if="summary.meta.imageTags?.length" class="inline-flex items-center gap-1 font-mono">
                <Boxes class="h-3.5 w-3.5" /> {{ summary.meta.imageTags?.join(", ") }}
              </span>
            </div>
          </div>
          <div class="flex shrink-0 items-center gap-2">
            <Button variant="outline" size="sm" @click="downloadExport('csv')">
              <Download class="h-3.5 w-3.5" /> CSV
            </Button>
            <Button variant="outline" size="sm" @click="downloadExport('json')">
              <FileJson class="h-3.5 w-3.5" /> JSON
            </Button>
          </div>
        </div>
      </Card>

      <!-- 2. KPI cards -->
      <div class="mb-4 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <KpiCard
            label="Critical"
            :value="kpiValue('CRITICAL')"
            accent="critical"
            :hint="kpiHint('CRITICAL')"
            :icon="Flame"
            clickable
            :active="kpiActive('CRITICAL')"
            @click="toggleKpi('CRITICAL')"
        />
        <KpiCard
            label="High"
            :value="kpiValue('HIGH')"
            accent="high"
            :hint="kpiHint('HIGH')"
            :icon="AlertTriangle"
            clickable
            :active="kpiActive('HIGH')"
            @click="toggleKpi('HIGH')"
        />
        <KpiCard
            label="Medium"
            :value="kpiValue('MEDIUM')"
            accent="medium"
            :hint="kpiHint('MEDIUM')"
            :icon="AlertTriangle"
            clickable
            :active="kpiActive('MEDIUM')"
            @click="toggleKpi('MEDIUM')"
        />
        <KpiCard
            label="Low"
            :value="kpiValue('LOW')"
            accent="low"
            :hint="kpiHint('LOW')"
            :icon="Shield"
            clickable
            :active="kpiActive('LOW')"
            @click="toggleKpi('LOW')"
        />
        <KpiCard
            label="Fixable"
            :value="kpiValue('FIXABLE')"
            accent="emerald"
            :hint="kpiHint('FIXABLE')"
            :icon="Wrench"
            clickable
            :active="kpiActive('FIXABLE')"
            @click="toggleKpi('FIXABLE')"
        />
        <KpiCard
            label="Occurrences"
            :value="kpiValue('OCCURRENCES')"
            accent="neutral"
            :hint="kpiHint('OCCURRENCES')"
            :icon="Boxes"
            clickable
            :active="kpiActive('OCCURRENCES')"
            @click="toggleKpi('OCCURRENCES')"
        />
      </div>

      <!-- 3. Charts row -->
      <div class="mb-4 grid grid-cols-1 gap-3 lg:grid-cols-3">
        <!-- Severity doughnut -->
        <Card class="lg:col-span-1">
          <div class="border-b border-border p-4 pb-3">
            <h3 class="text-sm font-semibold text-foreground">Severity distribution</h3>
            <p class="text-[11px] text-muted-foreground">Click a slice to filter the table</p>
          </div>
          <div class="flex items-center justify-center p-4">
            <SeverityChart
                :counts="summary.severity"
                :active="severity !== 'all' ? severity : null"
                @select="onSeveritySelect"
            />
          </div>
        </Card>

        <!-- Top risky packages -->
        <Card class="lg:col-span-2">
          <div class="flex items-center justify-between border-b border-border p-4 pb-3">
            <div>
              <h3 class="text-sm font-semibold text-foreground">Top risky packages</h3>
              <p class="text-[11px] text-muted-foreground">By occurrence count, top 5</p>
            </div>
            <Badge variant="secondary" class="font-mono">{{ topPackages.length }}</Badge>
          </div>
          <div class="divide-y divide-border">
            <div v-if="!topPackages.length" class="p-6 text-center text-xs text-muted-foreground">
              No packages in this scan.
            </div>
            <button
                v-for="(pkg, i) in topPackages"
                :key="pkg.package"
                type="button"
                class="flex w-full items-center gap-3 px-4 py-2.5 text-left transition-colors hover:bg-accent/40 focus:bg-accent/40 focus:outline-none"
                :title="`Filter table by ${pkg.package}`"
                @click="setPackageSearch(pkg.package)"
            >
              <span class="w-5 shrink-0 text-right font-mono text-xs tabular-nums text-muted-foreground">
                {{ i + 1 }}
              </span>
              <div class="min-w-0 flex-1 space-y-1">
                <div class="flex items-center justify-between gap-2">
                  <span class="truncate font-mono text-sm text-foreground" :title="pkg.package">{{ pkg.package }}</span>
                  <span class="shrink-0 font-mono text-xs tabular-nums text-muted-foreground">
                    {{ formatNumber(pkg.occurrences) }} occurrences
                  </span>
                </div>
                <!-- stacked severity bar -->
                <div class="flex h-1.5 w-full overflow-hidden rounded-full bg-muted">
                  <span
                      v-for="slice in topPkgSeverityBars(pkg)"
                      v-show="slice.count > 0"
                      :key="slice.code"
                      :style="{ width: `${slice.pct}%`, backgroundColor: slice.color }"
                      :class="slice.count === 0 ? 'hidden' : ''"
                      :title="`${slice.code}: ${slice.count}`"
                  />
                </div>
              </div>
              <div class="flex shrink-0 flex-col items-end gap-1">
                <PriorityBadge :level="priorityLevelFromScore(pkg.priorityScore)" />
                <span v-if="pkg.fixable > 0" class="font-mono text-[10px] text-emerald-600 dark:text-emerald-400">
                  {{ pkg.fixable }} fixable
                </span>
              </div>
            </button>
          </div>
        </Card>
      </div>

      <!-- 4. findings row -->
      <div v-if="findings.length" class="mb-4 grid grid-cols-1 gap-3 lg:grid-cols-2">
        <!-- Non-vuln findings -->
        <Card v-if="findings.length" class="border-purple-500/30">
          <div class="flex items-start gap-3 p-4">
            <Shield class="mt-0.5 h-5 w-5 text-purple-600 dark:text-purple-400" />
            <div class="min-w-0 flex-1 space-y-1.5">
              <p class="text-sm font-medium text-foreground">
                Non-vulnerability findings ({{ formatNumber(totalFindings) }})
              </p>
              <div class="flex flex-wrap gap-2">
                <Badge v-for="f in findings" :key="f.kind" variant="outline" class="gap-1">
                  <FindingKindBadge :kind="f.kind" />
                  <span class="font-mono tabular-nums">{{ f.count }}</span>
                </Badge>
              </div>
              <p class="text-[11px] text-muted-foreground">
                See the Findings tab for full details.
              </p>
            </div>
          </div>
        </Card>
      </div>

      <!-- 5. Vulnerabilities table -->
      <Card class="overflow-hidden">
        <!-- Toolbar -->
        <div class="flex flex-col gap-2 border-b border-border p-3 lg:flex-row lg:items-center lg:justify-between">
          <div class="flex flex-wrap items-center gap-2">
            <DropdownMenu align="start">
              <template #trigger>
                <Button variant="outline" size="sm">
                  Presets
                  <ChevronRight class="h-3 w-3 rotate-90" />
                </Button>
              </template>
              <template #content>
                <DropdownMenuItem
                    v-for="p in presets.slice(0, 4)"
                    :key="p.id"
                    @click="applyPreset(p)"
                >
                  {{ p.label }}
                </DropdownMenuItem>
                <Separator orientation="horizontal" class="my-1" />
                <DropdownMenuItem @click="applyPreset(presets[4])">
                  {{ presets[4].label }}
                </DropdownMenuItem>
              </template>
            </DropdownMenu>

            <div class="relative w-full sm:w-72">
              <Search class="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
              <Input
                  :model-value="search"
                  placeholder="Filter by CVE id, package, target…"
                  class="pl-8"
                  @update:model-value="onSearchInput"
              />
            </div>

            <Select v-model="severity" class="w-32" @update:model-value="(v) => { severity = v as Severity | 'all'; page = 1 }">
              <option value="all">All severities</option>
              <option v-for="s in SEVERITY_ORDER" :key="s" :value="s">{{ s }}</option>
            </Select>

            <Select v-model="fixable" class="w-32" @update:model-value="(v) => { fixable = v as 'all' | 'true' | 'false'; page = 1 }">
              <option value="all">Fixable: any</option>
              <option value="true">Fixable: yes</option>
              <option value="false">Fixable: no</option>
            </Select>

            <Select v-model="priority" class="w-32" @update:model-value="(v) => { priority = v as PriorityLevel | 'all'; page = 1 }">
              <option value="all">All priorities</option>
              <option value="P0">P0</option>
              <option value="P1">P1</option>
              <option value="P2">P2</option>
              <option value="P3">P3</option>
              <option value="P4">P4</option>
            </Select>

            <Tooltip side="top">
              <template #trigger>
                <Button variant="ghost" size="icon" class="h-8 w-8">
                  <Info class="h-4 w-4" />
                </Button>
              </template>
              <template #content>
                Click a KPI card or doughnut slice to filter. Click column headers to sort. Click a row to see full CVE details.
              </template>
            </Tooltip>
          </div>

          <div v-if="vulnFetching" class="flex items-center gap-1 text-xs text-primary">
            <Loader2 class="h-3 w-3 animate-spin" /> updating…
          </div>
        </div>

        <!-- Active filter chips -->
        <div v-if="chips.length" class="flex flex-wrap items-center gap-1.5 border-b border-border bg-muted/20 px-3 py-2">
          <span class="text-[11px] text-muted-foreground">Active:</span>
          <span
              v-for="chip in chips"
              :key="chip.key"
              class="inline-flex items-center gap-1 rounded-full border border-border bg-background px-2 py-0.5 text-[11px]"
          >
            {{ chip.label }}
            <button
                type="button"
                class="rounded-full p-0.5 hover:bg-accent"
                :title="`Clear ${chip.label}`"
                @click="chip.clear"
            >
              <X class="h-3 w-3" />
            </button>
          </span>
          <button
              type="button"
              class="text-[11px] text-primary underline-offset-2 hover:underline"
              @click="applyPreset(presets[4])"
          >
            Clear all
          </button>
        </div>

        <!-- Loading -->
        <div v-if="vulnLoading" class="space-y-2 p-4">
          <Skeleton v-for="i in 8" :key="i" class="h-12 w-full" />
        </div>

        <!-- Error -->
        <div v-else-if="vulnError" class="flex items-start gap-3 p-4">
          <AlertCircle class="mt-0.5 h-5 w-5 text-destructive" />
          <div class="space-y-1">
            <p class="text-sm font-medium text-destructive">Could not load vulnerabilities</p>
            <p class="text-xs text-muted-foreground">
              {{ vulnErr instanceof Error ? vulnErr.message : "Unknown error" }}
            </p>
          </div>
        </div>

        <!-- Empty -->
        <div v-else-if="!rows.length" class="flex flex-col items-center justify-center px-6 py-16 text-center">
          <div class="mb-4 flex h-14 w-14 items-center justify-center rounded-full bg-muted text-muted-foreground">
            <Shield class="h-6 w-6" />
          </div>
          <p class="text-sm font-medium text-foreground">
            {{ chips.length ? "No vulnerabilities match the current filters" : "No vulnerabilities in this scan" }}
          </p>
          <p class="mt-1 text-xs text-muted-foreground">
            {{ chips.length ? "Try clearing filters or adjusting the search." : "Run a scan with --scanners vuln to populate this view." }}
          </p>
        </div>

        <!-- Table -->
        <Table v-else>
          <TableHeader>
            <TableRow class="bg-muted/40 hover:bg-muted/40">
              <TableHead class="w-[70px] text-center">Priority</TableHead>
              <TableHead class="w-[110px]">Severity</TableHead>
              <TableHead class="w-[260px]">
                <button
                    type="button"
                    class="inline-flex items-center gap-1 text-xs font-medium uppercase tracking-wider hover:text-foreground"
                    @click="toggleSort('vulnerabilityId')"
                >
                  CVE
                  <component :is="sortIcon('vulnerabilityId')" class="h-3 w-3" />
                </button>
              </TableHead>
              <TableHead class="w-[220px]">
                <button
                    type="button"
                    class="inline-flex items-center gap-1 text-xs font-medium uppercase tracking-wider hover:text-foreground"
                    @click="toggleSort('pkgName')"
                >
                  Package
                  <component :is="sortIcon('pkgName')" class="h-3 w-3" />
                </button>
              </TableHead>
              <TableHead class="w-[120px]">Installed</TableHead>
              <TableHead class="w-[120px]">Fixed</TableHead>
              <TableHead class="w-[70px] text-right">CVSS</TableHead>
              <TableHead>Target</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            <TableRow
                v-for="row in rows"
                :key="row.id"
                class="cursor-pointer"
                @click="openRow(row)"
            >
              <TableCell class="text-center">
                <button
                    type="button"
                    class="inline-flex items-center gap-1"
                    @click.stop="toggleSort('priorityScore')"
                >
                  <PriorityBadge :level="row.priorityLevel" />
                </button>
              </TableCell>
              <TableCell>
                <SeverityBadge :severity="row.severity" />
              </TableCell>
              <TableCell>
                <div class="flex flex-col gap-0.5">
                  <span class="font-mono text-xs text-foreground">{{ row.vulnerabilityId }}</span>
                  <span v-if="row.title" class="text-[11px] text-muted-foreground line-clamp-1" :title="row.title">
                    {{ row.title }}
                  </span>
                </div>
              </TableCell>
              <TableCell>
                <div class="flex flex-col gap-0.5">
                  <span class="truncate font-mono text-xs text-foreground" :title="row.pkgName">
                    {{ row.pkgName }}
                  </span>
                  <span v-if="row.type" class="text-[10px] text-muted-foreground">{{ row.type }}</span>
                </div>
              </TableCell>
              <TableCell>
                <span v-if="row.installedVersion" class="font-mono text-xs text-foreground">
                  {{ row.installedVersion }}
                </span>
                <span v-else class="text-xs text-muted-foreground">—</span>
              </TableCell>
              <TableCell>
                <span v-if="row.fixedVersion" class="font-mono text-xs text-emerald-600 dark:text-emerald-400">
                  {{ row.fixedVersion }}
                </span>
                <span v-else class="text-xs text-muted-foreground">—</span>
              </TableCell>
              <TableCell class="text-right font-mono text-xs tabular-nums text-foreground">
                {{ row.cvssMaxScore != null ? row.cvssMaxScore.toFixed(1) : "—" }}
              </TableCell>
              <TableCell>
                <span class="block max-w-[200px] truncate font-mono text-[11px] text-muted-foreground" :title="row.target">
                  {{ row.target }}
                </span>
              </TableCell>
            </TableRow>
          </TableBody>
        </Table>

        <!-- Pagination -->
        <div
            v-if="pagination && rows.length"
            class="flex items-center justify-between border-t border-border px-3 py-2 text-xs text-muted-foreground"
        >
          <div>
            {{ formatNumber((pagination.page - 1) * pagination.pageSize + (rows.length ? 1 : 0)) }} –
            {{ formatNumber((pagination.page - 1) * pagination.pageSize + rows.length) }}
            of {{ formatNumber(pagination.total) }}
          </div>
          <div class="flex items-center gap-2">
            <Button variant="outline" size="icon" class="h-7 w-7" :disabled="page <= 1" @click="goPrev">
              <ChevronLeft class="h-3.5 w-3.5" />
            </Button>
            <span class="font-mono tabular-nums">
              {{ pagination.page }} / {{ Math.max(1, pagination.totalPages) }}
            </span>
            <Button variant="outline" size="icon" class="h-7 w-7" :disabled="page >= totalPages" @click="goNext">
              <ChevronRight class="h-3.5 w-3.5" />
            </Button>
          </div>
        </div>
      </Card>
    </template>

    <!-- Vulnerability drawer -->
    <VulnerabilityDrawer
        v-if="selectedVulnId"
        :scan-id="scanId"
        :vuln-id="selectedVulnId"
        :open="drawerOpen"
        @update:open="(v) => (drawerOpen = v)"
    />
  </div>
</template>
