<script setup lang="ts">
import { ref, computed, watch } from "vue";
import { useRouter } from "vue-router";
import {
  Boxes,
  Flame,
  Wrench,
  AlertTriangle,
  Shield,
  BarChart3,
  Package as PackageIcon,
  Cpu,
  Layers,
  Upload,
  AlertCircle,
  Loader2,
  Radar,
} from "@lucide/vue";
import Button from "@/components/ui/Button.vue";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Badge, Skeleton } from "@/components/ui/primitives";
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
  SEVERITY_ORDER,
  SEVERITY_COLORS,
  priorityLevelFromScore,
  FINDING_KIND_LABELS,
} from "@/lib/format";
import { cn } from "@/lib/utils";
import KpiCard from "@/components/common/KpiCard.vue";
import type { ScanListEntry, ScanSummary, SeverityCounts, Severity } from "@/lib/types";

const router = useRouter();

// ---- fetch scan list ----
const {
  data: scanList,
  isLoading: scanListLoading,
  isError: scanListError,
  error: scanListErr,
  refetch,
} = useApi<ScanListEntry[]>(() => api.listScans(), () => [], { refetchInterval: 30_000 });

// ---- fetch summaries in parallel ----
const summaries = ref<ScanSummary[]>([]);
const summariesLoading = ref(false);
const summariesError = ref<unknown>(null);

async function loadSummaries(list: ScanListEntry[]) {
  summariesLoading.value = true;
  summariesError.value = null;
  try {
    const results = await Promise.all(
      list.map((entry) =>
        api.getSummary(entry.id).catch(() => null),
      ),
    );
    summaries.value = results.filter((s): s is ScanSummary => s !== null);
  } catch (e) {
    summariesError.value = e;
  } finally {
    summariesLoading.value = false;
  }
}

watch(
  () => scanList.value,
  (list) => {
    if (list && list.length) {
      void loadSummaries(list);
    } else {
      summaries.value = [];
    }
  },
  { immediate: true },
);

// ---- aggregation ----
const isLoading = computed(() => scanListLoading.value || summariesLoading.value);

interface AggregatedPkg {
  package: string;
  occurrences: number;
  severity: SeverityCounts;
  fixable: number;
  priorityScore: number;
  firstScanId: string;
  scans: Set<string>;
}

const totalScans = computed(() => scanList.value?.length ?? 0);
const totalOccurrences = computed(() =>
  summaries.value.reduce((acc, s) => acc + s.vulnerabilityOccurrences, 0),
);
const uniqueCves = computed(() =>
  summaries.value.reduce((acc, s) => acc + s.uniqueVulnerabilityIds, 0),
);
const totalCritical = computed(() =>
  summaries.value.reduce((acc, s) => acc + s.severity.critical, 0),
);
const totalHigh = computed(() =>
  summaries.value.reduce((acc, s) => acc + s.severity.high, 0),
);
const totalFixable = computed(() =>
  summaries.value.reduce((acc, s) => acc + s.fixable, 0),
);
const avgCritical = computed(() =>
  totalScans.value > 0 ? totalCritical.value / totalScans.value : 0,
);

interface SeveritySlice {
  code: Severity;
  key: keyof SeverityCounts;
  count: number;
  pct: number;
  color: string;
}

const severityTotals = computed<SeverityCounts>(() => {
  const out: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  for (const s of summaries.value) {
    out.critical += s.severity.critical;
    out.high += s.severity.high;
    out.medium += s.severity.medium;
    out.low += s.severity.low;
    out.unknown += s.severity.unknown;
  }
  return out;
});

const severitySlices = computed<SeveritySlice[]>(() => {
  const total = SEVERITY_ORDER.reduce(
    (acc, code) => acc + (severityTotals.value[code.toLowerCase() as keyof SeverityCounts] ?? 0),
    0,
  );
  return SEVERITY_ORDER.map((code) => {
    const key = code.toLowerCase() as keyof SeverityCounts;
    const count = severityTotals.value[key] ?? 0;
    return {
      code,
      key,
      count,
      pct: total > 0 ? (count / total) * 100 : 0,
      color: SEVERITY_COLORS[code],
    };
  });
});

const severityTotal = computed(() =>
  severitySlices.value.reduce((acc, s) => acc + s.count, 0),
);

// ---- scans over time ----
interface TimelineBar {
  scanId: string;
  artifactName: string;
  uploadedAt: number;
  total: number;
  critical: number;
  high: number;
  color: string;
  heightPct: number;
}

const timeline = computed<TimelineBar[]>(() => {
  const sorted = [...summaries.value].sort((a, b) => a.uploadedAt - b.uploadedAt);
  if (!sorted.length) return [];
  const maxTotal = Math.max(...sorted.map((s) => s.vulnerabilityOccurrences), 1);
  return sorted.map((s) => {
    const total = s.vulnerabilityOccurrences;
    const critical = s.severity.critical;
    let color: string;
    if (critical === 0) color = "#10b981"; // emerald
    else if (critical <= 2) color = "#f59e0b"; // amber
    else if (critical <= 5) color = "#ea580c"; // orange
    else color = "#dc2626"; // red
    return {
      scanId: s.scanId,
      artifactName: s.artifactName,
      uploadedAt: s.uploadedAt,
      total,
      critical,
      high: s.severity.high,
      color,
      heightPct: Math.max(4, (total / maxTotal) * 100),
    };
  });
});

// ---- top artifacts ----
interface ArtifactRow {
  scanId: string;
  artifactName: string;
  artifactType: string | null;
  total: number;
  critical: number;
  high: number;
  fixable: number;
  uploadedAt: number;
}

const topArtifacts = computed<ArtifactRow[]>(() =>
  [...summaries.value]
    .map((s) => ({
      scanId: s.scanId,
      artifactName: s.artifactName,
      artifactType: s.artifactType,
      total: s.vulnerabilityOccurrences,
      critical: s.severity.critical,
      high: s.severity.high,
      fixable: s.fixable,
      uploadedAt: s.uploadedAt,
    }))
    .sort((a, b) => b.total - a.total),
);

// ---- top packages across scans ----
const aggregatedPackages = computed<AggregatedPkg[]>(() => {
  const byName = new Map<string, AggregatedPkg>();
  for (const s of summaries.value) {
    for (const p of s.topPackages) {
      let entry = byName.get(p.package);
      if (!entry) {
        entry = {
          package: p.package,
          occurrences: 0,
          severity: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
          fixable: 0,
          priorityScore: 0,
          firstScanId: s.scanId,
          scans: new Set(),
        };
        byName.set(p.package, entry);
      }
      entry.occurrences += p.occurrences;
      entry.severity.critical += p.severity.critical;
      entry.severity.high += p.severity.high;
      entry.severity.medium += p.severity.medium;
      entry.severity.low += p.severity.low;
      entry.severity.unknown += p.severity.unknown;
      entry.fixable += p.fixable;
      entry.priorityScore = Math.max(entry.priorityScore, p.priorityScore);
      entry.scans.add(s.scanId);
    }
  }
  return [...byName.values()]
    .sort((a, b) => b.occurrences - a.occurrences)
    .slice(0, 10);
});

// ---- scanner usage ----
interface ScannerBar {
  key: string;
  label: string;
  count: number;
  pct: number;
  color: string;
}

const scannerUsage = computed<ScannerBar[]>(() => {
  const categories: Record<string, { label: string; color: string }> = {
    vuln: { label: "Vulnerabilities", color: "bg-red-500" },
    misconfig: { label: "Misconfigurations", color: "bg-purple-500" },
    secret: { label: "Secrets", color: "bg-pink-500" },
    license: { label: "Licenses", color: "bg-cyan-500" },
  };
  const counts: Record<string, number> = { vuln: 0, misconfig: 0, secret: 0, license: 0 };
  for (const s of summaries.value) {
    if (s.scanners.includes("vuln")) counts.vuln++;
    if (s.scanners.includes("misconfig") || s.scanners.includes("misconfiguration")) counts.misconfig++;
    if (s.scanners.includes("secret")) counts.secret++;
    if (s.scanners.includes("license")) counts.license++;
  }
  const totalScansCount = Math.max(1, summaries.value.length);
  return Object.entries(categories).map(([key, meta]) => ({
    key,
    label: meta.label,
    count: counts[key],
    pct: (counts[key] / totalScansCount) * 100,
    color: meta.color,
  }));
});

// ---- navigation ----
function openScan(scanId: string) {
  router.push({ name: "dashboard", params: { scanId } });
}

function goUpload() {
  router.push({ name: "upload" });
}

function artifactTypeLabel(t: string | null): string {
  if (!t) return "—";
  return ARTIFACT_TYPE_LABELS[t] ?? t;
}
</script>

<template>
  <div class="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
<!-- Loading skeleton -->
    <div v-if="isLoading" class="space-y-4">
      <div class="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <Skeleton v-for="i in 6" :key="i" class="h-24 w-full" />
      </div>
      <Skeleton class="h-24 w-full" />
      <Skeleton class="h-64 w-full" />
      <Skeleton class="h-64 w-full" />
    </div>

    <!-- Error -->
    <Card v-else-if="scanListError" class="border-destructive/40 bg-destructive/5">
      <div class="flex items-start gap-3 p-4">
        <AlertCircle class="mt-0.5 h-5 w-5 text-destructive" />
        <div class="space-y-1">
          <p class="text-sm font-medium text-destructive">Could not load scans</p>
          <p class="text-xs text-muted-foreground">
            {{ scanListErr instanceof Error ? scanListErr.message : "Unknown error" }}
          </p>
        </div>
        <Button class="ml-auto" variant="outline" size="sm" @click="refetch">Try again</Button>
      </div>
    </Card>

    <!-- Empty state -->
    <Card v-else-if="!totalScans" class="border-dashed">
      <div class="flex flex-col items-center justify-center px-6 py-16 text-center">
        <div class="mb-4 flex h-14 w-14 items-center justify-center rounded-full bg-muted text-muted-foreground">
          <BarChart3 class="h-6 w-6" />
        </div>
        <p class="text-sm font-medium text-foreground">No scans yet</p>
        <p class="mt-1 text-xs text-muted-foreground">
          Upload a Trivy JSON report or run a live scan to see aggregate statistics here.
        </p>
        <div class="mt-5 flex items-center gap-2">
          <Button size="sm" @click="router.push({ name: 'upload' })">Upload report</Button>
          <Button variant="outline" size="sm" @click="router.push({ name: 'scan' })">Run a scan</Button>
        </div>
      </div>
    </Card>

    <template v-else>
      <!-- 1. KPI cards -->
      <div class="mb-4 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        <KpiCard label="Total Scans" :value="totalScans" accent="neutral" :icon="Radar" hint="Stored reports" />
        <KpiCard label="Total Vulns" :value="totalOccurrences" accent="neutral" :icon="Boxes" hint="Occurrences" />
        <KpiCard label="Unique CVEs" :value="uniqueCves" accent="sky" :icon="AlertCircle" hint="Distinct IDs" />
        <KpiCard label="Critical" :value="totalCritical" accent="critical" :icon="Flame" hint="Across all scans" />
        <KpiCard label="Fixable" :value="totalFixable" accent="emerald" :icon="Wrench" hint="Have a fix version" />
        <KpiCard label="Avg Crit/Scan" :value="avgCritical.toFixed(1)" accent="high" :icon="AlertTriangle" hint="Per scan avg" />
      </div>

      <!-- 2. Aggregate severity bar -->
      <Card class="mb-4">
        <CardHeader class="pb-3">
          <CardTitle>Severity breakdown</CardTitle>
          <CardDescription>Across {{ formatNumber(totalScans) }} scans, {{ formatNumber(severityTotal) }} total vulnerabilities</CardDescription>
        </CardHeader>
        <CardContent>
          <div class="flex h-7 w-full overflow-hidden rounded-md border border-border">
            <div
              v-for="s in severitySlices"
              v-show="s.count > 0"
              :key="s.code"
              :style="{ width: `${s.pct}%`, backgroundColor: s.color }"
              :class="s.count === 0 ? 'hidden' : ''"
              class="flex items-center justify-center text-[10px] font-medium text-white transition-all"
              :title="`${s.code}: ${s.count} (${s.pct.toFixed(1)}%)`"
            >
              <span v-if="s.pct > 6" class="font-mono">{{ s.count }}</span>
            </div>
            <div v-if="severityTotal === 0" class="flex flex-1 items-center justify-center text-xs text-muted-foreground">
              No vulnerabilities
            </div>
          </div>
          <!-- legend -->
          <div class="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-5">
            <div
              v-for="s in severitySlices"
              :key="s.code"
              class="flex items-center justify-between rounded-md border border-border bg-muted/30 px-2 py-1.5"
            >
              <div class="flex items-center gap-1.5">
                <span class="h-2.5 w-2.5 rounded-sm" :style="{ backgroundColor: s.color }" />
                <span class="text-[11px] font-medium uppercase text-foreground">{{ s.code }}</span>
              </div>
              <div class="flex flex-col items-end">
                <span class="font-mono text-xs font-semibold tabular-nums text-foreground">{{ s.count }}</span>
                <span class="text-[10px] text-muted-foreground">{{ s.pct.toFixed(1) }}%</span>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      <!-- 3. Scans over time -->
      <Card class="mb-4">
        <CardHeader class="pb-3">
          <CardTitle>Scans over time</CardTitle>
          <CardDescription>One bar per scan, ordered by upload time. Color reflects critical count. Click to open.</CardDescription>
        </CardHeader>
        <CardContent>
          <div v-if="timeline.length === 0" class="py-8 text-center text-xs text-muted-foreground">
            No scans to display.
          </div>
          <div v-else class="flex h-48 items-end justify-center gap-3 overflow-x-auto pt-4 sm:justify-start">
            <button
              v-for="(bar, i) in timeline"
              :key="bar.scanId"
              type="button"
              class="group flex h-full w-20 shrink-0 flex-col justify-end focus:outline-none"
              :title="`${bar.artifactName} — ${bar.total} vulns, ${bar.critical} critical, ${formatTimestamp(bar.uploadedAt)}`"
              @click="openScan(bar.scanId)"
            >
              <div class="relative flex w-full justify-center">
                <span
                  class="absolute -top-5 whitespace-nowrap rounded bg-foreground px-1.5 py-0.5 text-[10px] font-mono text-background opacity-0 transition-opacity group-hover:opacity-100"
                >
                  {{ bar.total }}
                </span>
              </div>
              <div
                class="w-full rounded-t-md transition-all group-hover:brightness-110"
                :style="{ height: `${bar.heightPct}%`, backgroundColor: bar.color }"
              />
              <span class="mt-1 block truncate text-center text-[9px] text-muted-foreground" :title="bar.artifactName">
                {{ bar.artifactName.slice(0, 8) }}{{ bar.artifactName.length > 8 ? "…" : "" }}
              </span>
              <span class="block text-center font-mono text-[9px] text-muted-foreground">
                {{ formatRelativeTime(bar.uploadedAt) }}
              </span>
            </button>
          </div>
          <!-- legend -->
          <div class="mt-3 flex flex-wrap items-center gap-3 text-[10px] text-muted-foreground">
            <span class="inline-flex items-center gap-1"><span class="h-2 w-2 rounded-sm bg-emerald-500" /> 0 critical</span>
            <span class="inline-flex items-center gap-1"><span class="h-2 w-2 rounded-sm bg-amber-500" /> 1–2</span>
            <span class="inline-flex items-center gap-1"><span class="h-2 w-2 rounded-sm bg-orange-500" /> 3–5</span>
            <span class="inline-flex items-center gap-1"><span class="h-2 w-2 rounded-sm bg-red-600" /> 6+</span>
          </div>
        </CardContent>
      </Card>

      <!-- 4. Top vulnerable artifacts table -->
      <Card class="mb-4 overflow-hidden">
        <CardHeader class="pb-3">
          <CardTitle>Top vulnerable artifacts</CardTitle>
          <CardDescription>All scans sorted by total vulnerability count. Click a row to open its dashboard.</CardDescription>
        </CardHeader>
        <Table>
          <TableHeader>
            <TableRow class="bg-muted/40 hover:bg-muted/40">
              <TableHead>Artifact</TableHead>
              <TableHead class="w-[120px]">Type</TableHead>
              <TableHead class="w-[80px] text-right">Total</TableHead>
              <TableHead class="w-[80px] text-right">Critical</TableHead>
              <TableHead class="w-[80px] text-right">High</TableHead>
              <TableHead class="w-[80px] text-right">Fixable</TableHead>
              <TableHead class="w-[120px] text-right">Uploaded</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            <TableRow
              v-for="row in topArtifacts"
              :key="row.scanId"
              class="cursor-pointer"
              @click="openScan(row.scanId)"
            >
              <TableCell>
                <div class="flex items-center gap-2">
                  <div class="flex h-7 w-7 items-center justify-center rounded-md bg-muted text-muted-foreground">
                    <Layers class="h-3.5 w-3.5" />
                  </div>
                  <span class="truncate text-sm font-medium text-foreground" :title="row.artifactName">{{ row.artifactName }}</span>
                </div>
              </TableCell>
              <TableCell>
                <Badge variant="outline" class="font-normal">{{ artifactTypeLabel(row.artifactType) }}</Badge>
              </TableCell>
              <TableCell class="text-right font-mono text-sm tabular-nums">{{ formatNumber(row.total) }}</TableCell>
              <TableCell class="text-right">
                <Badge v-if="row.critical > 0" variant="destructive" class="font-mono tabular-nums">
                  <Flame class="h-3 w-3" />{{ row.critical }}
                </Badge>
                <span v-else class="text-xs text-muted-foreground">0</span>
              </TableCell>
              <TableCell class="text-right font-mono text-sm tabular-nums">{{ row.high }}</TableCell>
              <TableCell class="text-right">
                <span v-if="row.fixable > 0" class="font-mono text-sm text-emerald-600 dark:text-emerald-400 tabular-nums">
                  {{ row.fixable }}
                </span>
                <span v-else class="text-xs text-muted-foreground">0</span>
              </TableCell>
              <TableCell class="text-xs text-muted-foreground text-right">{{ formatRelativeTime(row.uploadedAt) }}</TableCell>
            </TableRow>
          </TableBody>
        </Table>
      </Card>

      <!-- 5. Top packages across all scans + 6. Scanner usage side by side -->
      <div class="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <!-- Top packages -->
        <Card class="lg:col-span-2 overflow-hidden">
          <CardHeader class="pb-3">
            <CardTitle>Top packages across all scans</CardTitle>
            <CardDescription>Aggregated by package name, top 10. Click a row to open the scan where it was first found.</CardDescription>
          </CardHeader>
          <Table>
            <TableHeader>
              <TableRow class="bg-muted/40 hover:bg-muted/40">
                <TableHead class="w-[40px] text-center">#</TableHead>
                <TableHead>Package</TableHead>
                <TableHead class="w-[80px] text-right">Occurrences</TableHead>
                <TableHead class="w-[140px]">Severity</TableHead>
                <TableHead class="w-[80px] text-right">Fixable</TableHead>
                <TableHead class="w-[80px]">Priority</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              <TableRow
                v-for="(pkg, i) in aggregatedPackages"
                :key="pkg.package"
                class="cursor-pointer"
                @click="openScan(pkg.firstScanId)"
              >
                <TableCell class="text-center font-mono text-xs tabular-nums text-muted-foreground">{{ i + 1 }}</TableCell>
                <TableCell>
                  <div class="flex flex-col gap-0.5">
                    <span class="truncate font-mono text-xs text-foreground" :title="pkg.package">{{ pkg.package }}</span>
                    <span class="text-[10px] text-muted-foreground">{{ pkg.scans.size }} scan{{ pkg.scans.size === 1 ? "" : "s" }}</span>
                  </div>
                </TableCell>
                <TableCell class="text-right font-mono text-xs tabular-nums">{{ formatNumber(pkg.occurrences) }}</TableCell>
                <TableCell>
                  <div class="flex h-2 w-full overflow-hidden rounded-full bg-muted">
                    <span
                      v-for="code in SEVERITY_ORDER"
                      v-show="(pkg.severity[code.toLowerCase() as keyof SeverityCounts] ?? 0) > 0"
                      :key="code"
                      :style="{
                        width: `${((pkg.severity[code.toLowerCase() as keyof SeverityCounts] ?? 0) / Math.max(1, pkg.occurrences)) * 100}%`,
                        backgroundColor: SEVERITY_COLORS[code],
                      }"
                      :title="`${code}: ${pkg.severity[code.toLowerCase() as keyof SeverityCounts] ?? 0}`"
                    />
                  </div>
                </TableCell>
                <TableCell class="text-right">
                  <span v-if="pkg.fixable > 0" class="font-mono text-xs text-emerald-600 dark:text-emerald-400 tabular-nums">
                    {{ pkg.fixable }}
                  </span>
                  <span v-else class="text-xs text-muted-foreground">—</span>
                </TableCell>
                <TableCell>
                  <span
                    :class="cn('inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-bold', {
                      'bg-red-600 text-white': priorityLevelFromScore(pkg.priorityScore) === 'P0',
                      'bg-red-500/80 text-white': priorityLevelFromScore(pkg.priorityScore) === 'P1',
                      'bg-orange-500/80 text-white': priorityLevelFromScore(pkg.priorityScore) === 'P2',
                      'bg-yellow-500/80 text-white': priorityLevelFromScore(pkg.priorityScore) === 'P3',
                      'bg-emerald-500/80 text-white': priorityLevelFromScore(pkg.priorityScore) === 'P4',
                    })"
                  >
                    {{ priorityLevelFromScore(pkg.priorityScore) }}
                  </span>
                </TableCell>
              </TableRow>
            </TableBody>
          </Table>
        </Card>

        <!-- Scanner usage -->
        <Card class="lg:col-span-1">
          <CardHeader class="pb-3">
            <CardTitle>Scanner usage</CardTitle>
            <CardDescription>Which scanner categories ran</CardDescription>
          </CardHeader>
          <CardContent class="space-y-3">
            <div v-for="sc in scannerUsage" :key="sc.key" class="space-y-1">
              <div class="flex items-center justify-between text-xs">
                <span class="text-muted-foreground">{{ sc.label }}</span>
                <span class="font-mono tabular-nums text-foreground">{{ sc.count }} / {{ totalScans }}</span>
              </div>
              <div class="h-2 w-full overflow-hidden rounded-full bg-muted">
                <div
                  :class="cn('h-full transition-all', sc.color)"
                  :style="{ width: `${sc.pct}%` }"
                />
              </div>
              <div class="text-right text-[10px] text-muted-foreground">{{ sc.pct.toFixed(0) }}% of scans</div>
            </div>
            <div class="mt-2 border-t border-border pt-2 text-[10px] text-muted-foreground">
              {{ FINDING_KIND_LABELS.misconfiguration }}, {{ FINDING_KIND_LABELS.secret }}, and
              {{ FINDING_KIND_LABELS.license }} scans produce the Findings view.
            </div>
          </CardContent>
        </Card>
      </div>
    </template>
  </div>
</template>
