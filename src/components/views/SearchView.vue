<script setup lang="ts">
import { ref, computed, watch, onMounted, onUnmounted, nextTick } from "vue";
import { useRouter } from "vue-router";
import {
  Search,
  ShieldCheck,
  Inbox,
  AlertCircle,
  Loader2,
  ArrowUpRight,
  ExternalLink,
  Bug,
} from "@lucide/vue";
import Button from "@/components/ui/Button.vue";
import Input from "@/components/ui/Input.vue";
import { Card, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
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
import { SEVERITY_ORDER, severityRank, formatNumber } from "@/lib/format";
import { cn } from "@/lib/utils";
import { SeverityBadge, PriorityBadge } from "@/components/common/Badges";
import VulnerabilityDrawer from "@/components/dashboard/VulnerabilityDrawer.vue";
import type {
  ScanListEntry,
  VulnerabilityListItem,
  Severity,
} from "@/lib/types";

const router = useRouter();

// ---- fetch scans ----
const {
  data: scanList,
  isLoading: scansLoading,
  isError: scansError,
  error: scansErr,
  refetch,
} = useApi<ScanListEntry[]>(() => api.listScans(), () => [], { refetchInterval: 30_000 });

// ---- fetch vulnerabilities per scan ----
interface IndexedRow extends VulnerabilityListItem {
  scanId: string;
  scanArtifactName: string;
}

const allRows = ref<IndexedRow[]>([]);
const rowsLoading = ref(false);
const rowsError = ref<unknown>(null);

async function loadAllRows(list: ScanListEntry[]) {
  rowsLoading.value = true;
  rowsError.value = null;
  try {
    const results = await Promise.all(
      list.map((entry) =>
        api
          .listVulnerabilities(entry.id, { pageSize: 100, sortBy: "priorityScore", sortOrder: "desc" })
          .then((res) => ({
            scanId: entry.id,
            scanArtifactName: entry.artifactName,
            rows: res.data,
          }))
          .catch(() => ({ scanId: entry.id, scanArtifactName: entry.artifactName, rows: [] as VulnerabilityListItem[] })),
      ),
    );
    const out: IndexedRow[] = [];
    for (const r of results) {
      for (const v of r.rows) {
        out.push({ ...v, scanId: r.scanId, scanArtifactName: r.scanArtifactName });
      }
    }
    allRows.value = out;
  } catch (e) {
    rowsError.value = e;
  } finally {
    rowsLoading.value = false;
  }
}

watch(
  () => scanList.value,
  (list) => {
    if (list && list.length) {
      void loadAllRows(list);
    } else {
      allRows.value = [];
    }
  },
  { immediate: true },
);

// ---- search input with 200ms debounce ----
const query = ref("");
const debouncedQuery = ref("");
let searchTimer: ReturnType<typeof setTimeout> | null = null;
const searchInputRef = ref<InstanceType<typeof Input> | HTMLInputElement | null>(null);

function onQueryInput(v: string) {
  query.value = v;
  if (searchTimer) clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    debouncedQuery.value = v.trim();
  }, 200);
}

// ---- client-side filter ----
const results = computed<IndexedRow[]>(() => {
  const q = debouncedQuery.value.toLowerCase();
  if (!q) return [];
  const filtered = allRows.value.filter((r) => {
    return (
      r.vulnerabilityId.toLowerCase().includes(q) ||
      r.pkgName.toLowerCase().includes(q) ||
      r.target.toLowerCase().includes(q) ||
      (r.title ?? "").toLowerCase().includes(q)
    );
  });
  // Sort by severity rank, then priority score desc.
  filtered.sort((a, b) => {
    const sa = severityRank(a.severity as Severity);
    const sb = severityRank(b.severity as Severity);
    if (sa !== sb) return sa - sb;
    return b.priorityScore - a.priorityScore;
  });
  // Cap at 500.
  return filtered.slice(0, 500);
});

const resultsCapped = computed(() => {
  const q = debouncedQuery.value.toLowerCase();
  if (!q) return false;
  const filtered = allRows.value.filter((r) => {
    return (
      r.vulnerabilityId.toLowerCase().includes(q) ||
      r.pkgName.toLowerCase().includes(q) ||
      r.target.toLowerCase().includes(q) ||
      (r.title ?? "").toLowerCase().includes(q)
    );
  });
  return filtered.length > 500;
});

const contributingScans = computed(() => {
  const ids = new Set<string>();
  for (const r of results.value) ids.add(r.scanId);
  return ids.size;
});

const isLoading = computed(() => scansLoading.value || rowsLoading.value);

// ---- selected vuln → drawer ----
const selectedVuln = ref<{ scanId: string; vulnId: string } | null>(null);
const drawerOpen = computed({
  get: () => !!selectedVuln.value,
  set: (v: boolean) => {
    if (!v) selectedVuln.value = null;
  },
});

function openRow(row: IndexedRow) {
  selectedVuln.value = { scanId: row.scanId, vulnId: row.id };
}

function goToScan(scanId: string) {
  router.push({ name: "dashboard", params: { scanId } });
}

// ---- autofocus on mount ----
const inputEl = ref<HTMLInputElement | null>(null);
onMounted(async () => {
  await nextTick();
  // The Input component renders a native <input>; the ref might be a wrapper.
  // Find the input via querySelector for autofocus.
  const el = document.querySelector<HTMLInputElement>('[data-search-input]');
  if (el) el.focus();
});

onUnmounted(() => {
  if (searchTimer) clearTimeout(searchTimer);
});
</script>

<template>
  <div class="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
<!-- Prominent search input -->
    <Card class="mb-4 overflow-hidden">
      <div class="relative">
        <Search class="pointer-events-none absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-muted-foreground" />
        <input
          ref="inputEl"
          data-search-input
          :value="query"
          type="text"
          placeholder="Search CVE ID (e.g. CVE-2024-…), package name (openssl), target (alpine:3.19), or title…"
          class="h-14 w-full rounded-md border-0 bg-transparent pl-12 pr-4 text-base shadow-sm focus:outline-none focus:ring-1 focus:ring-ring"
          @input="(e) => onQueryInput((e.target as HTMLInputElement).value)"
        />
      </div>
    </Card>

    <!-- Loading -->
    <Card v-if="isLoading" class="overflow-hidden">
      <div class="space-y-2 p-4">
        <Skeleton v-for="i in 8" :key="i" class="h-12 w-full" />
      </div>
    </Card>

    <!-- Scans error -->
    <Card v-else-if="scansError" class="border-destructive/40 bg-destructive/5">
      <div class="flex items-start gap-3 p-4">
        <AlertCircle class="mt-0.5 h-5 w-5 text-destructive" />
        <div class="space-y-1">
          <p class="text-sm font-medium text-destructive">Could not load scans</p>
          <p class="text-xs text-muted-foreground">
            {{ scansErr instanceof Error ? scansErr.message : "Unknown error" }}
          </p>
        </div>
        <Button class="ml-auto" variant="outline" size="sm" @click="refetch">Try again</Button>
      </div>
    </Card>

    <!-- Empty state: no scans -->
    <Card v-else-if="!scanList || scanList.length === 0" class="border-dashed">
      <div class="flex flex-col items-center justify-center px-6 py-16 text-center">
        <div class="mb-4 flex h-14 w-14 items-center justify-center rounded-full bg-muted text-muted-foreground">
          <Inbox class="h-6 w-6" />
        </div>
        <p class="text-sm font-medium text-foreground">No scans to search</p>
        <p class="mt-1 text-xs text-muted-foreground">
          Upload a Trivy JSON report or run a live scan first — its vulnerabilities will appear here.
        </p>
        <div class="mt-5 flex items-center gap-2">
          <Button size="sm" @click="router.push({ name: 'upload' })">Upload report</Button>
          <Button variant="outline" size="sm" @click="router.push({ name: 'scan' })">Run a scan</Button>
        </div>
      </div>
    </Card>

    <!-- Empty state: no query -->
    <Card v-else-if="!debouncedQuery" class="border-dashed">
      <div class="flex flex-col items-center justify-center px-6 py-16 text-center">
        <div class="mb-4 flex h-14 w-14 items-center justify-center rounded-full bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
          <ShieldCheck class="h-6 w-6" />
        </div>
        <p class="text-sm font-medium text-foreground">Start typing to search</p>
        <p class="mt-1 max-w-md text-xs text-muted-foreground">
          The search covers CVE IDs, package names, targets, and titles across every scan.
          Results are sorted by severity and priority, capped at 500 rows.
        </p>
        <div class="mt-4 flex flex-wrap justify-center gap-2 text-[11px]">
          <button
            type="button"
            class="rounded-full border border-border bg-background px-3 py-1 font-mono text-muted-foreground hover:bg-accent hover:text-foreground"
            @click="onQueryInput('CVE-2024')"
          >
            CVE-2024-…
          </button>
          <button
            type="button"
            class="rounded-full border border-border bg-background px-3 py-1 font-mono text-muted-foreground hover:bg-accent hover:text-foreground"
            @click="onQueryInput('openssl')"
          >
            openssl
          </button>
          <button
            type="button"
            class="rounded-full border border-border bg-background px-3 py-1 font-mono text-muted-foreground hover:bg-accent hover:text-foreground"
            @click="onQueryInput('alpine')"
          >
            alpine
          </button>
        </div>
      </div>
    </Card>

    <!-- Empty state: no results -->
    <Card v-else-if="results.length === 0" class="border-dashed">
      <div class="flex flex-col items-center justify-center px-6 py-16 text-center">
        <div class="mb-4 flex h-14 w-14 items-center justify-center rounded-full bg-muted text-muted-foreground">
          <Search class="h-6 w-6" />
        </div>
        <p class="text-sm font-medium text-foreground">No matches for "{{ debouncedQuery }}"</p>
        <p class="mt-1 text-xs text-muted-foreground">
          Try a different keyword — perhaps a package name, target, or CVE ID prefix.
        </p>
      </div>
    </Card>

    <!-- Results -->
    <template v-else>
      <!-- Result count + contributing scans badge -->
      <div class="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div class="flex items-center gap-2 text-sm text-muted-foreground">
          <span>
            <span class="font-semibold text-foreground">{{ formatNumber(results.length) }}</span>
            {{ results.length === 1 ? "match" : "matches" }}
            <span v-if="resultsCapped" class="text-amber-600 dark:text-amber-400"> (capped at 500)</span>
          </span>
          <Badge variant="secondary" class="font-mono">
            {{ contributingScans }} scan{{ contributingScans === 1 ? "" : "s" }}
          </Badge>
        </div>
        <Button variant="ghost" size="sm" @click="onQueryInput('')">
          Clear
        </Button>
      </div>

      <!-- Results table -->
      <Card class="overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow class="bg-muted/40 hover:bg-muted/40">
              <TableHead class="w-[110px]">Severity</TableHead>
              <TableHead class="w-[240px]">CVE</TableHead>
              <TableHead class="w-[200px]">Package</TableHead>
              <TableHead class="w-[120px]">Installed</TableHead>
              <TableHead class="w-[120px]">Fixed</TableHead>
              <TableHead class="w-[80px]">Priority</TableHead>
              <TableHead class="w-[200px]">Scan</TableHead>
              <TableHead>Target</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            <TableRow
              v-for="row in results"
              :key="`${row.scanId}:${row.id}`"
              class="cursor-pointer"
              @click="openRow(row)"
            >
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
                  <span class="truncate font-mono text-xs text-foreground" :title="row.pkgName">{{ row.pkgName }}</span>
                  <span v-if="row.type" class="text-[10px] text-muted-foreground">{{ row.type }}</span>
                </div>
              </TableCell>
              <TableCell>
                <span v-if="row.installedVersion" class="font-mono text-xs text-foreground">{{ row.installedVersion }}</span>
                <span v-else class="text-xs text-muted-foreground">—</span>
              </TableCell>
              <TableCell>
                <span v-if="row.fixedVersion" class="font-mono text-xs text-emerald-600 dark:text-emerald-400">
                  {{ row.fixedVersion }}
                </span>
                <span v-else class="text-xs text-muted-foreground">—</span>
              </TableCell>
              <TableCell>
                <PriorityBadge :level="row.priorityLevel" />
              </TableCell>
              <TableCell>
                <button
                  type="button"
                  class="inline-flex items-center gap-1.5 rounded-md border border-border bg-background px-2 py-1 text-[11px] hover:bg-accent hover:text-accent-foreground"
                  :title="`Open dashboard for ${row.scanArtifactName}`"
                  @click.stop="goToScan(row.scanId)"
                >
                  <Bug class="h-3 w-3 text-muted-foreground" />
                  <span class="truncate font-medium text-foreground" style="max-width: 140px">{{ row.scanArtifactName }}</span>
                  <ArrowUpRight class="h-3 w-3 text-muted-foreground" />
                </button>
              </TableCell>
              <TableCell>
                <span class="block max-w-[200px] truncate font-mono text-[11px] text-muted-foreground" :title="row.target">
                  {{ row.target }}
                </span>
              </TableCell>
            </TableRow>
          </TableBody>
        </Table>
      </Card>
    </template>

    <!-- Vulnerability drawer -->
    <VulnerabilityDrawer
      v-if="selectedVuln"
      :scan-id="selectedVuln.scanId"
      :vuln-id="selectedVuln.vulnId"
      :open="drawerOpen"
      @update:open="(v) => { if (!v) selectedVuln = null }"
    />
  </div>
</template>
