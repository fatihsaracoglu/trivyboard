<script setup lang="ts">
import { ref, computed } from "vue";
import { Search, ArrowUpDown, ArrowUp, ArrowDown, Package as PackageIcon, AlertCircle, Loader2 } from "@lucide/vue";
import Button from "@/components/ui/Button.vue";
import Input from "@/components/ui/Input.vue";
import { Card } from "@/components/ui/card";
import { Badge, Skeleton, Progress } from "@/components/ui/primitives";
import {
  Table, TableHeader, TableBody, TableRow, TableHead, TableCell,
} from "@/components/ui/table";
import { useApi } from "@/composables/useApi";
import { api } from "@/lib/api";
import { formatNumber, SEVERITY_BG, priorityLevelFromScore } from "@/lib/format";
import { cn } from "@/lib/utils";
import { PriorityBadge } from "@/components/common/Badges";
import type { PackagesResponse, Severity, SeverityCounts } from "@/lib/types";

const props = defineProps<{ scanId: string }>();

type SortField = "package" | "occurrences" | "priorityScore";
type SortOrder = "asc" | "desc";

const search = ref("");
const sortBy = ref<SortField>("priorityScore");
const sortOrder = ref<SortOrder>("desc");
const limit = ref(100);

// Debounce search input so we don't fire one request per keystroke.
let searchTimer: ReturnType<typeof setTimeout> | null = null;
const debouncedSearch = ref("");
function onSearchInput(v: string) {
  search.value = v;
  if (searchTimer) clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    debouncedSearch.value = v;
  }, 200);
}

const { data, isLoading, isError, error, isFetching } = useApi<PackagesResponse>(
  () => api.listPackages(props.scanId, {
    search: debouncedSearch.value || undefined,
    sortBy: sortBy.value,
    sortOrder: sortOrder.value,
    limit: limit.value,
  }),
  () => [debouncedSearch.value, sortBy.value, sortOrder.value, limit.value, props.scanId],
);

const rows = computed(() => data.value?.data ?? []);

const SEVS: Array<{ key: keyof SeverityCounts; label: string; code: Severity }> = [
  { key: "critical", label: "C", code: "CRITICAL" },
  { key: "high", label: "H", code: "HIGH" },
  { key: "medium", label: "M", code: "MEDIUM" },
  { key: "low", label: "L", code: "LOW" },
  { key: "unknown", label: "U", code: "UNKNOWN" },
];

function toggleSort(field: SortField) {
  if (sortBy.value === field) {
    sortOrder.value = sortOrder.value === "asc" ? "desc" : "asc";
  } else {
    sortBy.value = field;
    sortOrder.value = field === "package" ? "asc" : "desc";
  }
}

function sortIcon(field: SortField) {
  if (sortBy.value !== field) return ArrowUpDown;
  return sortOrder.value === "asc" ? ArrowUp : ArrowDown;
}

function priorityScorePct(score: number): number {
  // priorityScore range is roughly 0–150; normalize to 0–100 for the Progress bar.
  return Math.min(100, Math.max(0, (score / 150) * 100));
}
</script>

<template>
  <div class="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
    <!-- Filters -->
<!-- Loading -->
    <Card v-if="isLoading" class="overflow-hidden">
      <div class="space-y-2 p-4">
        <Skeleton v-for="i in 8" :key="i" class="h-12 w-full" />
      </div>
    </Card>

    <!-- Error -->
    <Card v-else-if="isError" class="border-destructive/40 bg-destructive/5">
      <div class="flex items-start gap-3 p-4">
        <AlertCircle class="mt-0.5 h-5 w-5 text-destructive" />
        <div class="space-y-1">
          <p class="text-sm font-medium text-destructive">Failed to load packages</p>
          <p class="text-xs text-muted-foreground">
            {{ error instanceof Error ? error.message : "Unknown error" }}
          </p>
        </div>
      </div>
    </Card>

    <!-- Empty -->
    <Card v-else-if="!rows.length" class="border-dashed">
      <div class="flex flex-col items-center justify-center px-6 py-16 text-center">
        <div class="mb-4 flex h-14 w-14 items-center justify-center rounded-full bg-muted text-muted-foreground">
          <PackageIcon class="h-6 w-6" />
        </div>
        <p class="text-sm font-medium text-foreground">
          {{ search ? "No packages match your filter" : "No packages in this scan" }}
        </p>
        <p class="mt-1 text-xs text-muted-foreground">
          {{ search ? "Try clearing the search box." : "Run a scan that produces package vulnerabilities." }}
        </p>
      </div>
    </Card>

    <!-- Table -->
    <Card v-else class="overflow-hidden">
      <Table>
        <TableHeader>
          <TableRow class="bg-muted/40 hover:bg-muted/40">
            <TableHead>
              <button
                type="button"
                class="inline-flex items-center gap-1 text-xs font-medium uppercase tracking-wider hover:text-foreground"
                @click="toggleSort('package')"
              >
                Package
                <component :is="sortIcon('package')" class="h-3 w-3" />
              </button>
            </TableHead>
            <TableHead class="w-[100px] text-right">
              <button
                type="button"
                class="inline-flex items-center gap-1 text-xs font-medium uppercase tracking-wider hover:text-foreground"
                @click="toggleSort('occurrences')"
              >
                Occurrences
                <component :is="sortIcon('occurrences')" class="h-3 w-3" />
              </button>
            </TableHead>
            <TableHead class="w-[200px]">Severity</TableHead>
            <TableHead class="w-[90px] text-right">Fixable</TableHead>
            <TableHead class="w-[180px]">
              <button
                type="button"
                class="inline-flex items-center gap-1 text-xs font-medium uppercase tracking-wider hover:text-foreground"
                @click="toggleSort('priorityScore')"
              >
                Priority
                <component :is="sortIcon('priorityScore')" class="h-3 w-3" />
              </button>
            </TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow v-for="pkg in rows" :key="pkg.package">
            <TableCell>
              <div class="flex flex-col gap-0.5">
                <span class="font-mono text-sm text-foreground">{{ pkg.package }}</span>
                <span class="text-[11px] text-muted-foreground">
                  {{ pkg.targets.length }} {{ pkg.targets.length === 1 ? "target" : "targets" }}
                </span>
              </div>
            </TableCell>
            <TableCell class="text-right font-mono text-sm tabular-nums">
              {{ formatNumber(pkg.occurrences) }}
            </TableCell>
            <TableCell>
              <div class="flex flex-wrap items-center gap-1">
                <template v-for="s in SEVS" :key="s.key">
                  <span
                    v-if="pkg.severity[s.key] > 0"
                    :class="cn('inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[10px] font-medium', SEVERITY_BG[s.code])"
                    :title="`${s.code}: ${pkg.severity[s.key]}`"
                  >
                    {{ s.label }}{{ pkg.severity[s.key] }}
                  </span>
                </template>
                <span
                  v-if="!pkg.severity.critical && !pkg.severity.high && !pkg.severity.medium && !pkg.severity.low && !pkg.severity.unknown"
                  class="text-xs text-muted-foreground"
                >
                  —
                </span>
              </div>
            </TableCell>
            <TableCell class="text-right">
              <Badge v-if="pkg.fixable > 0" variant="secondary" class="font-mono tabular-nums">
                {{ pkg.fixable }}
              </Badge>
              <span v-else class="text-xs text-muted-foreground">—</span>
            </TableCell>
            <TableCell>
              <div class="flex items-center gap-2">
                <Progress :value="priorityScorePct(pkg.priorityScore)" class="h-1.5 flex-1" />
                <span class="font-mono text-xs tabular-nums text-foreground">
                  {{ pkg.priorityScore }}
                </span>
                <PriorityBadge :level="priorityLevelFromScore(pkg.priorityScore)" />
              </div>
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>
    </Card>
  </div>
</template>
