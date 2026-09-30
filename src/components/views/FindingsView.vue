<script setup lang="ts">
import { ref, computed } from "vue";
import {
  Search,
  ChevronLeft,
  ChevronRight,
  AlertCircle,
  ShieldAlert,
  KeyRound,
  ScrollText,
  FileWarning,
  Loader2,
} from "@lucide/vue";
import Button from "@/components/ui/Button.vue";
import Input from "@/components/ui/Input.vue";
import Select from "@/components/ui/Select.vue";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/primitives";
import {
  Table, TableHeader, TableBody, TableRow, TableHead, TableCell,
} from "@/components/ui/table";
import { useApi } from "@/composables/useApi";
import { api } from "@/lib/api";
import { formatNumber, FINDING_KIND_LABELS, safeUrl } from "@/lib/format";
import { cn } from "@/lib/utils";
import { SeverityBadge, FindingKindBadge } from "@/components/common/Badges";
import type { FindingsResponse, FindingRow, FindingSummaryItem, FindingKind } from "@/lib/types";

const props = defineProps<{ scanId: string }>();

const search = ref("");
const kindFilter = ref<string>("all"); // "all" | FindingKind
const page = ref(1);
const pageSize = ref(20);

// Debounced search; resets to page 1 on change.
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
function onKindChange(v: string) {
  kindFilter.value = v;
  page.value = 1;
}

const { data, isLoading, isError, error, isFetching } = useApi<FindingsResponse>(
  () => api.listFindings(props.scanId, {
    page: page.value,
    pageSize: pageSize.value,
    search: debouncedSearch.value || undefined,
    type: kindFilter.value !== "all" ? kindFilter.value : undefined,
  }),
  () => [props.scanId, page.value, pageSize.value, debouncedSearch.value, kindFilter.value],
);

const rows = computed<FindingRow[]>(() => data.value?.data ?? []);
const summary = computed<FindingSummaryItem[]>(() => data.value?.summary ?? []);
const pagination = computed(() => data.value?.pagination);
const totalPages = computed(() => pagination.value?.totalPages ?? 1);

const SUMMARY_META: Record<FindingKind, { icon: typeof ShieldAlert; accent: string }> = {
  misconfiguration: { icon: ShieldAlert, accent: "text-purple-500" },
  secret: { icon: KeyRound, accent: "text-pink-500" },
  license: { icon: ScrollText, accent: "text-cyan-500" },
};

const KINDS: FindingKind[] = ["misconfiguration", "secret", "license"];

function summaryFor(kind: FindingKind): FindingSummaryItem | undefined {
  return summary.value.find((s) => s.kind === kind);
}

function goPrev() {
  if (page.value > 1) page.value--;
}
function goNext() {
  if (page.value < totalPages.value) page.value++;
}

function locationText(row: FindingRow): string {
  if (row.file && row.startLine) {
    return `${row.file}:${row.startLine}${row.endLine && row.endLine !== row.startLine ? `-${row.endLine}` : ""}`;
  }
  if (row.file) return row.file;
  return row.target;
}
</script>

<template>
  <div class="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
<!-- Summary cards -->
    <div class="mb-5 grid grid-cols-1 gap-3 sm:grid-cols-3">
      <Card
        v-for="kind in KINDS"
        :key="kind"
        :class="cn(
          'overflow-hidden',
          kindFilter === kind && 'border-primary ring-1 ring-primary/30',
        )"
      >
        <button
          type="button"
          class="flex w-full items-center justify-between p-4 text-left focus:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          @click="onKindChange(kindFilter === kind ? 'all' : kind)"
        >
          <div class="flex items-center gap-3">
            <div :class="cn('flex h-10 w-10 items-center justify-center rounded-md bg-muted', SUMMARY_META[kind].accent)">
              <component :is="SUMMARY_META[kind].icon" class="h-5 w-5" />
            </div>
            <div class="space-y-0.5">
              <div class="text-xs uppercase tracking-wider text-muted-foreground">
                {{ FINDING_KIND_LABELS[kind] }}
              </div>
              <div class="font-mono text-2xl font-semibold tabular-nums text-foreground">
                {{ summaryFor(kind) ? formatNumber(summaryFor(kind)!.count) : "0" }}
              </div>
            </div>
          </div>
          <div class="flex flex-col items-end gap-1 text-right text-[10px] text-muted-foreground">
            <span
              v-if="summaryFor(kind) && summaryFor(kind)!.severity.critical > 0"
              class="rounded bg-red-500/15 px-1.5 py-0.5 font-mono text-red-700 dark:text-red-300"
            >
              {{ summaryFor(kind)!.severity.critical }} crit
            </span>
            <span
              v-if="summaryFor(kind) && summaryFor(kind)!.severity.high > 0"
              class="rounded bg-orange-500/15 px-1.5 py-0.5 font-mono text-orange-700 dark:text-orange-300"
            >
              {{ summaryFor(kind)!.severity.high }} high
            </span>
          </div>
        </button>
      </Card>
    </div>

    <!-- Filters -->
    <div class="mb-4 flex flex-col gap-2 sm:flex-row sm:items-center">
      <div class="relative flex-1">
        <Search class="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
        <Input
          :model-value="search"
          placeholder="Filter by title, message, source id, target…"
          class="pl-8"
          @update:model-value="onSearchInput"
        />
      </div>
      <div class="flex items-center gap-2">
        <span class="text-xs text-muted-foreground">Kind</span>
        <Select :model-value="kindFilter" class="w-44" @update:model-value="onKindChange">
          <option value="all">All kinds</option>
          <option v-for="k in KINDS" :key="k" :value="k">{{ FINDING_KIND_LABELS[k] }}</option>
        </Select>
      </div>
    </div>

    <!-- Loading -->
    <Card v-if="isLoading" class="overflow-hidden">
      <div class="space-y-2 p-4">
        <Skeleton v-for="i in 5" :key="i" class="h-12 w-full" />
      </div>
    </Card>

    <!-- Error -->
    <Card v-else-if="isError" class="border-destructive/40 bg-destructive/5">
      <div class="flex items-start gap-3 p-4">
        <AlertCircle class="mt-0.5 h-5 w-5 text-destructive" />
        <div class="space-y-1">
          <p class="text-sm font-medium text-destructive">Failed to load findings</p>
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
          <FileWarning class="h-6 w-6" />
        </div>
        <p class="text-sm font-medium text-foreground">
          {{ search || kindFilter !== "all" ? "No findings match your filters" : "No findings in this scan" }}
        </p>
        <p class="mt-1 text-xs text-muted-foreground">
          {{ search || kindFilter !== "all" ? "Try adjusting the filters above." : "Run a scan with --scanners misconfig,secret,license to populate this view." }}
        </p>
      </div>
    </Card>

    <!-- Table -->
    <Card v-else class="overflow-hidden">
      <Table>
        <TableHeader>
          <TableRow class="bg-muted/40 hover:bg-muted/40">
            <TableHead class="w-[120px]">Kind</TableHead>
            <TableHead class="w-[110px]">Severity</TableHead>
            <TableHead>Title & message</TableHead>
            <TableHead class="w-[260px]">Target</TableHead>
            <TableHead class="w-[160px]">Source ID</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow v-for="row in rows" :key="row.id">
            <TableCell>
              <FindingKindBadge :kind="row.kind" />
            </TableCell>
            <TableCell>
              <SeverityBadge v-if="row.severity" :severity="row.severity" />
              <span v-else class="text-xs text-muted-foreground">—</span>
            </TableCell>
            <TableCell>
              <div class="flex flex-col gap-0.5">
                <span class="text-sm font-medium text-foreground">
                  {{ row.title || row.sourceId || "Untitled finding" }}
                </span>
                <span v-if="row.message" class="text-xs text-muted-foreground line-clamp-2">
                  {{ row.message }}
                </span>
                <div v-if="row.references && row.references.length" class="mt-1 flex flex-wrap gap-1">
                  <a
                    v-for="(ref, i) in row.references.slice(0, 2)"
                    :key="i"
                    :href="safeUrl(ref) ?? '#'"
                    target="_blank"
                    rel="noopener noreferrer"
                    class="text-[10px] text-primary underline-offset-2 hover:underline"
                    @click.stop
                  >
                    ref {{ i + 1 }}
                  </a>
                  <span v-if="row.references.length > 2" class="text-[10px] text-muted-foreground">
                    +{{ row.references.length - 2 }}
                  </span>
                </div>
              </div>
            </TableCell>
            <TableCell>
              <div class="flex flex-col gap-0.5">
                <span class="truncate font-mono text-[11px] text-foreground" :title="row.target">
                  {{ row.target }}
                </span>
                <span v-if="row.file" class="truncate font-mono text-[10px] text-muted-foreground" :title="locationText(row)">
                  {{ locationText(row) }}
                </span>
                <span v-if="row.packageName" class="text-[10px] text-muted-foreground">
                  pkg: <span class="font-mono">{{ row.packageName }}</span>
                  <span v-if="row.installedVersion" class="font-mono"> @ {{ row.installedVersion }}</span>
                </span>
              </div>
            </TableCell>
            <TableCell>
              <span v-if="row.sourceId" class="font-mono text-[11px] text-muted-foreground">
                {{ row.sourceId }}
              </span>
              <span v-else class="text-xs text-muted-foreground">—</span>
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>

      <!-- Pagination -->
      <div v-if="pagination" class="flex items-center justify-between border-t border-border px-3 py-2 text-xs text-muted-foreground">
        <div>
          {{ formatNumber((pagination.page - 1) * pagination.pageSize + (rows.length ? 1 : 0)) }} –
          {{ formatNumber((pagination.page - 1) * pagination.pageSize + rows.length) }}
          of {{ formatNumber(pagination.total) }}
        </div>
        <div class="flex items-center gap-2">
          <Button
            variant="outline"
            size="icon"
            class="h-7 w-7"
            :disabled="page <= 1"
            @click="goPrev"
          >
            <ChevronLeft class="h-3.5 w-3.5" />
          </Button>
          <span class="font-mono tabular-nums">
            {{ pagination.page }} / {{ Math.max(1, pagination.totalPages) }}
          </span>
          <Button
            variant="outline"
            size="icon"
            class="h-7 w-7"
            :disabled="page >= totalPages"
            @click="goNext"
          >
            <ChevronRight class="h-3.5 w-3.5" />
          </Button>
        </div>
      </div>
    </Card>
  </div>
</template>
