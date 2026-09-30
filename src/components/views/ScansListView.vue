<script setup lang="ts">
// ScansListView — history table of every uploaded or trivy-run scan.
// Auto-refreshes every 15s. Click a row → open dashboard. Delete with confirm dialog.
import { ref, computed } from "vue";
import { useRouter } from "vue-router";
import {
  FileJson,
  Trash2,
  ExternalLink,
  Inbox,
  RefreshCw,
  AlertCircle,
  Loader2,
  Flame,
  Container,
  FolderTree,
  GitBranch,
} from "@lucide/vue";
import Button from "@/components/ui/Button.vue";
import ConfirmDialog from "@/components/ui/ConfirmDialog.vue";
import { Card } from "@/components/ui/card";
import { Badge, Skeleton } from "@/components/ui/primitives";
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "@/components/ui/table";
import { useApi, useMutation } from "@/composables/useApi";
import { useToast } from "@/composables/useToast";
import { api } from "@/lib/api";
import { formatNumber, formatRelativeTime, ARTIFACT_TYPE_LABELS } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { ScanListEntry, ScanSource } from "@/lib/types";

const router = useRouter();
const { toast } = useToast();

const { data, isLoading, isError, error, isFetching, refetch } = useApi<ScanListEntry[]>(
    () => api.listScans(),
    () => [],
    { refetchInterval: 15_000 },
);

const deleteMutation = useMutation((id: string) => api.deleteScan(id));

// Delete dialog state
const deleteTarget = ref<ScanListEntry | null>(null);
const isDeleting = ref(false);

const sorted = computed<ScanListEntry[]>(() => {
  if (!data.value) return [];
  return [...data.value].sort((a, b) => b.uploadedAt - a.uploadedAt);
});

function openDashboard(scanId: string) {
  router.push({ name: "dashboard", params: { scanId } });
}

function requestDelete(entry: ScanListEntry) {
  deleteTarget.value = entry;
}

function cancelDelete() {
  deleteTarget.value = null;
}

async function confirmDelete() {
  const entry = deleteTarget.value;
  if (!entry) return;
  isDeleting.value = true;
  const result = await deleteMutation.mutate(entry.id);
  isDeleting.value = false;
  deleteTarget.value = null;
  if (result !== null) {
    toast.success("Scan deleted", {
      description: `${entry.artifactName} (${entry.filename})`,
    });
    await refetch();
  } else {
    toast.error("Could not delete scan", {
      description: deleteMutation.error.value instanceof Error
          ? deleteMutation.error.value.message
          : "Unknown error",
    });
  }
}

function artifactTypeLabel(t: string | null): string {
  if (!t) return "—";
  return ARTIFACT_TYPE_LABELS[t] ?? t;
}

// Resolve the source type for a list entry. New entries from the backend
// carry `sourceType` directly; older entries (or a backend that hasn't
// been upgraded yet) fall back to the filename heuristic so the icon +
// badge keep working.
function resolveSourceType(entry: ScanListEntry): ScanSource {
  if (entry.sourceType) return entry.sourceType;
  if (/^trivy-(image)-/.test(entry.filename)) return "docker-image";
  if (/^trivy-(fs)-/.test(entry.filename)) return "filesystem";
  if (/^trivy-(repo)-/.test(entry.filename)) return "git-local";
  return "trivy-json";
}

const SOURCE_ICON: Record<ScanSource, typeof FileJson> = {
  "trivy-json": FileJson,
  "docker-image": Container,
  "filesystem": FolderTree,
  "git-local": GitBranch,
  "git-remote": GitBranch,
};

const SOURCE_LABEL: Record<ScanSource, string> = {
  "trivy-json": "Upload",
  "docker-image": "Docker",
  "filesystem": "FS",
  "git-local": "Git (local)",
  "git-remote": "Git (remote)",
};

const SOURCE_ICON_CLASS: Record<ScanSource, string> = {
  "trivy-json": "bg-muted text-muted-foreground",
  "docker-image": "bg-primary/10 text-primary",
  "filesystem": "bg-primary/10 text-primary",
  "git-local": "bg-primary/10 text-primary",
  "git-remote": "bg-primary/10 text-primary",
};
</script>

<template>
  <div class="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
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
          <p class="text-sm font-medium text-destructive">Could not load scans</p>
          <p class="text-xs text-muted-foreground">
            {{ error instanceof Error ? error.message : "Unknown error" }}
          </p>
        </div>
        <Button class="ml-auto" variant="outline" size="sm" @click="refetch">Try again</Button>
      </div>
    </Card>

    <!-- Empty state -->
    <Card v-else-if="!sorted.length" class="border-dashed">
      <div class="flex flex-col items-center justify-center px-6 py-16 text-center">
        <div class="mb-4 flex h-14 w-14 items-center justify-center rounded-full bg-muted text-muted-foreground">
          <Inbox class="h-6 w-6" />
        </div>
        <p class="text-sm font-medium text-foreground">No scans yet</p>
        <p class="mt-1 text-xs text-muted-foreground">
          Upload a Trivy JSON report or run a live scan to populate this list.
        </p>
        <div class="mt-5 flex items-center gap-2">
          <Button size="sm" @click="router.push({ name: 'upload' })">Upload report</Button>
          <Button variant="outline" size="sm" @click="router.push({ name: 'scan' })">Run a scan</Button>
        </div>
      </div>
    </Card>

    <!-- Table -->
    <Card v-else class="overflow-hidden">
      <div class="flex items-center justify-between border-b border-border bg-muted/30 px-4 py-2">
        <span class="text-xs text-muted-foreground">{{ data?.length ?? 0 }} scans · auto-refreshes every 15s</span>
        <Button variant="ghost" size="sm" class="h-7 gap-1.5 text-xs" @click="refetch" :disabled="isFetching">
          <RefreshCw :class="cn('h-3.5 w-3.5', isFetching && 'animate-spin')" />
          Refresh
        </Button>
      </div>
      <Table>
        <TableHeader>
          <TableRow class="bg-muted/40 hover:bg-muted/40">
            <TableHead class="w-[44px]"></TableHead>
            <TableHead>Artifact</TableHead>
            <TableHead class="w-[110px] text-left">Source</TableHead>
            <TableHead class="w-[140px] text-left">Type</TableHead>
            <TableHead class="w-[90px] text-right">Vulns</TableHead>
            <TableHead class="w-[110px] text-right">Critical</TableHead>
            <TableHead class="w-[140px] text-right">Uploaded</TableHead>
            <TableHead class="w-[140px] pr-4 text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          <TableRow
              v-for="entry in sorted"
              :key="entry.id"
              class="cursor-pointer"
              @click="openDashboard(entry.id)"
          >
            <TableCell>
              <div
                  :class="cn(
                  'flex h-8 w-8 items-center justify-center rounded-md',
                  SOURCE_ICON_CLASS[resolveSourceType(entry)],
                )"
              >
                <component :is="SOURCE_ICON[resolveSourceType(entry)]" class="h-4 w-4" />
              </div>
            </TableCell>
            <TableCell>
              <div class="flex flex-col gap-0.5">
                <span class="text-sm font-medium text-foreground">{{ entry.artifactName }}</span>
                <span class="font-mono text-[11px] text-muted-foreground">{{ entry.filename }}</span>
              </div>
            </TableCell>
            <TableCell>
              <Badge variant="outline" class="font-normal">
                {{ SOURCE_LABEL[resolveSourceType(entry)] }}
              </Badge>
            </TableCell>
            <TableCell>
              <Badge variant="outline" class="font-normal">
                {{ artifactTypeLabel(entry.artifactType) }}
              </Badge>
            </TableCell>
            <TableCell class="text-right font-mono text-sm tabular-nums">
              {{ formatNumber(entry.totalVulnerabilities) }}
            </TableCell>
            <TableCell class="text-right">
              <Badge
                  v-if="entry.critical > 0"
                  variant="destructive"
                  class="font-mono tabular-nums text-white"
              >
                <Flame class="h-3 w-3" />
                {{ entry.critical }}
              </Badge>
              <span v-else class="text-xs text-muted-foreground">0</span>
            </TableCell>
            <TableCell class="text-xs text-muted-foreground text-right pr-4">
              {{ formatRelativeTime(entry.uploadedAt) }}
            </TableCell>
            <TableCell class="text-right pr-4">
              <div class="flex items-center justify-end gap-1">
                <Button
                    variant="ghost"
                    size="icon"
                    class="h-8 w-8"
                    title="Open dashboard"
                    @click.stop="openDashboard(entry.id)"
                >
                  <ExternalLink class="h-3.5 w-3.5" />
                </Button>
                <Button
                    variant="ghost"
                    size="icon"
                    class="h-8 w-8 text-muted-foreground hover:text-destructive"
                    title="Delete scan"
                    @click.stop="requestDelete(entry)"
                >
                  <Trash2 class="h-3.5 w-3.5" />
                </Button>
              </div>
            </TableCell>
          </TableRow>
        </TableBody>
      </Table>
    </Card>

    <!-- Delete confirmation dialog -->
    <ConfirmDialog
        :open="!!deleteTarget"
        title="Delete scan"
        :message="deleteTarget ? `Delete ${deleteTarget.artifactName} (${deleteTarget.filename})? This action cannot be undone.` : ''"
        confirm-label="Delete"
        variant="destructive"
        :loading="isDeleting"
        @confirm="confirmDelete"
        @cancel="cancelDelete"
    />
  </div>
</template>
