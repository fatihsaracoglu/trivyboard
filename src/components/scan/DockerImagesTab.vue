<script setup lang="ts">
import { ref, computed } from "vue";
import { useRouter } from "vue-router";
import { api } from "@/lib/api";
import { useApi } from "@/composables/useApi";
import { useScanJob } from "@/composables/useScanJob";
import { useToast } from "@/composables/useToast";
import { useUiStore } from "@/stores/ui";
import { cn } from "@/lib/utils";
import { formatBytes, formatRelativeTime } from "@/lib/format";
import Button from "@/components/ui/Button.vue";
import Input from "@/components/ui/Input.vue";
import Checkbox from "@/components/ui/Checkbox.vue";
import { Label } from "@/components/ui/primitives";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/primitives";
import ScanProgressPanel from "./ScanProgressPanel.vue";
import {
  Container,
  Loader2,
  RefreshCw,
  ScanLine,
  Search,
  AlertTriangle,
  Layers,
  XCircle,
} from "@lucide/vue";

const router = useRouter();
const toast = useToast();
const ui = useUiStore();

const search = ref("");
const selected = ref<string | null>(null);
const scanners = ref<string[]>(["vuln"]);

const imagesQuery = useApi(
    () => api.listDockerImages(),
    () => [],
    { refetchInterval: 0 },
);

const filtered = computed(() => {
  const list = imagesQuery.data.value?.data ?? [];
  if (!search.value) return list;
  const q = search.value.toLowerCase();
  return list.filter((img) =>
      (img.repoTags ?? []).some((t) => t.toLowerCase().includes(q)) ||
      img.shortId?.toLowerCase().includes(q),
  );
});

const scanJob = useScanJob({
  onComplete: (job) => {
    toast.toast.success("Scan complete", {
      description: `Job ${job.id}`,
    });
    const id = job.scanId ?? job.id;
    ui.openScan(id, "dashboard");
    router.push({ name: "dashboard", params: { scanId: id } });
  },
  onFailed: (job) => {
    toast.toast.error("Scan failed", {
      description: job.error || "Trivy scan did not complete successfully.",
    });
  },
  onCancelled: () => {
    toast.toast.info("Scan cancelled");
  },
});

async function doScan() {
  const img = (imagesQuery.data.value?.data ?? []).find((i) => i.id === selected.value);
  const value = img?.repoDigests?.[0] ?? img?.repoTags?.[0] ?? img?.shortId ?? selected.value ?? "";
  await scanJob.startScan({
    target: "image",
    value,
    scanners: scanners.value.length ? scanners.value : undefined,
  });
}

async function cancelScan() {
  await scanJob.cancelScan();
}

function toggleScanner(id: string) {
  scanners.value = scanners.value.includes(id)
      ? scanners.value.filter((s) => s !== id)
      : [...scanners.value, id];
}

const SCANNER_OPTIONS = [
  { id: "vuln", label: "Vulnerabilities" },
  { id: "misconfig", label: "Misconfigurations" },
  { id: "secret", label: "Secrets" },
  { id: "license", label: "Licenses" },
];
</script>

<template>
  <div class="space-y-4">
    <Card>
      <CardHeader class="pb-3">
        <div class="flex items-center justify-between gap-2">
          <div>
            <CardTitle class="text-base flex items-center gap-2">
              <Layers class="h-4 w-4 text-emerald-500" />
              Local Docker images
            </CardTitle>
            <CardDescription class="mt-1 text-xs">
              <span v-if="imagesQuery.data.value?.source === 'unavailable'" class="inline-flex items-center gap-1.5 text-yellow-600 dark:text-yellow-400">
                <AlertTriangle class="h-3.5 w-3.5" />
                Docker daemon is not running. Install Docker or start the daemon to list and scan images.
              </span>
              <span v-else-if="imagesQuery.data.value?.source === 'empty'" class="inline-flex items-center gap-1.5 text-muted-foreground">
                <Container class="h-3.5 w-3.5" />
                Docker daemon is running but no images found. Pull an image first (e.g. <code class="font-mono">docker pull alpine:3.19</code>).
              </span>
              <span v-else class="inline-flex items-center gap-1.5 text-emerald-600 dark:text-emerald-400">
                <span class="h-1.5 w-1.5 rounded-full bg-emerald-500" />
                Docker daemon is running.
              </span>
            </CardDescription>
          </div>
          <Button variant="outline" size="sm" @click="imagesQuery.refetch()" :disabled="imagesQuery.isFetching.value">
            <RefreshCw :class="cn('mr-1.5 h-3.5 w-3.5', imagesQuery.isFetching.value && 'animate-spin')" />
            Refresh
          </Button>
        </div>
      </CardHeader>
      <CardContent class="space-y-3">
        <div class="relative">
          <Search class="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input v-model="search" placeholder="Filter by tag or id…" class="pl-8" />
        </div>

        <div v-if="imagesQuery.isLoading.value" class="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
          <Skeleton v-for="i in 6" :key="i" class="h-20 rounded-lg" />
        </div>
        <div v-else-if="imagesQuery.isError.value" class="rounded-md border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive">
          Failed to load images. {{ String(imagesQuery.error.value) }}
        </div>
        <div v-else-if="filtered.length === 0" class="rounded-md border border-dashed border-border p-6 text-center text-sm text-muted-foreground">
          No images match your filter.
        </div>
        <div v-else class="grid max-h-[460px] gap-2 overflow-y-auto pr-1 sm:grid-cols-2 lg:grid-cols-3">
          <button
              v-for="img in filtered"
              :key="img.id"
              type="button"
              @click="selected = img.id"
              :disabled="scanJob.isPending.value"
              :class="cn(
              'group flex flex-col gap-2 rounded-lg border p-3 text-left transition-colors',
              selected === img.id
                ? 'border-emerald-500 bg-emerald-500/5'
                : 'border-border bg-background hover:border-emerald-500/40 hover:bg-emerald-500/5',
              scanJob.isPending.value && 'cursor-not-allowed opacity-50',
            )"
          >
            <div class="flex items-start justify-between gap-2">
              <div class="flex items-center gap-2 min-w-0">
                <Container class="h-4 w-4 shrink-0 text-emerald-500" />
                <span class="truncate text-sm font-medium" :title="img.repoTags?.[0] ?? 'untagged'">
                  {{ img.repoTags?.[0] ?? 'untagged' }}
                </span>
              </div>
              <span v-if="selected === img.id" class="rounded bg-emerald-500 px-1.5 py-0.5 text-[10px] font-medium text-white">selected</span>
            </div>
            <div class="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-muted-foreground">
              <span>{{ formatBytes(img.size) }}</span>
              <span class="text-muted-foreground/40">·</span>
              <span>{{ formatRelativeTime(img.created * 1000) }}</span>
            </div>
            <div v-if="img.repoDigests?.[0]" class="truncate text-[10px] font-mono text-muted-foreground/70" :title="img.repoDigests[0]">
              {{ img.repoDigests[0] }}
            </div>
          </button>
        </div>
      </CardContent>
    </Card>

    <Card>
      <CardHeader class="pb-3">
        <CardTitle class="text-base">Scan options</CardTitle>
        <CardDescription class="text-xs">Choose which scanners to run. At least one is recommended.</CardDescription>
      </CardHeader>
      <CardContent class="space-y-3">
        <div class="grid grid-cols-2 gap-2 sm:grid-cols-4">
          <div v-for="opt in SCANNER_OPTIONS" :key="opt.id" class="flex items-center gap-2">
            <Checkbox :id="`scanner-${opt.id}`" :model-value="scanners.includes(opt.id)" @update:model-value="toggleScanner(opt.id)" />
            <Label :for="`scanner-${opt.id}`">{{ opt.label }}</Label>
          </div>
        </div>
        <div class="flex items-center justify-between gap-2 rounded-md border border-border bg-muted/30 p-3">
          <div class="flex flex-col gap-1.5 text-xs text-muted-foreground">
            <div>
              <span v-if="selected">
                Ready to scan <code class="font-mono">{{ (imagesQuery.data.value?.data ?? []).find(i => i.id === selected)?.repoTags?.[0] ?? selected }}</code>.
              </span>
              <span v-else>Select an image above to enable scanning.</span>
            </div>
          </div>
          <div class="flex items-center gap-2">
            <Button
                v-if="scanJob.isPending.value && !scanJob.isSync.value"
                variant="outline"
                size="sm"
                class="border-destructive/40 text-destructive hover:bg-destructive/10 hover:text-destructive"
                @click="cancelScan"
            >
              <XCircle class="mr-1.5 h-4 w-4" />
              Cancel
            </Button>
            <Button
                v-else
                size="sm"
                :disabled="!selected || scanners.length === 0"
                @click="doScan"
            >
              <ScanLine class="mr-2 h-4 w-4" />
              Run scan
            </Button>
          </div>
        </div>

        <!-- Scan progress panel -->
        <ScanProgressPanel
            :status="scanJob.jobStatus.value"
            :error="scanJob.jobError.value"
            target="image"
            :active-target="scanJob.lastTarget.value"
            :value="scanJob.lastValue.value"
            :elapsed-label="scanJob.elapsedLabel.value"
            :is-sync="scanJob.isSync.value"
            @cancel="cancelScan"
        />

        <!-- Final fallback error display if the createScanJob call itself
             threw (e.g. validation error returned by the backend). -->
        <div
            v-if="scanJob.jobStatus.value === 'failed' && scanJob.createError.value"
            class="rounded-md border border-destructive/30 bg-destructive/5 p-3 text-xs text-destructive"
        >
          {{ scanJob.createError.value instanceof Error ? scanJob.createError.value.message : 'Scan failed.' }}
        </div>
      </CardContent>
    </Card>
  </div>
</template>