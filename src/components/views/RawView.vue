<script setup lang="ts">
import { ref, computed } from "vue";
import {
  Copy,
  Check,
  Download,
  AlertCircle,
  FileJson,
  Loader2,
} from "@lucide/vue";
import Button from "@/components/ui/Button.vue";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Badge, Skeleton } from "@/components/ui/primitives";
import { useApi } from "@/composables/useApi";
import { useToast } from "@/composables/useToast";
import { api } from "@/lib/api";
import { formatNumber, ARTIFACT_TYPE_LABELS } from "@/lib/format";
import type { ScanMeta } from "@/lib/types";

const props = defineProps<{ scanId: string }>();

const { toast } = useToast();

const { data, isLoading, isError, error, isFetching } = useApi<ScanMeta>(
  () => api.getScan(props.scanId),
  () => [props.scanId],
);

const scan = computed<ScanMeta | null>(() => data.value ?? null);
const prettyJson = computed(() =>
  scan.value ? JSON.stringify(scan.value, null, 2) : "",
);

const copied = ref(false);
async function copyJson() {
  try {
    await navigator.clipboard.writeText(prettyJson.value);
    copied.value = true;
    setTimeout(() => (copied.value = false), 1500);
    toast.success("Copied to clipboard");
  } catch {
    toast.error("Could not copy", { description: "Clipboard API unavailable." });
  }
}

const stats = computed(() => {
  if (!scan.value) return [];
  const s = scan.value;
  return [
    { label: "Schema", value: s.schemaVersion != null ? `v${s.schemaVersion}` : "—" },
    { label: "Artifact type", value: s.artifactType ? (ARTIFACT_TYPE_LABELS[s.artifactType] ?? s.artifactType) : "—" },
    { label: "Results", value: formatNumber(s.resultCount) },
    { label: "Targets", value: formatNumber(s.targetCount) },
    { label: "Occurrences", value: formatNumber(s.vulnerabilityOccurrences) },
    { label: "Unique CVEs", value: formatNumber(s.uniqueVulnerabilityIds) },
  ];
});

const csvUrl = computed(() => (scan.value ? api.exportUrl(scan.value.id, "csv") : null));
const jsonExportUrl = computed(() => (scan.value ? api.exportUrl(scan.value.id, "json") : null));
</script>

<template>
  <div class="mx-auto max-w-5xl px-4 py-6 sm:px-6 lg:px-8">
<!-- Loading -->
    <Card v-if="isLoading">
      <div class="space-y-3 p-4">
        <Skeleton class="h-6 w-1/3" />
        <Skeleton class="h-4 w-full" />
        <Skeleton class="h-4 w-2/3" />
        <Skeleton class="h-64 w-full" />
      </div>
    </Card>

    <!-- Error -->
    <Card v-else-if="isError" class="border-destructive/40 bg-destructive/5">
      <div class="flex items-start gap-3 p-4">
        <AlertCircle class="mt-0.5 h-5 w-5 text-destructive" />
        <div class="space-y-1">
          <p class="text-sm font-medium text-destructive">Failed to load scan</p>
          <p class="text-xs text-muted-foreground">
            {{ error instanceof Error ? error.message : "Unknown error" }}
          </p>
        </div>
      </div>
    </Card>

    <!-- Content -->
    <template v-else-if="scan">
      <!-- Badge row -->
      <div class="mb-4 grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
        <Card v-for="stat in stats" :key="stat.label" class="overflow-hidden py-2">
          <CardContent class="px-3 py-2.5">
            <div class="text-[10px] uppercase tracking-wider text-muted-foreground">
              {{ stat.label }}
            </div>
            <div class="mt-0.5 font-mono text-sm font-medium text-foreground">
              {{ stat.value }}
            </div>
          </CardContent>
        </Card>
      </div>

      <!-- Artifact name + filename -->
      <Card class="mb-4">
        <CardHeader>
          <div class="flex items-start justify-between gap-3">
            <div class="space-y-1">
              <CardTitle class="text-base">{{ scan.artifactName }}</CardTitle>
              <CardDescription class="font-mono text-xs">{{ scan.filename }}</CardDescription>
            </div>
          </div>
        </CardHeader>
      </Card>

      <!-- Findings summary -->
      <Card v-if="scan.findings && scan.findings.length" class="mb-4">
        <CardHeader>
          <CardTitle class="text-sm">Non-vulnerability findings</CardTitle>
        </CardHeader>
        <CardContent>
          <div class="flex flex-wrap gap-2">
            <Badge
              v-for="f in scan.findings"
              :key="f.kind"
              variant="secondary"
              class="font-mono"
            >
              {{ f.kind }}: {{ f.count }}
            </Badge>
          </div>
        </CardContent>
      </Card>

      <!-- Pretty-printed JSON -->
      <Card class="overflow-hidden">
        <CardHeader class="border-b border-border">
          <CardTitle class="flex items-center gap-2 text-sm">
            <FileJson class="h-4 w-4 text-muted-foreground" />
            Scan payload
          </CardTitle>
        </CardHeader>
        <CardContent class="p-0">
          <pre class="max-h-[60vh] overflow-auto bg-muted/30 p-4 font-mono text-[11px] leading-relaxed text-foreground"><code>{{ prettyJson }}</code></pre>
        </CardContent>
      </Card>
    </template>
  </div>
</template>
