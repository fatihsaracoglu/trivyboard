<script setup lang="ts">
import { computed } from "vue";
import {
  Target as TargetIcon,
  AlertCircle,
  Layers,
  Boxes,
  Wrench,
} from "@lucide/vue";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge, Skeleton } from "@/components/ui/primitives";
import { useApi } from "@/composables/useApi";
import { api } from "@/lib/api";
import { formatNumber, SEVERITY_COLORS, SEVERITY_ORDER } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { TargetsResponse, Severity, SeverityCounts, TargetSummary } from "@/lib/types";

const props = defineProps<{ scanId: string }>();

const { data, isLoading, isError, error } = useApi<TargetsResponse>(
  () => api.listTargets(props.scanId),
  () => [props.scanId],
);

const targets = computed<TargetSummary[]>(() => data.value?.data ?? []);

interface SeveritySlice {
  code: Severity;
  key: keyof SeverityCounts;
  count: number;
  pct: number;
}

function severitySlices(sev: SeverityCounts): SeveritySlice[] {
  const total = SEVERITY_ORDER.reduce((acc, code) => {
    const key = code.toLowerCase() as keyof SeverityCounts;
    return acc + (sev[key] ?? 0);
  }, 0);
  return SEVERITY_ORDER.map((code) => {
    const key = code.toLowerCase() as keyof SeverityCounts;
    const count = sev[key] ?? 0;
    return {
      code,
      key,
      count,
      pct: total > 0 ? (count / total) * 100 : 0,
    };
  });
}

function classLabel(c: string | null): string {
  if (!c) return "—";
  // Map common Trivy class ids to friendly labels.
  const map: Record<string, string> = {
    "os-pkgs": "OS Packages",
    "lang-pkgs": "Language Packages",
    config: "Config",
    secret: "Secret",
    license: "License",
    "custom": "Custom",
  };
  return map[c] ?? c;
}

function typeLabel(t: string | null): string {
  if (!t) return "—";
  return t;
}

function openTarget(target: string) {
  // No per-target route yet; on click we just keep it visual.
  // A future iteration can deep-link to a filtered dashboard view.
  void target;
}
</script>

<template>
  <div class="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
<!-- Loading -->
    <div v-if="isLoading" class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
      <Card v-for="i in 6" :key="i">
        <div class="space-y-3 p-4">
          <Skeleton class="h-5 w-2/3" />
          <Skeleton class="h-4 w-1/3" />
          <Skeleton class="h-3 w-full" />
          <Skeleton class="h-3 w-1/2" />
        </div>
      </Card>
    </div>

    <!-- Error -->
    <Card v-else-if="isError" class="border-destructive/40 bg-destructive/5">
      <div class="flex items-start gap-3 p-4">
        <AlertCircle class="mt-0.5 h-5 w-5 text-destructive" />
        <div class="space-y-1">
          <p class="text-sm font-medium text-destructive">Failed to load targets</p>
          <p class="text-xs text-muted-foreground">
            {{ error instanceof Error ? error.message : "Unknown error" }}
          </p>
        </div>
      </div>
    </Card>

    <!-- Empty -->
    <Card v-else-if="!targets.length" class="border-dashed">
      <div class="flex flex-col items-center justify-center px-6 py-16 text-center">
        <div class="mb-4 flex h-14 w-14 items-center justify-center rounded-full bg-muted text-muted-foreground">
          <TargetIcon class="h-6 w-6" />
        </div>
        <p class="text-sm font-medium text-foreground">No targets in this scan</p>
        <p class="mt-1 text-xs text-muted-foreground">
          The report may not have included target-level results.
        </p>
      </div>
    </Card>

    <!-- Grid -->
    <div v-else class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
      <Card
        v-for="t in targets"
        :key="t.target"
        class="cursor-pointer transition-colors hover:border-primary/40 hover:bg-accent/30"
        @click="openTarget(t.target)"
      >
        <CardHeader class="pb-2">
          <div class="flex items-start justify-between gap-2">
            <div class="min-w-0 flex-1 space-y-1">
              <CardTitle class="truncate font-mono text-sm" :title="t.target">
                {{ t.target }}
              </CardTitle>
              <div class="flex flex-wrap items-center gap-1">
                <Badge variant="outline" class="font-normal">
                  <Layers class="h-3 w-3" />
                  {{ classLabel(t.class) }}
                </Badge>
                <Badge variant="outline" class="font-normal">
                  <Boxes class="h-3 w-3" />
                  {{ typeLabel(t.type) }}
                </Badge>
              </div>
            </div>
            <div class="text-right">
              <div class="font-mono text-xl font-semibold tabular-nums text-foreground">
                {{ formatNumber(t.total) }}
              </div>
              <div class="text-[10px] uppercase tracking-wider text-muted-foreground">total</div>
            </div>
          </div>
        </CardHeader>
        <CardContent class="space-y-2.5">
          <!-- Stacked severity bar -->
          <div class="flex h-2 w-full overflow-hidden rounded-full bg-muted">
            <template v-for="slice in severitySlices(t.severity)" :key="slice.code">
              <div
                v-if="slice.count > 0"
                :style="{ width: `${slice.pct}%`, backgroundColor: SEVERITY_COLORS[slice.code] }"
                :class="cn('h-full transition-all')"
                :title="`${slice.code}: ${slice.count}`"
              />
            </template>
          </div>

          <!-- Per-severity counts -->
          <div class="grid grid-cols-5 gap-1">
            <div
              v-for="slice in severitySlices(t.severity)"
              :key="slice.code"
              class="flex flex-col items-center gap-0.5 rounded py-1"
              :class="slice.count > 0 ? '' : 'opacity-40'"
            >
              <span
                class="h-1.5 w-1.5 rounded-full"
                :style="{ backgroundColor: SEVERITY_COLORS[slice.code] }"
              />
              <span class="font-mono text-[10px] tabular-nums text-foreground">{{ slice.count }}</span>
              <span class="text-[9px] uppercase text-muted-foreground">{{ slice.code[0] }}</span>
            </div>
          </div>

          <!-- Fixable -->
          <div class="flex items-center justify-between border-t border-border pt-2 text-xs">
            <span class="flex items-center gap-1 text-muted-foreground">
              <Wrench class="h-3 w-3" />
              Fixable
            </span>
            <span class="font-mono tabular-nums text-foreground">
              {{ formatNumber(t.fixable) }}
              <span class="text-muted-foreground"> / {{ formatNumber(t.total) }}</span>
            </span>
          </div>
        </CardContent>
      </Card>
    </div>
  </div>
</template>
