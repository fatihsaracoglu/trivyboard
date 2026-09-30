<script setup lang="ts">
// ScanProgressPanel — a prominent progress card shown during a scan.
// Displays: current status, target + value being scanned, elapsed time,
// a visual progress bar, and a Cancel button (async mode only).
//
// The panel only renders when this tab's target matches the active scan's
// target (so it doesn't show on all three scan tabs simultaneously).
// It auto-hides 3 seconds after reaching a terminal state.
import { computed, ref, watch, onUnmounted } from "vue";
import {
  Loader2, CheckCircle2, XCircle, CircleSlash, Clock, X, ScanLine,
  Container, FolderTree, GitBranch,
} from "@lucide/vue";
import { cn } from "@/lib/utils";
import type { JobStatus, ScanTarget } from "@/lib/types";

const props = defineProps<{
  status: JobStatus | null;
  error?: string | null;
  target?: ScanTarget;
  value?: string;
  elapsedLabel?: string;
  isSync?: boolean;
  // The active scan's target (from the global store). When set, the panel
  // only shows if this tab's `target` matches it.
  activeTarget?: string;
}>();

const emit = defineEmits<{
  cancel: [];
}>();

// Only show the panel if:
// 1. There's a status, AND
// 2. This tab's target matches the active scan's target (or activeTarget is
//    not set, in which case we show regardless), AND
// 3. The auto-hide timer hasn't fired yet.
// Show the panel whenever there's a status (including terminal states so the
// user sees the result briefly before navigation).
//
// KEY: If the component mounts and the status is ALREADY terminal (completed/
// failed/cancelled), don't show the panel at all — the scan already finished
// and the user is just returning to the page. Only show the panel for active
// scans or for the brief moment after a scan reaches terminal state while
// the user is still watching.
const isInitiallyTerminal = props.status === "completed" || props.status === "failed" || props.status === "cancelled";
const hidden = ref(isInitiallyTerminal);
let hideTimer: ReturnType<typeof setTimeout> | null = null;

function clearHideTimer() {
  if (hideTimer !== null) {
    clearTimeout(hideTimer);
    hideTimer = null;
  }
}

// Watch for status CHANGES — only react to transitions, not the initial value.
// When the status transitions TO a terminal state, show briefly then auto-hide.
watch(
    () => props.status,
    (s, oldS) => {
      // Only react to actual status changes (not the initial mount).
      if (s === oldS) return;
      clearHideTimer();
      if (s === null) {
        hidden.value = true;
        return;
      }
      hidden.value = false;
      if (s === "completed" || s === "failed" || s === "cancelled") {
        const delay = props.isSync ? 1500 : 3000;
        hideTimer = setTimeout(() => {
          hidden.value = true;
        }, delay);
      }
    },
);

onUnmounted(() => clearHideTimer());

const showPanel = computed(() => {
  if (!props.status || hidden.value) return false;
  // If activeTarget is provided, only show on the tab whose target matches.
  if (props.activeTarget && props.target) {
    const targetMap: Record<string, string> = {
      image: "image",
      fs: "fs",
      repo: "repo",
    };
    return targetMap[props.activeTarget] === props.target;
  }
  return true;
});

const cfg = computed<{
  label: string;
  sublabel: string;
  icon: typeof Loader2;
  spin: boolean;
  barClass: string;
  textClass: string;
  bgClass: string;
  pct: number;
}>(() => {
  switch (props.status) {
    case "queued":
      return {
        label: "Queued",
        sublabel: "Waiting for a worker…",
        icon: CircleSlash,
        spin: false,
        barClass: "bg-muted-foreground",
        textClass: "text-muted-foreground",
        bgClass: "border-border bg-muted/30",
        pct: 10,
      };
    case "running":
      return {
        label: "Running Trivy",
        sublabel: "Scanning for vulnerabilities…",
        icon: Loader2,
        spin: true,
        barClass: "bg-blue-500",
        textClass: "text-blue-600 dark:text-blue-400",
        bgClass: "border-blue-500/30 bg-blue-500/5",
        pct: 55,
      };
    case "processing":
      return {
        label: "Processing result",
        sublabel: "Normalizing vulnerabilities…",
        icon: Loader2,
        spin: true,
        barClass: "bg-blue-500",
        textClass: "text-blue-600 dark:text-blue-400",
        bgClass: "border-blue-500/30 bg-blue-500/5",
        pct: 85,
      };
    case "completed":
      return {
        label: "Completed",
        sublabel: "Opening dashboard…",
        icon: CheckCircle2,
        spin: false,
        barClass: "bg-emerald-500",
        textClass: "text-emerald-600 dark:text-emerald-400",
        bgClass: "border-emerald-500/30 bg-emerald-500/5",
        pct: 100,
      };
    case "failed":
      return {
        label: "Failed",
        sublabel: props.error || "Scan failed",
        icon: XCircle,
        spin: false,
        barClass: "bg-destructive",
        textClass: "text-destructive",
        bgClass: "border-destructive/30 bg-destructive/5",
        pct: 100,
      };
    case "cancelled":
      return {
        label: "Cancelled",
        sublabel: "Scan was cancelled",
        icon: CircleSlash,
        spin: false,
        barClass: "bg-muted-foreground",
        textClass: "text-muted-foreground",
        bgClass: "border-border bg-muted/30",
        pct: 0,
      };
    default:
      return {
        label: "Unknown",
        sublabel: "",
        icon: CircleSlash,
        spin: false,
        barClass: "bg-muted",
        textClass: "text-muted-foreground",
        bgClass: "border-border bg-muted/30",
        pct: 0,
      };
  }
});

const targetIcon = computed(() => {
  switch (props.target) {
    case "image": return Container;
    case "fs": return FolderTree;
    case "repo": return GitBranch;
    default: return ScanLine;
  }
});

const targetLabel = computed(() => {
  switch (props.target) {
    case "image": return "Docker image";
    case "fs": return "Filesystem";
    case "repo": return "Repository";
    default: return "Scan";
  }
});
</script>

<template>
  <Transition name="progress-slide">
    <div
        v-if="showPanel"
        :class="cn('rounded-lg border p-4 transition-colors', cfg.bgClass)"
    >
      <!-- Top row: status icon + label + elapsed + cancel -->
      <div class="flex items-start justify-between gap-3">
        <div class="flex items-center gap-3">
          <div
              :class="cn(
              'flex h-9 w-9 shrink-0 items-center justify-center rounded-md',
              cfg.textClass,
              cfg.bgClass.includes('blue') && 'bg-blue-500/10',
              cfg.bgClass.includes('emerald') && 'bg-emerald-500/10',
              cfg.bgClass.includes('destructive') && 'bg-destructive/10',
              cfg.bgClass.includes('muted') && 'bg-muted',
            )"
          >
            <component
                :is="cfg.icon"
                :class="cn('h-5 w-5', cfg.spin && 'animate-spin')"
            />
          </div>
          <div>
            <div :class="cn('text-sm font-semibold', cfg.textClass)">
              {{ cfg.label }}
            </div>
            <div class="text-xs text-muted-foreground">
              {{ cfg.sublabel }}
            </div>
          </div>
        </div>

        <div class="flex items-center gap-2">
          <!-- Elapsed time -->
          <div
              v-if="elapsedLabel"
              class="flex items-center gap-1.5 rounded-md bg-background/60 px-2 py-1 text-xs text-muted-foreground"
          >
            <Clock class="h-3 w-3" />
            <span class="font-mono tabular-nums">{{ elapsedLabel }}</span>
          </div>

          <!-- Cancel button (async mode only, while pending) -->
          <button
              v-if="!isSync && (status === 'queued' || status === 'running' || status === 'processing')"
              type="button"
              class="inline-flex items-center gap-1.5 rounded-md border border-destructive/40 px-2.5 py-1 text-xs font-medium text-destructive transition-colors hover:bg-destructive/10"
              @click="emit('cancel')"
          >
            <X class="h-3 w-3" />
            Cancel
          </button>
        </div>
      </div>

      <!-- Scan target info -->
      <div v-if="value" class="mt-3 flex items-center gap-2 text-xs text-muted-foreground">
        <component :is="targetIcon" class="h-3.5 w-3.5 shrink-0" />
        <span class="font-medium">{{ targetLabel }}</span>
        <span class="text-muted-foreground/40">·</span>
        <code class="truncate font-mono text-foreground/80" :title="value">{{ value }}</code>
      </div>

      <!-- Progress bar -->
      <div class="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-muted">
        <div
            :class="cn('h-full transition-all duration-500', cfg.barClass)"
            :style="{ width: `${cfg.pct}%` }"
        />
      </div>

      <!-- Step indicators -->
      <div class="mt-3 flex items-center justify-between text-[10px] font-medium uppercase tracking-wider">
        <span :class="status === 'queued' || status === 'running' || status === 'processing' || status === 'completed' ? cfg.textClass : 'text-muted-foreground/40'">
          Queued
        </span>
        <span :class="status === 'running' || status === 'processing' || status === 'completed' ? cfg.textClass : 'text-muted-foreground/40'">
          Scanning
        </span>
        <span :class="status === 'processing' || status === 'completed' ? cfg.textClass : 'text-muted-foreground/40'">
          Processing
        </span>
        <span :class="status === 'completed' ? cfg.textClass : 'text-muted-foreground/40'">
          Done
        </span>
      </div>
    </div>
  </Transition>
</template>

<style scoped>
.progress-slide-enter-active,
.progress-slide-leave-active {
  transition: all 0.3s ease;
}
.progress-slide-enter-from {
  opacity: 0;
  transform: translateY(-8px);
}
.progress-slide-leave-to {
  opacity: 0;
  transform: translateY(-8px);
}
</style>