// useScanJob — composable that delegates to the global scanJob Pinia store.
//
// The scan state now lives in the Pinia store so it persists across page
// navigations. The AppShell renders a global progress bar from the store,
// so the user can see scan progress even after leaving the scan page.
//
// When the user returns to the scan tab, the component reads the existing
// store state and shows the full ScanProgressPanel.

import { computed } from "vue";
import { useScanJobStore } from "@/stores/scanJob";
import type { ScanJob } from "@/lib/types";

export interface UseScanJobOptions {
  onComplete?: (job: ScanJob) => void;
  onFailed?: (job: ScanJob) => void;
  onCancelled?: (job: ScanJob) => void;
}

export function useScanJob(opts: UseScanJobOptions = {}) {
  const store = useScanJobStore();

  // Register callbacks so the store can fire them when the job completes.
  // This is called on every render of the component that uses the composable,
  // but it's idempotent — the callbacks just get overwritten.
  store.setCallbacks(opts);

  return {
    jobId: computed(() => store.jobId),
    jobStatus: computed(() => store.jobStatus),
    jobError: computed(() => store.jobError),
    scanId: computed(() => store.scanId),
    isPending: computed(() => store.isPending),
    isTerminal: computed(() => store.isTerminal),
    isSync: computed(() => store.isSync),
    createError: computed<unknown>(() => null),
    elapsedMs: computed(() => store.elapsedMs),
    elapsedLabel: computed(() => store.elapsedLabel),
    lastTarget: computed(() => store.lastTarget),
    lastValue: computed(() => store.lastValue),
    startScan: store.startScan,
    cancelScan: store.cancelScan,
    reset: store.reset,
  };
}
