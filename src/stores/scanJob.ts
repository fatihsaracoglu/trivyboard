// Pinia store for the active scan job. This persists across page navigations
// so the user can see scan progress even after leaving the scan page.
//
// The scan tabs (DockerImagesTab / FilesystemTab / RepositoryTab) call
// `startScan()` which creates the job and starts polling. The AppShell
// renders a global progress bar from the store, so the user can see scan
// progress even after leaving the scan page.
//
// When the user returns to the scan tab, the component reads the existing
// store state and shows the full ScanProgressPanel.
//
// Supports both sync and async scan modes:
// - Async (SCAN_MODE=async): POST /api/scans returns {job: {id, status: "queued"}}
//   immediately. The store polls GET /api/scans/:id/status until terminal.
//   Cancel is available via POST /api/scans/:id/cancel.
// - Sync (SCAN_MODE=sync): POST /api/scans blocks until trivy finishes, then
//   returns {scan: {...}} directly. The store shows "running" during the
//   blocking request (no cancel available). On response, status jumps to
//   "completed" and the onComplete callback navigates to the dashboard.

import { defineStore } from "pinia";
import { ref, computed, readonly, nextTick } from "vue";
import { api } from "@/lib/api";
import type { JobStatus, ScanJob, ScanRunRequest, ScanMeta, ScanTarget } from "@/lib/types";

const POLL_INTERVAL_MS = 1500;

const ACTIVE_STATUSES: ReadonlySet<JobStatus> = new Set([
  "queued",
  "running",
  "processing",
]);

export const useScanJobStore = defineStore("scanJob", () => {
  const jobId = ref<string | null>(null);
  const jobStatus = ref<JobStatus | null>(null);
  const jobError = ref<string | null>(null);
  const scanId = ref<string | null>(null);
  const isPending = ref(false);
  const isSync = ref(false);
  const lastTarget = ref<ScanTarget | "">("");
  const lastValue = ref<string>("");
  const startTime = ref<number | null>(null);
  const elapsedMs = ref(0);

  let pollTimer: ReturnType<typeof setInterval> | null = null;
  let elapsedTimer: ReturnType<typeof setInterval> | null = null;

  // Callbacks set by the component that started the scan (for navigation).
  let onCompleteCb: ((job: ScanJob) => void) | null = null;
  let onFailedCb: ((job: ScanJob) => void) | null = null;
  let onCancelledCb: ((job: ScanJob) => void) | null = null;

  function clearTimers() {
    if (pollTimer !== null) { clearInterval(pollTimer); pollTimer = null; }
    if (elapsedTimer !== null) { clearInterval(elapsedTimer); elapsedTimer = null; }
  }

  function startElapsedTimer() {
    if (elapsedTimer !== null) clearInterval(elapsedTimer);
    startTime.value = Date.now();
    elapsedMs.value = 0;
    elapsedTimer = setInterval(() => {
      if (startTime.value) elapsedMs.value = Date.now() - startTime.value;
    }, 100);
  }

  function stopElapsedTimer() {
    if (elapsedTimer !== null) { clearInterval(elapsedTimer); elapsedTimer = null; }
    if (startTime.value) elapsedMs.value = Date.now() - startTime.value;
  }

  const elapsedLabel = computed(() => {
    const ms = elapsedMs.value;
    if (ms < 1000) return "0s";
    const s = Math.floor(ms / 1000);
    if (s < 60) return `${(ms / 1000).toFixed(1)}s`;
    const m = Math.floor(s / 60);
    const rs = s % 60;
    return `${m}m ${rs.toString().padStart(2, "0")}s`;
  });

  const isTerminal = computed(
      () => jobStatus.value !== null && !ACTIVE_STATUSES.has(jobStatus.value),
  );

  // Active = a scan is in progress (either sync blocking or async polling).
  // In sync mode, isSync=true but we still want to show the progress bar
  // during the blocking HTTP request.
  const isActive = computed(
      () => isPending.value && jobStatus.value !== null && ACTIVE_STATUSES.has(jobStatus.value),
  );

  function reset() {
    clearTimers();
    jobId.value = null;
    jobStatus.value = null;
    jobError.value = null;
    scanId.value = null;
    isPending.value = false;
    isSync.value = false;
    lastTarget.value = "";
    lastValue.value = "";
    startTime.value = null;
    elapsedMs.value = 0;
    // Note: callbacks are NOT cleared here. They are set by useScanJob()
    // during component setup and must survive across startScan calls.
  }

  function setCallbacks(opts: {
    onComplete?: (job: ScanJob) => void;
    onFailed?: (job: ScanJob) => void;
    onCancelled?: (job: ScanJob) => void;
  }) {
    onCompleteCb = opts.onComplete ?? null;
    onFailedCb = opts.onFailed ?? null;
    onCancelledCb = opts.onCancelled ?? null;
  }

  async function startScan(req: ScanRunRequest, opts?: {
    onComplete?: (job: ScanJob) => void;
    onFailed?: (job: ScanJob) => void;
    onCancelled?: (job: ScanJob) => void;
  }) {
    if (isPending.value) return;
    if (opts) setCallbacks(opts);
    reset();
    isPending.value = true;
    lastTarget.value = req.target;
    lastValue.value = req.value;
    startElapsedTimer();

    // Set status to "running" IMMEDIATELY so the progress panel + global bar
    // show during the blocking HTTP request (both sync and async modes).
    // In async mode, this will be updated to "queued" when the job response
    // arrives, then polled through running → processing → completed.
    // In sync mode, the request blocks, then status jumps to "completed".
    jobStatus.value = "running";

    // Default to sync mode — the Cancel button is hidden in sync mode
    // because you can't abort a blocking HTTP request. If the API returns
    // a job object (async mode), we set isSync=false below to enable cancel.
    isSync.value = true;

    // Wait for Vue to paint the "running" UI before the blocking API call.
    // Without this, Vue batches the "running" → "completed" state change
    // and never renders the progress bar (especially in sync mode where the
    // HTTP request blocks the event loop).
    await nextTick();

    try {
      const res = await api.createScanJob(req);
      const jobData = (res as { job?: ScanJob }).job;
      const scanData = (res as { scan?: ScanMeta }).scan;

      if (jobData) {
        // Async mode — got a job object. Enable the Cancel button.
        isSync.value = false;
        jobId.value = jobData.id;
        jobStatus.value = jobData.status;
        await pollOnce();
        if (jobStatus.value && ACTIVE_STATUSES.has(jobStatus.value)) {
          pollTimer = setInterval(pollOnce, POLL_INTERVAL_MS);
        }
      } else if (scanData) {
        // Sync mode — got the scan directly. The HTTP request blocked until
        // trivy finished. Status was "running" during the request; now it's
        // "completed".
        isSync.value = true;
        scanId.value = scanData.id;
        jobStatus.value = "completed";
        isPending.value = false;
        stopElapsedTimer();
        onCompleteCb?.({
          id: scanData.id,
          status: "completed",
          target: req.target,
          value: req.value,
          sourceType: scanData.artifactType as ScanJob["sourceType"],
          queuedAt: scanData.uploadedAt,
          scanId: scanData.id,
        });
      } else {
        throw new Error("Unexpected response from scan endpoint");
      }
    } catch (err) {
      jobStatus.value = "failed";
      jobError.value = err instanceof Error ? err.message : String(err);
      isPending.value = false;
      stopElapsedTimer();
      onFailedCb?.({
        id: "",
        status: "failed",
        target: req.target,
        value: req.value,
        sourceType: "trivy-json",
        queuedAt: 0,
        error: jobError.value ?? undefined,
      });
    }
  }

  async function pollOnce() {
    const id = jobId.value;
    if (!id) return;
    try {
      const res = await api.getJobStatus(id);
      const job = res.job;
      jobStatus.value = job.status;
      jobError.value = job.error ?? null;
      if (job.scanId) scanId.value = job.scanId;
      if (!ACTIVE_STATUSES.has(job.status)) {
        clearTimers();
        stopElapsedTimer();
        isPending.value = false;
        if (job.status === "completed") onCompleteCb?.(job);
        else if (job.status === "failed") onFailedCb?.(job);
        else if (job.status === "cancelled") onCancelledCb?.(job);
      }
    } catch {
      clearTimers();
      stopElapsedTimer();
      isPending.value = false;
      jobStatus.value = "failed";
      jobError.value = "Polling error";
    }
  }

  async function cancelScan() {
    // Cancel is only available in async mode (sync mode blocks — can't cancel).
    if (isSync.value) return;
    const id = jobId.value;
    if (!id || !isPending.value) return;
    try {
      const res = await api.cancelJob(id);
      if (res.ok) {
        jobStatus.value = "cancelled";
        clearTimers();
        stopElapsedTimer();
        isPending.value = false;
        onCancelledCb?.({
          id, status: "cancelled", target: "fs", value: "",
          sourceType: "trivy-json", queuedAt: 0,
        });
      } else if (res.error) {
        jobError.value = res.error;
      }
    } catch (err) {
      jobError.value = err instanceof Error ? err.message : String(err);
    }
  }

  return {
    jobId: readonly(jobId),
    jobStatus: readonly(jobStatus),
    jobError: readonly(jobError),
    scanId: readonly(scanId),
    isPending: readonly(isPending),
    isSync: readonly(isSync),
    isTerminal,
    isActive,
    elapsedMs: readonly(elapsedMs),
    elapsedLabel,
    lastTarget: readonly(lastTarget),
    lastValue: readonly(lastValue),
    startScan,
    cancelScan,
    reset,
    setCallbacks,
    clearTimers,
  };
});
