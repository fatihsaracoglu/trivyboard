<script setup lang="ts">
// RepositoryTab — lets the user enter a git URL or local repo path and scan it with `trivy repo`.
//
// Uses the new async scan-job API: POST /api/scans (JSON) → polls
// GET /api/scans/:id/status every 1.5s until terminal, with a Cancel
// button that POSTs /api/scans/:id/cancel.
import { ref } from "vue";
import { useRouter } from "vue-router";
import { useScanJob } from "@/composables/useScanJob";
import { useToast } from "@/composables/useToast";
import { useUiStore } from "@/stores/ui";
import Button from "@/components/ui/Button.vue";
import Input from "@/components/ui/Input.vue";
import Checkbox from "@/components/ui/Checkbox.vue";
import { Label } from "@/components/ui/primitives";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import ScanProgressPanel from "./ScanProgressPanel.vue";
import { GitBranch, ScanLine, AlertTriangle, XCircle } from "@lucide/vue";

const router = useRouter();
const toast = useToast();
const ui = useUiStore();

const repo = ref("");
const scanners = ref<string[]>(["vuln"]);

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
  await scanJob.startScan({
    target: "repo",
    value: repo.value.trim(),
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

const PRESETS: { label: string; value: string }[] = [];
</script>

<template>
  <Card>
    <CardHeader class="pb-3">
      <CardTitle class="text-base flex items-center gap-2">
        <GitBranch class="h-4 w-4 text-emerald-500" />
        Repository scan
      </CardTitle>
      <CardDescription class="text-xs">
        Runs <code class="font-mono">trivy repo --format json &lt;url-or-path&gt;</code> on the backend host.
      </CardDescription>
    </CardHeader>
    <CardContent class="space-y-4">
      <div class="space-y-2">
        <Label class="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Git URL or local repo path</Label>
        <Input v-model="repo" placeholder="https://github.com/aquasecurity/trivy  ·  /path/to/repo" class="font-mono" :disabled="scanJob.isPending.value" />
        <div class="flex flex-wrap gap-2">
          <button
              v-for="p in PRESETS"
              :key="p.value"
              type="button"
              @click="repo = p.value"
              :disabled="scanJob.isPending.value"
              class="rounded-md border border-border bg-muted/40 px-2 py-1 text-[11px] text-muted-foreground transition-colors hover:border-emerald-500/40 hover:text-foreground"
          >
            {{ p.label }}
          </button>
        </div>
      </div>

      <div class="space-y-2">
        <Label class="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Scanners</Label>
        <div class="grid grid-cols-2 gap-2 sm:grid-cols-4">
          <div v-for="opt in SCANNER_OPTIONS" :key="opt.id" class="flex items-center gap-2">
            <Checkbox :id="`repo-scanner-${opt.id}`" :model-value="scanners.includes(opt.id)" @update:model-value="toggleScanner(opt.id)" :disabled="scanJob.isPending.value" />
            <Label :for="`repo-scanner-${opt.id}`">{{ opt.label }}</Label>
          </div>
        </div>
      </div>

      <div class="flex items-center justify-between gap-2 rounded-md border border-border bg-muted/30 p-3">
        <div class="flex flex-col gap-1.5 text-xs text-muted-foreground">
          <div>
            <span v-if="repo">Will scan <code class="font-mono">{{ repo }}</code>.</span>
            <span v-else class="inline-flex items-center gap-1.5">
              <AlertTriangle class="h-3.5 w-3.5 text-yellow-500" />
              Enter a repository URL or path to enable scanning.
            </span>
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
              :disabled="!repo.trim() || scanners.length === 0"
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
          target="repo"
          :active-target="scanJob.lastTarget.value"
          :value="scanJob.lastValue.value"
          :elapsed-label="scanJob.elapsedLabel.value"
          :is-sync="scanJob.isSync.value"
          @cancel="cancelScan"
      />

      <div
          v-if="scanJob.jobStatus.value === 'failed' && scanJob.createError.value"
          class="rounded-md border border-destructive/30 bg-destructive/5 p-3 text-xs text-destructive"
      >
        {{ scanJob.createError.value instanceof Error ? scanJob.createError.value.message : 'Scan failed.' }}
      </div>
    </CardContent>
  </Card>
</template>
