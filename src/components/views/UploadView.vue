<script setup lang="ts">
import { ref, computed } from "vue";
import { useRouter } from "vue-router";
import { UploadCloud, FileJson, AlertCircle, Loader2 } from "@lucide/vue";
import Button from "@/components/ui/Button.vue";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { useMutation } from "@/composables/useApi";
import { useToast } from "@/composables/useToast";
import { api, ApiRequestError } from "@/lib/api";
import { cn } from "@/lib/utils";

const router = useRouter();
const { toast } = useToast();

const upload = useMutation((file: File) => api.uploadScan(file));

const isDragging = ref(false);
const fileInput = ref<HTMLInputElement | null>(null);
const errorMsg = computed(() => {
  if (!upload.isError.value) return null;
  const err = upload.error.value;
  if (err instanceof ApiRequestError) {
    return {
      code: err.code,
      message: err.message,
      status: err.status,
      details: err.details,
    };
  }
  return {
    code: "UNKNOWN",
    message: err instanceof Error ? err.message : "Unexpected error",
    status: 0,
    details: undefined,
  };
});

function onDragOver(e: DragEvent) {
  e.preventDefault();
  isDragging.value = true;
}
function onDragLeave(e: DragEvent) {
  e.preventDefault();
  isDragging.value = false;
}
function onDrop(e: DragEvent) {
  e.preventDefault();
  isDragging.value = false;
  const file = e.dataTransfer?.files?.[0];
  if (file) handleFile(file);
}
function onFileChange(e: Event) {
  const input = e.target as HTMLInputElement;
  const file = input.files?.[0];
  if (file) handleFile(file);
  // reset so picking the same file twice still fires change
  input.value = "";
}
function browse() {
  fileInput.value?.click();
}

async function handleFile(file: File) {
  // Quick client-side sanity: must be JSON-ish by name. Backend will validate.
  if (!/\.(json)$/i.test(file.name) && file.type !== "application/json") {
    toast.warning("Expected a .json file", {
      description: `Selected file: ${file.name}`,
    });
  }
  const result = await upload.mutate(file);
  if (result) {
    toast.success("Scan uploaded", {
      description: `${result.scan.artifactName} · ${result.scan.resultCount} results`,
    });
    router.push({ name: "dashboard", params: { scanId: result.scan.id } });
  } else {
    toast.error("Upload failed", {
      description: errorMsg.value?.message ?? "See the error panel below.",
    });
  }
}
</script>

<template>
  <div class="mx-auto max-w-3xl px-4 py-8 sm:px-6 lg:px-8">
<!-- Drop zone -->
    <Card
      :class="cn(
        'border-2 border-dashed transition-colors',
        isDragging ? 'border-primary bg-primary/5' : 'border-border',
      )"
    >
      <div
        role="button"
        tabindex="0"
        class="flex cursor-pointer flex-col items-center justify-center px-6 py-14 text-center focus:outline-none"
        @dragover="onDragOver"
        @dragleave="onDragLeave"
        @drop="onDrop"
        @click="browse"
        @keydown.enter="browse"
        @keydown.space.prevent="browse"
      >
        <div
          :class="cn(
            'mb-4 flex h-14 w-14 items-center justify-center rounded-full',
            isDragging ? 'bg-primary/10 text-primary' : 'bg-muted text-muted-foreground',
          )"
        >
          <UploadCloud class="h-6 w-6" />
        </div>
        <p class="text-sm font-medium text-foreground">
          {{ isDragging ? "Drop the file to upload" : "Drag & drop a Trivy JSON file" }}
        </p>
        <p class="mt-1 text-xs text-muted-foreground">
          or
          <span class="text-primary underline-offset-2 hover:underline">browse</span>
          from your computer
        </p>
        <input
          ref="fileInput"
          type="file"
          accept="application/json,.json"
          class="hidden"
          @change="onFileChange"
        />
      </div>
    </Card>

    <!-- Pending state -->
    <div v-if="upload.isPending.value" class="mt-4 flex items-center gap-2 text-sm text-muted-foreground">
      <Loader2 class="h-4 w-4 animate-spin" />
      Uploading…
    </div>

    <!-- Error panel -->
    <Card v-if="errorMsg" class="mt-4 border-destructive/40 bg-destructive/5">
      <CardHeader class="pb-2">
        <CardTitle class="flex items-center gap-2 text-base text-destructive">
          <AlertCircle class="h-4 w-4" />
          Upload failed
        </CardTitle>
        <CardDescription class="text-destructive/80">
          The backend rejected the report.
        </CardDescription>
      </CardHeader>
      <CardContent class="space-y-2 text-sm">
        <div class="grid grid-cols-1 gap-2 sm:grid-cols-3">
          <div class="rounded-md border border-destructive/30 bg-background/60 p-2">
            <div class="text-[10px] uppercase tracking-wider text-muted-foreground">Code</div>
            <div class="font-mono text-xs text-destructive">{{ errorMsg.code }}</div>
          </div>
          <div class="rounded-md border border-destructive/30 bg-background/60 p-2">
            <div class="text-[10px] uppercase tracking-wider text-muted-foreground">HTTP status</div>
            <div class="font-mono text-xs text-destructive">{{ errorMsg.status || "—" }}</div>
          </div>
          <div class="rounded-md border border-destructive/30 bg-background/60 p-2">
            <div class="text-[10px] uppercase tracking-wider text-muted-foreground">Message</div>
            <div class="text-xs text-foreground">{{ errorMsg.message }}</div>
          </div>
        </div>
        <details v-if="errorMsg.details" class="rounded-md border border-border bg-muted/40 p-2 text-xs">
          <summary class="cursor-pointer text-muted-foreground">Backend details</summary>
          <pre class="mt-2 max-h-48 overflow-auto font-mono text-[11px] text-foreground">{{ JSON.stringify(errorMsg.details, null, 2) }}</pre>
        </details>
      </CardContent>
    </Card>

    <!-- Footer hint -->
    <div class="mt-10 flex items-center gap-2 text-xs text-muted-foreground">
      <FileJson class="h-3.5 w-3.5" />
      <span>
        Run a scan locally with
        <code class="rounded bg-muted px-1 py-0.5 font-mono">trivy image --format json --output report.json alpine:3.19</code>
      </span>
    </div>
  </div>
</template>
