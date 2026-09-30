<script setup lang="ts">
// AppShell — the main application layout with sidebar navigation, topbar, and footer.
// Wraps <router-view/> so all routes render inside this shell.
import { computed } from "vue";
import { useRoute, useRouter } from "vue-router";
import { useUiStore } from "@/stores/ui";
import { useScanJobStore } from "@/stores/scanJob";
import { useTheme } from "@/composables/useTheme";
import { cn } from "@/lib/utils";
import Tooltip from "@/components/ui/Tooltip.vue";
import Button from "@/components/ui/Button.vue";
import pkg from "../../../package.json";
import {
  CloudUpload, Radar, History, LayoutDashboard, Package, Target as TargetIcon,
  Flag, FileJson, ShieldCheck, Sun, Moon, FolderGit2, ExternalLink, Activity,
  Search as SearchIcon, BarChart3, Loader2, X,
} from "@lucide/vue";

const appVersion = pkg.version;

const route = useRoute();
const router = useRouter();
const ui = useUiStore();
const scanJob = useScanJobStore();
const { isDark, toggle } = useTheme();

interface NavItem {
  name: string;
  label: string;
  icon: typeof CloudUpload;
  requiresScan?: boolean;
}

const PRIMARY_NAV: NavItem[] = [
  { name: "scan", label: "Run Scan", icon: Radar },
  { name: "upload", label: "Upload", icon: CloudUpload },
  { name: "scans", label: "Scans", icon: History },
  { name: "search", label: "Search", icon: SearchIcon },
  { name: "stats", label: "Statistics", icon: BarChart3 },
];

const SCAN_NAV: NavItem[] = [
  { name: "dashboard", label: "Dashboard", icon: LayoutDashboard, requiresScan: true },
  { name: "packages", label: "Packages", icon: Package, requiresScan: true },
  { name: "targets", label: "Targets", icon: TargetIcon, requiresScan: true },
  { name: "findings", label: "Findings", icon: Flag, requiresScan: true },
  { name: "raw", label: "Raw Report", icon: FileJson, requiresScan: true },
];

const currentTitle = computed(() => {
  const titles: Record<string, { title: string; subtitle: string }> = {
    upload: { title: "Upload Report", subtitle: "Drop a Trivy JSON to visualize" },
    scan: { title: "Run Scan", subtitle: "Scan docker images, filesystems, or git repositories with Trivy" },
    scans: { title: "Scans", subtitle: "All uploaded and scanned reports" },
    search: { title: "Global Search", subtitle: "Find a CVE or package across all your scans" },
    stats: { title: "Statistics", subtitle: "Aggregate metrics across all scans" },
    dashboard: { title: "Dashboard", subtitle: "Executive summary and KPIs" },
    packages: { title: "Packages", subtitle: "Vulnerabilities grouped by package" },
    targets: { title: "Targets", subtitle: "Vulnerabilities grouped by target" },
    findings: { title: "Findings", subtitle: "Misconfigurations, secrets, and licenses" },
    raw: { title: "Raw Report", subtitle: "Normalized scan payload" },
  };
  return titles[ui.view] ?? { title: "trivyboard", subtitle: "" };
});

function navigate(name: string) {
  router.push({ name });
}

function navigateScan(name: string) {
  if (!ui.scanId) return;
  router.push({ name, params: { scanId: ui.scanId } });
}
</script>

<template>
  <div class="flex h-screen min-h-0 w-full bg-background text-foreground">
    <!-- Sidebar -->
    <aside class="flex h-full w-[240px] flex-col border-r border-border bg-sidebar/50 backdrop-blur">
      <!-- Logo -->
      <div class="flex items-center gap-2.5 px-5 py-5 border-b border-border">
        <div class="flex h-9 w-9 items-center justify-center rounded-md bg-gradient-to-br from-emerald-500 to-teal-600 text-white shadow-sm">
          <ShieldCheck class="h-5 w-5" />
        </div>
        <div class="min-w-0">
          <span class="brand-text text-lg">trivyboard</span>
        </div>
      </div>

      <!-- Nav -->
      <nav class="flex-1 overflow-y-auto px-3 py-4 space-y-6">
        <div class="space-y-1">
          <div class="px-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
            Workspace
          </div>

          <button
              v-for="item in PRIMARY_NAV"
              :key="item.name"
              type="button"
              @click="navigate(item.name)"
              :class="cn('group flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
                ui.view === item.name
                  ? 'bg-primary/10 text-primary'
                  : 'text-muted-foreground hover:bg-muted hover:text-foreground',
              )"
          >
            <component
                :is="item.icon"
                :class="cn(
                  'h-4 w-4 shrink-0',
                  ui.view === item.name && 'text-primary',
                )"
            />
            <span class="truncate">{{ item.label }}</span>
            <span
                v-if="ui.view === item.name"
                class="ml-auto h-1.5 w-1.5 rounded-full bg-primary"
            />
          </button>
        </div>

        <div v-if="ui.scanId" class="space-y-1">
          <div class="px-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
            Current scan
          </div>

          <button
              v-for="item in SCAN_NAV"
              :key="item.name"
              type="button"
              @click="navigateScan(item.name)"
              :disabled="item.requiresScan && !ui.scanId"
              :class="cn('group flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
                ui.view === item.name
                  ? 'bg-primary/10 text-primary'
                  : 'text-muted-foreground hover:bg-muted hover:text-foreground',
                item.requiresScan &&
                  !ui.scanId &&
                  'cursor-not-allowed opacity-40 hover:bg-transparent hover:text-muted-foreground',
              )"
          >
            <component
                :is="item.icon"
                :class="cn(
                  'h-4 w-4 shrink-0',
                  ui.view === item.name && 'text-primary',
                )"
            />
            <span class="truncate">{{ item.label }}</span>
            <span
                v-if="ui.view === item.name"
                class="ml-auto h-1.5 w-1.5 rounded-full bg-primary"
            />
          </button>
        </div>
      </nav>

      <!-- Bottom bar -->
      <div class="flex items-center justify-between border-t border-border px-3 py-3">
        <Button variant="ghost" size="icon" aria-label="Toggle theme" @click="toggle" class="h-9 w-9">
          <Sun v-if="isDark()" class="h-4 w-4" />
          <Moon v-else class="h-4 w-4" />
        </Button>
        <div class="flex items-center gap-1">
          <a href="https://github.com/fatihsaracoglu/trivyboard" target="_blank" rel="noreferrer" class="flex items-center">
            <Button variant="ghost" size="icon" as="a" class="h-9 w-9">
              <div class="h-4 w-4">
                <svg role="img" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><title>GitHub</title><path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"/></svg>
              </div>
            </Button>
          </a>
        </div>
      </div>
    </aside>

    <!-- Main area -->
    <div class="flex min-w-0 flex-1 flex-col">
      <!-- Topbar -->
      <header class="flex h-14 shrink-0 items-center justify-between border-b border-border bg-background/60 px-6 backdrop-blur">
        <div>
          <h1 class="text-base font-semibold leading-tight">{{ currentTitle.title }}</h1>
          <p class="text-xs text-muted-foreground">{{ currentTitle.subtitle }}</p>
        </div>
        <div v-if="ui.scanId" class="hidden md:flex items-center gap-2 rounded-md border border-border bg-muted/40 px-3 py-1.5">
          <span class="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Scan ID</span>
          <code class="text-xs font-mono text-foreground/80 max-w-[280px] truncate" :title="ui.scanId">
            {{ ui.scanId.split(':').slice(0, 2).join(':') }}
          </code>
        </div>
      </header>

      <!-- Global scan progress bar (visible on all pages while a scan runs) -->
      <div
          v-if="scanJob.isActive && route.name !== 'scan'"
          class="flex shrink-0 items-center gap-3 border-b border-blue-500/20 bg-blue-500/5 px-4 py-1.5"
      >
        <Loader2 class="h-3.5 w-3.5 shrink-0 animate-spin text-blue-500" />
        <span class="text-xs font-medium text-blue-600 dark:text-blue-400">
          {{ scanJob.jobStatus === 'queued' ? 'Scan queued' : 'Scan running' }}
        </span>
        <span class="hidden sm:inline text-xs text-muted-foreground">
          {{ scanJob.lastTarget }} · <code class="font-mono">{{ scanJob.lastValue }}</code>
        </span>
        <span class="font-mono text-xs tabular-nums text-muted-foreground">
          {{ scanJob.elapsedLabel }}
        </span>
        <div class="ml-2 h-1 flex-1 overflow-hidden rounded-full bg-muted">
          <div
              class="h-full bg-blue-500 transition-all duration-1000"
              :style="{ width: scanJob.jobStatus === 'queued' ? '15%' : scanJob.jobStatus === 'running' ? '55%' : '85%' }"
          />
        </div>
        <button
            v-if="!scanJob.isSync"
            type="button"
            class="inline-flex items-center gap-1 rounded-md border border-destructive/30 px-2 py-0.5 text-[10px] font-medium text-destructive transition-colors hover:bg-destructive/10"
            @click="scanJob.cancelScan()"
        >
          <X class="h-2.5 w-2.5" />
          Cancel
        </button>
      </div>

      <!-- Content -->
      <main class="flex-1 overflow-auto">
        <div class="mx-auto w-full max-w-[1600px] px-4 py-6 sm:px-6 lg:px-8">
          <router-view />
        </div>
      </main>

      <!-- Footer -->
      <footer class="mt-auto border-t border-border bg-background/60 px-6 py-2 text-xs text-muted-foreground">
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-2">
            <ShieldCheck class="h-3.5 w-3.5 text-emerald-500" />
            <span>trivyboard</span>
          </div>
          <div class="flex items-center gap-3">
            <span class="font-mono">v{{ appVersion }}</span>
          </div>
        </div>
      </footer>
    </div>
  </div>
</template>