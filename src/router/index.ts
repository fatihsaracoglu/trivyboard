import { createRouter, createWebHashHistory, type RouteRecordRaw } from "vue-router";
import { useUiStore } from "@/stores/ui";

const routes: RouteRecordRaw[] = [
  {
    path: "/",
    redirect: "/scan",
  },
  {
    path: "/upload",
    name: "upload",
    component: () => import("@/components/views/UploadView.vue"),
    meta: { title: "Upload Report" },
  },
  {
    path: "/scan",
    name: "scan",
    component: () => import("@/components/views/ScanView.vue"),
    meta: { title: "Run Scan" },
  },
  {
    path: "/scans",
    name: "scans",
    component: () => import("@/components/views/ScansListView.vue"),
    meta: { title: "Scans" },
  },
  {
    path: "/search",
    name: "search",
    component: () => import("@/components/views/SearchView.vue"),
    meta: { title: "Global Search" },
  },
  {
    path: "/stats",
    name: "stats",
    component: () => import("@/components/views/StatsView.vue"),
    meta: { title: "Statistics" },
  },
  {
    path: "/dashboard/:scanId",
    name: "dashboard",
    component: () => import("@/components/views/DashboardView.vue"),
    meta: { title: "Dashboard" },
    props: true,
  },
  {
    path: "/packages/:scanId",
    name: "packages",
    component: () => import("@/components/views/PackagesView.vue"),
    meta: { title: "Packages" },
    props: true,
  },
  {
    path: "/targets/:scanId",
    name: "targets",
    component: () => import("@/components/views/TargetsView.vue"),
    meta: { title: "Targets" },
    props: true,
  },
  {
    path: "/findings/:scanId",
    name: "findings",
    component: () => import("@/components/views/FindingsView.vue"),
    meta: { title: "Findings" },
    props: true,
  },
  {
    path: "/raw/:scanId",
    name: "raw",
    component: () => import("@/components/views/RawView.vue"),
    meta: { title: "Raw Report" },
    props: true,
  },
  {
    path: "/:pathMatch(.*)*",
    name: "not-found",
    component: () => import("@/components/views/NotFoundView.vue"),
    meta: { title: "Not Found" },
  },
];

export const router = createRouter({
  history: createWebHashHistory(),
  routes,
  scrollBehavior() {
    return { top: 0 };
  },
});

router.beforeEach((to) => {
  const ui = useUiStore();
  const scanId = to.params.scanId as string | undefined;
  ui.setScanId(scanId ?? null);
  ui.setView((to.name as ViewId) ?? "upload");
  if (to.meta?.title) {
    document.title = `${to.meta.title} · trivyboard`;
  }
});

type ViewId = import("@/stores/ui").ViewId;
