// Pinia UI store
// Holds the active view + scanId. Vue Router (hash mode) is the source of
// truth for navigation; this store mirrors it for easy access in components.

import { defineStore } from "pinia";
import { ref } from "vue";

export type ViewId =
  | "upload"
  | "scan"
  | "scans"
  | "dashboard"
  | "packages"
  | "targets"
  | "findings"
  | "raw"
  | "search"
  | "stats";

export const useUiStore = defineStore("ui", () => {
  const scanId = ref<string | null>(null);
  const view = ref<ViewId>("scan");

  function setScanId(id: string | null) {
    scanId.value = id;
  }

  function setView(v: ViewId) {
    view.value = v;
  }

  function openScan(id: string, v: ViewId = "dashboard") {
    scanId.value = id;
    view.value = v;
  }

  return { scanId, view, setScanId, setView, openScan };
});
