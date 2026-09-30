import { ref, watch } from "vue";

type Theme = "light" | "dark";

const STORAGE_KEY = "trivy-dashboard-theme";
const theme = ref<Theme>("light");
let initialized = false;

function applyTheme(t: Theme) {
  if (typeof document === "undefined") return;
  const root = document.documentElement;
  if (t === "dark") {
    root.classList.add("dark");
  } else {
    root.classList.remove("dark");
  }
}

export function initTheme() {
  if (initialized) return;
  initialized = true;
  try {
    const stored = localStorage.getItem(STORAGE_KEY) as Theme | null;
    if (stored === "light" || stored === "dark") {
      theme.value = stored;
    }
  } catch {
    /* ignore */
  }
  applyTheme(theme.value);
  watch(theme, (t) => {
    applyTheme(t);
    try {
      localStorage.setItem(STORAGE_KEY, t);
    } catch {
      /* ignore */
    }
  });
}

export function useTheme() {
  return {
    theme,
    isDark: () => theme.value === "dark",
    toggle: () => {
      theme.value = theme.value === "dark" ? "light" : "dark";
    },
    setTheme: (t: Theme) => {
      theme.value = t;
    },
  };
}
