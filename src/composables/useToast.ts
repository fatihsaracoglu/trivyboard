import { ref } from "vue";

export interface Toast {
  id: number;
  title?: string;
  description?: string;
  variant: "default" | "success" | "error" | "warning";
  duration: number;
}

const toasts = ref<Toast[]>([]);
let nextId = 1;

function dismiss(id: number) {
  const idx = toasts.value.findIndex((t) => t.id === id);
  if (idx >= 0) toasts.value.splice(idx, 1);
}

function push(toast: Omit<Toast, "id" | "duration"> & { duration?: number }) {
  const id = nextId++;
  const t: Toast = {
    id,
    duration: toast.duration ?? 5000,
    ...toast,
  };
  toasts.value.push(t);
  if (t.duration > 0) {
    setTimeout(() => dismiss(id), t.duration);
  }
  return id;
}

export function useToast() {
  return {
    toasts,
    dismiss,
    toast: {
      success: (title: string, opts?: { description?: string }) =>
        push({ title, variant: "success", ...opts }),
      error: (title: string, opts?: { description?: string }) =>
        push({ title, variant: "error", ...opts }),
      warning: (title: string, opts?: { description?: string }) =>
        push({ title, variant: "warning", ...opts }),
      info: (title: string, opts?: { description?: string }) =>
        push({ title, variant: "default", ...opts }),
    },
  };
}
