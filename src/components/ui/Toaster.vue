<script setup lang="ts">
import { useToast } from "@/composables/useToast";
import { CheckCircle2, XCircle, AlertTriangle, Info, X } from "@lucide/vue";
import { cn } from "@/lib/utils";

const { toasts, dismiss } = useToast();

const icons = {
  success: CheckCircle2,
  error: XCircle,
  warning: AlertTriangle,
  default: Info,
};

const variantClasses = {
  success: "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
  error: "border-destructive/30 bg-destructive/10 text-destructive",
  warning: "border-yellow-500/30 bg-yellow-500/10 text-yellow-700 dark:text-yellow-300",
  default: "border-border bg-background text-foreground",
};
</script>

<template>
  <Teleport to="body">
    <div class="pointer-events-none fixed top-4 right-4 z-[100] flex w-full max-w-sm flex-col gap-2">
      <TransitionGroup name="toast">
        <div
          v-for="t in toasts"
          :key="t.id"
          :class="cn(
            'pointer-events-auto relative flex items-start gap-3 rounded-lg border p-4 shadow-lg backdrop-blur',
            variantClasses[t.variant],
          )"
          role="alert"
        >
          <component :is="icons[t.variant]" class="mt-0.5 h-4 w-4 shrink-0" />
          <div class="flex-1 min-w-0">
            <div v-if="t.title" class="text-sm font-semibold">{{ t.title }}</div>
            <div v-if="t.description" class="mt-0.5 text-xs text-muted-foreground">{{ t.description }}</div>
          </div>
          <button
            type="button"
            class="shrink-0 rounded-sm opacity-60 transition-opacity hover:opacity-100"
            @click="dismiss(t.id)"
          >
            <X class="h-3.5 w-3.5" />
          </button>
        </div>
      </TransitionGroup>
    </div>
  </Teleport>
</template>

<style scoped>
.toast-enter-active,
.toast-leave-active {
  transition: all 0.3s ease;
}
.toast-enter-from {
  opacity: 0;
  transform: translateX(100%);
}
.toast-leave-to {
  opacity: 0;
  transform: translateX(100%);
}
</style>
