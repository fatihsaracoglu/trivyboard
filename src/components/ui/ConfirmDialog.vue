<script setup lang="ts">
// ConfirmDialog — a reusable confirmation popup dialog.
// Renders a centered modal with a title, message, and Cancel/Confirm buttons.
import { AlertTriangle, Loader2 } from "@lucide/vue";
import Button from "@/components/ui/Button.vue";

const props = withDefaults(
    defineProps<{
      open: boolean;
      title?: string;
      message?: string;
      confirmLabel?: string;
      cancelLabel?: string;
      variant?: "destructive" | "default";
      loading?: boolean;
    }>(),
    {
      title: "Confirm",
      message: "Are you sure?",
      confirmLabel: "Confirm",
      cancelLabel: "Cancel",
      variant: "default",
      loading: false,
    },
);

const emit = defineEmits<{
  confirm: [];
  cancel: [];
}>();
</script>

<template>
  <Teleport to="body">
    <Transition name="dialog">
      <div v-if="open" class="fixed inset-0 z-[100] flex items-center justify-center p-4">
        <!-- Backdrop -->
        <div
            class="absolute inset-0 bg-black/50 backdrop-blur-sm"
            @click="emit('cancel')"
        />
        <!-- Dialog -->
        <div class="relative w-full max-w-sm rounded-lg border border-border bg-card p-6 shadow-lg">
          <div class="flex items-start gap-3">
            <div
                v-if="variant === 'destructive'"
                class="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-destructive/10 text-destructive"
            >
              <AlertTriangle class="h-5 w-5" />
            </div>
            <div class="flex-1 min-w-0">
              <h3 class="text-base font-semibold text-foreground">{{ title }}</h3>
              <p class="mt-1 text-sm text-muted-foreground">{{ message }}</p>
            </div>
          </div>
          <div class="mt-5 flex items-center justify-end gap-2">
            <Button variant="outline" size="sm" @click="emit('cancel')" :disabled="loading">
              {{ cancelLabel }}
            </Button>
            <Button
                :variant="variant === 'destructive' ? 'destructive' : 'default'"
                size="sm"
                @click="emit('confirm')"
                :disabled="loading"
            >
              <Loader2 v-if="loading" class="mr-1.5 h-3.5 w-3.5 animate-spin" />
              {{ confirmLabel }}
            </Button>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<style scoped>
.dialog-enter-active,
.dialog-leave-active {
  transition: opacity 0.2s ease;
}
.dialog-enter-from,
.dialog-leave-to {
  opacity: 0;
}
</style>
