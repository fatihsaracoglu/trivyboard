<script setup lang="ts">
import { watch } from "vue";
import { X } from "@lucide/vue";
import { cn } from "@/lib/utils";

const props = withDefaults(
  defineProps<{
    open: boolean;
    side?: "right" | "left" | "top" | "bottom";
    class?: string;
  }>(),
  {
    side: "right",
    class: "",
  },
);

const emit = defineEmits<{
  "update:open": [value: boolean];
}>();

function close() {
  emit("update:open", false);
}

// Esc closes the sheet.
watch(
  () => props.open,
  (isOpen) => {
    if (!isOpen) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") close();
    };
    window.addEventListener("keydown", handler);
    // Clean up when sheet closes.
    const stop = watch(
      () => props.open,
      (stillOpen) => {
        if (!stillOpen) {
          window.removeEventListener("keydown", handler);
          stop();
        }
      },
    );
  },
  { immediate: true },
);

const sideClasses: Record<string, string> = {
  right: "inset-y-0 right-0 h-full w-full sm:max-w-xl border-l",
  left: "inset-y-0 left-0 h-full w-full sm:max-w-xl border-r",
  top: "inset-x-0 top-0 max-h-[85vh] border-b",
  bottom: "inset-x-0 bottom-0 max-h-[85vh] border-t",
};
</script>

<template>
  <Teleport to="body">
    <Transition name="sheet">
      <div v-if="open" class="fixed inset-0 z-50">
        <!-- Backdrop -->
        <div
          class="absolute inset-0 bg-black/50 backdrop-blur-sm"
          @click="close"
        />
        <!-- Panel -->
        <div
          :class="cn(
            'absolute bg-background shadow-lg flex flex-col',
            sideClasses[side],
            props.class,
          )"
        >
          <!-- Close button -->
          <button
            type="button"
            class="absolute right-4 top-4 z-10 rounded-sm opacity-70 transition-opacity hover:opacity-100 focus:outline-none focus:ring-2 focus:ring-ring"
            @click="close"
          >
            <X class="h-4 w-4" />
            <span class="sr-only">Close</span>
          </button>
          <!-- Content -->
          <div class="flex flex-1 flex-col overflow-hidden">
            <slot />
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<style scoped>
.sheet-enter-active,
.sheet-leave-active {
  transition: opacity 0.2s ease;
}
.sheet-enter-from,
.sheet-leave-to {
  opacity: 0;
}
</style>
