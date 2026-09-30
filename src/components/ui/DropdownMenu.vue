<script setup lang="ts">
import { ref, onUnmounted } from "vue";
import { cn } from "@/lib/utils";

const props = withDefaults(
  defineProps<{
    align?: "start" | "end";
    class?: string;
  }>(),
  {
    align: "end",
    class: "",
  },
);

const open = ref(false);

function toggle() {
  open.value = !open.value;
}
function close() {
  open.value = false;
}

// Close on outside click.
function onDocClick(e: MouseEvent) {
  const target = e.target as HTMLElement;
  if (!target.closest('[data-dropdown-root]')) {
    close();
  }
}

if (typeof document !== "undefined") {
  document.addEventListener("click", onDocClick);
  onUnmounted(() => document.removeEventListener("click", onDocClick));
}
</script>

<template>
  <div class="relative inline-flex" data-dropdown-root>
    <div @click="toggle">
      <slot name="trigger" />
    </div>
    <Transition name="dropdown">
      <div
        v-if="open"
        :class="cn(
          'absolute z-50 mt-2 min-w-[12rem] overflow-hidden rounded-md border border-border bg-popover p-1 text-popover-foreground shadow-md',
          props.align === 'end' ? 'right-0' : 'left-0',
          props.class,
        )"
        role="menu"
      >
        <slot name="content" />
      </div>
    </Transition>
  </div>
</template>

<style scoped>
.dropdown-enter-active,
.dropdown-leave-active {
  transition: opacity 0.15s ease, transform 0.15s ease;
}
.dropdown-enter-from,
.dropdown-leave-to {
  opacity: 0;
  transform: translateY(-4px);
}
</style>
