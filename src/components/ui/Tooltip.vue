<script setup lang="ts">
import { ref } from "vue";
import { cn } from "@/lib/utils";

const props = withDefaults(
  defineProps<{
    side?: "top" | "right" | "bottom" | "left";
    class?: string;
    block?: boolean;
  }>(),
  {
    side: "top",
    class: "",
    block: false,
  },
);

const show = ref(false);
let timer: ReturnType<typeof setTimeout> | null = null;

function onEnter() {
  if (timer) clearTimeout(timer);
  timer = setTimeout(() => { show.value = true; }, 150);
}
function onLeave() {
  if (timer) clearTimeout(timer);
  timer = setTimeout(() => { show.value = false; }, 100);
}

const sideClasses: Record<string, string> = {
  top: "bottom-full left-1/2 -translate-x-1/2 mb-2",
  right: "left-full top-1/2 -translate-y-1/2 ml-2",
  bottom: "top-full left-1/2 -translate-x-1/2 mt-2",
  left: "right-full top-1/2 -translate-y-1/2 mr-2",
};

const wrapperClass = cn(
  "relative",
  props.block ? "block w-full" : "inline-flex",
);
</script>

<template>
  <div
    :class="wrapperClass"
    @mouseenter="onEnter"
    @mouseleave="onLeave"
    @focusin="onEnter"
    @focusout="onLeave"
  >
    <slot name="trigger" />
    <Transition name="tooltip">
      <div
        v-if="show"
        :class="cn(
          'absolute z-50 overflow-hidden rounded-md bg-primary px-3 py-1.5 text-xs text-primary-foreground shadow-md whitespace-nowrap pointer-events-none',
          sideClasses[side],
          props.class,
        )"
        role="tooltip"
      >
        <slot name="content" />
      </div>
    </Transition>
  </div>
</template>

<style scoped>
.tooltip-enter-active,
.tooltip-leave-active {
  transition: opacity 0.15s ease, transform 0.15s ease;
}
.tooltip-enter-from,
.tooltip-leave-to {
  opacity: 0;
  transform: translateX(0) scale(0.95);
}
</style>
