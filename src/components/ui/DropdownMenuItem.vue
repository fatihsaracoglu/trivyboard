<script setup lang="ts">
import { cn } from "@/lib/utils";

const props = withDefaults(
  defineProps<{
    disabled?: boolean;
    class?: string;
  }>(),
  {
    disabled: false,
    class: "",
  },
);
</script>

<template>
  <button
    type="button"
    role="menuitem"
    :disabled="disabled"
    :class="cn(
      'relative flex w-full cursor-pointer select-none items-center rounded-sm px-2 py-1.5 text-xs outline-none transition-colors focus:bg-accent focus:text-accent-foreground hover:bg-accent hover:text-accent-foreground disabled:pointer-events-none disabled:opacity-50',
      props.class,
    )"
  >
    <slot />
  </button>
</template>
