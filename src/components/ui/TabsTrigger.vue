<script setup lang="ts">
import { inject, computed, type Ref } from "vue";
import { cn } from "@/lib/utils";

const props = defineProps<{
  value: string;
  disabled?: boolean;
}>();

const active = inject<Ref<string>>("tabs:active");
const setActive = inject<(v: string) => void>("tabs:setActive");

const isActive = computed(() => active?.value === props.value);

function onClick() {
  if (props.disabled) return;
  setActive?.(props.value);
}
</script>

<template>
  <button
    type="button"
    role="tab"
    :disabled="disabled"
    :class="cn(
      'inline-flex items-center justify-center gap-1.5 whitespace-nowrap rounded-md px-3 py-1 text-sm font-medium ring-offset-background transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50',
      isActive ? 'bg-background text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground',
    )"
    @click="onClick"
  >
    <slot />
  </button>
</template>
