<script setup lang="ts">
import { computed } from "vue";
import { cn } from "@/lib/utils";
import { ChevronDown } from "@lucide/vue";

const props = withDefaults(
  defineProps<{
    modelValue?: string;
    disabled?: boolean;
    class?: string;
  }>(),
  {
    modelValue: "",
    disabled: false,
  },
);

const emit = defineEmits<{
  "update:modelValue": [value: string];
}>();

const classes = computed(() =>
  cn(
    "flex h-8 w-full items-center justify-between rounded-md border border-input bg-transparent px-3 py-1 text-xs shadow-sm focus:outline-none focus:ring-1 focus:ring-ring disabled:cursor-not-allowed disabled:opacity-50",
    props.class,
  ),
);

function onChange(e: Event) {
  emit("update:modelValue", (e.target as HTMLSelectElement).value);
}
</script>

<template>
  <div :class="cn('relative', disabled && 'opacity-50')">
    <select
      :value="modelValue"
      :disabled="disabled"
      :class="classes"
      @change="onChange"
      style="appearance: none; -webkit-appearance: none; -moz-appearance: none; padding-right: 28px;"
    >
      <slot />
    </select>
    <ChevronDown class="pointer-events-none absolute right-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
  </div>
</template>
