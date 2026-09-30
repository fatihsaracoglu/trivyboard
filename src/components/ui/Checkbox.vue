<script setup lang="ts">
import { computed } from "vue";
import { cn } from "@/lib/utils";
import { Check } from "@lucide/vue";

const props = withDefaults(
  defineProps<{
    modelValue?: boolean;
    disabled?: boolean;
    id?: string;
  }>(),
  {
    modelValue: false,
    disabled: false,
  },
);

const emit = defineEmits<{
  "update:modelValue": [value: boolean];
}>();

function toggle() {
  if (props.disabled) return;
  emit("update:modelValue", !props.modelValue);
}

const classes = computed(() =>
  cn(
    "flex h-4 w-4 items-center justify-center rounded border transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-1",
    props.modelValue
      ? "border-primary bg-primary text-primary-foreground"
      : "border-input bg-background",
    props.disabled && "cursor-not-allowed opacity-50",
  ),
);
</script>

<template>
  <button
    type="button"
    role="checkbox"
    :id="id"
    :aria-checked="modelValue"
    :disabled="disabled"
    :class="classes"
    @click="toggle"
  >
    <Check v-if="modelValue" class="h-3 w-3" />
  </button>
</template>
