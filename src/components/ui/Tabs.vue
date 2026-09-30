<script setup lang="ts">
import { provide, ref, watch } from "vue";

const props = defineProps<{
  modelValue: string;
}>();

const emit = defineEmits<{
  "update:modelValue": [value: string];
}>();

const active = ref(props.modelValue);
watch(() => props.modelValue, (v) => { active.value = v; });
watch(active, (v) => emit("update:modelValue", v));

// Provide the active value + setter to child TabsTrigger/TabsContent via inject.
provide("tabs:active", active);
provide("tabs:setActive", (v: string) => { active.value = v; });
</script>

<template>
  <div class="w-full">
    <slot />
  </div>
</template>
