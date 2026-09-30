<script setup lang="ts">
import { inject, computed, type Ref } from "vue";

const props = defineProps<{
  value: string;
}>();

const active = inject<Ref<string>>("tabs:active");
const show = computed(() => active?.value === props.value);
</script>

<template>
  <div v-if="show" role="tabpanel" class="mt-2 focus-visible:outline-none">
    <slot />
  </div>
</template>
