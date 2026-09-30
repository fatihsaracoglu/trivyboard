<script setup lang="ts">
import { computed } from "vue";
import { cn } from "@/lib/utils";

type Accent = "neutral" | "critical" | "high" | "medium" | "low" | "emerald" | "sky";

const props = withDefaults(
  defineProps<{
    label: string;
    value: number | string;
    accent?: Accent;
    hint?: string;
    active?: boolean;
    icon?: unknown;
    clickable?: boolean;
  }>(),
  {
    accent: "neutral",
    active: false,
    clickable: false,
  },
);

defineEmits<{
  click: [];
}>();

const accentRail: Record<Accent, string> = {
  neutral: "bg-muted-foreground/50",
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-yellow-500",
  low: "bg-sky-500",
  emerald: "bg-emerald-500",
  sky: "bg-sky-500",
};

const accentText: Record<Accent, string> = {
  neutral: "text-foreground",
  critical: "text-red-600 dark:text-red-400",
  high: "text-orange-600 dark:text-orange-400",
  medium: "text-yellow-600 dark:text-yellow-400",
  low: "text-sky-600 dark:text-sky-400",
  emerald: "text-emerald-600 dark:text-emerald-400",
  sky: "text-sky-600 dark:text-sky-400",
};

const valueDisplay = computed(() => {
  if (typeof props.value === "number") {
    return new Intl.NumberFormat("en-US").format(props.value);
  }
  return props.value;
});
</script>

<template>
  <component
    :is="clickable ? 'button' : 'div'"
    :type="clickable ? 'button' : undefined"
    :class="cn(
      'relative w-full overflow-hidden rounded-lg border bg-card p-4 text-left shadow-sm transition-colors',
      clickable && 'cursor-pointer hover:bg-accent/40 focus:outline-none focus-visible:ring-2 focus-visible:ring-ring',
      active && 'border-primary ring-1 ring-primary/30 bg-accent/30',
      !active && 'border-border',
    )"
    @click="clickable ? $emit('click') : undefined"
  >
    <!-- left accent rail -->
    <span :class="cn('absolute left-0 top-0 h-full w-1', accentRail[accent])" />
    <div class="flex flex-col gap-1 pl-2">
      <div class="flex items-center justify-between">
        <span class="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
          {{ label }}
        </span>
        <component
          v-if="icon"
          :is="icon"
          :class="cn('h-4 w-4', accentText[accent])"
        />
      </div>
      <div :class="cn('font-mono text-2xl font-semibold tabular-nums', accentText[accent])">
        {{ valueDisplay }}
      </div>
      <div v-if="hint" class="text-[11px] text-muted-foreground">{{ hint }}</div>
    </div>
  </component>
</template>
