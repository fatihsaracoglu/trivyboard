<script setup lang="ts">
import { computed } from "vue";
import { cn } from "@/lib/utils";
import { SEVERITY_COLORS, SEVERITY_ORDER, formatNumber } from "@/lib/format";
import type { Severity, SeverityCounts } from "@/lib/types";

const props = withDefaults(
  defineProps<{
    counts: SeverityCounts;
    active?: Severity | null;
    class?: string;
  }>(),
  { active: null },
);

const emit = defineEmits<{
  select: [severity: Severity];
}>();

interface Slice {
  code: Severity;
  count: number;
  pct: number;
  dash: number;
  offset: number;
  color: string;
}

const total = computed(() =>
  SEVERITY_ORDER.reduce((acc, code) => {
    const key = code.toLowerCase() as keyof SeverityCounts;
    return acc + (props.counts[key] ?? 0);
  }, 0),
);

// Stroke geometry — the circle's circumference = 2πr. We use r=54 so the
// circumference is ~339.29; the value is computed once.
const RADIUS = 54;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

const slices = computed<Slice[]>(() => {
  const out: Slice[] = [];
  let cumulative = 0;
  for (const code of SEVERITY_ORDER) {
    const key = code.toLowerCase() as keyof SeverityCounts;
    const count = props.counts[key] ?? 0;
    const pct = total.value > 0 ? count / total.value : 0;
    const dash = pct * CIRCUMFERENCE;
    // Each segment starts at -offset so it draws clockwise from 12 o'clock.
    const offset = -cumulative * CIRCUMFERENCE;
    out.push({
      code,
      count,
      pct: pct * 100,
      dash,
      offset,
      color: SEVERITY_COLORS[code],
    });
    cumulative += pct;
  }
  return out;
});

const legend = computed(() =>
  SEVERITY_ORDER.map((code) => {
    const key = code.toLowerCase() as keyof SeverityCounts;
    const count = props.counts[key] ?? 0;
    return {
      code,
      count,
      pct: total.value > 0 ? (count / total.value) * 100 : 0,
      color: SEVERITY_COLORS[code],
    };
  }),
);

function onSelect(s: Slice) {
  if (s.count === 0) return;
  if (props.active === s.code) {
    // Clicking the active slice again deselects — emit UNKNOWN as a sentinel
    // is awkward; instead the parent toggles off when receiving the same
    // severity twice. Simpler: just emit and let parent decide.
    emit("select", s.code);
  } else {
    emit("select", s.code);
  }
}
</script>

<template>
  <div :class="cn('flex flex-col items-center gap-4', props.class)">
    <div class="relative h-44 w-44">
      <svg
        viewBox="0 0 130 120"
        class="h-full w-full -rotate-90"
        role="img"
        aria-label="Severity distribution doughnut chart"
      >
        <!-- background ring -->
        <circle
          cx="60"
          cy="60"
          :r="RADIUS"
          fill="none"
          stroke="currentColor"
          stroke-width="14"
          class="text-muted/40"
        />
        <!-- segments -->
        <g v-for="s in slices" :key="s.code">
          <circle
            v-if="s.count > 0"
            cx="60"
            cy="60"
            :r="RADIUS"
            fill="none"
            :stroke="s.color"
            stroke-width="14"
            :stroke-dasharray="`${s.dash} ${CIRCUMFERENCE - s.dash}`"
            :stroke-dashoffset="s.offset"
            :class="cn(
              'cursor-pointer transition-opacity',
              active && active !== s.code && 'opacity-40',
            )"
            @click="onSelect(s)"
          >
            <title>{{ s.code }}: {{ s.count }}</title>
          </circle>
        </g>
      </svg>
      <!-- center label -->
      <div class="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
        <span class="text-[10px] uppercase tracking-wider text-muted-foreground">Total</span>
        <span class="font-mono text-2xl font-semibold tabular-nums text-foreground">
          {{ formatNumber(total) }}
        </span>
        <span class="text-[10px] text-muted-foreground">vulnerabilities</span>
      </div>
    </div>

    <!-- legend -->
    <div class="grid w-full grid-cols-5 gap-1">
      <button
        v-for="l in legend"
        :key="l.code"
        type="button"
        :class="cn(
          'flex flex-col items-center gap-0.5 rounded-md border px-1 py-1 text-[10px] transition-colors',
          active === l.code
            ? 'border-primary bg-primary/10'
            : 'border-border hover:bg-accent/50',
          l.count === 0 && 'opacity-40',
        )"
        :disabled="l.count === 0"
        @click="emit('select', l.code)"
      >
        <span class="flex items-center gap-1">
          <span
            class="inline-block h-2 w-2 rounded-sm"
            :style="{ backgroundColor: l.color }"
          />
          <span class="font-medium uppercase">{{ l.code[0] }}</span>
        </span>
        <span class="font-mono tabular-nums text-foreground">{{ l.count }}</span>
        <span class="text-muted-foreground">{{ l.pct.toFixed(0) }}%</span>
      </button>
    </div>
  </div>
</template>
