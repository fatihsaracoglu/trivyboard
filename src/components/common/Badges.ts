import { defineComponent, h } from "vue";
import { cn } from "@/lib/utils";
import {
  SEVERITY_BG,
  PRIORITY_COLORS,
  PRIORITY_DESCRIPTIONS,
  FINDING_KIND_COLORS,
  FINDING_KIND_LABELS,
} from "@/lib/format";
import type { Severity, PriorityLevel, FindingKind } from "@/lib/types";

const severityLabels: Record<Severity, string> = {
  CRITICAL: "Critical",
  HIGH: "High",
  MEDIUM: "Medium",
  LOW: "Low",
  UNKNOWN: "Unknown",
};

export const SeverityBadge = defineComponent({
  name: "SeverityBadge",
  props: {
    severity: { type: String as () => Severity, required: true },
    class: { type: String, default: "" },
  },
  setup(props, ctx) {
    return () =>
      h(
        "span",
        {
          class: cn(
            "inline-flex items-center rounded-md border px-2 py-0.5 text-[11px] font-medium uppercase tracking-wide",
            SEVERITY_BG[props.severity] ?? SEVERITY_BG.UNKNOWN,
            props.class,
          ),
          title: severityLabels[props.severity],
        },
        [
          h("span", { class: "h-1.5 w-1.5 rounded-full", style: { backgroundColor: "currentColor" } }),
          h("span", { class: "ml-1" }, severityLabels[props.severity]),
        ],
      );
  },
});

export const PriorityBadge = defineComponent({
  name: "PriorityBadge",
  props: {
    level: { type: String as () => PriorityLevel, required: true },
    class: { type: String, default: "" },
  },
  setup(props, ctx) {
    return () =>
      h(
        "span",
        {
          class: cn(
            "inline-flex items-center justify-center rounded px-1.5 py-0.5 text-[11px] font-bold tracking-wide",
            PRIORITY_COLORS[props.level] ?? PRIORITY_COLORS.P4,
            props.class,
          ),
          title: PRIORITY_DESCRIPTIONS[props.level] ?? "",
        },
        props.level,
      );
  },
});

export const FindingKindBadge = defineComponent({
  name: "FindingKindBadge",
  props: {
    kind: { type: String as () => FindingKind, required: true },
    class: { type: String, default: "" },
  },
  setup(props, ctx) {
    return () =>
      h(
        "span",
        {
          class: cn(
            "inline-flex items-center rounded-md border px-2 py-0.5 text-[11px] font-medium",
            FINDING_KIND_COLORS[props.kind] ?? FINDING_KIND_COLORS.misconfiguration,
            props.class,
          ),
        },
        FINDING_KIND_LABELS[props.kind] ?? props.kind,
      );
  },
});
