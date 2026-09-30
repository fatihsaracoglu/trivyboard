import { defineComponent, h, computed } from "vue";
import { cn } from "@/lib/utils";

const badgeVariants: Record<string, string> = {
  default: "border-transparent bg-primary text-primary-foreground",
  secondary: "border-transparent bg-secondary text-secondary-foreground",
  destructive: "border-transparent bg-destructive text-destructive-foreground",
  outline: "text-foreground border-border",
};

export const Badge = defineComponent({
  name: "Badge",
  props: {
    variant: { type: String, default: "default" },
    class: { type: String, default: "" },
  },
  setup(props, ctx) {
    return () =>
      h(
        "span",
        {
          class: cn(
            "inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium transition-colors focus:outline-none",
            badgeVariants[props.variant] ?? badgeVariants.default,
            props.class,
          ),
        },
        ctx.slots.default?.(),
      );
  },
});

export const Skeleton = defineComponent({
  name: "Skeleton",
  props: { class: { type: String, default: "" } },
  setup(props, ctx) {
    return () =>
      h("div", {
        class: cn("animate-pulse rounded-md bg-muted", props.class),
        ...ctx.attrs,
      });
  },
});

export const Label = defineComponent({
  name: "Label",
  props: {
    for: { type: String, default: undefined },
    class: { type: String, default: "" },
  },
  setup(props, ctx) {
    return () =>
      h(
        "label",
        {
          for: props.for,
          class: cn(
            "text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70 cursor-pointer",
            props.class,
          ),
        },
        ctx.slots.default?.(),
      );
  },
});

export const Separator = defineComponent({
  name: "Separator",
  props: {
    orientation: { type: String, default: "horizontal" },
    class: { type: String, default: "" },
  },
  setup(props, ctx) {
    return () =>
      h("div", {
        class: cn(
          "shrink-0 bg-border",
          props.orientation === "horizontal" ? "h-px w-full" : "h-full w-px",
          props.class,
        ),
        ...ctx.attrs,
      });
  },
});

export const Progress = defineComponent({
  name: "Progress",
  props: {
    value: { type: Number, default: 0 },
    class: { type: String, default: "" },
  },
  setup(props, ctx) {
    const pct = computed(() => Math.min(100, Math.max(0, props.value)));
    return () =>
      h("div", {
        class: cn("relative h-2 w-full overflow-hidden rounded-full bg-muted", props.class),
        ...ctx.attrs,
      }, [
        h("div", {
          class: "h-full bg-primary transition-all",
          style: { width: `${pct.value}%` },
        }),
      ]);
  },
});
