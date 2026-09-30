import { defineComponent, h, type SetupContext } from "vue";

const cardClass = "rounded-lg border border-border bg-card text-card-foreground shadow-sm";
const cardHeaderClass = "flex flex-col space-y-1.5 p-4";
const cardTitleClass = "text-base font-semibold leading-none tracking-tight";
const cardDescriptionClass = "text-sm text-muted-foreground";
const cardContentClass = "p-4 pt-0";

export const Card = defineComponent({
  name: "Card",
  setup(_, ctx) {
    return () => h("div", { class: cardClass }, ctx.slots.default?.());
  },
});

export const CardHeader = defineComponent({
  name: "CardHeader",
  setup(_, ctx) {
    return () => h("div", { class: cardHeaderClass }, ctx.slots.default?.());
  },
});

export const CardTitle = defineComponent({
  name: "CardTitle",
  setup(_, ctx) {
    return () => h("div", { class: cardTitleClass }, ctx.slots.default?.());
  },
});

export const CardDescription = defineComponent({
  name: "CardDescription",
  setup(_, ctx) {
    return () => h("p", { class: cardDescriptionClass }, ctx.slots.default?.());
  },
});

export const CardContent = defineComponent({
  name: "CardContent",
  setup(_, ctx) {
    return () => h("div", { class: cardContentClass }, ctx.slots.default?.());
  },
});
