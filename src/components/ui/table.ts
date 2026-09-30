import { defineComponent, h } from "vue";

const tableWrapperClass = "relative w-full overflow-auto";
const tableClass = "w-full caption-bottom text-sm";
const theadClass = "[&_tr]:border-b";
const tbodyClass = "[&_tr:last-child]:border-0";
const trClass = "border-b border-border transition-colors hover:bg-muted/50 data-[state=selected]:bg-muted";
const thClass = "h-10 px-3 text-left align-middle font-medium text-muted-foreground [&:has([role=checkbox])]:pr-0";
const tdClass = "p-3 align-middle [&:has([role=checkbox])]:pr-0";

export const Table = defineComponent({
  name: "Table",
  setup(_, ctx: SetupContext) {
    return () => h("div", { class: tableWrapperClass }, [
      h("table", { class: tableClass }, ctx.slots.default?.()),
    ]);
  },
});

export const TableHeader = defineComponent({
  name: "TableHeader",
  setup(_, ctx: SetupContext) {
    return () => h("thead", { class: theadClass }, ctx.slots.default?.());
  },
});

export const TableBody = defineComponent({
  name: "TableBody",
  setup(_, ctx: SetupContext) {
    return () => h("tbody", { class: tbodyClass }, ctx.slots.default?.());
  },
});

export const TableRow = defineComponent({
  name: "TableRow",
  setup(_, ctx: SetupContext) {
    return () =>
      h("tr", { class: trClass, ...ctx.attrs }, ctx.slots.default?.());
  },
});

export const TableHead = defineComponent({
  name: "TableHead",
  setup(_, ctx: SetupContext) {
    return () =>
      h("th", { class: thClass, ...ctx.attrs }, ctx.slots.default?.());
  },
});

export const TableCell = defineComponent({
  name: "TableCell",
  setup(_, ctx: SetupContext) {
    return () =>
      h("td", { class: tdClass, ...ctx.attrs }, ctx.slots.default?.());
  },
});

// Type import for setup context
import type { SetupContext } from "vue";
