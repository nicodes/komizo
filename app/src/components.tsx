// The shared chrome, in plain elements and Tailwind utilities. The palette
// comes from src/index.css's @theme; there is no styling runtime beyond
// Tailwind's compile-time one -- the page is served by the CLI from an
// embedded export, and every runtime in it is code in the trust base of a
// screen that can restart an app.
import type { JSX, ParentProps } from "solid-js";
export function Section(props: ParentProps<{ title: string }>) {
  return (
    <section class="rounded-xl border border-edge bg-card p-4 mb-4 flex flex-col gap-2">
      <h2 class="text-dim text-[13px] uppercase tracking-wider mb-1">{props.title}</h2>
      {props.children}
    </section>
  );
}
export function Row(props: { label: string; children: JSX.Element }) {
  return (
    <div class="flex items-center justify-between gap-3">
      <span class="text-dim text-sm">{props.label}</span>
      <span class="flex items-center gap-2 text-sm text-ink min-w-0">{props.children}</span>
    </div>
  );
}

export function Dim(props: ParentProps) {
  return <p class="text-dim text-[13px] leading-relaxed">{props.children}</p>;
}

// Badge is a state word coloured by whether it is good news. The mapping is
// deliberately small: running/ready/ok are good, stopped/exited/failed are
// not, and anything else is a warning rather than a guess.
export function Badge(props: { word: string }) {
  const color = () => {
    const w = props.word.toLowerCase();
    if (w === "running" || w === "ready" || w === "ok") return "text-good border-good";
    if (w === "stopped" || w === "exited" || w === "failed") return "text-bad border-bad";
    return "text-warn border-warn";
  };
  return (
    <span class={`inline-block rounded-full border px-2.5 py-0.5 text-xs font-semibold ${color()}`}>
      {props.word}
    </span>
  );
}

// Bar is a used/total bar, two divs and a percentage -- a chart library would
// pull a render pipeline into a page that does not need one.
export function Bar(props: { used: number; total: number; alert?: boolean }) {
  const pct = () => (props.total > 0 ? Math.min(100, Math.round((props.used / props.total) * 100)) : 0);
  return (
    <div class="h-2 grow rounded bg-edge overflow-hidden">
      <div
        class="h-2 rounded"
        classList={{ "bg-bad": props.alert === true, "bg-accent": props.alert !== true }}
        style={{ width: `${pct()}%` }}
      />
    </div>
  );
}
