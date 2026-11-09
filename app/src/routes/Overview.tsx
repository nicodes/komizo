import {A} from "@solidjs/router";
import {createResource, createSignal, For, Show} from "solid-js";
import {readHistory, readStatus} from "@/lib/api";
import {deploymentStatus, resourceNumber} from "@/lib/deployment";
import {collectOverview} from "@/lib/overview";
import {ago, formatBytes} from "@/lib/format";
import {Badge, Dim, Row, Section} from "@/components";

export default function Overview() {
  const [generation, setGeneration] = createSignal(0);
  const [view] = createResource(generation, () => collectOverview({status: readStatus, history: readHistory}));
  const current = () => view()?.status;
  const resources = () => current()?.status.host?.resources;
  return <main class="min-h-screen bg-bg"><div class="mx-auto max-w-3xl p-4">
    <header class="mb-5 flex items-baseline justify-between"><h1 class="text-ink text-lg font-semibold">komizo</h1>
      <button class="text-accent text-sm disabled:opacity-50" disabled={view.loading} onClick={() => setGeneration(value => value + 1)} type="button">{view.loading ? "refreshing…" : "refresh"}</button></header>
    <Show when={view()?.errors.status}><Section title="Host unavailable"><Dim>{view()?.errors.status}</Dim><Dim>The local UI is running. The remote host has not supplied a current observation.</Dim></Section></Show>
    <Show when={current()} fallback={<Dim>{view.loading ? "Reading owner host…" : "No current host observation."}</Dim>}>{value => <>
      <Section title="Host"><Row label="host">{value().host}</Row><Row label="observed">{ago(value().captured_at)}</Row>
        <Row label="memory total">{formatBytes(resourceNumber(resources(), "memory_total_bytes"))}</Row>
        <Row label="memory available">{formatBytes(resourceNumber(resources(), "memory_available_bytes"))}</Row>
        <Row label="swap free">{formatBytes(resourceNumber(resources(), "swap_free_bytes"))} / {formatBytes(resourceNumber(resources(), "swap_total_bytes"))}</Row>
        <Show when={value().status.host?.boot_id}><Row label="boot">{value().status.host?.boot_id?.slice(0, 12)}</Row></Show>
      </Section>
      <Section title="Applications"><Show when={value().status.instances.length === 0}><Dim>No accepted application instances.</Dim></Show>
        <For each={value().status.instances}>{instance => <A class="flex justify-between gap-3 rounded-lg border border-edge p-3" href={`/app/${encodeURIComponent(instance.application)}/${encodeURIComponent(instance.instance)}`}>
          <span><span class="text-ink font-semibold">{instance.application}</span><Dim>{instance.instance} · {instance.source?.revision.slice(0, 12) ?? instance.release_digest.slice(7, 19)}</Dim></span>
          <Badge word={deploymentStatus(instance)}/>
        </A>}</For>
      </Section>
    </>}</Show>
    <Section title="Recent observations"><Dim>Samples collected by this local UI session. Application operation history is retained by the host.</Dim>
      <Show when={(view()?.history?.samples.length ?? 0) === 0}><Dim>No successful observations collected yet.</Dim></Show>
      <For each={view()?.history?.samples.slice(-5).reverse()}>{sample => <Row label={ago(sample.captured_at)}>{sample.status.instances.length} instances · {formatBytes(resourceNumber(sample.status.host?.resources, "memory_available_bytes"))} available</Row>}</For>
      <Show when={view()?.errors.history}><Dim>{view()?.errors.history}</Dim></Show>
    </Section>
  </div></main>;
}
