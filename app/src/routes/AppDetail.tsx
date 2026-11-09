import {A, useParams} from "@solidjs/router";
import {createResource, createSignal, For, Show} from "solid-js";
import {readLogs, readOperation, readStatus, runAction} from "@/lib/api";
import {actionable, deploymentStatus, propose, resourceNumber} from "@/lib/deployment";
import {formatBytes} from "@/lib/format";
import type {ActionName, ActionRequest, Operation} from "@/lib/types";
import {Badge, Dim, Row, Section} from "@/components";
const ACTIONS: ActionName[] = ["start", "stop", "restart", "backup"];

export default function AppDetail() {
  const params = useParams<{application: string; instance: string}>();
  const [instance, {refetch}] = createResource(() => `${params.application}/${params.instance}`, async () => (await readStatus()).status.instances.find(value => value.application === params.application && value.instance === params.instance));
  const [busy, setBusy] = createSignal(false);
  const [pending, setPending] = createSignal<{request: ActionRequest; operation_id: string}>();
  const [result, setResult] = createSignal<Operation>();
  const [message, setMessage] = createSignal("");
  const [logs, setLogs] = createSignal("");
  const [service, setService] = createSignal("");
  const act = async (action: ActionName) => {
    if (busy() || !instance()) return;
    setBusy(true); setResult(undefined); setMessage("");
    try {
      const selected = await propose(instance()!, action); setPending(selected);
      const response = await runAction(selected.request);
      setResult(response.result);
      setMessage(response.confirmation === "unconfirmed" ? response.message || "Admission is unconfirmed. Inspect before another change." : "Host operation observed.");
    } catch (error) {setMessage(`${String(error)}. Inspect the proposed operation before another change.`);}
    finally {setBusy(false); void refetch();}
  };
  const inspect = async () => {
    const selected = pending(); if (!selected || busy()) return;
    setBusy(true);
    try {setResult(await readOperation(selected.request.application, selected.request.instance, selected.operation_id, selected.request.release_digest)); setMessage("Host operation observed.");}
    catch (error) {setMessage(`Operation admission remains unconfirmed: ${String(error)}`);}
    finally {setBusy(false); void refetch();}
  };
  const unresolved = () => pending() && (!result() || result()!.reconciliation_required || !["ready", "prepared_stopped", "failed"].includes(result()!.phase));
  const showLogs = async () => {
    if (!service()) return;
    try {setLogs((await readLogs(params.application, params.instance, service())).text);}
    catch (error) {setLogs(`Logs unavailable: ${String(error)}`);}
  };
  return <main class="min-h-screen bg-bg"><div class="mx-auto max-w-3xl p-4">
    <header class="mb-5 flex items-baseline justify-between"><h1 class="text-ink text-lg font-semibold">{params.application} <span class="text-dim text-sm">{params.instance}</span></h1><A class="text-accent text-sm" href="/">all applications</A></header>
    <Show when={instance.error}><Dim>Host observation unavailable: {String(instance.error)}</Dim></Show>
    <Show when={instance()} fallback={<Dim>{instance.loading ? "Reading application…" : "This instance is unavailable."}</Dim>}>{value => <>
      <Section title="Release"><Row label="status"><Badge word={deploymentStatus(value())}/></Row><Row label="intent">{value().desired_running ? "running" : "stopped"}</Row>
        <Row label="release"><span class="break-all font-mono text-xs">{value().release_digest}</span></Row>
        <Show when={value().source}><Row label="source">{value().source?.repository} · {value().source?.revision.slice(0, 12)}</Row></Show>
        <Show when={value().prepared}><Row label="prepared for start"><span class="break-all font-mono text-xs">{value().prepared?.release_digest}</span></Row></Show>
        <Show when={value().expires_at}><Row label="expires">{new Date(value().expires_at! * 1000).toLocaleString()}</Row></Show>
      </Section>
      <Section title="Resources"><Row label="memory current / limit">{formatBytes(resourceNumber(value().resources, "memory_current_bytes"))} / {formatBytes(resourceNumber(value().resources, "memory_max_bytes"))}</Row>
        <Row label="swap current / limit">{formatBytes(resourceNumber(value().resources, "memory_swap_current_bytes"))} / {formatBytes(resourceNumber(value().resources, "memory_swap_max_bytes"))}</Row>
        <Row label="processes current / limit">{resourceNumber(value().resources, "pids_current") ?? "—"} / {resourceNumber(value().resources, "pids_max") ?? "—"}</Row>
        <Dim>Unavailable measurements are shown as —.</Dim>
      </Section>
      <Section title="Actions"><div class="flex flex-wrap gap-2"><For each={ACTIONS}>{action => <button type="button" class="rounded-lg border border-accent px-4 py-2 text-sm text-accent disabled:opacity-40" disabled={busy() || !!unresolved() || !actionable(value(), action)} onClick={() => void act(action)}>{action === "backup" ? "back up" : action}</button>}</For></div>
        <Show when={(value().unresolved_operations?.length ?? 0) > 0}><Dim>An operation requires inspection before another change.</Dim></Show>
        <Show when={message()}><Dim>{message()}</Dim></Show>
        <Show when={pending()}>{selected => <><Row label="operation"><span class="font-mono text-xs break-all">{selected().operation_id}</span></Row><button type="button" class="text-accent text-sm self-start disabled:opacity-40" disabled={busy()} onClick={() => void inspect()}>inspect operation</button></>}</Show>
        <Show when={result()}>{operation => <Row label="observed outcome"><Badge word={operation().phase}/></Row>}</Show>
      </Section>
      <Section title="Services"><Show when={Object.keys(value().services).length === 0}><Dim>This release serves static assets without application containers.</Dim></Show>
        <For each={Object.entries(value().services)}>{([name, current]) => <Row label={name}><Badge word={current.health || current.state || "unavailable"}/><span>{formatBytes(resourceNumber(current.resources, "memory_current_bytes", "memory_current"))}</span></Row>}</For>
      </Section>
      <Section title="Routes"><Show when={(value().routes?.length ?? 0) === 0}><Dim>No route observation is available.</Dim></Show><For each={value().routes}>{route => <Dim>{route.host}{route.path}</Dim>}</For></Section>
      <Section title="Operation history"><Show when={(value().operations?.length ?? 0) === 0}><Dim>No retained operation observations are available.</Dim></Show><For each={value().operations}>{operation => <Row label={operation.operation_id.slice(0, 12)}><Badge word={operation.phase}/></Row>}</For></Section>
      <Section title="Logs"><div class="flex gap-2"><select class="rounded border border-edge bg-bg p-2 text-ink" value={service()} onChange={event => setService(event.currentTarget.value)}><option value="">select service or job</option><For each={value().log_targets ?? Object.keys(value().services)}>{name => <option value={name}>{name}</option>}</For></select><button type="button" class="text-accent text-sm" disabled={!service()} onClick={() => void showLogs()}>read logs</button></div><Show when={logs()}><pre class="overflow-auto max-h-96 whitespace-pre-wrap break-words text-xs text-ink">{logs()}</pre></Show></Section>
    </>}</Show>
  </div></main>;
}
