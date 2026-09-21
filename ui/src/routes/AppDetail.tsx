// One app on this box: what it is, what serves it, and the three things the
// allowlist permits doing to it.
//
// The buttons are a convenience, NOT the boundary. The allowlist is enforced
// server-side in the CLI -- a request for anything but start/stop/restart is
// refused no matter what this page sends, and ui_test.go pins that.
import { useParams } from "@solidjs/router";
import { createResource, createSignal, For, Show } from "solid-js";
import { readReport, runAction } from "@/lib/api";
import { ago } from "@/lib/format";
import { Badge, Dim, Row, Section } from "@/components";
const ACTIONS = ["restart", "start", "stop"] as const;
export default function AppDetail() {
  const params = useParams<{ name: string }>();
  const [app, { refetch }] = createResource(async () => {
    const rep = await readReport();
    return rep.report.apps.find((a) => a.name === params.name) ?? null;
  });
  const [busy, setBusy] = createSignal<string | null>(null);
  // What the box said when it acted. Shown rather than toasted: a command
  // that changed something on somebody's server leaves its answer on screen.
  const [answer, setAnswer] = createSignal<string | null>(null);
  const act = async (action: (typeof ACTIONS)[number]) => {
    if (busy()) return;
    setBusy(action);
    setAnswer(null);
    try {
      const res = await runAction(params.name, action);
      setAnswer(res.output.trim() || `${action}: done`);
    } catch (e) {
      setAnswer(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
      // Re-read after acting: the report is the truth, the button's answer is
      // a moment ago.
      void refetch();
    }
  };
  return (
    <main class="min-h-screen bg-bg">
      <div class="mx-auto max-w-3xl p-4">
        <Show when={app()} fallback={<Dim>{app.error ? `${params.name} is not an app on this box.` : "reading the box…"}</Dim>}>
          {(a) => (
            <>
              <header class="mb-4">
                <h1 class="text-ink text-lg font-semibold">{a().name}</h1>
              </header>

              <Section title="app">
                <Row label="state">
                  <Badge
                    word={
                      a().stopped
                        ? "stopped"
                        : (a().containers ?? []).some((c) => c.state === "running")
                          ? "running"
                          : "down"
                    }
                  />
                </Row>
                <Row label="deployed">{a().version ?? "none"}</Row>
                <Row label="config">{a().config_image ?? "—"}</Row>
                <Show when={a().stopped && a().stopped_at}>
                  <Row label="stopped">{`${ago(a().stopped_at!)}${a().stopped_by ? ` by ${a().stopped_by}` : ""}`}</Row>
                </Show>
              </Section>

              <Section title="actions">
                <div class="flex gap-2.5">
                  <For each={ACTIONS}>
                    {(action) => (
                      <button
                        type="button"
                        disabled={busy() !== null}
                        onClick={() => void act(action)}
                        class="rounded-lg border border-accent px-4 py-2 text-sm font-semibold text-accent min-w-21 disabled:opacity-50">
                        {busy() === action ? "…" : action}
                      </button>
                    )}
                  </For>
                </div>
                <Show when={answer()}>
                  <Dim>{answer()}</Dim>
                </Show>
                <Dim>
                  These three and no others: the allowlist is enforced by the CLI that serves this page, not by it.
                </Dim>
              </Section>

              <Section title="services">
                <Show when={(a().containers ?? []).length === 0}>
                  <Dim>No containers.</Dim>
                </Show>
                <For each={a().containers ?? []}>
                  {(c) => (
                    <div class="flex items-center justify-between gap-3">
                      <span class="min-w-0">
                        <span class="text-ink text-sm">{c.service}</span>
                        <Dim>{c.status ?? c.state}</Dim>
                      </span>
                      <Badge word={c.state} />
                    </div>
                  )}
                </For>
              </Section>

              <Section title="routes">
                <Show when={(a().hosts ?? []).length === 0}>
                  <Dim>This app publishes no hostnames.</Dim>
                </Show>
                <For each={a().hosts ?? []}>
                  {(h) => <Row label={h.name}>{h.service ? `→ ${h.service}` : "→ gate"}</Row>}
                </For>
              </Section>

              <Show when={(a().known_as ?? []).length > 0}>
                <Section title="known as">
                  <Dim>{(a().known_as ?? []).join(", ")}</Dim>
                </Section>
              </Show>
            </>
          )}
        </Show>
      </div>
    </main>
  );
}
