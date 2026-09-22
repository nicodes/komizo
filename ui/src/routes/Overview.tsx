// The one screen v1 is mostly about: this box, read off the box itself.
//
// The shape mirrors the RN-port overview (status and problems first, usage
// next, apps after), and every byte on it arrived from /api/ on the same
// listener that served this page -- the report the daemon writes, the command
// results it leaves. There is no account, no registry, no second service in
// the path.
import { A } from "@solidjs/router";
import { createResource, For, Show } from "solid-js";
import { readBackups, readEvents, readMetrics, readReport } from "@/lib/api";
import { ago, formatBytes, formatDuration } from "@/lib/format";
import { Badge, Bar, Dim, Row, Section } from "@/components";
export default function Overview() {
  // One load on open and one per refresh click. No polling loop: the report
  // itself is written on a timer, and a page that re-asks faster than the box
  // re-measures is reading the same file twice.
  const [report, { refetch }] = createResource(async () => (await readReport()).report);
  const [events] = createResource(async () => (await readEvents()).events);
  const [metrics] = createResource(async () => await readMetrics());
  const [backups] = createResource(async () => await readBackups());
  const requestTotal = () =>
    (metrics()?.metrics.rows ?? []).reduce((n, r) => n + (r.c2 ?? 0) + (r.c3 ?? 0) + (r.c4 ?? 0) + (r.c5 ?? 0), 0);
  return (
    <main class="min-h-screen bg-bg">
      <div class="mx-auto max-w-3xl p-4">
        <header class="mb-4 flex items-baseline justify-between">
          <h1 class="text-ink text-lg font-semibold">komizo</h1>
          <button
            class="text-accent text-sm hover:underline"
            onClick={() => void refetch()}
            type="button">
            refresh
          </button>
        </header>

        <Show when={report.error}>
          <Section title="could not read this box">
            <Dim>{String(report.error)}</Dim>
            <Dim>komizo ui serves what the box wrote -- a box that has never reported has nothing to show yet.</Dim>
          </Section>
        </Show>

        <Show when={report()} fallback={<Dim>reading the box…</Dim>}>
          {(rep) => {
            const mem = () => rep().system.mem;
            const memUsed = () => (mem() ? mem()!.total - mem()!.available : 0);
            return (
              <>
                <Section title="server">
                  <Row label="state">
                    <Badge word={rep().server.state} />
                  </Row>
                  <Row label="os">{rep().server.os ?? "—"}</Row>
                  <Row label="uptime">{formatDuration(rep().server.uptime_s)}</Row>
                  <Row label="docker">{rep().server.docker ?? "—"}</Row>
                  <Row label="agent">{rep().server.komizo.agent ?? "—"}</Row>
                  <Row label="reported">{ago(rep().at)}</Row>
                </Section>

                <Show when={rep().problems.length > 0}>
                  <Section title="problems">
                    <For each={rep().problems}>
                      {(p) => (
                        <div>
                          <p class="text-warn text-sm font-semibold">
                            {p.kind}
                            {p.app ? ` · ${p.app}` : ""}
                          </p>
                          <Dim>{p.detail}</Dim>
                        </div>
                      )}
                    </For>
                  </Section>
                </Show>

                <Section title="usage">
                  <Show when={mem()}>
                    {(m) => (
                      <div class="flex items-center gap-2.5">
                        <span class="text-dim text-[13px] w-28">memory</span>
                        <Bar used={memUsed()} total={m().total} alert={memUsed() / m().total > 0.9} />
                        <span class="text-ink text-xs w-32 text-right">
                          {formatBytes(memUsed())} / {formatBytes(m().total)}
                        </span>
                      </div>
                    )}
                  </Show>
                  <For each={rep().system.disks ?? []}>
                    {(d) => (
                      <div class="flex items-center gap-2.5">
                        <span class="text-dim text-[13px] w-28">{d.mount}</span>
                        <Bar used={d.used} total={d.size} alert={d.used / d.size > 0.9} />
                        <span class="text-ink text-xs w-32 text-right">
                          {formatBytes(d.used)} / {formatBytes(d.size)}
                        </span>
                      </div>
                    )}
                  </For>
                  <Show when={rep().system.cores !== undefined}>
                    <Dim>{rep().system.cores} cores</Dim>
                  </Show>
                </Section>

                <Section title="apps">
                  <Show when={rep().apps.length === 0}>
                    <Dim>No apps yet. `komizo add` puts one here.</Dim>
                  </Show>
                  <For each={rep().apps}>
                    {(a) => (
                      <A
                        href={`/app/${encodeURIComponent(a.name)}`}
                        class="flex items-center justify-between gap-3 py-1.5 group">
                        <span class="min-w-0">
                          <span class="text-ink text-sm group-hover:text-accent">{a.name}</span>
                          <Dim>
                            {a.version ?? "none"}
                            {(a.hosts ?? []).length > 0 ? ` · ${(a.hosts ?? []).map((h) => h.name).join(", ")}` : ""}
                          </Dim>
                        </span>
                        <Badge
                          word={
                            a.stopped
                              ? "stopped"
                              : (a.containers ?? []).some((c) => c.state === "running")
                                ? "running"
                                : "down"
                          }
                        />
                      </A>
                    )}
                  </For>
                  <Show when={(rep().orphans ?? []).length > 0}>
                    <Dim>orphan directories: {(rep().orphans ?? []).join(", ")}</Dim>
                  </Show>
                </Section>

                <Section title="proxy & network">
                  <Show when={rep().proxy} fallback={<Dim>No shared proxy on this box.</Dim>}>
                    {(p) => (
                      <>
                        <Row label="proxy">
                          <Badge word={p().state} />
                        </Row>
                        <Row label="image">{p().image ?? "—"}</Row>
                        <Show when={p().tls_ask}>
                          <Row label="on-demand tls">{p().tls_ask}</Row>
                        </Show>
                      </>
                    )}
                  </Show>
                  <Show when={rep().network}>
                    {(n) => <Row label="network">{`${n().name} · ${(n().members ?? []).length} attached`}</Row>}
                  </Show>
                  <Show when={metrics() && metrics()!.metrics.rows.length > 0}>
                    <Dim>requests in the measured window: {requestTotal()}</Dim>
                  </Show>
                </Section>

                <Section title="events">
                  <Show when={(events() ?? []).length === 0}>
                    <Dim>Nothing has been told to this box yet.</Dim>
                  </Show>
                  <For each={events() ?? []}>
                    {(e) => (
                      <div class="flex items-center gap-2.5">
                        <Badge word={e.ok ? "ok" : "failed"} />
                        <span class="min-w-0">
                          <span class="text-ink text-sm">{e.op}</span>
                          <Dim>
                            {ago(e.at)}
                            {e.detail ? ` · ${e.detail}` : ""}
                          </Dim>
                        </span>
                      </div>
                    )}
                  </For>
                </Section>

                <Show when={rep().sweep}>
                  {(sw) => (
                    <Section title="disk hygiene">
                      <Row label="last sweep">{ago(sw().at)}</Row>
                      <Row label="swept">
                        {`${sw().removed} dangling image${sw().removed === 1 ? "" : "s"} · ${formatBytes(sw().reclaimed_bytes)} reclaimed`}
                      </Row>
                      <Show when={sw().skipped > 0}>
                        <Row label="kept">{`${sw().skipped} (docker or the rules said no)`}</Row>
                      </Show>
                      <Show when={sw().note}>
                        <Dim>{sw().note}</Dim>
                      </Show>
                      <Dim>Only dangling images older than {sw().min_age_days} days are ever swept — tagged images, anything a container references, volumes, and anything state names are always kept.</Dim>
                    </Section>
                  )}
                </Show>

                <Section title="backups">
                  <Dim>{backups()?.note ?? "—"}</Dim>
                </Section>
              </>
            );
          }}
        </Show>
      </div>
    </main>
  );
}
