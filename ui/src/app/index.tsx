// The one screen v1 is mostly about: this box, read off the box itself.
//
// The shape mirrors the reference app's server detail (status and problems
// first, usage next, apps after), but every byte on it arrived from /api/ on
// the same listener that served this page -- the report the daemon writes,
// the history it samples, the command results it leaves. There is no account,
// no registry, no second service in the path.
import { Link } from 'expo-router';
import React, { useCallback, useEffect, useState } from 'react';
import { Pressable, RefreshControl, ScrollView, StyleSheet, Text, View } from 'react-native';
import { readBackups, readEvents, readMetrics, readReport } from '@/lib/api';
import type { BackupsResponse, BoxEvent, MetricsResponse, Report } from '@/lib/types';
import { ago, Badge, Bar, Body, Dim, formatBytes, formatDuration, Row, Section, theme } from '@/lib/ui';
export default function Overview() {
  const [report, setReport] = useState<Report | null>(null);
  const [events, setEvents] = useState<BoxEvent[]>([]);
  const [metrics, setMetrics] = useState<MetricsResponse | null>(null);
  const [backups, setBackups] = useState<BackupsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  // One load on open and one per refresh gesture. No polling loop: the report
  // itself is written on a timer, and a page that re-asks faster than the box
  // re-measures is reading the same file twice.
  const load = useCallback(async () => {
    try {
      const [rep, ev, met, bak] = await Promise.all([
        readReport(),
        readEvents(),
        readMetrics(),
        readBackups(),
      ]);
      setReport(rep.report);
      setEvents(ev.events);
      setMetrics(met);
      setBackups(bak);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);
  useEffect(() => {
    void load();
  }, [load]);
  if (error) {
    return (
      <View style={styles.center}>
        <Body>could not read this box: {error}</Body>
        <Dim>komizo ui serves what the box wrote -- a box that has never reported has nothing to show yet.</Dim>
      </View>
    );
  }
  if (!report) {
    return (
      <View style={styles.center}>
        <Dim>reading the box…</Dim>
      </View>
    );
  }

  const mem = report.system.mem;
  const memUsed = mem ? mem.total - mem.available : 0;

  return (
    <ScrollView
      style={styles.page}
      contentContainerStyle={styles.content}
      refreshControl={<RefreshControl refreshing={false} onRefresh={() => void load()} tintColor={theme.dim} />}>
      <Section title="server">
        <Row label="state">
          <Badge word={report.server.state} />
        </Row>
        <Row label="os">{report.server.os ?? '—'}</Row>
        <Row label="uptime">{formatDuration(report.server.uptime_s)}</Row>
        <Row label="docker">{report.server.docker ?? '—'}</Row>
        <Row label="agent">{report.server.komizo.agent ?? '—'}</Row>
        <Row label="reported">{ago(report.at)}</Row>
      </Section>

      {report.problems.length > 0 && (
        <Section title="problems">
          {report.problems.map((p, i) => (
            <View key={i} style={styles.problem}>
              <Text style={styles.problemKind}>{p.kind}{p.app ? ` · ${p.app}` : ''}</Text>
              <Dim>{p.detail}</Dim>
            </View>
          ))}
        </Section>
      )}

      <Section title="usage">
        {mem && (
          <View style={styles.usageRow}>
            <Text style={styles.usageLabel}>memory</Text>
            <Bar used={memUsed} total={mem.total} color={memUsed / mem.total > 0.9 ? theme.bad : theme.accent} />
            <Text style={styles.usageValue}>
              {formatBytes(memUsed)} / {formatBytes(mem.total)}
            </Text>
          </View>
        )}
        {(report.system.disks ?? []).map((d) => (
          <View key={d.mount} style={styles.usageRow}>
            <Text style={styles.usageLabel}>{d.mount}</Text>
            <Bar used={d.used} total={d.size} color={d.used / d.size > 0.9 ? theme.bad : theme.accent} />
            <Text style={styles.usageValue}>
              {formatBytes(d.used)} / {formatBytes(d.size)}
            </Text>
          </View>
        ))}
        {report.system.cores !== undefined && <Dim>{report.system.cores} cores</Dim>}
      </Section>

      <Section title="apps">
        {report.apps.length === 0 && <Dim>No apps yet. `komizo add` puts one here.</Dim>}
        {report.apps.map((a) => (
          <Link key={a.name} href={`/app/${encodeURIComponent(a.name)}`} asChild>
            <Pressable style={styles.appRow}>
              <View style={{ flexShrink: 1 }}>
                <Body>{a.name}</Body>
                <Dim>
                  {a.version ?? 'none'}
                  {(a.hosts ?? []).length > 0 ? ` · ${(a.hosts ?? []).map((h) => h.name).join(', ')}` : ''}
                </Dim>
              </View>
              <Badge word={a.stopped ? 'stopped' : (a.containers ?? []).some((c) => c.state === 'running') ? 'running' : 'down'} />
            </Pressable>
          </Link>
        ))}
        {(report.orphans ?? []).length > 0 && (
          <Dim>orphan directories: {(report.orphans ?? []).join(', ')}</Dim>
        )}
      </Section>

      <Section title="proxy & network">
        {report.proxy ? (
          <>
            <Row label="proxy">
              <Badge word={report.proxy.state} />
            </Row>
            <Row label="image">{report.proxy.image ?? '—'}</Row>
            {report.proxy.tls_ask !== undefined && report.proxy.tls_ask !== '' && (
              <Row label="on-demand tls">{report.proxy.tls_ask}</Row>
            )}
          </>
        ) : (
          <Dim>No shared proxy on this box.</Dim>
        )}
        {report.network && (
          <Row label="network">{`${report.network.name} · ${(report.network.members ?? []).length} attached`}</Row>
        )}
        {metrics && metrics.metrics.rows.length > 0 && (
          <Dim>
            requests in the measured window:{' '}
            {metrics.metrics.rows.reduce((n, r) => n + (r.c2 ?? 0) + (r.c3 ?? 0) + (r.c4 ?? 0) + (r.c5 ?? 0), 0)}
          </Dim>
        )}
      </Section>

      <Section title="events">
        {events.length === 0 && <Dim>Nothing has been told to this box yet.</Dim>}
        {events.map((e) => (
          <View key={e.id} style={styles.eventRow}>
            <Badge word={e.ok ? 'ok' : 'failed'} />
            <View style={{ flexShrink: 1 }}>
              <Body>{e.op}</Body>
              <Dim>
                {ago(e.at)}
                {e.detail ? ` · ${e.detail}` : ''}
              </Dim>
            </View>
          </View>
        ))}
      </Section>

      <Section title="backups">
        <Dim>{backups?.note ?? '—'}</Dim>
      </Section>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  page: { flex: 1, backgroundColor: theme.bg },
  content: { padding: 16, maxWidth: 760, width: '100%', alignSelf: 'center' },
  center: { flex: 1, backgroundColor: theme.bg, alignItems: 'center', justifyContent: 'center', padding: 24, gap: 8 },
  problem: { gap: 2 },
  problemKind: { color: theme.warn, fontSize: 14, fontWeight: '600' },
  usageRow: { flexDirection: 'row', alignItems: 'center', gap: 10 },
  usageLabel: { color: theme.dim, fontSize: 13, width: 110 },
  usageValue: { color: theme.text, fontSize: 12, width: 130, textAlign: 'right' },
  appRow: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', gap: 12, paddingVertical: 6 },
  eventRow: { flexDirection: 'row', alignItems: 'center', gap: 10 },
});
