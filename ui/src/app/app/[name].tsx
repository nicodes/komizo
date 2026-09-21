// One app on this box: what it is, what serves it, and the three things the
// allowlist permits doing to it.
//
// The buttons are a convenience, NOT the boundary. The allowlist is enforced
// server-side in the CLI -- a request for anything but start/stop/restart is
// refused no matter what this page sends, and ui_test.go pins that.
import { Stack, useLocalSearchParams } from 'expo-router';
import React, { useCallback, useEffect, useState } from 'react';
import { ActivityIndicator, Pressable, ScrollView, StyleSheet, Text, View } from 'react-native';
import { readReport, runAction } from '@/lib/api';
import type { App } from '@/lib/types';
import { ago, Badge, Body, Dim, Row, Section, theme } from '@/lib/ui';
const ACTIONS = ['restart', 'start', 'stop'] as const;
export default function AppDetail() {
  const { name } = useLocalSearchParams<{ name: string }>();
  const [app, setApp] = useState<App | null>(null);
  const [missing, setMissing] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  // What the box said when it acted. Shown rather than toasted: a command
  // that changed something on somebody's server leaves its answer on screen.
  const [answer, setAnswer] = useState<string | null>(null);
  const load = useCallback(async () => {
    const rep = await readReport();
    const found = rep.report.apps.find((a) => a.name === name) ?? null;
    setApp(found);
    setMissing(!found);
  }, [name]);
  useEffect(() => {
    void load().catch(() => setMissing(true));
  }, [load]);
  const act = async (action: (typeof ACTIONS)[number]) => {
    if (!name || busy) return;
    setBusy(action);
    setAnswer(null);
    try {
      const res = await runAction(name, action);
      setAnswer(res.output.trim() || `${action}: done`);
    } catch (e) {
      setAnswer(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
      // Re-read after acting: the report is the truth, the button's answer is
      // a moment ago.
      void load().catch(() => undefined);
    }
  };
  if (missing) {
    return (
      <View style={styles.center}>
        <Body>{name} is not an app on this box.</Body>
      </View>
    );
  }
  if (!app) {
    return (
      <View style={styles.center}>
        <Dim>reading the box…</Dim>
      </View>
    );
  }

  return (
    <ScrollView style={styles.page} contentContainerStyle={styles.content}>
      <Stack.Screen options={{ title: app.name }} />

      <Section title="app">
        <Row label="state">
          <Badge word={app.stopped ? 'stopped' : (app.containers ?? []).some((c) => c.state === 'running') ? 'running' : 'down'} />
        </Row>
        <Row label="deployed">{app.version ?? 'none'}</Row>
        <Row label="config">{app.config_image ?? '—'}</Row>
        {app.stopped && app.stopped_at && (
          <Row label="stopped">{`${ago(app.stopped_at)}${app.stopped_by ? ` by ${app.stopped_by}` : ''}`}</Row>
        )}
      </Section>

      <Section title="actions">
        <View style={styles.actions}>
          {ACTIONS.map((a) => (
            <Pressable
              key={a}
              onPress={() => void act(a)}
              disabled={busy !== null}
              style={[styles.actionButton, busy !== null && styles.actionDisabled]}>
              {busy === a ? <ActivityIndicator color={theme.text} /> : <Text style={styles.actionText}>{a}</Text>}
            </Pressable>
          ))}
        </View>
        {answer && <Dim>{answer}</Dim>}
        <Dim>
          These three and no others: the allowlist is enforced by the CLI that serves this page, not by it.
        </Dim>
      </Section>

      <Section title="services">
        {(app.containers ?? []).length === 0 && <Dim>No containers.</Dim>}
        {(app.containers ?? []).map((c) => (
          <View key={c.name} style={styles.serviceRow}>
            <View style={{ flexShrink: 1 }}>
              <Body>{c.service}</Body>
              <Dim>{c.status ?? c.state}</Dim>
            </View>
            <Badge word={c.state} />
          </View>
        ))}
      </Section>

      <Section title="routes">
        {(app.hosts ?? []).length === 0 && <Dim>This app publishes no hostnames.</Dim>}
        {(app.hosts ?? []).map((h) => (
          <Row key={h.name} label={h.name}>
            {h.service ? `→ ${h.service}` : '→ gate'}
          </Row>
        ))}
      </Section>

      {(app.known_as ?? []).length > 0 && (
        <Section title="known as">
          <Dim>{(app.known_as ?? []).join(', ')}</Dim>
        </Section>
      )}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  page: { flex: 1, backgroundColor: theme.bg },
  content: { padding: 16, maxWidth: 760, width: '100%', alignSelf: 'center' },
  center: { flex: 1, backgroundColor: theme.bg, alignItems: 'center', justifyContent: 'center', padding: 24 },
  actions: { flexDirection: 'row', gap: 10 },
  actionButton: {
    borderWidth: 1,
    borderColor: theme.accent,
    borderRadius: 8,
    paddingHorizontal: 18,
    paddingVertical: 8,
    minWidth: 84,
    alignItems: 'center',
  },
  actionDisabled: { opacity: 0.5 },
  actionText: { color: theme.accent, fontSize: 14, fontWeight: '600' },
  serviceRow: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', gap: 12 },
});
