// The shared chrome: a dark theme, one section card, one labelled row, one
// bar. Plain Views and StyleSheet -- no styling runtime, no chart library --
// for the reason the reference tree recorded: the page is served by the CLI
// from an embedded export, and every runtime added to it is code in the trust
// base of a screen that can restart an app.

import React from 'react';
import { StyleSheet, Text, View } from 'react-native';

export const theme = {
  bg: '#0c1116',
  card: '#151d24',
  border: '#26313b',
  text: '#e6edf3',
  dim: '#8b98a5',
  good: '#3fb950',
  bad: '#f85149',
  warn: '#d29922',
  accent: '#58a6ff',
};

export function Section(props: { title: string; children: React.ReactNode }) {
  return (
    <View style={styles.section}>
      <Text style={styles.sectionTitle}>{props.title}</Text>
      {props.children}
    </View>
  );
}

export function Row(props: { label: string; children: React.ReactNode }) {
  return (
    <View style={styles.row}>
      <Text style={styles.rowLabel}>{props.label}</Text>
      <View style={styles.rowValue}>
        {typeof props.children === 'string' ? <Text style={styles.text}>{props.children}</Text> : props.children}
      </View>
    </View>
  );
}

export function Body(props: { children: React.ReactNode }) {
  return <Text style={styles.text}>{props.children}</Text>;
}

export function Dim(props: { children: React.ReactNode }) {
  return <Text style={styles.dim}>{props.children}</Text>;
}

// Badge is a state word coloured by whether it is good news. The mapping is
// deliberately small: running/ready/ok are good, stopped/exited are not, and
// anything else is a warning rather than a guess.
export function Badge(props: { word: string }) {
  const w = props.word.toLowerCase();
  const color = w === 'running' || w === 'ready' || w === 'ok' ? theme.good : w === 'stopped' || w === 'exited' ? theme.bad : theme.warn;
  return (
    <View style={[styles.badge, { borderColor: color }]}>
      <Text style={[styles.badgeText, { color }]}>{props.word}</Text>
    </View>
  );
}

// Bar is a used/total bar, plain Views. A chart library would pull a render
// pipeline into a page that does not need one; two boxes and a percentage say
// the same thing.
export function Bar(props: { used: number; total: number; color?: string }) {
  const pct = props.total > 0 ? Math.min(100, Math.round((props.used / props.total) * 100)) : 0;
  return (
    <View style={styles.barOuter}>
      <View style={[styles.barInner, { width: `${pct}%`, backgroundColor: props.color ?? theme.accent }]} />
    </View>
  );
}

export function formatBytes(n?: number): string {
  if (n === undefined || n === null) return '—';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let v = n;
  let u = 0;
  while (v >= 1024 && u < units.length - 1) {
    v /= 1024;
    u += 1;
  }
  return `${v >= 100 ? Math.round(v) : v.toFixed(1)} ${units[u]}`;
}

export function formatDuration(seconds?: number): string {
  if (seconds === undefined || seconds === null) return '—';
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

// ago is every timestamp on the page: the box's clock wrote them, the reader
// renders a duration. A future timestamp is a clock disagreement, shown as
// "just now" rather than a negative age.
export function ago(iso: string): string {
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return iso;
  const s = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (s < 90) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 90) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}

const styles = StyleSheet.create({
  section: {
    backgroundColor: theme.card,
    borderColor: theme.border,
    borderWidth: 1,
    borderRadius: 10,
    padding: 16,
    marginBottom: 16,
    gap: 8,
  },
  sectionTitle: { color: theme.dim, fontSize: 13, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 4 },
  row: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', gap: 12 },
  rowLabel: { color: theme.dim, fontSize: 14 },
  rowValue: { flexDirection: 'row', alignItems: 'center', gap: 8, flexShrink: 1 },
  text: { color: theme.text, fontSize: 14 },
  dim: { color: theme.dim, fontSize: 13, lineHeight: 19 },
  badge: { borderWidth: 1, borderRadius: 20, paddingHorizontal: 10, paddingVertical: 2 },
  badgeText: { fontSize: 12, fontWeight: '600' },
  barOuter: { height: 8, borderRadius: 4, backgroundColor: theme.border, overflow: 'hidden', flexGrow: 1 },
  barInner: { height: 8, borderRadius: 4 },
});
