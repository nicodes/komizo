// Talking to the box this page was served by.
//
// RELATIVE PATHS ONLY. There is no base URL, no env var, no configuration:
// the app is a static export embedded in the CLI and served by the same
// listener that answers /api/, on loopback or the tailnet interface. A URL
// knob here would be a way to point the app at a box it was not served by.
//
// The reference tree's box.ts carried an untrusted-transport stack -- read
// tokens, signed envelopes, retry -- because its reads crossed the internet.
// These do not leave the machine the page came from, so a fetch and a timeout
// are the whole of it.
import type {
  ActionResponse,
  BackupsResponse,
  EventsResponse,
  HistoryResponse,
  MetricsResponse,
  ReportResponse,
} from './types';

async function get<T>(path: string, signal?: AbortSignal): Promise<T> {
  const res = await fetch(path, { signal });
  if (!res.ok) {
    throw new Error(`${path}: ${res.status}`);
  }
  return (await res.json()) as T;
}

export function readReport(signal?: AbortSignal): Promise<ReportResponse> {
  return get<ReportResponse>('/api/report', signal);
}

export function readHistory(from: number, to: number, signal?: AbortSignal): Promise<HistoryResponse> {
  return get<HistoryResponse>(`/api/history?from=${from}&to=${to}`, signal);
}

export function readMetrics(signal?: AbortSignal): Promise<MetricsResponse> {
  return get<MetricsResponse>('/api/metrics', signal);
}

export function readEvents(signal?: AbortSignal): Promise<EventsResponse> {
  return get<EventsResponse>('/api/events', signal);
}

export function readBackups(signal?: AbortSignal): Promise<BackupsResponse> {
  return get<BackupsResponse>('/api/backups', signal);
}

// The only write. The server enforces the allowlist -- this type is a
// courtesy to the caller, not the boundary.
export async function runAction(
  app: string,
  action: 'start' | 'stop' | 'restart',
  signal?: AbortSignal,
): Promise<ActionResponse> {
  const res = await fetch('/api/action', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ app, action }),
    signal,
  });
  const body = (await res.json()) as ActionResponse;
  if (!res.ok) {
    throw new Error(body.output || `the box refused: ${res.status}`);
  }
  return body;
}
