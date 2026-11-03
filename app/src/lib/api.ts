// Talking to the box this page was served by.
//
// RELATIVE PATHS ONLY. There is no base URL, no env var, no configuration:
// the app is a static export embedded in the CLI and served by the same
// listener that answers /api/, on loopback or the tailnet interface. A URL
// knob here would be a way to point the app at a box it was not served by.
// ui_test.go pins this file to relative fetches.

import type {
  ActionResponse,
  BackupsResponse,
  EventsResponse,
  HistoryResponse,
  MetricsResponse,
  ReportResponse,
} from "./types";

export class APIError extends Error {
  constructor(message: string, readonly status: number, readonly code = "request_failed", readonly requestId = "") { super(message); }
}
async function failure(response: Response): Promise<APIError> {
  let message = `the box refused: ${response.status}`, code = "request_failed", requestId = response.headers.get("X-Request-ID") || "";
  try {
    const text = await response.text();
    const value = text.length <= 65536 ? JSON.parse(text) : undefined;
    if (typeof value?.error?.message === "string") message = value.error.message.slice(0,1024);
    else if (typeof value?.output === "string") message = value.output.slice(0,1024);
    if (typeof value?.error?.code === "string") code = value.error.code.slice(0,64);
    if (!requestId && typeof value?.error?.request_id === "string") requestId = value.error.request_id.slice(0,128);
  } catch { /* A proxy diagnostic is not a user-facing API message. */ }
  return new APIError(message, response.status, code, requestId);
}

async function get<T>(path: string, signal?: AbortSignal): Promise<T> {
  const res = await fetch(path, { signal });
  if (!res.ok) {
    throw await failure(res);
  }
  return (await res.json()) as T;
}

export function readReport(signal?: AbortSignal): Promise<ReportResponse> {
  return get<ReportResponse>("/api/report", signal);
}

export function readHistory(from: number, to: number, signal?: AbortSignal): Promise<HistoryResponse> {
  return get<HistoryResponse>(`/api/history?from=${from}&to=${to}`, signal);
}

export function readMetrics(signal?: AbortSignal): Promise<MetricsResponse> {
  return get<MetricsResponse>("/api/metrics", signal);
}

export function readEvents(signal?: AbortSignal): Promise<EventsResponse> {
  return get<EventsResponse>("/api/events", signal);
}

export function readBackups(signal?: AbortSignal): Promise<BackupsResponse> {
  return get<BackupsResponse>("/api/backups", signal);
}

// The only write. The server enforces the allowlist -- this type is a
// courtesy to the caller, not the boundary.
export async function runAction(
  app: string,
  action: "start" | "stop" | "restart",
  signal?: AbortSignal,
): Promise<ActionResponse> {
  const res = await fetch("/api/action", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ app, action }),
    signal,
  });
  if (!res.ok) {
    throw await failure(res);
  }
  return (await res.json()) as ActionResponse;
}
