import type {ActionRequest, ActionResponse, HistoryResponse, Logs, Operation, StatusResponse} from "./types";

export class APIError extends Error { constructor(message: string, readonly status: number) {super(message);} }
async function read<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(path, options);
  const text = await response.text();
  if (text.length > 4 << 20) throw new APIError("The response exceeded its limit.", response.status);
  let value: unknown;
  try {value = JSON.parse(text);} catch {throw new APIError("The local UI returned an unreadable response.", response.status);}
  if (!response.ok) {
    const error = value as {error?: {message?: string}};
    throw new APIError(error.error?.message?.slice(0, 1024) || "The observation is unavailable.", response.status);
  }
  return value as T;
}
export const readStatus = (signal?: AbortSignal) => read<StatusResponse>("/api/status", {signal});
export const readHistory = (signal?: AbortSignal) => read<HistoryResponse>("/api/history", {signal});
export function readOperation(application: string, instance: string, operation: string, release: string, signal?: AbortSignal) {
  return read<Operation>(`/api/operation?${new URLSearchParams({application, instance, operation, release_digest: release})}`, {signal});
}
export function readLogs(application: string, instance: string, service: string, signal?: AbortSignal) {
  return read<Logs>(`/api/logs?${new URLSearchParams({application, instance, service})}`, {signal});
}
export function runAction(request: ActionRequest, signal?: AbortSignal) {
  return read<ActionResponse>("/api/actions", {method: "POST", headers: {"Content-Type": "application/json", "X-Komizo-Request": "1"}, body: JSON.stringify(request), signal});
}
