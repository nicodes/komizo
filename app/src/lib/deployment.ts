import type {ActionName, ActionRequest, Instance, Operation} from "./types";

export function currentOperation(instance: Instance): Operation | undefined {
  return [...(instance.operations ?? []), ...(instance.unresolved_operations ?? [])].find(operation =>
    operation.operation_id === instance.operation_id && operation.release_digest === instance.release_digest);
}
export function deploymentStatus(instance: Instance): string {
  const operation = currentOperation(instance);
  if (!instance.desired_running) return instance.prepared ? "Prepared while stopped" : "Stopped by owner";
  if (!operation) return "Readiness unverified";
  if (operation.phase === "ready" && operation.ok) return "Readiness passed";
  if (operation.phase === "needs_reconciliation") return "Inspection required";
  if (operation.phase === "failed") return "Operation failed";
  return "Operation in progress";
}
export function actionable(instance: Instance, action: ActionName): boolean {
  return !!instance.actions?.[action] && (instance.unresolved_operations?.length ?? 0) === 0
    && (action === "start" ? !instance.desired_running : instance.desired_running);
}
export async function operationID(application: string, instance: string, nonce: string): Promise<string> {
  const bytes = new TextEncoder().encode(`komizo-operation-v1\0${application}\0${instance}\0${nonce}`);
  return [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))].map(value => value.toString(16).padStart(2, "0")).join("").slice(0, 32);
}
export async function propose(instance: Instance, action: ActionName): Promise<{request: ActionRequest; operation_id: string}> {
  const release = instance.actions?.[action]?.release_digest;
  if (!actionable(instance, action) || !release || !/^sha256:[a-f0-9]{64}$/.test(release)) throw new Error("Refresh and inspect this instance before another change.");
  const nonce = crypto.randomUUID().replaceAll("-", "");
  const request = {application: instance.application, instance: instance.instance, action, release_digest: release, nonce};
  return {request, operation_id: await operationID(instance.application, instance.instance, nonce)};
}
export function resourceNumber(resources: Record<string, unknown> | null | undefined, ...names: string[]): number | undefined {
  for (const name of names) {
    const value = resources?.[name];
    if (typeof value === "number" && Number.isFinite(value) && value >= 0) return value;
  }
  return undefined;
}
