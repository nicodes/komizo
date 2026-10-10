import type { App } from "./types";

export function deploymentStatus(app: App): string {
  const operation = app.deployment;
  if (!operation || operation.candidate !== app.version) return "Readiness unverified";
  switch (operation.phase) {
    case "ready": return "Readiness passed";
    case "activated": return "Activated; readiness unverified";
    case "readiness_failed": return "Readiness failed";
    case "failed":
    case "activation_failed": return "Deployment failed";
    case "admitted":
    case "configured":
    case "activating": return "Deployment in progress";
    case "prepared_stopped": return "Prepared while stopped";
    default: return "Readiness unverified";
  }
}
