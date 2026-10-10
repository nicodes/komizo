import type {ReportResponse, EventsResponse, MetricsResponse, BackupsResponse} from "./types";

// Settle one refresh together. Partial failures are evidence, rather than an
// exception that can tear down the screen or a fabricated zero measurement.
export async function collectOverview(readers: {
  report: () => Promise<ReportResponse>;
  events: () => Promise<EventsResponse>;
  metrics: () => Promise<MetricsResponse>;
  backups: () => Promise<BackupsResponse>;
}) {
  const [report, events, metrics, backups] = await Promise.allSettled([
    readers.report(), readers.events(), readers.metrics(), readers.backups(),
  ]);
  return {
    report: report.status === "fulfilled" ? report.value.report : undefined,
    events: events.status === "fulfilled" ? events.value.events : undefined,
    metrics: metrics.status === "fulfilled" ? metrics.value : undefined,
    backups: backups.status === "fulfilled" ? backups.value : undefined,
    errors: {
      report: report.status === "rejected" ? String(report.reason) : undefined,
      events: events.status === "rejected" ? String(events.reason) : undefined,
      metrics: metrics.status === "rejected" ? String(metrics.reason) : undefined,
      backups: backups.status === "rejected" ? String(backups.reason) : undefined,
    },
  };
}
