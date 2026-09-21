// The shapes the box serves, mirrored from box/report.go, box/system.go and
// box/result.go by hand. TYPES ONLY: this module compiles to nothing, which is
// the point -- a value here would be a mistake.
//
// The JSON field names are the contract and must match the Go structs tag for
// tag. The serve test in internal/app/ui_test.go pins the documents against
// the Go types, so a drift fails in Go, not in a browser.

export type Report = {
  v: number;
  at: string;
  server: Server;
  proxy?: Proxy;
  network?: Network;
  apps: App[];
  orphans?: string[];
  system: System;
  problems: Problem[];
};

export type Server = {
  state: string; // ready | docker-stopped | bare
  docker?: string;
  os?: string;
  uptime_s?: number;
  komizo: { installed: boolean; version?: string; stamp?: string; agent?: string };
};

export type Proxy = {
  state: string; // running | stopped
  network?: string;
  image?: string;
  status?: string;
  tls_ask?: string;
};

export type Network = {
  name: string;
  members?: { container: string; aliases?: string[] }[];
};

export type App = {
  name: string;
  user?: string;
  dir?: string;
  version?: string;
  config_image?: string;
  known_as?: string[];
  stopped?: boolean;
  stopped_by?: string;
  stopped_at?: string;
  containers?: Container[];
  hosts?: Host[];
};

export type Host = {
  name: string;
  service?: string;
};

export type Container = {
  service: string;
  name: string;
  state: string;
  status?: string;
  image?: string;
  started_at?: string;
  finished_at?: string;
};

export type Problem = {
  kind: string;
  detail: string;
  app?: string;
};

export type System = {
  cores?: number;
  cpu?: { total: number; idle: number };
  mem?: { total: number; used: number; available: number; swap?: { total: number; used: number } };
  disks?: { mount: string; dev?: string; used: number; size: number; available: number }[];
  containers?: { app: string; service: string; cpu_usec?: number; mem?: number; limit?: number }[];
  volumes?: { app: string; service: string; name: string; bytes: number }[];
};

export type Sample = {
  at: string;
  system: System;
};

export type Metrics = {
  span?: { from: number; to: number };
  rows: { minute: number; app: string; service?: string; c2?: number; c3?: number; c4?: number; c5?: number }[];
};

// An event is a command the box was told and what came of it -- the daemon's
// results directory, which is the only box-local record of things happening.
export type BoxEvent = {
  id: string;
  op: string;
  at: string;
  ok: boolean;
  detail?: string;
};

// What `komizo ui` serves under /api/. Every document carries v, the same
// rule the box's own API holds itself to: a document that does not state its
// schema is one the reader has to guess at.
export type ReportResponse = { v: number; report: Report };
export type HistoryResponse = { v: number; from: number; to: number; samples: Sample[] };
export type MetricsResponse = { v: number; from: number; to: number; metrics: Metrics };
export type EventsResponse = { v: number; events: BoxEvent[] };

// No box-local backup state exists yet (the CLI never wrote any), so v1
// serves the empty list and says so -- the screen shows the absence honestly
// rather than inventing a shape nothing writes.
export type BackupsResponse = { v: number; backups: string[]; note: string };

// The action allowlist, server-side in the CLI: these three verbs and no
// others, whatever the UI sends.
export type ActionRequest = { app: string; action: "start" | "stop" | "restart" };
export type ActionResponse = { v: number; ok: boolean; output: string };
