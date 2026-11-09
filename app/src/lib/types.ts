export type ActionName = "start" | "stop" | "restart" | "backup";
export type Operation = {
  kind: "komizo.operation"; version: 1; operation_id: string; application: string;
  instance: string; release_digest: string; phase: string; ok: boolean;
  reconciliation_required?: boolean; action?: string; admitted_at?: number; failure?: {message?: string};
  backup?: {status: string; files?: {name: string; size_bytes: number; sha256: string}[]};
};
export type Resources = Record<string, unknown>;
export type Service = {container_id?: string | null; state?: string | null; health?: string | null; resources?: Resources};
export type Instance = {
  application: string; instance: string; release_digest: string; desired_running: boolean; removed?: boolean;
  operation_id: string; expires_at?: number | null;
  source?: {repository: string; revision: string};
  prepared?: {release_digest: string; operation_id: string; source?: {repository: string; revision: string}} | null;
  actions?: Partial<Record<ActionName, {release_digest: string}>>;
  services: Record<string, Service>; log_targets?: string[]; operations?: Operation[]; unresolved_operations?: Operation[];
  resources?: Resources | null; secret_generations?: Record<string, string>;
  routes?: {host: string; path: string}[]; volumes?: string[];
};
export type HostStatus = {
  kind: "komizo.status"; version: 1; observed_at?: string;
  host?: {boot_id?: string; resources?: Resources}; instances: Instance[];
};
export type Observation = {captured_at: string; status: HostStatus};
export type StatusResponse = Observation & {kind: "komizo.ui.status"; version: 1; host: string};
export type HistoryResponse = {kind: "komizo.ui.history"; version: 1; scope: string; samples: Observation[]};
export type ActionRequest = {application: string; instance: string; action: ActionName; release_digest: string; nonce: string};
export type ActionResponse = {kind: "komizo.ui.action"; version: 1; confirmation: "confirmed" | "observed" | "unconfirmed"; operation_id: string; result?: Operation; message?: string};
export type Logs = {kind: "komizo.logs"; version: 1; application: string; instance: string; service: string; container_id: string; text: string};
