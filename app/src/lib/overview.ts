import type {HistoryResponse, StatusResponse} from "./types";

export async function collectOverview(readers: {status: () => Promise<StatusResponse>; history: () => Promise<HistoryResponse>}) {
  let status: StatusResponse | undefined, history: HistoryResponse | undefined;
  const errors: {status?: string; history?: string} = {};
  try {status = await readers.status();} catch (error) {errors.status = String(error);}
  try {history = await readers.history();} catch (error) {errors.history = String(error);}
  return {status, history, errors};
}
