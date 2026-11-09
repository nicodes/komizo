const KEY = "komizo.owner.session";
let memory: string | undefined;

export function ownerCapability(): string | undefined {
  if (typeof window === "undefined") return undefined;
  const fragment = window.location.hash;
  if (fragment.startsWith("#komizo-session=")) {
    const selected = fragment.slice("#komizo-session=".length);
    window.history.replaceState(null, "", window.location.pathname + window.location.search);
    memory = /^[a-f0-9]{64}$/.test(selected) ? selected : undefined;
    try {
      if (memory) window.sessionStorage.setItem(KEY, memory);
      else window.sessionStorage.removeItem(KEY);
    } catch { /* The current page can still use its private in-memory capability. */ }
  }
  if (!memory) {
    try { memory = window.sessionStorage.getItem(KEY) ?? undefined; } catch { return undefined; }
  }
  return memory && /^[a-f0-9]{64}$/.test(memory) ? memory : undefined;
}
