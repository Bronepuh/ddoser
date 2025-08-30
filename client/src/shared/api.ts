// Единая точка правды для базового URL API
export const API_BASE =
  (import.meta.env.VITE_API_BASE as string) ??
  (import.meta.env.DEV ? 'http://localhost:5043/api' : '/ddoser/api');

export async function scanOnce(domain: string) {
  const url = `${API_BASE}/scan?domain=${encodeURIComponent(domain)}`;
  const r = await fetch(url, { headers: { Accept: 'application/json' } });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}
