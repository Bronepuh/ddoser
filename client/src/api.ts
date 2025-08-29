import type { ScanResponse } from './types';

export const API_BASE = import.meta.env.DEV
  ? 'http://localhost:5043/api'
  : '/ddoser/api';

export async function scanOnce(domain: string): Promise<ScanResponse> {
  const res = await fetch(
    `${API_BASE}/scan?domain=${encodeURIComponent(domain)}`
  );
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}
