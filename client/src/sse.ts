import type { CheckId, StreamEvent } from './types';
import { API_BASE } from './api';

export type SSEHandlers = {
  onStart?: (id: CheckId) => void;
  onResult?: (evt: Extract<StreamEvent, { type: 'result' }>) => void;
  onError?: (id: CheckId, message: string) => void;
  onDone?: () => void;
};

export async function streamScan(domain: string, h: SSEHandlers) {
  const url = `${API_BASE}/scan/stream?domain=${encodeURIComponent(domain)}`;
  const res = await fetch(url, { headers: { Accept: 'text/event-stream' } });
  if (
    !res.ok ||
    !res.body ||
    !(res.headers.get('content-type') || '').includes('text/event-stream')
  ) {
    throw new Error('SSE unsupported');
  }
  const reader = res.body.getReader();
  const dec = new TextDecoder();
  let buf = '';
  let evtLines: string[] = [];

  const dispatch = (lines: string[]) => {
    const data = lines
      .filter((l) => l.startsWith('data:'))
      .map((l) => l.slice(5).trim())
      .join('\n');
    if (!data) return;
    try {
      const evt = JSON.parse(data) as StreamEvent;
      if (evt.type === 'start') h.onStart?.(evt.checkId);
      else if (evt.type === 'result') h.onResult?.(evt);
      else if (evt.type === 'error') h.onError?.(evt.checkId, evt.message);
    } catch {}
  };

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    let i;
    while ((i = buf.indexOf('\n')) !== -1) {
      const raw = buf.slice(0, i);
      buf = buf.slice(i + 1);
      const line = raw.replace(/\r$/, '');
      if (line === '') {
        dispatch(evtLines);
        evtLines = [];
      } else if (!line.startsWith(':')) evtLines.push(line);
    }
  }
  if (evtLines.length) dispatch(evtLines);
  h.onDone?.();
}
