export type Severity = 'info' | 'low' | 'medium' | 'high';
export type Finding = {
  id: string;
  title: string;
  severity: Severity;
  evidence: string;
  recommendation: string;
};
export type CheckId = 'dns' | 'tls' | 'http';
export type CheckResult = {
  checkId: CheckId | string;
  ok: boolean;
  findings: Finding[];
  raw?: any;
  passed?: string[];
};
export type ScanResponse = {
  domain: string;
  results: CheckResult[];
  score: number;
};

// Streaming events
export type StreamEvent =
  | { type: 'start'; checkId: CheckId }
  | { type: 'result'; payload: CheckResult }
  | { type: 'error'; checkId: CheckId; message: string };
