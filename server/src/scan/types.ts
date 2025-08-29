export type Severity = 'info' | 'low' | 'medium' | 'high';
export type Finding = {
  id: string;
  title: string;
  severity: Severity;
  evidence: string;
  recommendation: string;
};
export type CheckResult = {
  checkId: 'dns' | 'tls' | 'http' | string;
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
