import type { Severity } from '@shared/types';
import { Tag } from 'antd';

export function sevTag(sev: Severity) {
  if (sev === 'high') return <Tag color="error">HIGH</Tag>;
  if (sev === 'medium') return <Tag color="warning">MEDIUM</Tag>;
  if (sev === 'low') return <Tag color="processing">LOW</Tag>;
  return <Tag>INFO</Tag>;
}
