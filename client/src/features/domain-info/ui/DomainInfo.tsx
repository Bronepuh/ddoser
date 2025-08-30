/* eslint-disable @typescript-eslint/no-explicit-any */

import {
  CheckCircleTwoTone,
  GlobalOutlined,
  InfoCircleTwoTone,
  WarningTwoTone,
} from '@ant-design/icons';
import type { ScanResponse } from '@shared/types';
import {
  Card,
  Descriptions,
  Divider,
  List,
  Space,
  Tag,
  Typography,
} from 'antd';
import styles from './DomainInfo.module.scss';

const { Text, Title } = Typography;

function settledArray<T = any>(s: any): T[] {
  return s && s.status === 'fulfilled' ? (s.value as T[]) : [];
}
function settledSoa(s: any): any | null {
  return s && s.status === 'fulfilled' ? s.value : null;
}
function settledDS(s: any): { ok?: boolean; hasDS?: boolean } | null {
  return s && s.status === 'fulfilled' ? (s.value as any) : null;
}

type Props = { data: ScanResponse | null };

export const DomainInfo = ({ data }: Props) => {
  if (!data) return null;

  const dnsRes = data.results.find((r) => r.checkId === 'dns');
  const tlsRes = data.results.find((r) => r.checkId === 'tls');
  const httpRes = data.results.find((r) => r.checkId === 'http');

  const dnsRaw = (dnsRes?.raw as any) || {};
  const A = settledArray<string>(dnsRaw.A);
  const AAAA = settledArray<string>(dnsRaw.AAAA);
  const NS = settledArray<string>(dnsRaw.NS);
  const MX = settledArray<{ exchange: string }>(dnsRaw.MX);
  const TXT = settledArray<string[]>(dnsRaw.TXT).map((rr) => rr.join(''));
  const CAA = settledArray<any>(dnsRaw.CAA);
  const SOA = settledSoa(dnsRaw.SOA);
  const DS = settledDS(dnsRaw.DS);
  const ipInfo = (dnsRaw?.ipInfo as Array<any>) || [];

  const tlsRaw = (tlsRes?.raw as any) || {};
  const httpRaw = (httpRes?.raw as any) || {};
  const httpHeaders: Record<string, string> = httpRaw.headers || {};
  const serverBanner =
    httpHeaders['server'] || httpHeaders['x-powered-by'] || '';

  return (
    <Card
      className={styles.card}
      title={
        <Space>
          <InfoCircleTwoTone twoToneColor="#1677ff" />
          Информация по домену
        </Space>
      }
    >
      {/* DNS */}
      <div className={styles.section}>
        <Title level={5}>DNS</Title>
        <Descriptions column={1} size="small" className={styles.descriptions}>
          <Descriptions.Item label="Домен">{data.domain}</Descriptions.Item>
          <Descriptions.Item label="A">
            {A.length ? (
              A.join(', ')
            ) : (
              <span style={{ color: '#9ca3af' }}>нет</span>
            )}
          </Descriptions.Item>
          <Descriptions.Item label="AAAA">
            {AAAA.length ? (
              AAAA.join(', ')
            ) : (
              <span style={{ color: '#9ca3af' }}>нет</span>
            )}
          </Descriptions.Item>
          <Descriptions.Item label="NS">
            {NS.length ? (
              NS.join(', ')
            ) : (
              <span style={{ color: '#9ca3af' }}>нет</span>
            )}
          </Descriptions.Item>
          <Descriptions.Item label="MX">
            {MX.length ? (
              MX.map((m) => m.exchange).join(', ')
            ) : (
              <span style={{ color: '#9ca3af' }}>нет</span>
            )}
          </Descriptions.Item>
          <Descriptions.Item label="TXT">
            {TXT.length ? (
              <Space direction="vertical" size={0}>
                {TXT.slice(0, 4).map((t, i) => (
                  <Text key={i} className={styles.txt}>
                    {t.length > 140 ? t.slice(0, 140) + '…' : t}
                  </Text>
                ))}
                {TXT.length > 4 && (
                  <Text type="secondary">ещё {TXT.length - 4}…</Text>
                )}
              </Space>
            ) : (
              <span style={{ color: '#9ca3af' }}>нет</span>
            )}
          </Descriptions.Item>
          <Descriptions.Item label="CAA">
            {CAA.length ? (
              CAA.map(
                (r: any) =>
                  r?.issue || r?.issuewild || r?.iodef || JSON.stringify(r)
              ).join(', ')
            ) : (
              <span style={{ color: '#9ca3af' }}>нет</span>
            )}
          </Descriptions.Item>
          <Descriptions.Item label="SOA">
            {SOA ? (
              <Space direction="vertical" size={0}>
                <Text>mname: {SOA.mname}</Text>
                <Text>rname: {SOA.rname}</Text>
                <Text>serial: {SOA.serial}</Text>
              </Space>
            ) : (
              <span style={{ color: '#9ca3af' }}>нет</span>
            )}
          </Descriptions.Item>
          <Descriptions.Item label="DNSSEC (DS)">
            {DS ? (
              DS.ok ? (
                DS.hasDS ? (
                  <Space>
                    <CheckCircleTwoTone twoToneColor="#52c41a" />
                    DS присутствует
                  </Space>
                ) : (
                  <Space>
                    <WarningTwoTone twoToneColor="#faad14" />
                    DS не найден
                  </Space>
                )
              ) : (
                <Space>
                  <WarningTwoTone twoToneColor="#faad14" />
                  Не удалось проверить
                </Space>
              )
            ) : (
              <span style={{ color: '#9ca3af' }}>нет данных</span>
            )}
          </Descriptions.Item>
        </Descriptions>
      </div>

      <Divider />

      {/* IP/ASN/Geo */}
      <div className={styles.section}>
        <Title level={5}>IP-адреса / ASN / Geo</Title>
        {ipInfo.length === 0 ? (
          <Text type="secondary">Нет данных об IP</Text>
        ) : (
          <List
            className={styles.ipList}
            dataSource={ipInfo}
            renderItem={(row: any) => (
              <List.Item>
                <div className={styles.ipCard}>
                  <div className={styles.ipHeader}>
                    <GlobalOutlined />
                    <Text strong>{row.ip}</Text>
                    {row.country && (
                      <Tag>
                        {row.country}
                        {row.country_code ? ` (${row.country_code})` : ''}
                      </Tag>
                    )}
                    {row.city && <Tag>{row.city}</Tag>}
                    {row.type && <Tag color="blue">{row.type}</Tag>}
                  </div>
                  <div className={styles.ipDetails}>
                    <div>
                      <Text type="secondary">PTR:</Text>{' '}
                      {row.ptr?.length ? row.ptr.join(', ') : '—'}
                    </div>
                    <div>
                      <Text type="secondary">ASN/Org:</Text>{' '}
                      {row.asn ? `AS${row.asn}` : '—'}
                      {row.org ? ` • ${row.org}` : ''}
                    </div>
                    <div>
                      <Text type="secondary">ISP:</Text> {row.isp || '—'}
                    </div>
                    <div>
                      <Text type="secondary">Timezone:</Text>{' '}
                      {row.timezone || '—'}
                    </div>
                  </div>
                </div>
              </List.Item>
            )}
          />
        )}
      </div>

      <Divider />

      {/* TLS */}
      <div className={styles.section}>
        <Title level={5}>TLS</Title>
        <Descriptions column={1} size="small" className={styles.descriptions}>
          <Descriptions.Item label="Протокол">
            {tlsRaw.protocol || '—'}
          </Descriptions.Item>
          <Descriptions.Item label="ALPN">
            {tlsRaw.alpn || '—'}
          </Descriptions.Item>
          <Descriptions.Item label="Шифр">
            {tlsRaw.cipher || '—'}
          </Descriptions.Item>
          <Descriptions.Item label="Сертификат">
            {tlsRaw.certSummary ? (
              <Space direction="vertical" size={0}>
                <Text>
                  Subject:{' '}
                  {tlsRaw.certSummary.subject?.CN ||
                    JSON.stringify(tlsRaw.certSummary.subject || {})}
                </Text>
                <Text>
                  Issuer:{' '}
                  {tlsRaw.certSummary.issuer?.CN ||
                    JSON.stringify(tlsRaw.certSummary.issuer || {})}
                </Text>
                <Text>Valid to: {tlsRaw.certSummary.valid_to || '—'}</Text>
              </Space>
            ) : (
              '—'
            )}
          </Descriptions.Item>
          <Descriptions.Item label="OCSP stapling">
            {typeof tlsRaw.ocspStapled === 'boolean' ? (
              tlsRaw.ocspStapled ? (
                <Space>
                  <CheckCircleTwoTone twoToneColor="#52c41a" />
                  включён
                </Space>
              ) : (
                <Space>
                  <WarningTwoTone twoToneColor="#faad14" />
                  отсутствует
                </Space>
              )
            ) : (
              '—'
            )}
          </Descriptions.Item>
        </Descriptions>
      </div>

      <Divider />

      {/* HTTP */}
      <div className={styles.section}>
        <Title level={5}>HTTP</Title>
        <Descriptions column={1} size="small" className={styles.descriptions}>
          <Descriptions.Item label="Код ответа">
            {httpRaw.status ?? '—'}
          </Descriptions.Item>
          <Descriptions.Item label="Баннер">
            {serverBanner || '—'}
          </Descriptions.Item>
          <Descriptions.Item label="Cookie">
            {Array.isArray(httpRaw.cookies) ? `${httpRaw.cookies.length}` : '—'}
          </Descriptions.Item>
          <Descriptions.Item label="Ключевые заголовки">
            <Space wrap>
              {[
                'strict-transport-security',
                'content-security-policy',
                'x-content-type-options',
                'x-frame-options',
                'referrer-policy',
                'permissions-policy',
              ]
                .map((h) => ({ h, v: httpHeaders[h] }))
                .map(({ h, v }) =>
                  v ? (
                    <Tag key={h} color="green">
                      {h}
                    </Tag>
                  ) : (
                    <Tag key={h}>{h}</Tag>
                  )
                )}
            </Space>
          </Descriptions.Item>
        </Descriptions>
      </div>
    </Card>
  );
};
