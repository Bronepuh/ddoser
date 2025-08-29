// src/App.tsx
import { useMemo, useRef, useState } from 'react';
import {
  App as AntdApp,
  Alert,
  Button,
  Card,
  Col,
  Collapse,
  Descriptions,
  Divider,
  Input,
  List,
  Progress,
  Result,
  Row,
  Skeleton,
  Space,
  Statistic,
  Tag,
  Typography,
  Spin,
} from 'antd';
import {
  CheckCircleTwoTone,
  CloudServerOutlined,
  InfoCircleTwoTone,
  LockOutlined,
  RadarChartOutlined,
  ThunderboltOutlined,
  WarningTwoTone,
  SecurityScanTwoTone,
  GlobalOutlined,
  DeploymentUnitOutlined,
} from '@ant-design/icons';

import { scanOnce } from './api';
import { streamScan } from './sse';
import type { CheckId, CheckResult, ScanResponse, Severity } from './types';

const { Paragraph, Text, Title } = Typography;

const sections: { key: CheckId; title: string; icon: React.ReactNode }[] = [
  { key: 'dns', title: 'DNS', icon: <CloudServerOutlined /> },
  { key: 'tls', title: 'TLS', icon: <LockOutlined /> },
  { key: 'http', title: 'HTTP', icon: <ThunderboltOutlined /> },
];

type SectionState = 'idle' | 'scanning' | 'done' | 'error';

function sevTag(sev: Severity) {
  if (sev === 'high') return <Tag color="error">HIGH</Tag>;
  if (sev === 'medium') return <Tag color="warning">MEDIUM</Tag>;
  if (sev === 'low') return <Tag color="processing">LOW</Tag>;
  return <Tag>INFO</Tag>;
}

function SectionStatus({ state }: { state: SectionState }) {
  if (state === 'scanning')
    return (
      <Space size={6}>
        <Spin size="small" />
        <span>Сканируем…</span>
      </Space>
    );
  if (state === 'done')
    return (
      <Space size={6}>
        <CheckCircleTwoTone twoToneColor="#52c41a" />
        <span>Готово</span>
      </Space>
    );
  if (state === 'error')
    return (
      <Space size={6}>
        <WarningTwoTone twoToneColor="#faad14" />
        <span>Ошибка</span>
      </Space>
    );
  return <span style={{ color: '#9ca3af' }}>Ожидание</span>;
}

/** мини-база знаний для раскрываемых карточек */
function kbForFinding(
  id: string,
  checkId?: string
): { description: string; attacks: string[] } {
  const KB: Record<string, { description: string; attacks: string[] }> = {
    // DNS
    'dns-caa-missing': {
      description:
        'Отсутствуют CAA-записи. Любой центр сертификации потенциально может выпустить сертификат на домен.',
      attacks: [
        'Mis-issuance у слабого CA',
        'BGP/DNS hijack + выпуск поддельного сертификата',
      ],
    },
    'dns-single-a': {
      description:
        'Только один A-адрес (origin). Низкая отказоустойчивость и риск DDoS/таргет-атаки.',
      attacks: [
        'DDoS на origin',
        'Точечная блокировка IP',
        'Инвентаризация origin-узла',
      ],
    },
    'mail-spf-missing': {
      description:
        'Нет SPF. Почтовые провайдеры не могут валидировать источник отправителя.',
      attacks: ['Спуфинг писем от вашего домена', 'Фишинг/BEC-атаки'],
    },
    'mail-dmarc-missing': {
      description:
        'Нет DMARC. Получатели не знают, как обращаться с несоответствующими письмами; нет отчётов.',
      attacks: ['Спуфинг/обход антиспама', 'Скрытые фишинговые рассылки'],
    },
    'dnssec-missing': {
      description:
        'DNSSEC не включён: в родительской зоне отсутствует DS. Ответы нельзя криптографически подтвердить.',
      attacks: [
        'DNS cache poisoning',
        'MITM между резолвером и авторитетным сервером',
      ],
    },

    // TLS
    'tls-old-proto': {
      description:
        'Согласуются старые версии TLS. Они имеют известные уязвимости и слабые шифры.',
      attacks: ['Protocol downgrade', 'POODLE/BEAST/CRIME-подобные атаки'],
    },
    'tls-weak-cipher': {
      description:
        'Согласован слабый набор шифров (RC4/3DES/MD5/DES/EXPORT). Нарушается конфиденциальность/целостность.',
      attacks: [
        'Разложение шифра',
        'Cipher-suite downgrade',
        'Chosen-ciphertext атаки',
      ],
    },
    'tls-no-h2': {
      description:
        'HTTP/2 не согласован по ALPN. Не критично, но снижает производительность и современные возможности.',
      attacks: ['Нет прямых атак; деградация производительности/ресурсов'],
    },
    'tls-ocsp-stapling-missing': {
      description:
        'OCSP Stapling не включён. Клиентам придётся опрашивать OCSP-сервер CA напрямую (медленнее, иногда soft-fail).',
      attacks: ['Нет прямых атак; privacy/availability риски у клиента'],
    },
    'tls-expiring': {
      description:
        'Сертификат скоро истечёт. При пропуске продления пользователи увидят фатальную ошибку.',
      attacks: ['DoS по валидации TLS', 'Принуждение к небезопасным обходам'],
    },

    // HTTP / заголовки
    'hsts-missing': {
      description:
        'Нет HSTS. Пользователя можно принудить на http:// или небезопасный редирект.',
      attacks: ['SSL-strip (HTTPS→HTTP)', 'Перехват cookie без Secure'],
    },
    'hsts-not-preload-ready': {
      description:
        'HSTS задан, но не соответствует preload (max-age≥31536000, includeSubDomains, preload).',
      attacks: ['Риск SSL-strip на части субдоменов/первом визите'],
    },
    'csp-missing': {
      description:
        'Нет Content-Security-Policy. Скрипты/фреймы могут грузиться откуда угодно → риск XSS/clickjacking.',
      attacks: [
        'Stored/Reflected XSS',
        'Инъекция внешних скриптов',
        'Clickjacking',
      ],
    },
    'csp-unsafe-inline': {
      description:
        'CSP допускает inline-скрипты (`unsafe-inline`). Усиленный риск XSS, даже при наличии CSP.',
      attacks: ['Inline XSS (bypass CSP)', 'DOM-based XSS'],
    },
    'csp-unsafe-eval': {
      description:
        'CSP допускает eval-подобные конструкции. Облегчает эксплуатацию XSS.',
      attacks: ['XSS через eval/new Function', 'Обход CSP'],
    },
    'xcto-missing': {
      description:
        'Нет X-Content-Type-Options: nosniff. Браузер будет «угадывать» тип контента.',
      attacks: ['MIME-sniffing → XSS (скрипт принят за текст/картинку)'],
    },
    'xfo-missing': {
      description:
        'Нет X-Frame-Options / frame-ancestors. Сайт можно встраивать в iframe третьей стороны.',
      attacks: ['Clickjacking', 'UI redressing'],
    },
    'referrer-missing': {
      description:
        'Нет Referrer-Policy. Полные URL/параметры могут утекать на внешние сайты через Referer.',
      attacks: ['Утечка токенов/ID через Referer'],
    },
    'perm-missing': {
      description:
        'Нет Permissions-Policy. Современные API (камера, сенсоры и т.д.) не ограничены политикой.',
      attacks: [
        'Злоупотребление доступом к сенсорам/медиа из внедрённого контента',
      ],
    },
    'coop-missing': {
      description: 'Нет COOP. Окно не изолировано от сторонних попапов.',
      attacks: ['XS-Leaks между окнами', 'Неожиданное взаимодействие окон'],
    },
    'coep-missing': {
      description:
        'Нет COEP. Не включён требуемый уровень изоляции для некоторых API.',
      attacks: ['Ограничения мощных API; XS-Leaks'],
    },
    'corp-missing': {
      description:
        'Нет CORP. Браузер может загружать кросс-ориджин ресурсы без явной политики.',
      attacks: ['Косвенные утечки через кросс-ориджин загрузки'],
    },
    'cors-wildcard-cred': {
      description:
        'CORS с `Access-Control-Allow-Origin: *` и `credentials: true` — запрещённое сочетание.',
      attacks: [
        'Кража данных с авторизованных запросов через произвольные сайты',
      ],
    },
    'banner-verbose': {
      description:
        'Сервер раскрывает версии/ПО. Помогает таргетировать известные CVE.',
      attacks: ['Фингерпринтинг и таргет-эксплуатация уязвимых версий'],
    },

    // Cookies (сводные)
    'cookie-issues': {
      description:
        'Некоторые cookie не имеют безопасных атрибутов (Secure/HttpOnly/SameSite) или нарушают правила префиксов.',
      attacks: [
        'Кража/перехват cookie',
        'CSRF при SameSite=None без Secure',
        'Повышение привилегий (__Host-)',
      ],
    },

    // HTTP поведение
    'no-http-to-https-redirect': {
      description:
        'HTTP (порт 80) не редиректит на HTTPS. Первичная загрузка может идти по незашифрованному каналу.',
      attacks: ['SSL-strip (downgrade)', 'Перехват/модификация ответа'],
    },
    'http-https-fetch-failed': {
      description:
        'Не удалось получить HTTPS-ответ. Возможны сетевые проблемы, TLS/редирект misconfig.',
      attacks: ['Недоступность сервиса', 'Ошибки TLS/SNI/ALPN/редиректов'],
    },
    'http-check-skipped': {
      description:
        'HTTP-проверка (порт 80) не выполнена. Невозможно подтвердить редирект на HTTPS.',
      attacks: ['Потенциальный SSL-strip при первом визите'],
    },

    // TLS общее
    'tls-conn-failed': {
      description:
        'Не удалось установить TLS-соединение. Возможны блокировка 443/tcp, проблемы SNI/сертификата/CDN/WAF.',
      attacks: [
        'Недоступность/DoS через сетевые ограничения',
        'Misconfig фронта (CDN/WAF)',
      ],
    },
  };

  if (KB[id]) return KB[id];
  if (checkId === 'dns')
    return {
      description: 'Проблема в DNS-конфигурации.',
      attacks: ['Подмена записей', 'Потеря отказоустойчивости'],
    };
  if (checkId === 'tls')
    return {
      description: 'Проблема в настройке TLS.',
      attacks: ['Downgrade/MITM', 'Слабые шифры/протоколы'],
    };
  return {
    description: 'Проблема на уровне HTTP-заголовков/поведения.',
    attacks: ['XSS/Clickjacking/CSRF', 'SSL-strip'],
  };
}

/** утилиты для блока «Информация по домену» */
function settledArray<T = any>(s: any): T[] {
  return s && s.status === 'fulfilled' ? (s.value as T[]) : [];
}
function settledSoa(s: any): any | null {
  return s && s.status === 'fulfilled' ? s.value : null;
}
function settledDS(s: any): { ok?: boolean; hasDS?: boolean } | null {
  return s && s.status === 'fulfilled' ? (s.value as any) : null;
}

export default function App() {
  const [domain, setDomain] = useState('bronepuh.ru');
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [data, setData] = useState<ScanResponse | null>(null);

  const [sectionStates, setSectionStates] = useState<
    Record<CheckId, SectionState>
  >({
    dns: 'idle',
    tls: 'idle',
    http: 'idle',
  });

  const resultsRef = useRef<Partial<Record<CheckId, CheckResult>>>({});

  const protectedItems = useMemo(() => {
    if (!data) return [] as { key: string; text: string }[];
    const items: string[] = [];
    for (const r of data.results)
      if (Array.isArray((r as any).passed)) items.push(...(r as any).passed);
    if (!items.length) {
      const http = data.results.find((r) => r.checkId === 'http');
      if (http) items.push('HTTPS доступен');
    }
    return items.map((text, i) => ({ key: `${i}`, text }));
  }, [data]);

  function resetForScan() {
    setErr(null);
    setSectionStates({ dns: 'idle', tls: 'idle', http: 'idle' });
    resultsRef.current = {};
  }

  async function runScan() {
    resetForScan();
    setLoading(true);
    try {
      let usedSSE = true;
      try {
        setSectionStates({
          dns: 'scanning',
          tls: 'scanning',
          http: 'scanning',
        });
        await streamScan(domain, {
          onStart: (id) =>
            setSectionStates((s) => ({ ...s, [id]: 'scanning' })),
          onResult: ({ payload }) => {
            const id = payload.checkId as CheckId;
            resultsRef.current[id] = payload;
            setSectionStates((s) => ({ ...s, [id]: 'done' }));
            const results = sections
              .map((s) => resultsRef.current[s.key])
              .filter(Boolean) as CheckResult[];
            if (results.length) setData({ domain, results, score: 0 }); // score ставит сервер — здесь просто обновим UI
          },
          onError: (id) => setSectionStates((s) => ({ ...s, [id]: 'error' })),
          onDone: async () => {
            // добираем финальный объект одним запросом (чтобы был score)
            try {
              const full = await scanOnce(domain);
              setData(full);
            } catch {}
          },
        });
      } catch {
        usedSSE = false;
      }
      if (!usedSSE) {
        setSectionStates({
          dns: 'scanning',
          tls: 'scanning',
          http: 'scanning',
        });
        const json = await scanOnce(domain);
        const next: Partial<Record<CheckId, CheckResult>> = {};
        json.results.forEach((r) => (next[r.checkId as CheckId] = r));
        resultsRef.current = next;
        setSectionStates({ dns: 'done', tls: 'done', http: 'done' });
        setData(json);
      }
    } catch (e: any) {
      setErr(e?.message || 'Scan failed');
    } finally {
      setLoading(false);
    }
  }

  /** ======== доменная информация из raw ======== */
  const dnsRes = data?.results.find((r) => r.checkId === 'dns');
  const tlsRes = data?.results.find((r) => r.checkId === 'tls');
  const httpRes = data?.results.find((r) => r.checkId === 'http');

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

  /** ======== UI ======== */
  return (
    <AntdApp>
      <Row justify="center" style={{ padding: '24px 16px' }}>
        <Col xs={24} sm={22} md={20} lg={18} xl={16} xxl={14}>
          {/* Header */}
          <Row gutter={[16, 16]} align="middle">
            <Col flex="auto">
              <Title level={2} style={{ marginBottom: 0 }}>
                Site Security Audit
              </Title>
              <Typography.Text type="secondary">
                Пассивная проверка DNS / TLS / HTTP по доменному имени.
              </Typography.Text>
            </Col>
            <Col>
              <Tag icon={<SecurityScanTwoTone twoToneColor="#1677ff" />}>
                Passive
              </Tag>
            </Col>
          </Row>

          {/* Input + button */}
          <Card style={{ marginTop: 16 }}>
            <Space.Compact style={{ width: '100%' }}>
              <Input
                size="large"
                placeholder="example.com"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                onPressEnter={runScan}
                allowClear
              />
              <Button
                type="primary"
                size="large"
                icon={<RadarChartOutlined />}
                loading={loading}
                onClick={runScan}
              >
                {loading ? 'Сканируем…' : 'Сканировать'}
              </Button>
            </Space.Compact>

            {err && (
              <Alert
                style={{ marginTop: 12 }}
                message="Ошибка сканирования"
                description={err}
                type="error"
                showIcon
              />
            )}
          </Card>

          {/* per-section statuses */}
          <Row gutter={[16, 16]} style={{ marginTop: 12 }}>
            {sections.map((s) => (
              <Col xs={24} md={8} key={s.key}>
                <Card size="small">
                  <Space
                    style={{ width: '100%', justifyContent: 'space-between' }}
                  >
                    <Space>
                      {s.icon}
                      <b>{s.title}</b>
                    </Space>
                    <SectionStatus state={sectionStates[s.key]} />
                  </Space>
                </Card>
              </Col>
            ))}
          </Row>

          {/* summary + score */}
          {data && (
            <Card style={{ marginTop: 16 }}>
              <Row gutter={[16, 16]} align="middle">
                <Col flex="auto">
                  <Title level={4} style={{ margin: 0 }}>
                    {data.domain.startsWith('http')
                      ? data.domain
                      : `https://${data.domain}`}
                  </Title>
                  <Typography.Text type="secondary">
                    Итоговый балл:
                  </Typography.Text>
                </Col>
                <Col>
                  <Statistic
                    value={data.score}
                    suffix="/ 100"
                    valueStyle={{
                      color:
                        data.score >= 80
                          ? '#52c41a'
                          : data.score >= 60
                          ? '#faad14'
                          : '#f5222d',
                    }}
                  />
                </Col>
                <Col span={24}>
                  <Progress
                    percent={data.score}
                    status={
                      data.score >= 80
                        ? 'success'
                        : data.score >= 60
                        ? 'active'
                        : 'exception'
                    }
                    showInfo={false}
                  />
                </Col>
              </Row>
            </Card>
          )}

          {/* ===== Информация по домену ===== */}
          {data && (
            <Card
              style={{ marginTop: 16 }}
              title={
                <Space>
                  <InfoCircleTwoTone twoToneColor="#1677ff" />
                  Информация по домену
                </Space>
              }
            >
              {/* Базовые DNS */}
              <Descriptions
                column={1}
                size="small"
                labelStyle={{ width: 220 }}
                items={[
                  { key: 'dom', label: 'Домен', children: data.domain },
                  {
                    key: 'a',
                    label: 'A',
                    children: A.length ? (
                      A.join(', ')
                    ) : (
                      <span style={{ color: '#9ca3af' }}>нет</span>
                    ),
                  },
                  {
                    key: 'aaaa',
                    label: 'AAAA',
                    children: AAAA.length ? (
                      AAAA.join(', ')
                    ) : (
                      <span style={{ color: '#9ca3af' }}>нет</span>
                    ),
                  },
                  {
                    key: 'ns',
                    label: 'NS',
                    children: NS.length ? (
                      NS.join(', ')
                    ) : (
                      <span style={{ color: '#9ca3af' }}>нет</span>
                    ),
                  },
                  {
                    key: 'mx',
                    label: 'MX',
                    children: MX.length ? (
                      MX.map((m) => m.exchange).join(', ')
                    ) : (
                      <span style={{ color: '#9ca3af' }}>нет</span>
                    ),
                  },
                  {
                    key: 'txt',
                    label: 'TXT (фрагменты)',
                    children: TXT.length ? (
                      <Space direction="vertical" size={0}>
                        {TXT.slice(0, 4).map((t, i) => (
                          <Text key={i} style={{ wordBreak: 'break-all' }}>
                            {t.length > 140 ? t.slice(0, 140) + '…' : t}
                          </Text>
                        ))}
                        {TXT.length > 4 && (
                          <Text type="secondary">ещё {TXT.length - 4}…</Text>
                        )}
                      </Space>
                    ) : (
                      <span style={{ color: '#9ca3af' }}>нет</span>
                    ),
                  },
                  {
                    key: 'caa',
                    label: 'CAA',
                    children: CAA.length ? (
                      CAA.map(
                        (r: any) =>
                          r?.issue ||
                          r?.issuewild ||
                          r?.iodef ||
                          JSON.stringify(r)
                      ).join(', ')
                    ) : (
                      <span style={{ color: '#9ca3af' }}>нет</span>
                    ),
                  },
                  {
                    key: 'soa',
                    label: 'SOA',
                    children: SOA ? (
                      <Space direction="vertical" size={0}>
                        <Text>mname: {SOA.mname}</Text>
                        <Text>rname: {SOA.rname}</Text>
                        <Text>serial: {SOA.serial}</Text>
                      </Space>
                    ) : (
                      <span style={{ color: '#9ca3af' }}>нет</span>
                    ),
                  },
                  {
                    key: 'dnssec',
                    label: 'DNSSEC (DS)',
                    children: DS ? (
                      DS.ok ? (
                        DS.hasDS ? (
                          <Space>
                            <CheckCircleTwoTone twoToneColor="#52c41a" />
                            <span>DS присутствует</span>
                          </Space>
                        ) : (
                          <Space>
                            <WarningTwoTone twoToneColor="#faad14" />
                            <span>DS не найден</span>
                          </Space>
                        )
                      ) : (
                        <Space>
                          <WarningTwoTone twoToneColor="#faad14" />
                          <span>Не удалось проверить</span>
                        </Space>
                      )
                    ) : (
                      <span style={{ color: '#9ca3af' }}>нет данных</span>
                    ),
                  },
                ]}
              />

              <Divider />

              {/* IP-инфо */}
              <Title level={5} style={{ marginTop: 0 }}>
                IP-адреса / ASN / Geo
              </Title>
              {ipInfo.length === 0 ? (
                <Text type="secondary">Нет данных об IP</Text>
              ) : (
                <List
                  dataSource={ipInfo}
                  renderItem={(row: any) => (
                    <List.Item>
                      <Space direction="vertical" style={{ width: '100%' }}>
                        <Space align="center">
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
                        </Space>
                        <Space split={<Divider type="vertical" />}>
                          <span>
                            <Text type="secondary">PTR:</Text>{' '}
                            {Array.isArray(row.ptr) && row.ptr.length
                              ? row.ptr.join(', ')
                              : '—'}
                          </span>
                          <span>
                            <Text type="secondary">ASN/Org:</Text>{' '}
                            {row.asn ? `AS${row.asn}` : '—'}
                            {row.org ? ` • ${row.org}` : ''}
                          </span>
                          <span>
                            <Text type="secondary">ISP:</Text> {row.isp || '—'}
                          </span>
                          <span>
                            <Text type="secondary">Timezone:</Text>{' '}
                            {row.timezone || '—'}
                          </span>
                        </Space>
                      </Space>
                    </List.Item>
                  )}
                />
              )}

              <Divider />

              {/* TLS сводка */}
              <Title level={5} style={{ marginTop: 0 }}>
                TLS
              </Title>
              <Descriptions
                column={1}
                size="small"
                labelStyle={{ width: 220 }}
                items={[
                  {
                    key: 'proto',
                    label: 'Протокол',
                    children: tlsRaw.protocol || '—',
                  },
                  { key: 'alpn', label: 'ALPN', children: tlsRaw.alpn || '—' },
                  {
                    key: 'cipher',
                    label: 'Шифр',
                    children: tlsRaw.cipher || '—',
                  },
                  {
                    key: 'cert',
                    label: 'Сертификат',
                    children: tlsRaw.certSummary ? (
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
                        <Text>
                          Valid to: {tlsRaw.certSummary.valid_to || '—'}
                        </Text>
                      </Space>
                    ) : (
                      '—'
                    ),
                  },
                  {
                    key: 'ocsp',
                    label: 'OCSP stapling',
                    children:
                      typeof tlsRaw.ocspStapled === 'boolean' ? (
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
                      ),
                  },
                ]}
              />

              <Divider />

              {/* HTTP сводка */}
              <Title level={5} style={{ marginTop: 0 }}>
                HTTP
              </Title>
              <Descriptions
                column={1}
                size="small"
                labelStyle={{ width: 220 }}
                items={[
                  {
                    key: 'status',
                    label: 'Код ответа',
                    children: httpRaw.status ?? '—',
                  },
                  {
                    key: 'server',
                    label: 'Баннер',
                    children: serverBanner || '—',
                  },
                  {
                    key: 'cookies',
                    label: 'Cookie',
                    children: Array.isArray(httpRaw.cookies)
                      ? `${httpRaw.cookies.length}`
                      : '—',
                  },
                  {
                    key: 'security',
                    label: 'Ключевые заголовки',
                    children: (
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
                    ),
                  },
                ]}
              />
            </Card>
          )}

          {/* ===== Защищено ===== */}
          <Row style={{ marginTop: 16 }}>
            <Col span={24}>
              <Card
                title={
                  <Space>
                    <CheckCircleTwoTone twoToneColor="#52c41a" />
                    Защищено
                  </Space>
                }
              >
                {!data ? (
                  <Skeleton active paragraph={{ rows: 6 }} />
                ) : protectedItems.length === 0 ? (
                  <Result
                    status="warning"
                    title="Пока нечего отмечать"
                    subTitle="Как только разделы пройдут без замечаний — они появятся здесь."
                  />
                ) : (
                  <List
                    dataSource={protectedItems}
                    renderItem={(item) => (
                      <List.Item>
                        <Space>
                          <CheckCircleTwoTone twoToneColor="#52c41a" />
                          {item.text}
                        </Space>
                      </List.Item>
                    )}
                  />
                )}
              </Card>
            </Col>
          </Row>

          {/* ===== Уязвимости (раскрываемые карточки) ===== */}
          <Row style={{ marginTop: 16 }}>
            <Col span={24}>
              <Card
                title={
                  <Space>
                    <WarningTwoTone twoToneColor="#f5222d" />
                    Уязвимости
                  </Space>
                }
              >
                {!data ? (
                  <Skeleton active paragraph={{ rows: 6 }} />
                ) : (
                  <Collapse
                    accordion={false}
                    expandIconPosition="end"
                    items={data.results.flatMap((r) =>
                      r.findings.map((g, idx) => {
                        const kb = kbForFinding(g.id, r.checkId);
                        const header = (
                          <Space wrap>
                            {sevTag(g.severity)}
                            <b>{g.title}</b>
                            <Tag>{String(r.checkId).toUpperCase()}</Tag>
                          </Space>
                        );
                        const body = (
                          <>
                            <Paragraph style={{ marginBottom: 8 }}>
                              <Text strong>Описание: </Text>
                              {kb.description}
                            </Paragraph>

                            <Divider style={{ margin: '10px 0' }} />

                            <Paragraph style={{ marginBottom: 6 }}>
                              <Text strong>Evidence:</Text> {g.evidence}
                            </Paragraph>
                            <Paragraph style={{ marginBottom: 0 }}>
                              <Text strong>Recommendation:</Text>{' '}
                              {g.recommendation}
                            </Paragraph>

                            <Divider style={{ margin: '10px 0' }} />

                            <Paragraph style={{ marginBottom: 6 }}>
                              <Text strong>Известные типы атак:</Text>
                            </Paragraph>
                            <ul style={{ marginTop: 0 }}>
                              {kb.attacks.map((a, i) => (
                                <li key={i}>
                                  <Text>{a}</Text>
                                </li>
                              ))}
                            </ul>
                          </>
                        );
                        return {
                          key: `${r.checkId}-${g.id}-${idx}`,
                          label: header,
                          children: body,
                        };
                      })
                    )}
                  />
                )}
              </Card>
            </Col>
          </Row>

          <Row style={{ marginTop: 24, marginBottom: 12 }} justify="center">
            <Col>
              <Space>
                <DeploymentUnitOutlined />
                <Typography.Text type="secondary">
                  Пассивные проверки: DNS / TLS / HTTP
                </Typography.Text>
              </Space>
            </Col>
          </Row>
        </Col>
      </Row>
    </AntdApp>
  );
}
