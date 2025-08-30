/* eslint-disable @typescript-eslint/no-explicit-any */
import { useCallback, useMemo, useRef, useState } from 'react';
import {
  Alert,
  Button,
  Card,
  Col,
  Collapse,
  Divider,
  Input,
  List,
  Progress,
  Result,
  Row,
  Space,
  Statistic,
  Tag,
  Typography,
  Spin,
} from 'antd';
import {
  CheckCircleTwoTone,
  CloudServerOutlined,
  LockOutlined,
  RadarChartOutlined,
  ThunderboltOutlined,
  WarningTwoTone,
  SecurityScanTwoTone,
  DeploymentUnitOutlined,
} from '@ant-design/icons';

import type {
  CheckId,
  CheckResult,
  ScanResponse,
  SectionState,
} from '@shared/types';
import { sevTag } from '@entities/ui/sev-tag/sevTag';
import { kbForFinding } from '@shared/utils/kb-for-finding';
import { streamScan } from '@shared/sse';
import { throttle } from '@shared/utils/throttle';
import { DomainInfo } from '@features/domain-info/ui/DomainInfo';
import { scanOnce } from '@shared/api';

const { Paragraph, Text, Title } = Typography;

const sections: { key: CheckId; title: string; icon: React.ReactNode }[] = [
  { key: 'dns', title: 'DNS', icon: <CloudServerOutlined /> },
  { key: 'tls', title: 'TLS', icon: <LockOutlined /> },
  { key: 'http', title: 'HTTP', icon: <ThunderboltOutlined /> },
];

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

export default function HomePage() {
  const [domain, setDomain] = useState('bronepuh.ru');
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [data, setData] = useState<ScanResponse | null>(null);
  const [progressScore, setProgressScore] = useState<number | null>(null);

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
    setProgressScore(0);
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

            // промежуточный прогресс
            const doneCount = Object.values(resultsRef.current).length;
            const tempScore = Math.round((doneCount / sections.length) * 100);

            // если финальный score известен, ограничиваем им
            setProgressScore(() => {
              if (data?.score != null) return Math.min(tempScore, data.score);
              return tempScore;
            });

            const results = sections
              .map((s) => resultsRef.current[s.key])
              .filter(Boolean) as CheckResult[];
            if (results.length)
              setData({ domain, results, score: data?.score ?? tempScore });
          },

          onError: (id) => setSectionStates((s) => ({ ...s, [id]: 'error' })),
          onDone: async () => {
            try {
              const full = await scanOnce(domain);
              setData(full);
              setProgressScore(full.score); // плавно добиваем до финала
            } catch (err) {
              console.log(err);
            }
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
        json.results.forEach((r: any) => (next[r.checkId as CheckId] = r));
        resultsRef.current = next;
        setSectionStates({ dns: 'done', tls: 'done', http: 'done' });
        setData(json);
        setProgressScore(json.score);
      }
    } catch (e: any) {
      setErr(e?.message || 'Scan failed');
    } finally {
      setLoading(false);
    }
  }

  // eslint-disable-next-line react-hooks/exhaustive-deps
  const runScanThrottled = useCallback(
    throttle(() => {
      runScan();
    }, 3000),
    [domain]
  );

  /** ======== UI ======== */
  return (
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
        <Card style={{ marginTop: 16 }} bodyStyle={{ padding: 0 }}>
          <Space.Compact style={{ width: '100%' }}>
            <Input
              size="large"
              placeholder="example.com"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              onPressEnter={runScanThrottled}
              allowClear
            />
            <Button
              type="primary"
              size="large"
              icon={<RadarChartOutlined />}
              loading={loading}
              onClick={runScanThrottled}
              disabled={loading}
              style={{ backgroundColor: '#0f9603', borderColor: '#0f9603' }}
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
        {loading || data ? (
          <Card style={{ marginTop: 16 }}>
            <Row gutter={[16, 16]} align="middle">
              <Col flex="auto">
                <Title level={4} style={{ margin: 0 }}>
                  {data?.domain
                    ? data.domain.startsWith('http')
                      ? data.domain
                      : `https://${data.domain}`
                    : domain}
                </Title>
                <Typography.Text type="secondary">
                  Итоговый балл:
                </Typography.Text>
              </Col>
              <Col>
                <Statistic
                  value={progressScore ?? 0}
                  suffix="/ 100"
                  valueStyle={{
                    color:
                      (progressScore ?? 0) >= 80
                        ? '#52c41a'
                        : (progressScore ?? 0) >= 60
                          ? '#faad14'
                          : '#f5222d',
                  }}
                />
              </Col>
              <Col span={24}>
                <Progress
                  percent={progressScore ?? 0}
                  status={
                    loading
                      ? 'active'
                      : (progressScore ?? 0) >= 80
                        ? 'success'
                        : (progressScore ?? 0) >= 60
                          ? 'active'
                          : 'exception'
                  }
                  showInfo={false}
                />
              </Col>
            </Row>
          </Card>
        ) : null}

        <DomainInfo data={data} />

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
                <></>
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
                <></>
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
  );
}
