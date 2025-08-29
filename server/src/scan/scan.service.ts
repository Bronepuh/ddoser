// server/src/scan/scan.service.ts
import { Injectable, BadRequestException } from '@nestjs/common';
import dns from 'node:dns/promises';
import tls from 'node:tls';
import type { CheckResult, Finding, ScanResponse } from './types';

function f(
  id: string,
  title: string,
  severity: Finding['severity'],
  evidence: string,
  recommendation: string,
): Finding {
  return { id, title, severity, evidence, recommendation };
}

const settle = <T>(p: Promise<T>) =>
  p
    .then((v) => ({ ok: true as const, value: v }))
    .catch((e) => ({ ok: false as const, error: e }));

async function fetchWithTimeout(url: string, ms = 8000) {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), ms);
  try {
    return await fetch(url, {
      method: 'GET',
      redirect: 'manual',
      signal: ac.signal,
    });
  } finally {
    clearTimeout(t);
  }
}

/** ---- DNSSEC (DS) via DoH ---- */
async function dohDS(domain: string) {
  try {
    const r = await fetchWithTimeout(
      `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=DS`,
      7000,
    );
    if (!r.ok) throw new Error(`DoH DS HTTP ${r.status}`);
    const json = (await r.json()) as any;
    const ans = Array.isArray(json?.Answer) ? json.Answer : [];
    const hasDS = ans.some((a: any) => a?.type === 43);
    return { ok: true as const, hasDS, raw: json };
  } catch (e) {
    return { ok: false as const, error: String((e as any)?.message || e) };
  }
}

/** ---- IP enrichment via ipwho.is + PTR ---- */
async function ipInfo(ip: string) {
  const base = `https://ipwho.is/${encodeURIComponent(ip)}`;
  const r = await fetchWithTimeout(base, 7000);
  if (!r.ok) throw new Error(`ipwho.is HTTP ${r.status}`);
  const j = (await r.json()) as any;
  if (j?.success === false)
    throw new Error(String(j?.message || 'ipwho.is error'));
  return j;
}

@Injectable()
export class ScanService {
  private async resolveAll(domain: string) {
    const S = <T>(p: Promise<T>) =>
      p
        .then((v) => ({ status: 'fulfilled' as const, value: v }))
        .catch((e) => ({ status: 'rejected' as const, reason: e }));
    const [A, AAAA, NS, MX, TXT, CAA, SOA, DS] = await Promise.all([
      S(dns.resolve4(domain)),
      S(dns.resolve6(domain)),
      S(dns.resolveNs(domain)),
      S(dns.resolveMx(domain)),
      S(dns.resolveTxt(domain)),
      S(
        (dns as any).resolveCaa
          ? (dns as any).resolveCaa(domain)
          : Promise.resolve([]),
      ),
      S(dns.resolveSoa(domain)),
      S(dohDS(domain)), // DNSSEC (DS) через DoH
    ]);
    return { A, AAAA, NS, MX, TXT, CAA, SOA, DS };
  }

  private getTlsInfo(host: string, port = 443): Promise<any> {
    return new Promise((resolve, reject) => {
      const sock = tls.connect(
        {
          host,
          port,
          servername: host,
          rejectUnauthorized: false,
          ALPNProtocols: ['h2', 'http/1.1'],
        },
        () => {
          const info = {
            protocol: sock.getProtocol(),
            cipher: sock.getCipher(),
            cert: sock.getPeerCertificate(true),
            alpn: (sock as any).alpnProtocol, // negotiated ALPN
            ocspStapled:
              typeof (sock as any).getOCSPResponse === 'function'
                ? Boolean((sock as any).getOCSPResponse())
                : undefined,
          };
          sock.end();
          resolve(info);
        },
      );
      sock.setTimeout(7000, () => sock.destroy(new Error('TLS timeout')));
      sock.on('error', reject);
    });
  }

  /** Сводим проблемы по одной записи на cookie */
  private summarizeCookieIssues(c: string) {
    const parts = c.split(';').map((s) => s.trim());
    const [nameValue, ...attrs] = parts;
    const name = (nameValue.split('=')[0] || '(anon)').trim();
    const hasSecure = attrs.some((a) => /^secure$/i.test(a));
    const hasHttpOnly = attrs.some((a) => /^httponly$/i.test(a));
    const sameSiteAttr = attrs.find((a) => /^samesite=/i.test(a));
    const sameSite = sameSiteAttr
      ? sameSiteAttr.split('=')[1]?.toLowerCase()
      : '';
    const hasDomain = attrs.some((a) => /^domain=/i.test(a));
    const pathAttr = attrs.find((a) => /^path=/i.test(a));
    const path = pathAttr ? pathAttr.split('=')[1] : '';

    const misses: string[] = [];
    if (!hasSecure) misses.push('Secure');
    if (!hasHttpOnly) misses.push('HttpOnly');
    if (!sameSite) misses.push('SameSite');
    if (sameSite === 'none' && !hasSecure)
      misses.push('SameSite=None без Secure');
    if (name.startsWith('__Secure-') && !hasSecure)
      misses.push('__Secure- без Secure');
    if (
      name.startsWith('__Host-') &&
      (!hasSecure || path !== '/' || hasDomain)
    ) {
      misses.push('__Host- требует Secure + Path=/ + без Domain');
    }

    let severity: Finding['severity'] = 'low';
    if (
      misses.includes('Secure') ||
      misses.includes('SameSite=None без Secure') ||
      misses.some((m) => m.startsWith('__Host-'))
    ) {
      severity = 'medium';
    }
    return { name, misses, severity };
  }

  /** ====================== ANALYZERS ====================== */

  private async analyzeDns(domain: string, dnsRaw: any): Promise<CheckResult> {
    const findings: Finding[] = [];
    const passed: string[] = [];

    const a =
      dnsRaw.A.status === 'fulfilled' ? (dnsRaw.A.value as string[]) : [];
    const aaaa =
      dnsRaw.AAAA.status === 'fulfilled' ? (dnsRaw.AAAA.value as string[]) : [];
    const ns =
      dnsRaw.NS.status === 'fulfilled' ? (dnsRaw.NS.value as string[]) : [];
    const mx =
      dnsRaw.MX.status === 'fulfilled'
        ? (dnsRaw.MX.value as { exchange: string }[])
        : [];
    const txt =
      dnsRaw.TXT.status === 'fulfilled' ? (dnsRaw.TXT.value as string[][]) : [];
    const caa =
      dnsRaw.CAA.status === 'fulfilled' ? (dnsRaw.CAA.value as any[]) : [];
    const dsRes =
      dnsRaw.DS.status === 'fulfilled'
        ? (dnsRaw.DS.value as Awaited<ReturnType<typeof dohDS>>)
        : null;

    // ---- IP enrichment (PTR + whois/ASN/geo) ----
    const ips = Array.from(new Set([...a, ...aaaa]));
    const ipInfoList = await Promise.all(
      ips.map(async (ip) => {
        const [ptrSet, whoSet] = await Promise.all([
          settle(dns.reverse(ip)),
          settle(ipInfo(ip)),
        ]);
        const ptr = ptrSet.ok ? (ptrSet.value as string[]) : [];
        const who = whoSet.ok ? whoSet.value : null;
        return {
          ip,
          ptr,
          country: who?.country || null,
          country_code: who?.country_code || null,
          region: who?.region || null,
          city: who?.city || null,
          type: who?.type || null, // residential/hosting
          asn: who?.connection?.asn || null,
          org: who?.connection?.org || who?.connection?.isp || null,
          isp: who?.connection?.isp || null,
          timezone:
            (who?.timezone && (who.timezone.id || who.timezone)) || null,
        };
      }),
    );

    // Плюсы
    if (Array.isArray(caa) && caa.length > 0) {
      const list = caa
        .map((r: any) => r?.issue || r?.issuewild || r?.iodef)
        .filter(Boolean)
        .join(', ');
      passed.push(`CAA задан${list ? `: ${list}` : ''}`);
    }
    if (ns.length >= 2) passed.push(`NS ≥ 2 (${ns.length})`);
    if (aaaa.length > 0)
      passed.push(`IPv6 поддерживается (${aaaa.length} AAAA)`);
    const spf = txt.find((rr) => rr.join('').toLowerCase().includes('v=spf1'));
    const dmarc = txt.find((rr) =>
      rr.join('').toLowerCase().includes('v=dmarc1'),
    );
    if (mx.length > 0 && spf) passed.push('SPF настроен');
    if (mx.length > 0 && dmarc) passed.push('DMARC настроен');
    if (dsRes?.ok && dsRes.hasDS) passed.push('DNSSEC: DS присутствует');

    // Минусы
    if (!caa || caa.length === 0) {
      findings.push(
        f(
          'dns-caa-missing',
          'CAA отсутствует',
          'low',
          'Нет CAA записей',
          'Добавьте CAA (например, issue "letsencrypt.org"/"digicert.com"), чтобы ограничить выпускающих CA.',
        ),
      );
    }
    if (a.length === 1) {
      findings.push(
        f(
          'dns-single-a',
          'Единственный A-адрес',
          'medium',
          `A ${domain} → ${a[0]}`,
          'Рассмотрите CDN/WAF перед origin; на firewall origin разрешите доступ только из диапазонов CDN.',
        ),
      );
    }
    if (ns.length <= 1) {
      findings.push(
        f(
          'dns-single-ns',
          'Недостаточная отказоустойчивость NS',
          'low',
          `NS count: ${ns.length}`,
          'Рекомендуется ≥2 NS у разных провайдеров/сетей.',
        ),
      );
    }
    if (mx.length > 0) {
      if (!spf)
        findings.push(
          f(
            'mail-spf-missing',
            'SPF отсутствует',
            'medium',
            'TXT v=spf1 не найден',
            'Добавьте SPF, ограничивающий источники отправки.',
          ),
        );
      if (!dmarc)
        findings.push(
          f(
            'mail-dmarc-missing',
            'DMARC отсутствует',
            'medium',
            'TXT _dmarc не найден',
            'Добавьте DMARC (p=quarantine или reject) и отчётные адреса.',
          ),
        );
    }
    if (dsRes && dsRes.ok && !dsRes.hasDS) {
      findings.push(
        f(
          'dnssec-missing',
          'DNSSEC не включён (нет DS в родительской зоне)',
          'medium',
          'Отсутствует DS-запись',
          'Включите DNSSEC на домене и опубликуйте DS у регистратора (родительская зона).',
        ),
      );
    } else if (dsRes && !dsRes.ok) {
      findings.push(
        f(
          'dnssec-check-unavailable',
          'Не удалось проверить DNSSEC (DoH)',
          'info',
          String(dsRes.error),
          'Проверьте DNSSEC вручную (dig +dnssec / DS у регистратора).',
        ),
      );
    }

    return {
      checkId: 'dns',
      ok: true,
      findings,
      raw: { ...dnsRaw, ipInfo: ipInfoList },
      passed,
    };
  }

  private analyzeTls(host: string, tlsInfo: any): CheckResult {
    const findings: Finding[] = [];
    const passed: string[] = [];

    const proto = (tlsInfo?.protocol || '').toString();
    if (proto && ['TLSv1.2', 'TLSv1.3'].includes(proto))
      passed.push(`TLS протокол: ${proto}`);
    if (proto && !['TLSv1.2', 'TLSv1.3'].includes(proto)) {
      findings.push(
        f(
          'tls-old-proto',
          'Старые версии TLS включены',
          'medium',
          `Negotiated: ${proto}`,
          'Отключите TLS1.0/1.1. Оставьте TLS1.2/1.3.',
        ),
      );
    }
    const cipherName = tlsInfo?.cipher?.name || '';
    if (/(AES_?GCM|CHACHA20)/i.test(cipherName))
      passed.push(`AEAD шифр: ${cipherName}`);
    if (/RC4|3DES|MD5|NULL|DES|EXPORT/i.test(cipherName)) {
      findings.push(
        f(
          'tls-weak-cipher',
          'Слабые шифры',
          'high',
          cipherName,
          'Отключите устаревшие шифры; используйте AEAD (AES-GCM/CHACHA20-POLY1305).',
        ),
      );
    }
    const alpn = String(tlsInfo?.alpn || '');
    if (alpn === 'h2') passed.push('ALPN: HTTP/2');
    else if (alpn && alpn !== 'h2') {
      findings.push(
        f(
          'tls-no-h2',
          'HTTP/2 не согласован по ALPN',
          'low',
          `ALPN: ${alpn}`,
          'Включите HTTP/2 на фронте (ALPN h2).',
        ),
      );
    }
    const stapled = tlsInfo?.ocspStapled;
    if (stapled === true) passed.push('OCSP stapling включён');
    else if (stapled === false) {
      findings.push(
        f(
          'tls-ocsp-stapling-missing',
          'OCSP stapling не включён',
          'info',
          'getOCSPResponse() пуст',
          'Рекомендуется включить OCSP stapling.',
        ),
      );
    }
    const cert = tlsInfo?.cert;
    if (cert && cert.valid_to) {
      const exp = new Date(cert.valid_to);
      const days = Math.round((+exp - Date.now()) / 86400000);
      if (Number.isFinite(days) && days >= 20)
        passed.push(`Сертификат действителен ещё ~${days} дн.`);
      if (Number.isFinite(days) && days < 20) {
        findings.push(
          f(
            'tls-expiring',
            'Скоро истекает сертификат',
            'medium',
            `~${days} дн.`,
            'Настройте автообновление сертификатов.',
          ),
        );
      }
    }

    return {
      checkId: 'tls',
      ok: true,
      findings,
      raw: {
        protocol: proto,
        cipher: cipherName,
        certSummary: {
          subject: cert?.subject,
          issuer: cert?.issuer,
          valid_to: cert?.valid_to,
        },
        alpn,
        ocspStapled: stapled,
      },
      passed,
    };
  }

  private analyzeHttpCommon(
    host: string,
    http: {
      status: number;
      headers: Record<string, string>;
      setCookies?: string[];
    },
  ): { findings: Finding[]; passed: string[]; raw: any } {
    const findings: Finding[] = [];
    const passed: string[] = [];
    const h = Object.fromEntries(
      Object.entries(http.headers).map(([k, v]) => [
        k.toLowerCase(),
        String(v),
      ]),
    );

    // HTTPS доступен
    passed.push('HTTPS доступен');

    // HSTS
    if (!h['strict-transport-security']) {
      findings.push(
        f(
          'hsts-missing',
          'Нет HSTS',
          'medium',
          'Заголовок Strict-Transport-Security отсутствует',
          'Добавьте HSTS: max-age=31536000; includeSubDomains; preload.',
        ),
      );
    } else {
      passed.push('HSTS задан');
      const v = h['strict-transport-security'];
      const maxAge = /max-age=(\d+)/i.exec(v)?.[1];
      const hasSub = /includesubdomains/i.test(v);
      const hasPreload = /preload/i.test(v);
      const age = maxAge ? parseInt(maxAge, 10) : 0;
      if (!(age >= 31536000 && hasSub && hasPreload)) {
        findings.push(
          f(
            'hsts-not-preload-ready',
            'HSTS не соответствует критериям preload',
            'low',
            v,
            'Для preload: max-age≥31536000, includeSubDomains и preload; убедитесь в 301/308 с HTTP→HTTPS.',
          ),
        );
      }
    }

    // CSP
    const cspStr =
      h['content-security-policy'] || h['content-security-policy-report-only'];
    if (!cspStr) {
      findings.push(
        f(
          'csp-missing',
          'Нет Content-Security-Policy',
          'medium',
          'CSP не задан',
          'Внедрите CSP (или Report-Only) и постепенно ужесточайте.',
        ),
      );
    } else {
      passed.push('CSP задан');
      const csp = cspStr.toLowerCase();
      if (/unsafe-inline/.test(csp))
        findings.push(
          f(
            'csp-unsafe-inline',
            'CSP допускает unsafe-inline',
            'low',
            'unsafe-inline в CSP',
            'Избегайте inline-скриптов, используйте nonce/sha*.',
          ),
        );
      if (/unsafe-eval/.test(csp))
        findings.push(
          f(
            'csp-unsafe-eval',
            'CSP допускает unsafe-eval',
            'low',
            'unsafe-eval в CSP',
            'Исключите eval-подобные конструкции.',
          ),
        );
    }

    // Базовые заголовки
    if (h['x-content-type-options']?.toLowerCase() === 'nosniff') {
      passed.push('X-Content-Type-Options: nosniff');
    } else {
      findings.push(
        f(
          'xcto-missing',
          'Нет X-Content-Type-Options: nosniff',
          'low',
          'Заголовок отсутствует/неверный',
          'Добавьте X-Content-Type-Options: nosniff.',
        ),
      );
    }

    if (
      h['x-frame-options'] ||
      (h['content-security-policy'] || '').includes('frame-ancestors')
    ) {
      passed.push('Защита от clickjacking включена');
    } else {
      findings.push(
        f(
          'xfo-missing',
          'Нет защиты от clickjacking',
          'low',
          'Нет X-Frame-Options или CSP frame-ancestors',
          'Добавьте X-Frame-Options: DENY/SAMEORIGIN или frame-ancestors.',
        ),
      );
    }

    if (h['referrer-policy']) {
      passed.push('Referrer-Policy задан');
    } else {
      findings.push(
        f(
          'referrer-missing',
          'Нет Referrer-Policy',
          'low',
          'Заголовок отсутствует',
          'Добавьте Referrer-Policy: strict-origin-when-cross-origin (или строже).',
        ),
      );
    }

    if (h['permissions-policy']) {
      passed.push('Permissions-Policy задан');
    } else {
      findings.push(
        f(
          'perm-missing',
          'Нет Permissions-Policy',
          'low',
          'Заголовок отсутствует',
          'Ограничьте доступ к чувствительным API через Permissions-Policy.',
        ),
      );
    }

    // Современные заголовки изоляции (информирование)
    if (h['cross-origin-opener-policy']) passed.push('COOP задан');
    else
      findings.push(
        f(
          'coop-missing',
          'Нет Cross-Origin-Opener-Policy',
          'info',
          'Заголовок отсутствует',
          'Добавьте COOP: same-origin (или same-origin-allow-popups).',
        ),
      );

    if (h['cross-origin-embedder-policy']) passed.push('COEP задан');
    else
      findings.push(
        f(
          'coep-missing',
          'Нет Cross-Origin-Embedder-Policy',
          'info',
          'Заголовок отсутствует',
          'Добавьте COEP: require-corp.',
        ),
      );

    if (h['cross-origin-resource-policy']) passed.push('CORP задан');
    else
      findings.push(
        f(
          'corp-missing',
          'Нет Cross-Origin-Resource-Policy',
          'info',
          'Заголовок отсутствует',
          'Добавьте CORP: same-origin/same-site при необходимости.',
        ),
      );

    // CORS
    const aco = h['access-control-allow-origin'];
    const acc = h['access-control-allow-credentials'];
    if (aco === '*' && acc === 'true') {
      findings.push(
        f(
          'cors-wildcard-cred',
          'Небезопасный CORS',
          'high',
          'ACA-Origin: * + credentials=true',
          'Нельзя использовать * с credentials. Укажите конкретные origin.',
        ),
      );
    }

    // Cookies
    const cookies: string[] =
      Array.isArray(http.setCookies) && http.setCookies.length
        ? http.setCookies
        : h['set-cookie']
          ? h['set-cookie'].split(/\r?\n/)
          : [];

    for (const c of cookies) {
      const { name, misses, severity } = this.summarizeCookieIssues(c);
      if (misses.length) {
        findings.push(
          f(
            'cookie-issues',
            `Cookie: ${name} — ${misses.join(', ')}`,
            severity,
            c,
            'Проставьте безопасные атрибуты (Secure/HttpOnly/SameSite и префиксы).',
          ),
        );
      } else {
        passed.push(`Cookie ${name}: атрибуты в порядке`);
      }
    }

    return {
      findings,
      passed,
      raw: { status: http.status, headers: h, cookies },
    };
  }

  private analyzeHttp(
    host: string,
    httpsResp: {
      status: number;
      headers: Record<string, string>;
      setCookies?: string[];
    },
    httpResp?: {
      status: number;
      headers: Record<string, string>;
      location?: string;
    },
  ): CheckResult {
    const https = this.analyzeHttpCommon(host, httpsResp);
    const findings = [...https.findings];
    const passed = [...https.passed];

    // HTTP → HTTPS редирект
    if (httpResp) {
      const st = httpResp.status;
      const loc =
        httpResp.location || (httpResp.headers['location'] as string) || '';
      const toHttps = /^https:\/\//i.test(loc || '');
      const isRedirect = st >= 300 && st < 400;
      if (isRedirect && toHttps) {
        passed.push('HTTP→HTTPS редирект настроен');
      } else {
        findings.push(
          f(
            'no-http-to-https-redirect',
            'HTTP не редиректит на HTTPS',
            'medium',
            `HTTP status=${st} location=${loc || '(нет)'}`,
            'Настройте 301/308 редирект c http:// на https://.',
          ),
        );
      }
    } else {
      findings.push(
        f(
          'http-check-skipped',
          'HTTP проверка (порт 80) не выполнена',
          'info',
          'Нет ответа с http://',
          'Проверьте, что http:// редиректит на https:// постоянным редиректом.',
        ),
      );
    }

    return { checkId: 'http', ok: true, findings, raw: https.raw, passed };
  }

  /** Балл: штрафы −, бонусы +, капы по секциям и по cookies */
  private score(results: CheckResult[]) {
    // Штрафы
    const sevW: Record<Finding['severity'], number> = {
      high: 25,
      medium: 7,
      low: 2,
      info: 0,
    };
    const negCaps: Record<string, number> = { dns: 40, tls: 30, http: 40 };
    let negative = 0;

    for (const r of results) {
      let sub = 0;
      let cookiePenalty = 0;
      for (const g of r.findings) {
        const w = sevW[g.severity] ?? 0;
        if (
          r.checkId === 'http' &&
          typeof (g as any).id === 'string' &&
          (g as any).id.startsWith('cookie-')
        ) {
          cookiePenalty += w;
        } else {
          sub += w;
        }
      }
      if (r.checkId === 'http') sub += Math.min(cookiePenalty, 12); // кап на cookies
      negative += Math.min(sub, negCaps[r.checkId] ?? 40);
    }

    // Бонусы по passed[]
    const bonusMap: [RegExp, number][] = [
      [/DNSSEC.*DS/i, 5],
      [/CAA задан/i, 2],
      [/NS ≥ 2/i, 2],
      [/SPF настроен/i, 2],
      [/DMARC настроен/i, 3],
      [/IPv6 поддерживается/i, 2],
      [/TLS протокол:\s*TLSv1\.3/i, 3],
      [/TLS протокол:\s*TLSv1\.2/i, 2],
      [/AEAD шифр/i, 2],
      [/ALPN:\s*HTTP\/2/i, 2],
      [/OCSP stapling включён/i, 2],
      [/Сертификат действителен/i, 1],
      [/HTTPS доступен/i, 3],
      [/HTTP→HTTPS редирект настроен/i, 4],
      [/HSTS задан/i, 3],
      [/CSP задан/i, 3],
      [/X-Content-Type-Options:\s*nosniff/i, 1],
      [/Защита от clickjacking включена/i, 1],
      [/Referrer-Policy задан/i, 1],
      [/Permissions-Policy задан/i, 1],
      [/COOP задан/i, 1],
      [/COEP задан/i, 1],
      [/CORP задан/i, 1],
    ];
    const bonusCaps: Record<string, number> = { dns: 12, tls: 12, http: 16 };

    let bonus = 0;
    for (const r of results) {
      let b = 0;
      const passed = (r as any).passed as string[] | undefined;
      if (passed) {
        for (const p of passed)
          for (const [re, w] of bonusMap) {
            if (re.test(p)) {
              b += w;
              break;
            }
          }
      }
      bonus += Math.min(b, bonusCaps[r.checkId] ?? 10);
    }

    const raw = 100 - negative + bonus;
    return Math.max(0, Math.min(100, raw));
  }

  /** ====================== PIPELINE ====================== */

  async scanDomain(domainRaw: string): Promise<ScanResponse> {
    const domain = domainRaw
      .trim()
      .toLowerCase()
      .replace(/^https?:\/\//, '')
      .replace(/\/.*$/, '');
    if (!/^[a-z0-9.-]+$/.test(domain))
      throw new BadRequestException('invalid domain');

    const dnsRaw = await this.resolveAll(domain);

    const [tlsSet, httpsSet, httpSet] = await Promise.all([
      settle(this.getTlsInfo(domain)),
      // HTTPS
      settle(
        (async () => {
          const r = await fetchWithTimeout(`https://${domain}/`, 8000);
          const headers = Object.fromEntries(r.headers.entries());
          let setCookies: string[] = [];
          const getSetCookie = (r.headers as any)?.getSetCookie;
          if (typeof getSetCookie === 'function') {
            try {
              setCookies = (r.headers as any).getSetCookie() || [];
            } catch {}
          }
          return { status: r.status, headers, setCookies };
        })(),
      ),
      // HTTP (для проверки редиректа)
      settle(
        (async () => {
          try {
            const r = await fetchWithTimeout(`http://${domain}/`, 8000);
            const headers = Object.fromEntries(r.headers.entries());
            const location =
              (headers['location'] as string) ||
              (headers['Location'] as any) ||
              '';
            return { status: r.status, headers, location };
          } catch {
            return { status: 0, headers: {}, location: '' };
          }
        })(),
      ),
    ]);

    const results: CheckResult[] = [];
    results.push(await this.analyzeDns(domain, dnsRaw));

    if (tlsSet.ok) results.push(this.analyzeTls(domain, tlsSet.value));
    else
      results.push({
        checkId: 'tls',
        ok: false,
        findings: [
          f(
            'tls-conn-failed',
            'Не удалось установить TLS-соединение',
            'medium',
            String(tlsSet.error?.message || tlsSet.error),
            'Проверьте доступность 443/tcp, SNI, сертификат и сетевые ACL/Firewall.',
          ),
        ],
        raw: { error: String(tlsSet.error) },
      });

    if (httpsSet.ok)
      results.push(
        this.analyzeHttp(
          domain,
          httpsSet.value,
          httpSet.ok ? httpSet.value : undefined,
        ),
      );
    else
      results.push({
        checkId: 'http',
        ok: false,
        findings: [
          f(
            'http-https-fetch-failed',
            'HTTP/HTTPS-проверка не выполнена',
            'medium',
            String(httpsSet.error?.message || httpsSet.error),
            'Проверьте доступность сайта по HTTPS и заголовки.',
          ),
        ],
        raw: { error: String(httpsSet.error) },
      });

    return { domain, results, score: this.score(results) };
  }

  // Для SSE: по одному шагу
  async scanSingle(domainRaw: string, step: 'dns' | 'tls' | 'http') {
    const domain = domainRaw
      .trim()
      .toLowerCase()
      .replace(/^https?:\/\//, '')
      .replace(/\/.*$/, '');
    if (!/^[a-z0-9.-]+$/.test(domain)) throw new Error('invalid domain');

    if (step === 'dns') {
      const dnsRaw = await this.resolveAll(domain);
      return await this.analyzeDns(domain, dnsRaw);
    }
    if (step === 'tls') {
      try {
        const info = await this.getTlsInfo(domain);
        return this.analyzeTls(domain, info);
      } catch (e: any) {
        return {
          checkId: 'tls',
          ok: false,
          findings: [
            f(
              'tls-conn-failed',
              'Не удалось установить TLS',
              'medium',
              String(e?.message || e),
              'Проверьте 443/tcp, SNI, сертификат/ACL.',
            ),
          ],
          raw: { error: String(e) },
        };
      }
    }
    // http
    try {
      const https = await (async () => {
        const r = await fetch(`https://${domain}/`, { redirect: 'manual' });
        const headers = Object.fromEntries(r.headers.entries());
        let setCookies: string[] = [];
        const getSetCookie = (r.headers as any)?.getSetCookie;
        if (typeof getSetCookie === 'function') {
          try {
            setCookies = (r.headers as any).getSetCookie() || [];
          } catch {}
        }
        return { status: r.status, headers, setCookies };
      })();
      let httpPlain:
        | { status: number; headers: Record<string, string>; location?: string }
        | undefined;
      try {
        const r = await fetch(`http://${domain}/`, { redirect: 'manual' });
        const headers = Object.fromEntries(r.headers.entries());
        const location =
          (headers['location'] as string) || (headers['Location'] as any) || '';
        httpPlain = { status: r.status, headers, location };
      } catch {}
      return this.analyzeHttp(domain, https, httpPlain);
    } catch (e: any) {
      return {
        checkId: 'http',
        ok: false,
        findings: [
          f(
            'http-fetch-failed',
            'HTTP-проверка не выполнена',
            'medium',
            String(e?.message || e),
            'Проверьте HTTPS и заголовки.',
          ),
        ],
        raw: { error: String(e) },
      };
    }
  }
}
