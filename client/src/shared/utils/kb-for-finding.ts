/** мини-база знаний для раскрываемых карточек */
export function kbForFinding(
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
