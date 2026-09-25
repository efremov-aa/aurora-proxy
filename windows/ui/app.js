(function () {
  'use strict';
  var V = { S: null, SUBS: null, STATS: null, MESH: null, RU: null, UPD: null, ROUTES: null, SET: null, SEC: null, TG: null };
  var CFG = { tab: 'dashboard', ruFailOnly: false, _rid: 0, policyOnce: false };
  var LS = { theme: 'aurora_theme', sec: 'aurora_sec_tok', tfa: 'aurora_2fa', lang: 'aurora_lang' };

  /* ================= I18N ================= */
  var LANGS = [
    { c: 'ru', n: 'Русский' }, { c: 'en', n: 'English' }, { c: 'es', n: 'Español' },
    { c: 'de', n: 'Deutsch' }, { c: 'fr', n: 'Français' }, { c: 'tr', n: 'Türkçe' },
    { c: 'pt', n: 'Português' }, { c: 'zh', n: '中文' }, { c: 'ar', n: 'العربية' }, { c: 'hi', n: 'हिन्दी' }
  ];
  var I18N = {
    ru: {
      'pol.head': 'Политика сервиса', 'pol.readOnly': 'Просмотр', 'pol.accept': 'Принимаю условия', 'ru.regions': 'Сегменты', 'ru.custom-ph': 'Свои домены через запятую (необязательно)',
      'dash.manage': 'Управление', 'pool.refresh-btn': 'Обновить ключи', 'pool.check-btn': 'Проверить ключи', 'mesh.ping-btn': 'Пинг меш',
      'nav.dash': 'Обзор', 'nav.keys': 'Ключи', 'nav.devices': 'Устройства',
      'nav.connect': 'Внешний доступ', 'nav.rusegment': 'Ру-сегмент', 'nav.tgws': 'TG-WS',
      'nav.mesh': 'Меш-сеть', 'nav.mesh-join': 'Подключение', 'nav.mesh-topo': 'Топология', 'nav.mesh-routes': 'Маршруты',
      'nav.shop': 'Магазин', 'nav.shop-plans': 'Тарифы', 'nav.shop-features': 'Функции', 'nav.shop-billing': 'Платежи',
      'nav.update': 'Обновление', 'nav.versions': 'Версии', 'nav.settings': 'Сервер', 'nav.security': 'Безопасность', 'nav.logs': 'Логи',
      'nav.group.home': 'Домашний прокси', 'nav.group.upd': 'Обновления', 'nav.group.set': 'Настройки',
      'g.you': 'Вы', 'g.yours': 'ваш', 'status.on': 'онлайн', 'status.off': 'оффлайн', 'status.warn': 'нестабильно',
      'status.online': 'работает', 'status.stopped': 'остановлен', 'status.active': 'активен', 'status.dead': 'мёртв',
      'status.bad': 'плохой', 'status.slow': 'медлен.', 'status.noip': 'noip', 'status.ok': 'ок', 'status.final': 'финал',
      'status.direct': 'direct', 'status.enabled': 'включено', 'status.disabled': 'выключено',
      'btn.vpn-off': '🌀 Включить VPN', 'btn.vpn-on': '🌀 VPN вкл', 'btn.rotate': '🎲 Сменить ключ', 'btn.choose': '💎 Выбрать',
      'btn.copy': '📋 Копировать', 'btn.save': 'Сохранить', 'btn.login': '🔑 Войти', 'btn.logout': 'Выйти',
      'k.keys': 'ключей: ', 'k.empty': 'ключей пока нет', 'k.mine': 'свой', 'k.github': 'github',
      'k.add-ok': 'Ключ добавлен 🐾', 'k.add-err': 'Ошибка добавления', 'k.need-vless': 'Нужна vless:// ссылка',
      'k.active-ok': 'активен 🐾', 'k.active-err': 'Не удалось активировать', 'k.clean-ok': 'Мёртвые ключи удалены 🐾',
      'k.set-active': 'Сделать активным',
      'd.empty': 'устройств пока нет',
      'c.on': 'включено', 'c.off': 'выключено', 'c.server': 'сервер', 'c.qr-na': 'QR недоступен', 'c.qr-na-off': 'QR недоступен офлайн',
      'c.secret-hint': 'Секреты видны только локально. Укажите X-Auth токен панели, если включён.',
      'ru.empty': 'проверка ещё не выполнялась', 'ru.avail': 'доступен', 'ru.unavail': 'недоступен', 'ru.all': 'все домены доступны ✅',
      'upd.avail': 'доступно', 'upd.cur': 'актуально', 'upd.msg-avail': 'Доступно обновление', 'upd.msg-cur': 'Установлена актуальная версия',
      'upd.checked': 'Проверено: ',
      'w.mesh-nodes': 'Узлов в сети:', 'w.mesh-exit': 'выход через', 'w.hub': 'хаб', 'w.mesh-none': 'Меш не подключён. Приглашение — во вкладке «Подключение».',
      'w.plan': 'Активный план:', 'w.ru': 'RU-доменов:', 'w.ru-ok': 'доступно',
      'mesh.connected': 'подключён', 'mesh.not': 'не подключён', 'mesh.member': 'участник', 'mesh.hub': 'хаб',
      'mesh.no-nodes': 'узлов нет — добавьте первый', 'mesh.node': 'узел',
      'routes.empty': 'маршрутов пока нет', 'routes.active': 'активен', 'routes.off': 'выкл',
      'plans.na': 'тарифы недоступны в этой сборке', 'plans.traffic': 'Трафик:', 'plans.devices': 'Устройств:', 'plans.keys': 'Ключей:',
      'plans.free': 'Бесплатно', 'plans.per-mo': '/мес', 'plans.current': 'текущий',
      'bill.empty': 'платежей пока нет',
      'sec.on': 'включён', 'sec.off': 'выключен', 'sec.access': 'LAN-only: ', 'sec.da': 'да', 'sec.no': 'нет', 'sec.blk': 'блок',
      'sec.rat': 'вкл', 'sec.rat-off': 'выкл',
      'log.empty': 'лог пуст', 'rec.empty': 'восстановлений не было',
      't.err': 'Сервер недоступен', 't.err-gen': 'Ошибка', 't.action-ok': 'Готово 🐾',
      'inv.need': 'Вставьте invite-код меша', 'inv.bad': 'invite не похож на aurora://invite — проверьте код',
      'inv.add-ok': 'Узел добавлен в меш 🕸️', 'inv.add-err': 'Не удалось подключиться', 'inv.leave-none': 'Нет узлов для отключения',
      'inv.leave-ok': 'Узлы удалены, вышли из меша 🕸️', 'inv.leave-err': 'Ошибка отключения', 'inv.regen-ok': 'Invite обновлён 🔄',
      'inv.regen-err': 'Не удалось', 'inv.copy-ok': 'Invite скопирован 🔗', 'inv.empty': 'Invite пока недоступен',
      'inv.topology': 'Топология обновлена 🕸️',
      'set.saved': 'Настройки сохранены 🐾', 'set.save-err': 'Ошибка сохранения',
      'sec.need-token': 'Введите токен', 'sec.accept': 'Токен принят, панель разблокирована 🛡️', 'sec.reject': 'Токен не принят (401)',
      'sec.logout': 'Выход выполнен', 'sec.rotate-ok': 'Reality-ключи ротированы 🔄', 'sec.rotate-na': 'Ротация недоступна в этой сборке',
      'upd.run-ok': 'Проверка запущена (фоново)', 'upd.check-err': 'Ошибка проверки', 'upd.apply-ok': 'Обновление запущено ⬆️',
      'upd.apply-err': 'Не удалось запустить', 'upd.admin': 'Управление каналом обновлений — в админ-панели 🐾',
      'plans.admin': 'Управление тарифами — в админ-панели 🐾', 'plans.buy': 'Тариф «', 'plans.buy2': '» — покупка в админ-панели 🐾',
      'feat.admin': 'Магазин недоступен в этой сборке 🐾', 'feat.buy': 'Функция «', 'feat.buy2': '» — витрина в публичной сборке 🐾',
      'vpn.on': 'VPN включён 🌀', 'vpn.off': 'VPN выключен', 'vpn.err': 'Ошибка', 'rot.ok': 'Ключ ротирован 🎲', 'rot.err': 'Не удалось ротировать',
      'pool.refresh': 'Пул обновлён 🔄', 'pool.check': 'Проверка ключей запущена в фоне 🧪', 'mesh.ping': 'Пинг меш запущен 📡',
      'mesh.policy-saved': 'Политика хаба сохранена 🎛',
      'copy.link-ok': 'Ссылка скопирована 📋', 'copy.link-na': 'Ссылка пока недоступна', 'ru.done': 'Проверка завершена 🇷🇺',
      'ru.run': 'Проверка запущена', 'ru.failonly': '💀 Только проблемы', 'ru.failonly-on': '💀 Только проблемы ✓',
      'tg.restarted': 'TG-WS перезапущен ✈️', 'tg.restart-err': 'Ошибка рестарта',
      'fmt.kb': 'КБ', 'fmt.mb': 'МБ', 'fmt.gb': 'ГБ', 'fmt.ul': 'Безлимит', 'fmt.per-mo': '/мес',
      'fmt.s': ' с', 'fmt.min': ' мин', 'fmt.h': ' ч', 'fmt.d': ' д',
      'dash.mode': 'Режим', 'dash.ip': 'Выходной IP', 'dash.conns': 'Соединения', 'dash.traffic': 'Трафик ↓ / ↑', 'dash.mesh-nodes': 'Меш-узлов', 'dash.plan': 'Тариф',
      'upd.details': 'Подробнее', 'upd.now': 'Обновить', 'w.proxy': 'Состояние прокси', 'w.check-ru': 'Проверить',
      'keys.uri-ph': 'vless://… вставьте свою ссылку (Reality)', 'keys.add': 'Свой ключ', 'keys.clean': 'Очистить мёртвые', 'keys.src': 'github + свои',
      'th.tag': 'Тег', 'th.source': 'Источник', 'th.status': 'Статус', 'th.ping': 'Пинг', 'th.exit': 'Exit IP', 'th.sites': 'Sites',
      'dev.head': 'Устройства в сети', 'th.device': 'Устройство', 'th.conn': 'Conn', 'th.dl': '↓ Скачано', 'th.ul': '↑ Отдано',
      'cx.head': 'Подключение извне', 'cx.hint': 'Готовая vless-ссылка на ваш прокси. Вставьте её в v2rayN / v2rayNG / NekoBox — и трафик пойдёт через этот сервер откуда угодно.', 'cx.addr': 'Адрес', 'cx.port': 'Порт', 'cx.uuid': 'UUID', 'cx.sni': 'SNI',
      'ru.partial': 'частично', 'ru.hint': 'Доступность российских ресурсов напрямую с сервера (без VPN). Если сегмент работает — RU-сайты открываются без прокси.', 'ru.ok': 'Доступно', 'ru.bad': 'Проблемы', 'ru.med': 'Медиана', 'ru.ts': 'Проверено',
      'ru.check-now': 'Проверить сейчас', 'th.domain': 'Домен', 'th.time': 'Время',
      'tgws.head': 'Telegram WS-прокси', 'tgws.proc': 'Процесс', 'tgws.secret': 'Секрет', 'tgws.restart': 'Рестарт TG-WS',
      'mj.head': 'Подключение к меш-сети', 'mj.p': 'Ваш прокси может быть частью приватной меш-сети Aurora. Это даёт доступ к эксклюзивным локациям других участников, автоматический обход блокировок и резервные маршруты.',
      'mj.invite-ph': 'Вставьте invite-код меша (например: aurora-home-a1b2c3d4)', 'mj.join': 'Подключиться', 'mj.st': 'Статус меша', 'mj.name': 'Имя меша', 'mj.role': 'Роль',
      'mj.nodes': 'Узлов доступно', 'mj.ping': 'Пинг до хаба', 'mj.enc': 'Шифрование', 'mj.what': 'Что даёт меш',
      'mj.leave': 'Покинуть меш', 'mj.regen': 'Обновить invite', 'mj.pol': 'Политика хаба', 'mj.pol-hint': 'Головной сервер управляет тем, какие вкладки видны у клиентов меша. Клиенты, подключённые по invite этого сервера, автоматически применяют политику (обновление каждые 15 сек).',
      'mj.master': 'Cервер — головной, управляет видимостью у клиентов', 'mj.show-mesh': 'Показывать клиентам вкладку «Меш-сеть»', 'mj.show-subs': 'Показывать клиентам вкладку «Магазин»',
      'mt.hint': 'Ваш прокси (в центре) и узлы других участников меша. Соединения активны, если трафик ходит через них.',
      'mrt.hint': 'Правила, какой трафик через какой узел выходит в интернет. Порядок — сверху вниз.', 'th.what': 'Что', 'th.via': 'Куда', 'th.proto': 'Протокол',
      'sp.head': 'Тарифные планы', 'sp.hint': 'Базовый набор функций прокси. Апгрейд — в один клик, применяется мгновенно, без потери соединений.', 'sp.loading': 'загрузка тарифов…', 'sp.comp': 'Состав тарифов', 'th.func': 'Функция', 'th.val': 'Значение',
      'sf.instant': '+ активируются мгновенно',
      'sb.head': 'Оплата и продление', 'sb.hint': 'Активный план, срок действия и история платежей. Продление — в один клик.', 'sb.plan': 'Текущий план', 'sb.until': 'Активен до', 'sb.buy': 'Продлить / сменить план', 'sb.hist': 'История платежей', 'sb.active': 'Активных', 'sb.income': 'Доход за месяц', 'sb.traffic-month': 'Трафик за месяц',
      'th.date': 'Дата', 'th.desc': 'Описание', 'th.sum': 'Сумма',
      'upd.apply': 'Обновить сейчас', 'upd.auto': 'Автообновление', 'upd.auto-hint': 'Обновление производится из GitHub-релизов. Бинарник скачивается, проверяется, заменяется атомарно — прокси перезапускается за пару секунд.',
      'upd.src': 'Источник обновлений', 'th.param': 'Параметр', 'upd.repo': 'Репозиторий', 'upd.sig': 'Проверка подписи', 'upd.rollback': 'Откат при сбое',
      'upd.check-now': 'Проверить сейчас', 'upd.stable': 'stable — только стабильные', 'upd.rc': 'rc — кандидаты в релиз', 'upd.nightly': 'nightly — ночные сборки',
      'upd.mode-auto': 'Автообновление включено', 'upd.mode-notify': 'Только уведомлять', 'upd.mode-off': 'Не проверять',
      'ver.head': 'История версий',
      'set.head': 'Параметры сервера', 'set.host': 'Хост', 'set.port': 'Xray-порт', 'set.ver': 'Версия', 'set.uptime': 'Аптайм',
      'set.common': 'Общие', 'set.mesh': 'Меш', 'set.name-ph': 'Название сервера', 'set.meshid-ph': 'ID меша', 'set.copy-invite': 'Копировать invite',
      'sec.hint': 'Admin-токен панели и Reality-ключи внешнего доступа. Меняется на живой конфиг.', 'sec.panel': 'Панель', 'sec.tok-ph': 'Admin-токен (Bearer) — нужен для POST /api/*', 'sec.acc-v': 'Access', 'sec.pbk-ph': 'public key', 'sec.rotate': 'Ротация ключей',
      'log.head': 'Системный лог', 'log.loading': 'загрузка…', 'log.refresh': 'Обновить', 'log.download': 'Скачать', 'rclog.head': 'Журнал recovery',
      'th.node': 'Узел', 'th.region': 'Регион', 'th.route': 'Маршрут', 'sec.tok': 'Admin-токен', 'sec.reality': 'Reality',
      'theme.sun': '🌙', 'theme.moon': '☀️'
    },
    en: {
      'pol.head': 'Service policy', 'pol.readOnly': 'View', 'pol.accept': 'I accept the terms', 'ru.regions': 'Segments', 'ru.custom-ph': 'Custom domains, comma separated (optional)',
      'dash.manage': 'Manage', 'pool.refresh-btn': 'Refresh keys', 'pool.check-btn': 'Check keys', 'mesh.ping-btn': 'Mesh ping',
      'nav.dash': 'Dashboard', 'nav.keys': 'Keys', 'nav.devices': 'Devices',
      'nav.connect': 'External access', 'nav.rusegment': 'RU segment', 'nav.tgws': 'TG-WS',
      'nav.mesh': 'Mesh', 'nav.mesh-join': 'Connect', 'nav.mesh-topo': 'Topology', 'nav.mesh-routes': 'Routes',
      'nav.shop': 'Store', 'nav.shop-plans': 'Plans', 'nav.shop-features': 'Features', 'nav.shop-billing': 'Billing',
      'nav.update': 'Update', 'nav.versions': 'Versions', 'nav.settings': 'Server', 'nav.security': 'Security', 'nav.logs': 'Logs',
      'nav.group.home': 'Home proxy', 'nav.group.upd': 'Updates', 'nav.group.set': 'Settings',
      'g.you': 'You', 'g.yours': 'yours', 'status.on': 'online', 'status.off': 'offline', 'status.warn': 'unstable',
      'status.online': 'running', 'status.stopped': 'stopped', 'status.active': 'active', 'status.dead': 'dead',
      'status.bad': 'bad', 'status.slow': 'slow', 'status.noip': 'noip', 'status.ok': 'ok', 'status.final': 'final',
      'status.direct': 'direct', 'status.enabled': 'enabled', 'status.disabled': 'disabled',
      'btn.vpn-off': '🌀 Enable VPN', 'btn.vpn-on': '🌀 VPN on', 'btn.rotate': '🎲 Rotate key', 'btn.choose': '💎 Choose',
      'btn.copy': '📋 Copy', 'btn.save': 'Save', 'btn.login': '🔑 Sign in', 'btn.logout': 'Sign out',
      'k.keys': 'keys: ', 'k.empty': 'no keys yet', 'k.mine': 'mine', 'k.github': 'github',
      'k.add-ok': 'Key added 🐾', 'k.add-err': 'Add failed', 'k.need-vless': 'A vless:// link is required',
      'k.active-ok': 'active 🐾', 'k.active-err': 'Could not activate', 'k.clean-ok': 'Dead keys removed 🐾',
      'k.set-active': 'Make active',
      'd.empty': 'no devices yet',
      'c.on': 'enabled', 'c.off': 'disabled', 'c.server': 'server', 'c.qr-na': 'QR unavailable', 'c.qr-na-off': 'QR offline unavailable',
      'c.secret-hint': 'Secrets are only visible locally. Provide the panel X-Auth token if enabled.',
      'ru.empty': 'check not run yet', 'ru.avail': 'available', 'ru.unavail': 'unavailable', 'ru.all': 'all domains available ✅',
      'upd.avail': 'available', 'upd.cur': 'up to date', 'upd.msg-avail': 'Update available', 'upd.msg-cur': 'Up to date',
      'upd.checked': 'Checked: ',
      'w.mesh-nodes': 'Mesh nodes:', 'w.mesh-exit': 'exit via', 'w.hub': 'hub', 'w.mesh-none': 'Mesh not connected. Invite is in the "Connect" tab.',
      'w.plan': 'Active plan:', 'w.ru': 'RU domains:', 'w.ru-ok': 'available',
      'mesh.connected': 'connected', 'mesh.not': 'not connected', 'mesh.member': 'member', 'mesh.hub': 'hub',
      'mesh.no-nodes': 'no nodes yet — add the first one', 'mesh.node': 'node',
      'routes.empty': 'no routes yet', 'routes.active': 'active', 'routes.off': 'off',
      'plans.na': 'plans unavailable in this build', 'plans.traffic': 'Traffic:', 'plans.devices': 'Devices:', 'plans.keys': 'Keys:',
      'plans.free': 'Free', 'plans.per-mo': '/mo', 'plans.current': 'current',
      'bill.empty': 'no payments yet',
      'sec.on': 'enabled', 'sec.off': 'disabled', 'sec.access': 'LAN-only: ', 'sec.da': 'yes', 'sec.no': 'no', 'sec.blk': 'block',
      'sec.rat': 'on', 'sec.rat-off': 'off',
      'log.empty': 'log is empty', 'rec.empty': 'no recoveries',
      't.err': 'Server unavailable', 't.err-gen': 'Error', 't.action-ok': 'Done 🐾',
      'inv.need': 'Paste the mesh invite code', 'inv.bad': 'invite does not look like aurora://invite — check the code',
      'inv.add-ok': 'Node added to mesh 🕸️', 'inv.add-err': 'Could not connect', 'inv.leave-none': 'No nodes to disconnect',
      'inv.leave-ok': 'Nodes removed, left the mesh 🕸️', 'inv.leave-err': 'Disconnect error', 'inv.regen-ok': 'Invite regenerated 🔄',
      'inv.regen-err': 'Failed', 'inv.copy-ok': 'Invite copied 🔗', 'inv.empty': 'Invite not available yet',
      'inv.topology': 'Topology updated 🕸️',
      'set.saved': 'Settings saved 🐾', 'set.save-err': 'Save error',
      'sec.need-token': 'Enter the token', 'sec.accept': 'Token accepted, panel unlocked 🛡️', 'sec.reject': 'Token rejected (401)',
      'sec.logout': 'Signed out', 'sec.rotate-ok': 'Reality keys rotated 🔄', 'sec.rotate-na': 'Rotation unavailable in this build',
      'upd.run-ok': 'Check started (background)', 'upd.check-err': 'Check error', 'upd.apply-ok': 'Update started ⬆️',
      'upd.apply-err': 'Could not start', 'upd.admin': 'Update channel is managed in the admin panel 🐾',
      'plans.admin': 'Plans are managed in the admin panel 🐾', 'plans.buy': 'Plan "', 'plans.buy2': '" — purchase in the admin panel 🐾',
      'feat.admin': 'Store unavailable in this build 🐾', 'feat.buy': 'Feature "', 'feat.buy2': '" — showcase in the public build 🐾',
      'vpn.on': 'VPN on 🌀', 'vpn.off': 'VPN off', 'vpn.err': 'Error', 'rot.ok': 'Key rotated 🎲', 'rot.err': 'Could not rotate',
      'pool.refresh': 'Pool refreshed 🔄', 'pool.check': 'Key check started in background 🧪', 'mesh.ping': 'Mesh ping started 📡',
      'mesh.policy-saved': 'Hub policy saved 🎛',
      'copy.link-ok': 'Link copied 📋', 'copy.link-na': 'Link not available yet', 'ru.done': 'Check finished 🇷🇺',
      'ru.run': 'Check started', 'ru.failonly': '💀 Only issues', 'ru.failonly-on': '💀 Only issues ✓',
      'tg.restarted': 'TG-WS restarted ✈️', 'tg.restart-err': 'Restart error',
      'fmt.kb': 'KB', 'fmt.mb': 'MB', 'fmt.gb': 'GB', 'fmt.ul': 'Unlimited', 'fmt.per-mo': '/mo',
      'fmt.s': ' s', 'fmt.min': ' min', 'fmt.h': ' h', 'fmt.d': ' d',
      'dash.mode': 'Mode', 'dash.ip': 'Exit IP', 'dash.conns': 'Connections', 'dash.traffic': 'Traffic ↓ / ↑', 'dash.mesh-nodes': 'Mesh nodes', 'dash.plan': 'Plan',
      'upd.details': 'Details', 'upd.now': 'Update', 'w.proxy': 'Proxy status', 'w.check-ru': 'Check',
      'keys.uri-ph': 'vless://… paste your link (Reality)', 'keys.add': 'Add key', 'keys.clean': 'Remove dead', 'keys.src': 'github + mine',
      'th.tag': 'Tag', 'th.source': 'Source', 'th.status': 'Status', 'th.ping': 'Ping', 'th.exit': 'Exit IP', 'th.sites': 'Sites',
      'dev.head': 'Devices on network', 'th.device': 'Device', 'th.conn': 'Conn', 'th.dl': '↓ Downloaded', 'th.ul': '↑ Uploaded',
      'cx.head': 'External connection', 'cx.hint': 'Ready vless-link to your proxy. Paste it in v2rayN / v2rayNG / NekoBox — and traffic will go through this server from anywhere.', 'cx.addr': 'Address', 'cx.port': 'Port', 'cx.uuid': 'UUID', 'cx.sni': 'SNI',
      'ru.partial': 'partial', 'ru.hint': 'Availability of Russian resources directly from the server (without VPN). If the segment works — RU sites open without proxy.', 'ru.ok': 'Available', 'ru.bad': 'Issues', 'ru.med': 'Median', 'ru.ts': 'Checked',
      'ru.check-now': 'Check now', 'th.domain': 'Domain', 'th.time': 'Time',
      'tgws.head': 'Telegram WS-proxy', 'tgws.proc': 'Process', 'tgws.secret': 'Secret', 'tgws.restart': 'Restart TG-WS',
      'mj.head': 'Join mesh network', 'mj.p': 'Your proxy can be part of the private Aurora mesh network. It gives access to exclusive locations of other members, automatic blocking bypass and backup routes.',
      'mj.invite-ph': 'Paste mesh invite code (e.g.: aurora-home-a1b2c3d4)', 'mj.join': 'Connect', 'mj.st': 'Mesh status', 'mj.name': 'Mesh name', 'mj.role': 'Role',
      'mj.nodes': 'Nodes available', 'mj.ping': 'Ping to hub', 'mj.enc': 'Encryption', 'mj.what': 'What mesh gives',
      'mj.leave': 'Leave mesh', 'mj.regen': 'Update invite', 'mj.pol': 'Hub policy', 'mj.pol-hint': 'The hub server controls which tabs clients of the mesh see. Clients connected by invite of this server automatically apply the policy (update every 15 sec).',
      'mj.master': 'Server is hub, controls visibility for clients', 'mj.show-mesh': 'Show “Mesh network” tab to clients', 'mj.show-subs': 'Show “Store” tab to clients',
      'mt.hint': 'Your proxy (in the center) and nodes of other mesh members. Connections are active if traffic goes through them.',
      'mrt.hint': 'Rules for which traffic goes to the internet via which node. Order is top to bottom.', 'th.what': 'What', 'th.via': 'Where', 'th.proto': 'Protocol',
      'sp.head': 'Plans', 'sp.hint': 'Basic set of proxy features. Upgrade in one click, applied instantly, without losing connections.', 'sp.loading': 'loading plans…', 'sp.comp': 'Plan contents', 'th.func': 'Feature', 'th.val': 'Value',
      'sf.instant': '+ activate instantly',
      'sb.head': 'Billing and renewal', 'sb.hint': 'Active plan, validity and payment history. Renewal — in one click.', 'sb.plan': 'Current plan', 'sb.until': 'Active until', 'sb.buy': 'Renew / change plan', 'sb.hist': 'Payment history',
      'th.date': 'Date', 'th.desc': 'Description', 'th.sum': 'Amount',
      'upd.apply': 'Update now', 'upd.auto': 'Auto-update', 'upd.auto-hint': 'Update is performed from GitHub releases. Binary is downloaded, verified, replaced atomically — proxy restarts in a couple of seconds.',
      'upd.src': 'Update source', 'th.param': 'Parameter', 'upd.repo': 'Repository', 'upd.sig': 'Signature check', 'upd.rollback': 'Rollback on failure',
      'upd.check-now': 'Check now', 'upd.stable': 'stable — stable only', 'upd.rc': 'rc — release candidates', 'upd.nightly': 'nightly — nightly builds',
      'upd.mode-auto': 'Auto-update enabled', 'upd.mode-notify': 'Notify only', 'upd.mode-off': 'Do not check',
      'ver.head': 'Version history',
      'set.head': 'Server parameters', 'set.host': 'Host', 'set.port': 'Xray port', 'set.ver': 'Version', 'set.uptime': 'Uptime',
      'set.common': 'Common', 'set.mesh': 'Mesh', 'set.name-ph': 'Server name', 'set.meshid-ph': 'Mesh ID', 'set.copy-invite': 'Copy invite',
      'sec.hint': 'Admin panel token and external Reality keys. Changes live config.', 'sec.panel': 'Panel', 'sec.tok-ph': 'Admin token (Bearer) — needed for POST /api/*', 'sec.acc-v': 'Access', 'sec.pbk-ph': 'public key', 'sec.rotate': 'Rotate keys',
      'log.head': 'System log', 'log.loading': 'loading…', 'log.refresh': 'Refresh', 'log.download': 'Download', 'rclog.head': 'Recovery journal',
      'th.node': 'Node', 'th.region': 'Region', 'th.route': 'Route', 'sec.tok': 'Admin token', 'sec.reality': 'Reality',
      'theme.sun': '🌙', 'theme.moon': '☀️'
    },
    es: {
      'pol.head': 'Política del servicio', 'pol.readOnly': 'Ver', 'pol.accept': 'Acepto los términos', 'ru.regions': 'Segmentos', 'ru.custom-ph': 'Dominios propios separados por comas (opcional)',
      'dash.manage': 'Gestión', 'pool.refresh-btn': 'Actualizar claves', 'pool.check-btn': 'Comprobar claves', 'mesh.ping-btn': 'Ping mesh',
      'nav.dash': 'Panel', 'nav.keys': 'Claves', 'nav.devices': 'Dispositivos',
      'nav.connect': 'Acceso externo', 'nav.rusegment': 'Segmento RU', 'nav.tgws': 'TG-WS',
      'nav.mesh': 'Red mesh', 'nav.mesh-join': 'Conexión', 'nav.mesh-topo': 'Topología', 'nav.mesh-routes': 'Rutas',
      'nav.shop': 'Tienda', 'nav.shop-plans': 'Planes', 'nav.shop-features': 'Funciones', 'nav.shop-billing': 'Pagos',
      'nav.update': 'Actualización', 'nav.versions': 'Versiones', 'nav.settings': 'Servidor', 'nav.security': 'Seguridad', 'nav.logs': 'Registros',
      'nav.group.home': 'Proxy doméstico', 'nav.group.upd': 'Actualizaciones', 'nav.group.set': 'Ajustes',
      'g.you': 'Usted', 'g.yours': 'suyo', 'status.on': 'en línea', 'status.off': 'desconectado', 'status.warn': 'inestable',
      'status.online': 'activo', 'status.stopped': 'detenido', 'status.active': 'activo', 'status.dead': 'muerto',
      'status.bad': 'malo', 'status.slow': 'lento', 'status.noip': 'noip', 'status.ok': 'ok', 'status.final': 'final',
      'status.direct': 'directo', 'status.enabled': 'activado', 'status.disabled': 'desactivado',
      'btn.vpn-off': '🌀 Activar VPN', 'btn.vpn-on': '🌀 VPN activa', 'btn.rotate': '🎲 Cambiar clave', 'btn.choose': '💎 Elegir',
      'btn.copy': '📋 Copiar', 'btn.save': 'Guardar', 'btn.login': '🔑 Entrar', 'btn.logout': 'Salir',
      'k.keys': 'claves: ', 'k.empty': 'aún no hay claves', 'k.mine': 'propia', 'k.github': 'github',
      'k.add-ok': 'Clave añadida 🐾', 'k.add-err': 'Error al añadir', 'k.need-vless': 'Se necesita un enlace vless://',
      'k.active-ok': 'activa 🐾', 'k.active-err': 'No se pudo activar', 'k.clean-ok': 'Claves muertas eliminadas 🐾',
      'k.set-active': 'Hacer activa',
      'd.empty': 'aún no hay dispositivos',
      'c.on': 'activado', 'c.off': 'desactivado', 'c.server': 'servidor', 'c.qr-na': 'QR no disponible', 'c.qr-na-off': 'QR sin conexión no disponible',
      'c.secret-hint': 'Los secretos solo se ven localmente. Indique el token X-Auth si está activado.',
      'ru.empty': 'verificación pendiente', 'ru.avail': 'disponible', 'ru.unavail': 'no disponible', 'ru.all': 'todos los dominios disponibles ✅',
      'upd.avail': 'disponible', 'upd.cur': 'actualizado', 'upd.msg-avail': 'Actualización disponible', 'upd.msg-cur': 'Versión actual',
      'upd.checked': 'Comprobado: ',
      'w.mesh-nodes': 'Nodos de mesh:', 'w.mesh-exit': 'salida por', 'w.hub': 'hub', 'w.mesh-none': 'Mesh no conectado. Invitación en la pestaña «Conexión».',
      'w.plan': 'Plan activo:', 'w.ru': 'Dominios RU:', 'w.ru-ok': 'disponibles',
      'mesh.connected': 'conectado', 'mesh.not': 'no conectado', 'mesh.member': 'miembro', 'mesh.hub': 'hub',
      'mesh.no-nodes': 'sin nodos — añada el primero', 'mesh.node': 'nodo',
      'routes.empty': 'aún no hay rutas', 'routes.active': 'activo', 'routes.off': 'apagado',
      'plans.na': 'planes no disponibles en esta versión', 'plans.traffic': 'Tráfico:', 'plans.devices': 'Dispositivos:', 'plans.keys': 'Claves:',
      'plans.free': 'Gratis', 'plans.per-mo': '/mes', 'plans.current': 'actual',
      'bill.empty': 'aún no hay pagos',
      'sec.on': 'activado', 'sec.off': 'desactivado', 'sec.access': 'Solo LAN: ', 'sec.da': 'sí', 'sec.no': 'no', 'sec.blk': 'bloqueo',
      'sec.rat': 'on', 'sec.rat-off': 'off',
      'log.empty': 'registro vacío', 'rec.empty': 'no hubo recuperaciones',
      't.err': 'Servidor no disponible', 't.err-gen': 'Error', 't.action-ok': 'Hecho 🐾',
      'inv.need': 'Pegue el código de invitación', 'inv.bad': 'invitación no parece aurora://invite — revise el código',
      'inv.add-ok': 'Nodo añadido a mesh 🕸️', 'inv.add-err': 'No se pudo conectar', 'inv.leave-none': 'No hay nodos para desconectar',
      'inv.leave-ok': 'Nodos eliminados, salió de mesh 🕸️', 'inv.leave-err': 'Error al desconectar', 'inv.regen-ok': 'Invitación renovada 🔄',
      'inv.regen-err': 'Error', 'inv.copy-ok': 'Invitación copiada 🔗', 'inv.empty': 'Invitación aún no disponible',
      'inv.topology': 'Topología actualizada 🕸️',
      'set.saved': 'Ajustes guardados 🐾', 'set.save-err': 'Error al guardar',
      'sec.need-token': 'Introduzca el token', 'sec.accept': 'Token aceptado, panel desbloqueado 🛡️', 'sec.reject': 'Token rechazado (401)',
      'sec.logout': 'Sesión cerrada', 'sec.rotate-ok': 'Claves Reality rotadas 🔄', 'sec.rotate-na': 'Rotación no disponible en esta versión',
      'upd.run-ok': 'Comprobación iniciada (fondo)', 'upd.check-err': 'Error de comprobación', 'upd.apply-ok': 'Actualización iniciada ⬆️',
      'upd.apply-err': 'No se pudo iniciar', 'upd.admin': 'El canal de actualizaciones se gestiona en el panel de administración 🐾',
      'plans.admin': 'Los planes se gestionan en el panel de administración 🐾', 'plans.buy': 'Plan «', 'plans.buy2': '» — compra en el panel de administración 🐾',
      'feat.admin': 'Tienda no disponible en esta versión 🐾', 'feat.buy': 'Función «', 'feat.buy2': '» — escaparate en la versión pública 🐾',
      'vpn.on': 'VPN activada 🌀', 'vpn.off': 'VPN desactivada', 'vpn.err': 'Error', 'rot.ok': 'Clave rotada 🎲', 'rot.err': 'No se pudo rotar',
      'pool.refresh': 'Pool actualizado 🔄', 'pool.check': 'Comprobación de claves en segundo plano 🧪', 'mesh.ping': 'Ping de mesh iniciado 📡',
      'mesh.policy-saved': 'Política del hub guardada 🎛',
      'copy.link-ok': 'Enlace copiado 📋', 'copy.link-na': 'Enlace aún no disponible', 'ru.done': 'Verificación finalizada 🇷🇺',
      'ru.run': 'Verificación iniciada', 'ru.failonly': '💀 Solo problemas', 'ru.failonly-on': '💀 Solo problemas ✓',
      'tg.restarted': 'TG-WS reiniciado ✈️', 'tg.restart-err': 'Error de reinicio',
      'fmt.kb': 'KB', 'fmt.mb': 'MB', 'fmt.gb': 'GB', 'fmt.ul': 'Ilimitado', 'fmt.per-mo': '/mes',
      'fmt.s': ' s', 'fmt.min': ' min', 'fmt.h': ' h', 'fmt.d': ' d',
      'dash.mode': 'Modo', 'dash.ip': 'IP de salida', 'dash.conns': 'Conexiones', 'dash.traffic': 'Tráfico ↓ / ↑', 'dash.mesh-nodes': 'Nodos mesh', 'dash.plan': 'Plan',
      'upd.details': 'Detalles', 'upd.now': 'Actualizar', 'w.proxy': 'Estado del proxy', 'w.check-ru': 'Comprobar',
      'keys.uri-ph': 'vless://… pega tu enlace (Reality)', 'keys.add': 'Añadir clave', 'keys.clean': 'Limpiar muertas', 'keys.src': 'github + propias',
      'th.tag': 'Etiqueta', 'th.source': 'Fuente', 'th.status': 'Estado', 'th.ping': 'Ping', 'th.exit': 'IP de salida', 'th.sites': 'Sites',
      'dev.head': 'Dispositivos en la red', 'th.device': 'Dispositivo', 'th.conn': 'Conn', 'th.dl': '↓ Descargado', 'th.ul': '↑ Subido',
      'cx.head': 'Conexión externa', 'cx.hint': 'Enlace vless listo para tu proxy. Pégalo en v2rayN / v2rayNG / NekoBox — y el tráfico pasará por este servidor desde cualquier lugar.', 'cx.addr': 'Dirección', 'cx.port': 'Puerto', 'cx.uuid': 'UUID', 'cx.sni': 'SNI',
      'ru.partial': 'parcial', 'ru.hint': 'Disponibilidad de recursos rusos directamente desde el servidor (sin VPN). Si el segmento funciona — los sitios RU abren sin proxy.', 'ru.ok': 'Disponible', 'ru.bad': 'Problemas', 'ru.med': 'Mediana', 'ru.ts': 'Comprobado',
      'ru.check-now': 'Comprobar ahora', 'th.domain': 'Dominio', 'th.time': 'Tiempo',
      'tgws.head': 'Proxy WS de Telegram', 'tgws.proc': 'Proceso', 'tgws.secret': 'Secreto', 'tgws.restart': 'Reiniciar TG-WS',
      'mj.head': 'Conectar a la red mesh', 'mj.p': 'Tu proxy puede ser parte de la red mesh privada Aurora. Da acceso a ubicaciones exclusivas de otros miembros, bypass automático de bloqueos y rutas de respaldo.',
      'mj.invite-ph': 'Pega el código de invite del mesh (p. ej.: aurora-home-a1b2c3d4)', 'mj.join': 'Conectar', 'mj.st': 'Estado del mesh', 'mj.name': 'Nombre del mesh', 'mj.role': 'Rol',
      'mj.nodes': 'Nodos disponibles', 'mj.ping': 'Ping al hub', 'mj.enc': 'Cifrado', 'mj.what': 'Qué da el mesh',
      'mj.leave': 'Salir del mesh', 'mj.regen': 'Actualizar invite', 'mj.pol': 'Política del hub', 'mj.pol-hint': 'El servidor hub controla qué pestañas ven los clientes del mesh. Los clientes conectados por invite de este servidor aplican la política automáticamente (actualización cada 15 s).',
      'mj.master': 'El servidor es hub, controla la visibilidad de los clientes', 'mj.show-mesh': 'Mostrar la pestaña “Red mesh” a los clientes', 'mj.show-subs': 'Mostrar la pestaña “Tienda” a los clientes',
      'mt.hint': 'Tu proxy (en el centro) y los nodos de otros miembros del mesh. Las conexiones están activas si el tráfico pasa por ellos.',
      'mrt.hint': 'Reglas de qué tráfico sale a internet por cada nodo. Orden de arriba a abajo.', 'th.what': 'Qué', 'th.via': 'Dónde', 'th.proto': 'Protocolo',
      'sp.head': 'Planes', 'sp.hint': 'Conjunto básico de funciones del proxy. Mejora con un clic, se aplica al instante, sin cortar conexiones.', 'sp.loading': 'cargando planes…', 'sp.comp': 'Contenido del plan', 'th.func': 'Función', 'th.val': 'Valor',
      'sf.instant': '+ se activan al instante',
      'sb.head': 'Pago y renovación', 'sb.hint': 'Plan activo, vigencia e historial de pagos. Renovación con un clic.', 'sb.plan': 'Plan actual', 'sb.until': 'Válido hasta', 'sb.buy': 'Renovar / cambiar plan', 'sb.hist': 'Historial de pagos',
      'th.date': 'Fecha', 'th.desc': 'Descripción', 'th.sum': 'Importe',
      'upd.apply': 'Actualizar ahora', 'upd.auto': 'Auto-actualización', 'upd.auto-hint': 'La actualización se realiza desde los lanzamientos de GitHub. El binario se descarga, verifica y reemplaza atómicamente — el proxy se reinicia en un par de segundos.',
      'upd.src': 'Fuente de actualización', 'th.param': 'Parámetro', 'upd.repo': 'Repositorio', 'upd.sig': 'Verificación de firma', 'upd.rollback': 'Reversión en fallo',
      'upd.check-now': 'Comprobar ahora', 'upd.stable': 'stable — solo estables', 'upd.rc': 'rc — candidatos de lanzamiento', 'upd.nightly': 'nightly — compilaciones nocturnas',
      'upd.mode-auto': 'Auto-actualización activada', 'upd.mode-notify': 'Solo notificar', 'upd.mode-off': 'No comprobar',
      'ver.head': 'Historial de versiones',
      'set.head': 'Parámetros del servidor', 'set.host': 'Host', 'set.port': 'Puerto Xray', 'set.ver': 'Versión', 'set.uptime': 'Uptime',
      'set.common': 'General', 'set.mesh': 'Mesh', 'set.name-ph': 'Nombre del servidor', 'set.meshid-ph': 'ID del mesh', 'set.copy-invite': 'Copiar invite',
      'sec.hint': 'Token de administración y claves Reality externas. Cambia la configuración en vivo.', 'sec.panel': 'Panel', 'sec.tok-ph': 'Token admin (Bearer) — necesario para POST /api/*', 'sec.acc-v': 'Acceso', 'sec.pbk-ph': 'clave pública', 'sec.rotate': 'Rotar claves',
      'log.head': 'Registro del sistema', 'log.loading': 'cargando…', 'log.refresh': 'Actualizar', 'log.download': 'Descargar', 'rclog.head': 'Registro de recovery',
      'th.node': 'Nodo', 'th.region': 'Región', 'th.route': 'Ruta', 'sec.tok': 'Token admin', 'sec.reality': 'Reality',
      'theme.sun': '🌙', 'theme.moon': '☀️'
    },
    de: {
      'pol.head': 'Dienstrichtlinie', 'pol.readOnly': 'Ansehen', 'pol.accept': 'Ich akzeptiere die Bedingungen', 'ru.regions': 'Segmente', 'ru.custom-ph': 'Eigene Domains, durch Komma getrennt (optional)',
      'dash.manage': 'Verwaltung', 'pool.refresh-btn': 'Schlüssel aktualisieren', 'pool.check-btn': 'Schlüssel prüfen', 'mesh.ping-btn': 'Mesh-Ping',
      'nav.dash': 'Übersicht', 'nav.keys': 'Schlüssel', 'nav.devices': 'Geräte',
      'nav.connect': 'Externer Zugriff', 'nav.rusegment': 'RU-Segment', 'nav.tgws': 'TG-WS',
      'nav.mesh': 'Mesh', 'nav.mesh-join': 'Verbinden', 'nav.mesh-topo': 'Topologie', 'nav.mesh-routes': 'Routen',
      'nav.shop': 'Shop', 'nav.shop-plans': 'Tarife', 'nav.shop-features': 'Funktionen', 'nav.shop-billing': 'Zahlungen',
      'nav.update': 'Update', 'nav.versions': 'Versionen', 'nav.settings': 'Server', 'nav.security': 'Sicherheit', 'nav.logs': 'Logs',
      'nav.group.home': 'Heim-Proxy', 'nav.group.upd': 'Updates', 'nav.group.set': 'Einstellungen',
      'g.you': 'Sie', 'g.yours': 'Ihres', 'status.on': 'online', 'status.off': 'offline', 'status.warn': 'instabil',
      'status.online': 'läuft', 'status.stopped': 'gestoppt', 'status.active': 'aktiv', 'status.dead': 'tot',
      'status.bad': 'schlecht', 'status.slow': 'langsam', 'status.noip': 'noip', 'status.ok': 'ok', 'status.final': 'final',
      'status.direct': 'direkt', 'status.enabled': 'aktiviert', 'status.disabled': 'deaktiviert',
      'btn.vpn-off': '🌀 VPN aktivieren', 'btn.vpn-on': '🌀 VPN an', 'btn.rotate': '🎲 Schlüssel wechseln', 'btn.choose': '💎 Wählen',
      'btn.copy': '📋 Kopieren', 'btn.save': 'Speichern', 'btn.login': '🔑 Anmelden', 'btn.logout': 'Abmelden',
      'k.keys': 'Schlüssel: ', 'k.empty': 'noch keine Schlüssel', 'k.mine': 'eigener', 'k.github': 'github',
      'k.add-ok': 'Schlüssel hinzugefügt 🐾', 'k.add-err': 'Hinzufügen fehlgeschlagen', 'k.need-vless': 'Ein vless://-Link ist erforderlich',
      'k.active-ok': 'aktiv 🐾', 'k.active-err': 'Aktivierung fehlgeschlagen', 'k.clean-ok': 'Tote Schlüssel entfernt 🐾',
      'k.set-active': 'Aktivieren',
      'd.empty': 'noch keine Geräte',
      'c.on': 'aktiviert', 'c.off': 'deaktiviert', 'c.server': 'Server', 'c.qr-na': 'QR nicht verfügbar', 'c.qr-na-off': 'QR offline nicht verfügbar',
      'c.secret-hint': 'Geheimnisse sind nur lokal sichtbar. Geben Sie das X-Auth-Token an, falls aktiviert.',
      'ru.empty': 'Prüfung noch nicht durchgeführt', 'ru.avail': 'verfügbar', 'ru.unavail': 'nicht verfügbar', 'ru.all': 'alle Domains verfügbar ✅',
      'upd.avail': 'verfügbar', 'upd.cur': 'aktuell', 'upd.msg-avail': 'Update verfügbar', 'upd.msg-cur': 'Aktuelle Version installiert',
      'upd.checked': 'Geprüft: ',
      'w.mesh-nodes': 'Mesh-Knoten:', 'w.mesh-exit': 'Ausgang über', 'w.hub': 'Hub', 'w.mesh-none': 'Mesh nicht verbunden. Einladung im Tab „Verbinden“.',
      'w.plan': 'Aktiver Tarif:', 'w.ru': 'RU-Domains:', 'w.ru-ok': 'verfügbar',
      'mesh.connected': 'verbunden', 'mesh.not': 'nicht verbunden', 'mesh.member': 'Mitglied', 'mesh.hub': 'Hub',
      'mesh.no-nodes': 'keine Knoten — fügen Sie den ersten hinzu', 'mesh.node': 'Knoten',
      'routes.empty': 'noch keine Routen', 'routes.active': 'aktiv', 'routes.off': 'aus',
      'plans.na': 'Tarife in diesem Build nicht verfügbar', 'plans.traffic': 'Traffic:', 'plans.devices': 'Geräte:', 'plans.keys': 'Schlüssel:',
      'plans.free': 'Kostenlos', 'plans.per-mo': '/Monat', 'plans.current': 'aktuell',
      'bill.empty': 'noch keine Zahlungen',
      'sec.on': 'aktiviert', 'sec.off': 'deaktiviert', 'sec.access': 'Nur LAN: ', 'sec.da': 'ja', 'sec.no': 'nein', 'sec.blk': 'Block',
      'sec.rat': 'an', 'sec.rat-off': 'aus',
      'log.empty': 'Log ist leer', 'rec.empty': 'keine Wiederherstellungen',
      't.err': 'Server nicht verfügbar', 't.err-gen': 'Fehler', 't.action-ok': 'Fertig 🐾',
      'inv.need': 'Mesh-Einladungscode einfügen', 'inv.bad': 'Einladung sieht nicht nach aurora://invite aus — Code prüfen',
      'inv.add-ok': 'Knoten zum Mesh hinzugefügt 🕸️', 'inv.add-err': 'Verbinden fehlgeschlagen', 'inv.leave-none': 'Keine Knoten zum Trennen',
      'inv.leave-ok': 'Knoten entfernt, Mesh verlassen 🕸️', 'inv.leave-err': 'Fehler beim Trennen', 'inv.regen-ok': 'Einladung erneuert 🔄',
      'inv.regen-err': 'Fehler', 'inv.copy-ok': 'Einladung kopiert 🔗', 'inv.empty': 'Einladung noch nicht verfügbar',
      'inv.topology': 'Topologie aktualisiert 🕸️',
      'set.saved': 'Einstellungen gespeichert 🐾', 'set.save-err': 'Fehler beim Speichern',
      'sec.need-token': 'Token eingeben', 'sec.accept': 'Token akzeptiert, Panel entsperrt 🛡️', 'sec.reject': 'Token abgelehnt (401)',
      'sec.logout': 'Abgemeldet', 'sec.rotate-ok': 'Reality-Schlüssel rotiert 🔄', 'sec.rotate-na': 'Rotation in diesem Build nicht verfügbar',
      'upd.run-ok': 'Prüfung gestartet (Hintergrund)', 'upd.check-err': 'Prüffehler', 'upd.apply-ok': 'Update gestartet ⬆️',
      'upd.apply-err': 'Start fehlgeschlagen', 'upd.admin': 'Update-Kanal wird in der Admin-Panel verwaltet 🐾',
      'plans.admin': 'Tarife werden in der Admin-Panel verwaltet 🐾', 'plans.buy': 'Tarif „', 'plans.buy2': '“ — Kauf in der Admin-Panel 🐾',
      'feat.admin': 'Shop in diesem Build nicht verfügbar 🐾', 'feat.buy': 'Funktion „', 'feat.buy2': '“ — Schaufenster im öffentlichen Build 🐾',
      'vpn.on': 'VPN aktiviert 🌀', 'vpn.off': 'VPN deaktiviert', 'vpn.err': 'Fehler', 'rot.ok': 'Schlüssel rotiert 🎲', 'rot.err': 'Rotation fehlgeschlagen',
      'pool.refresh': 'Pool aktualisiert 🔄', 'pool.check': 'Schlüsselprüfung im Hintergrund 🧪', 'mesh.ping': 'Mesh-Ping gestartet 📡',
      'mesh.policy-saved': 'Hub-Richtlinie gespeichert 🎛',
      'copy.link-ok': 'Link kopiert 📋', 'copy.link-na': 'Link noch nicht verfügbar', 'ru.done': 'Prüfung abgeschlossen 🇷🇺',
      'ru.run': 'Prüfung gestartet', 'ru.failonly': '💀 Nur Probleme', 'ru.failonly-on': '💀 Nur Probleme ✓',
      'tg.restarted': 'TG-WS neu gestartet ✈️', 'tg.restart-err': 'Neustart-Fehler',
      'fmt.kb': 'KB', 'fmt.mb': 'MB', 'fmt.gb': 'GB', 'fmt.ul': 'Unbegrenzt', 'fmt.per-mo': '/Monat',
      'fmt.s': ' s', 'fmt.min': ' min', 'fmt.h': ' h', 'fmt.d': ' d',
      'dash.mode': 'Modus', 'dash.ip': 'Exit-IP', 'dash.conns': 'Verbindungen', 'dash.traffic': 'Datenverkehr ↓ / ↑', 'dash.mesh-nodes': 'Mesh-Knoten', 'dash.plan': 'Tarif',
      'upd.details': 'Details', 'upd.now': 'Aktualisieren', 'w.proxy': 'Proxy-Status', 'w.check-ru': 'Prüfen',
      'keys.uri-ph': 'vless://… füge deinen Link ein (Reality)', 'keys.add': 'Eigener Schlüssel', 'keys.clean': 'Tote entfernen', 'keys.src': 'github + eigene',
      'th.tag': 'Tag', 'th.source': 'Quelle', 'th.status': 'Status', 'th.ping': 'Ping', 'th.exit': 'Exit-IP', 'th.sites': 'Sites',
      'dev.head': 'Geräte im Netzwerk', 'th.device': 'Gerät', 'th.conn': 'Conn', 'th.dl': '↓ Heruntergeladen', 'th.ul': '↑ Hochgeladen',
      'cx.head': 'Externe Verbindung', 'cx.hint': 'Fertiger vless-Link zu deinem Proxy. Füge ihn in v2rayN / v2rayNG / NekoBox ein — der Datenverkehr läuft über diesen Server von überall.', 'cx.addr': 'Adresse', 'cx.port': 'Port', 'cx.uuid': 'UUID', 'cx.sni': 'SNI',
      'ru.partial': 'teilweise', 'ru.hint': 'Verfügbarkeit russischer Ressourcen direkt vom Server (ohne VPN). Wenn das Segment funktioniert — RU-Seiten öffnen sich ohne Proxy.', 'ru.ok': 'Verfügbar', 'ru.bad': 'Probleme', 'ru.med': 'Median', 'ru.ts': 'Geprüft',
      'ru.check-now': 'Jetzt prüfen', 'th.domain': 'Domain', 'th.time': 'Zeit',
      'tgws.head': 'Telegram-WS-Proxy', 'tgws.proc': 'Prozess', 'tgws.secret': 'Geheimnis', 'tgws.restart': 'TG-WS neu starten',
      'mj.head': 'Mesh-Netzwerk beitreten', 'mj.p': 'Dein Proxy kann Teil des privaten Aurora-Mesh sein. Das gibt Zugang zu exklusiven Standorten anderer Teilnehmer, automatische Umgehung von Sperren und Backup-Routen.',
      'mj.invite-ph': 'Mesh-Invite-Code einfügen (z. B.: aurora-home-a1b2c3d4)', 'mj.join': 'Verbinden', 'mj.st': 'Mesh-Status', 'mj.name': 'Mesh-Name', 'mj.role': 'Rolle',
      'mj.nodes': 'Knoten verfügbar', 'mj.ping': 'Ping zum Hub', 'mj.enc': 'Verschlüsselung', 'mj.what': 'Was das Mesh bringt',
      'mj.leave': 'Mesh verlassen', 'mj.regen': 'Invite aktualisieren', 'mj.pol': 'Hub-Richtlinie', 'mj.pol-hint': 'Der Hub-Server steuert, welche Tabs die Mesh-Clients sehen. Per Invite dieses Servers verbundene Clients wenden die Richtlinie automatisch an (Aktualisierung alle 15 s).',
      'mj.master': 'Server ist Hub, steuert Sichtbarkeit der Clients', 'mj.show-mesh': 'Den Tabs „Mesh-Netzwerk“ für Clients zeigen', 'mj.show-subs': 'Den Tab „Shop“ für Clients zeigen',
      'mt.hint': 'Dein Proxy (in der Mitte) und die Knoten anderer Teilnehmer. Verbindungen sind aktiv, wenn der Datenverkehr darüber läuft.',
      'mrt.hint': 'Regeln, welcher Datenverkehr über welchen Knoten ins Internet geht. Reihenfolge von oben nach unten.', 'th.what': 'Was', 'th.via': 'Wohin', 'th.proto': 'Protokoll',
      'sp.head': 'Tarife', 'sp.hint': 'Basissatz der Proxy-Funktionen. Upgrade mit einem Klick, wird sofort angewendet, ohne Verbindungsverlust.', 'sp.loading': 'Tarife laden…', 'sp.comp': 'Tarifinhalt', 'th.func': 'Funktion', 'th.val': 'Wert',
      'sf.instant': '+ aktivieren sofort',
      'sb.head': 'Zahlung und Verlängerung', 'sb.hint': 'Aktiver Tarif, Laufzeit und Zahlungshistorie. Verlängerung mit einem Klick.', 'sb.plan': 'Aktueller Tarif', 'sb.until': 'Gültig bis', 'sb.buy': 'Verlängern / Tarif wechseln', 'sb.hist': 'Zahlungshistorie',
      'th.date': 'Datum', 'th.desc': 'Beschreibung', 'th.sum': 'Betrag',
      'upd.apply': 'Jetzt aktualisieren', 'upd.auto': 'Auto-Update', 'upd.auto-hint': 'Das Update kommt aus den GitHub-Releases. Der Binär wird heruntergeladen, verifiziert, atomar ersetzt — der Proxy startet in wenigen Sekunden neu.',
      'upd.src': 'Update-Quelle', 'th.param': 'Parameter', 'upd.repo': 'Repository', 'upd.sig': 'Signaturprüfung', 'upd.rollback': 'Rollback bei Fehler',
      'upd.check-now': 'Jetzt prüfen', 'upd.stable': 'stable — nur stabile', 'upd.rc': 'rc — Release-Kandidaten', 'upd.nightly': 'nightly — Nachtbuilds',
      'upd.mode-auto': 'Auto-Update aktiviert', 'upd.mode-notify': 'Nur benachrichtigen', 'upd.mode-off': 'Nicht prüfen',
      'ver.head': 'Versionshistorie',
      'set.head': 'Serverparameter', 'set.host': 'Host', 'set.port': 'Xray-Port', 'set.ver': 'Version', 'set.uptime': 'Uptime',
      'set.common': 'Allgemein', 'set.mesh': 'Mesh', 'set.name-ph': 'Servername', 'set.meshid-ph': 'Mesh-ID', 'set.copy-invite': 'Invite kopieren',
      'sec.hint': 'Admin-Token des Panels und externe Reality-Schlüssel. Änderung am laufenden Konfig.', 'sec.panel': 'Panel', 'sec.tok-ph': 'Admin-Token (Bearer) — nötig für POST /api/*', 'sec.acc-v': 'Zugriff', 'sec.pbk-ph': 'öffentlicher Schlüssel', 'sec.rotate': 'Schlüssel rotieren',
      'log.head': 'Systemlog', 'log.loading': 'laden…', 'log.refresh': 'Aktualisieren', 'log.download': 'Herunterladen', 'rclog.head': 'Recovery-Journal',
      'th.node': 'Knoten', 'th.region': 'Region', 'th.route': 'Route', 'sec.tok': 'Admin-Token', 'sec.reality': 'Reality',
      'theme.sun': '🌙', 'theme.moon': '☀️'
    },
    fr: {
      'pol.head': 'Politique du service', 'pol.readOnly': 'Voir', 'pol.accept': 'J\'accepte les conditions', 'ru.regions': 'Segments', 'ru.custom-ph': 'Domaines personnalisés séparés par des virgules (optionnel)',
      'dash.manage': 'Gestion', 'pool.refresh-btn': 'Actualiser les clés', 'pool.check-btn': 'Vérifier les clés', 'mesh.ping-btn': 'Ping mesh',
      'nav.dash': 'Tableau de bord', 'nav.keys': 'Clés', 'nav.devices': 'Appareils',
      'nav.connect': 'Accès externe', 'nav.rusegment': 'Segment RU', 'nav.tgws': 'TG-WS',
      'nav.mesh': 'Réseau mesh', 'nav.mesh-join': 'Connexion', 'nav.mesh-topo': 'Topologie', 'nav.mesh-routes': 'Itinéraires',
      'nav.shop': 'Boutique', 'nav.shop-plans': 'Forfaits', 'nav.shop-features': 'Fonctions', 'nav.shop-billing': 'Paiements',
      'nav.update': 'Mise à jour', 'nav.versions': 'Versions', 'nav.settings': 'Serveur', 'nav.security': 'Sécurité', 'nav.logs': 'Journaux',
      'nav.group.home': 'Proxy domestique', 'nav.group.upd': 'Mises à jour', 'nav.group.set': 'Réglages',
      'g.you': 'Vous', 'g.yours': 'vôtre', 'status.on': 'en ligne', 'status.off': 'hors ligne', 'status.warn': 'instable',
      'status.online': 'actif', 'status.stopped': 'arrêté', 'status.active': 'actif', 'status.dead': 'mort',
      'status.bad': 'mauvais', 'status.slow': 'lent', 'status.noip': 'noip', 'status.ok': 'ok', 'status.final': 'final',
      'status.direct': 'direct', 'status.enabled': 'activé', 'status.disabled': 'désactivé',
      'btn.vpn-off': '🌀 Activer VPN', 'btn.vpn-on': '🌀 VPN actif', 'btn.rotate': '🎲 Changer de clé', 'btn.choose': '💎 Choisir',
      'btn.copy': '📋 Copier', 'btn.save': 'Enregistrer', 'btn.login': '🔑 Se connecter', 'btn.logout': 'Se déconnecter',
      'k.keys': 'clés : ', 'k.empty': 'aucune clé', 'k.mine': 'personnelle', 'k.github': 'github',
      'k.add-ok': 'Clé ajoutée 🐾', 'k.add-err': 'Échec de l\'ajout', 'k.need-vless': 'Un lien vless:// est requis',
      'k.active-ok': 'active 🐾', 'k.active-err': 'Activation impossible', 'k.clean-ok': 'Clés mortes supprimées 🐾',
      'k.set-active': 'Rendre active',
      'd.empty': 'aucun appareil',
      'c.on': 'activé', 'c.off': 'désactivé', 'c.server': 'serveur', 'c.qr-na': 'QR indisponible', 'c.qr-na-off': 'QR hors ligne indisponible',
      'c.secret-hint': 'Les secrets ne sont visibles que localement. Indiquez le jeton X-Auth s\'il est activé.',
      'ru.empty': 'vérification pas encore effectuée', 'ru.avail': 'disponible', 'ru.unavail': 'indisponible', 'ru.all': 'tous les domaines disponibles ✅',
      'upd.avail': 'disponible', 'upd.cur': 'à jour', 'upd.msg-avail': 'Mise à jour disponible', 'upd.msg-cur': 'Version actuelle installée',
      'upd.checked': 'Vérifié : ',
      'w.mesh-nodes': 'Nœuds mesh :', 'w.mesh-exit': 'sortie via', 'w.hub': 'hub', 'w.mesh-none': 'Mesh non connecté. Invitation dans l\'onglet « Connexion ».',
      'w.plan': 'Forfait actif :', 'w.ru': 'Domaines RU :', 'w.ru-ok': 'disponibles',
      'mesh.connected': 'connecté', 'mesh.not': 'non connecté', 'mesh.member': 'membre', 'mesh.hub': 'hub',
      'mesh.no-nodes': 'aucun nœud — ajoutez le premier', 'mesh.node': 'nœud',
      'routes.empty': 'aucun itinéraire', 'routes.active': 'actif', 'routes.off': 'désactivé',
      'plans.na': 'forfaits indisponibles dans cette version', 'plans.traffic': 'Trafic :', 'plans.devices': 'Appareils :', 'plans.keys': 'Clés :',
      'plans.free': 'Gratuit', 'plans.per-mo': '/mois', 'plans.current': 'actuel',
      'bill.empty': 'aucun paiement',
      'sec.on': 'activé', 'sec.off': 'désactivé', 'sec.access': 'LAN uniquement : ', 'sec.da': 'oui', 'sec.no': 'non', 'sec.blk': 'blocage',
      'sec.rat': 'on', 'sec.rat-off': 'off',
      'log.empty': 'journal vide', 'rec.empty': 'aucune récupération',
      't.err': 'Serveur indisponible', 't.err-gen': 'Erreur', 't.action-ok': 'Terminé 🐾',
      'inv.need': 'Collez le code d\'invitation mesh', 'inv.bad': 'l\'invitation ne ressemble pas à aurora://invite — vérifiez le code',
      'inv.add-ok': 'Nœud ajouté au mesh 🕸️', 'inv.add-err': 'Connexion impossible', 'inv.leave-none': 'Aucun nœud à déconnecter',
      'inv.leave-ok': 'Nœuds supprimés, sorti du mesh 🕸️', 'inv.leave-err': 'Erreur de déconnexion', 'inv.regen-ok': 'Invitation renouvelée 🔄',
      'inv.regen-err': 'Échec', 'inv.copy-ok': 'Invitation copiée 🔗', 'inv.empty': 'Invitation pas encore disponible',
      'inv.topology': 'Topologie mise à jour 🕸️',
      'set.saved': 'Réglages enregistrés 🐾', 'set.save-err': 'Erreur d\'enregistrement',
      'sec.need-token': 'Saisissez le jeton', 'sec.accept': 'Jeton accepté, panneau débloqué 🛡️', 'sec.reject': 'Jeton refusé (401)',
      'sec.logout': 'Déconnexion effectuée', 'sec.rotate-ok': 'Clés Reality rotées 🔄', 'sec.rotate-na': 'Rotation indisponible dans cette version',
      'upd.run-ok': 'Vérification lancée (arrière-plan)', 'upd.check-err': 'Erreur de vérification', 'upd.apply-ok': 'Mise à jour lancée ⬆️',
      'upd.apply-err': 'Impossible de lancer', 'upd.admin': 'Le canal de mise à jour se gère dans le panneau d\'administration 🐾',
      'plans.admin': 'Les forfaits se gèrent dans le panneau d\'administration 🐾', 'plans.buy': 'Forfait « ', 'plans.buy2': ' » — achat dans le panneau d\'administration 🐾',
      'feat.admin': 'Boutique indisponible dans cette version 🐾', 'feat.buy': 'Fonction « ', 'feat.buy2': ' » — vitrine dans la version publique 🐾',
      'vpn.on': 'VPN activé 🌀', 'vpn.off': 'VPN désactivé', 'vpn.err': 'Erreur', 'rot.ok': 'Clé rotée 🎲', 'rot.err': 'Rotation impossible',
      'pool.refresh': 'Pool mis à jour 🔄', 'pool.check': 'Vérification des clés en arrière-plan 🧪', 'mesh.ping': 'Ping mesh lancé 📡',
      'mesh.policy-saved': 'Politique du hub enregistrée 🎛',
      'copy.link-ok': 'Lien copié 📋', 'copy.link-na': 'Lien pas encore disponible', 'ru.done': 'Vérification terminée 🇷🇺',
      'ru.run': 'Vérification lancée', 'ru.failonly': '💀 Problèmes uniquement', 'ru.failonly-on': '💀 Problèmes uniquement ✓',
      'tg.restarted': 'TG-WS redémarré ✈️', 'tg.restart-err': 'Erreur de redémarrage',
      'fmt.kb': 'Ko', 'fmt.mb': 'Mo', 'fmt.gb': 'Go', 'fmt.ul': 'Illimité', 'fmt.per-mo': '/mois',
      'fmt.s': ' s', 'fmt.min': ' min', 'fmt.h': ' h', 'fmt.d': ' j',
      'dash.mode': 'Mode', 'dash.ip': 'IP de sortie', 'dash.conns': 'Connexions', 'dash.traffic': 'Trafic ↓ / ↑', 'dash.mesh-nodes': 'Nœuds mesh', 'dash.plan': 'Forfait',
      'upd.details': 'Détails', 'upd.now': 'Mettre à jour', 'w.proxy': 'État du proxy', 'w.check-ru': 'Vérifier',
      'keys.uri-ph': 'vless://… collez votre lien (Reality)', 'keys.add': 'Ajouter clé', 'keys.clean': 'Supprimer les mortes', 'keys.src': 'github + miennes',
      'th.tag': 'Tag', 'th.source': 'Source', 'th.status': 'Statut', 'th.ping': 'Ping', 'th.exit': 'IP de sortie', 'th.sites': 'Sites',
      'dev.head': 'Appareils du réseau', 'th.device': 'Appareil', 'th.conn': 'Conn', 'th.dl': '↓ Téléchargé', 'th.ul': '↑ Envoyé',
      'cx.head': 'Connexion externe', 'cx.hint': 'Lien vless prêt pour votre proxy. Collez-le dans v2rayN / v2rayNG / NekoBox — le trafic passera par ce serveur de n\'importe où.', 'cx.addr': 'Adresse', 'cx.port': 'Port', 'cx.uuid': 'UUID', 'cx.sni': 'SNI',
      'ru.partial': 'partiel', 'ru.hint': 'Disponibilité des ressources russes directement depuis le serveur (sans VPN). Si le segment fonctionne — les sites RU s\'ouvrent sans proxy.', 'ru.ok': 'Disponible', 'ru.bad': 'Problèmes', 'ru.med': 'Médiane', 'ru.ts': 'Vérifié',
      'ru.check-now': 'Vérifier maintenant', 'th.domain': 'Domaine', 'th.time': 'Temps',
      'tgws.head': 'Proxy WS Telegram', 'tgws.proc': 'Processus', 'tgws.secret': 'Secret', 'tgws.restart': 'Redémarrer TG-WS',
      'mj.head': 'Rejoindre le réseau mesh', 'mj.p': 'Votre proxy peut faire partie du réseau mesh privé Aurora. Cela donne accès à des localisations exclusives d\'autres membres, au contournement automatique des blocages et à des routes de secours.',
      'mj.invite-ph': 'Collez le code invite du mesh (ex. : aurora-home-a1b2c3d4)', 'mj.join': 'Connecter', 'mj.st': 'État du mesh', 'mj.name': 'Nom du mesh', 'mj.role': 'Rôle',
      'mj.nodes': 'Nœuds disponibles', 'mj.ping': 'Ping vers le hub', 'mj.enc': 'Chiffrement', 'mj.what': 'Ce que le mesh apporte',
      'mj.leave': 'Quitter le mesh', 'mj.regen': 'Actualiser l\'invite', 'mj.pol': 'Politique du hub', 'mj.pol-hint': 'Le serveur hub contrôle les onglets visibles par les clients du mesh. Les clients connectés par l\'invite de ce serveur appliquent automatiquement la politique (mise à jour toutes les 15 s).',
      'mj.master': 'Le serveur est hub, contrôle la visibilité des clients', 'mj.show-mesh': 'Afficher l\'onglet « Réseau mesh » aux clients', 'mj.show-subs': 'Afficher l\'onglet « Boutique » aux clients',
      'mt.hint': 'Votre proxy (au centre) et les nœuds d\'autres membres du mesh. Les connexions sont actives si le trafic passe par eux.',
      'mrt.hint': 'Règles de quel trafic sort vers internet via quel nœud. Ordre de haut en bas.', 'th.what': 'Quoi', 'th.via': 'Où', 'th.proto': 'Protocole',
      'sp.head': 'Forfaits', 'sp.hint': 'Ensemble de base des fonctions du proxy. Amélioration en un clic, appliquée instantanément, sans couper les connexions.', 'sp.loading': 'chargement des forfaits…', 'sp.comp': 'Contenu du forfait', 'th.func': 'Fonction', 'th.val': 'Valeur',
      'sf.instant': '+ s\'activent instantanément',
      'sb.head': 'Paiement et prolongation', 'sb.hint': 'Forfait actif, validité et historique des paiements. Prolongation en un clic.', 'sb.plan': 'Forfait actuel', 'sb.until': 'Valable jusqu\'au', 'sb.buy': 'Prolonger / changer de forfait', 'sb.hist': 'Historique des paiements',
      'th.date': 'Date', 'th.desc': 'Description', 'th.sum': 'Montant',
      'upd.apply': 'Mettre à jour maintenant', 'upd.auto': 'Mise à jour auto', 'upd.auto-hint': 'La mise à jour provient des releases GitHub. Le binaire est téléchargé, vérifié, remplacé atomiquement — le proxy redémarre en quelques secondes.',
      'upd.src': 'Source de mise à jour', 'th.param': 'Paramètre', 'upd.repo': 'Dépôt', 'upd.sig': 'Vérification de signature', 'upd.rollback': 'Restauration en cas d\'échec',
      'upd.check-now': 'Vérifier maintenant', 'upd.stable': 'stable — uniquement stables', 'upd.rc': 'rc — candidats de release', 'upd.nightly': 'nightly — builds nocturnes',
      'upd.mode-auto': 'Mise à jour auto activée', 'upd.mode-notify': 'Notifier seulement', 'upd.mode-off': 'Ne pas vérifier',
      'ver.head': 'Historique des versions',
      'set.head': 'Paramètres du serveur', 'set.host': 'Hôte', 'set.port': 'Port Xray', 'set.ver': 'Version', 'set.uptime': 'Uptime',
      'set.common': 'Général', 'set.mesh': 'Mesh', 'set.name-ph': 'Nom du serveur', 'set.meshid-ph': 'ID du mesh', 'set.copy-invite': 'Copier l\'invite',
      'sec.hint': 'Jeton du panneau admin et clés Reality externes. Change la config en direct.', 'sec.panel': 'Panneau', 'sec.tok-ph': 'Jeton admin (Bearer) — requis pour POST /api/*', 'sec.acc-v': 'Accès', 'sec.pbk-ph': 'clé publique', 'sec.rotate': 'Rotation des clés',
      'log.head': 'Journal système', 'log.loading': 'chargement…', 'log.refresh': 'Actualiser', 'log.download': 'Télécharger', 'rclog.head': 'Journal recovery',
      'th.node': 'Nœud', 'th.region': 'Région', 'th.route': 'Itinéraire', 'sec.tok': 'Jeton admin', 'sec.reality': 'Reality',
      'theme.sun': '🌙', 'theme.moon': '☀️'
    },
    tr: {
      'pol.head': 'Hizmet politikası', 'pol.readOnly': 'Görüntüle', 'pol.accept': 'Koşulları kabul ediyorum', 'ru.regions': 'Segmentler', 'ru.custom-ph': 'Virgülle ayrılmış özel alan adları (isteğe bağlı)',
      'dash.manage': 'Yönetim', 'pool.refresh-btn': 'Anahtarları güncelle', 'pool.check-btn': 'Anahtarları kontrol et', 'mesh.ping-btn': 'Mesh ping',
      'nav.dash': 'Genel Bakış', 'nav.keys': 'Anahtarlar', 'nav.devices': 'Cihazlar',
      'nav.connect': 'Dış erişim', 'nav.rusegment': 'RU segmenti', 'nav.tgws': 'TG-WS',
      'nav.mesh': 'Mesh', 'nav.mesh-join': 'Bağlan', 'nav.mesh-topo': 'Topoloji', 'nav.mesh-routes': 'Rotalar',
      'nav.shop': 'Mağaza', 'nav.shop-plans': 'Planlar', 'nav.shop-features': 'Özellikler', 'nav.shop-billing': 'Ödemeler',
      'nav.update': 'Güncelleme', 'nav.versions': 'Sürümler', 'nav.settings': 'Sunucu', 'nav.security': 'Güvenlik', 'nav.logs': 'Günlükler',
      'nav.group.home': 'Ev proxy', 'nav.group.upd': 'Güncellemeler', 'nav.group.set': 'Ayarlar',
      'g.you': 'Siz', 'g.yours': 'sizin', 'status.on': 'çevrimiçi', 'status.off': 'çevrimdışı', 'status.warn': 'dengesiz',
      'status.online': 'çalışıyor', 'status.stopped': 'durdu', 'status.active': 'aktif', 'status.dead': 'ölü',
      'status.bad': 'kötü', 'status.slow': 'yavaş', 'status.noip': 'noip', 'status.ok': 'tamam', 'status.final': 'final',
      'status.direct': 'doğrudan', 'status.enabled': 'açık', 'status.disabled': 'kapalı',
      'btn.vpn-off': '🌀 VPN\'i aç', 'btn.vpn-on': '🌀 VPN açık', 'btn.rotate': '🎲 Anahtarı değiştir', 'btn.choose': '💎 Seç',
      'btn.copy': '📋 Kopyala', 'btn.save': 'Kaydet', 'btn.login': '🔑 Giriş', 'btn.logout': 'Çıkış',
      'k.keys': 'anahtar: ', 'k.empty': 'henüz anahtar yok', 'k.mine': 'benim', 'k.github': 'github',
      'k.add-ok': 'Anahtar eklendi 🐾', 'k.add-err': 'Ekleme başarısız', 'k.need-vless': 'vless:// bağlantısı gerekli',
      'k.active-ok': 'aktif 🐾', 'k.active-err': 'Aktifleştirilemedi', 'k.clean-ok': 'Ölü anahtarlar silindi 🐾',
      'k.set-active': 'Aktif yap',
      'd.empty': 'henüz cihaz yok',
      'c.on': 'açık', 'c.off': 'kapalı', 'c.server': 'sunucu', 'c.qr-na': 'QR kullanılamıyor', 'c.qr-na-off': 'QR çevrimdışı kullanılamıyor',
      'c.secret-hint': 'Sırlar yalnızca yerelde görünür. Etkinse panel X-Auth jetonunu girin.',
      'ru.empty': 'kontrol henüz yapılmadı', 'ru.avail': 'erişilebilir', 'ru.unavail': 'erişilemez', 'ru.all': 'tüm alan adları erişilebilir ✅',
      'upd.avail': 'mevcut', 'upd.cur': 'güncel', 'upd.msg-avail': 'Güncelleme mevcut', 'upd.msg-cur': 'Güncel sürüm kurulu',
      'upd.checked': 'Kontrol: ',
      'w.mesh-nodes': 'Mesh düğümleri:', 'w.mesh-exit': 'çıkış', 'w.hub': 'hub', 'w.mesh-none': 'Mesh bağlı değil. Davet "Bağlan" sekmesinde.',
      'w.plan': 'Aktif plan:', 'w.ru': 'RU alan adları:', 'w.ru-ok': 'erişilebilir',
      'mesh.connected': 'bağlı', 'mesh.not': 'bağlı değil', 'mesh.member': 'üye', 'mesh.hub': 'hub',
      'mesh.no-nodes': 'düğüm yok — ilkini ekleyin', 'mesh.node': 'düğüm',
      'routes.empty': 'henüz rota yok', 'routes.active': 'aktif', 'routes.off': 'kapalı',
      'plans.na': 'planlar bu sürümde yok', 'plans.traffic': 'Trafik:', 'plans.devices': 'Cihazlar:', 'plans.keys': 'Anahtarlar:',
      'plans.free': 'Ücretsiz', 'plans.per-mo': '/ay', 'plans.current': 'mevcut',
      'bill.empty': 'henüz ödeme yok',
      'sec.on': 'açık', 'sec.off': 'kapalı', 'sec.access': 'Yalnızca LAN: ', 'sec.da': 'evet', 'sec.no': 'hayır', 'sec.blk': 'engelle',
      'sec.rat': 'açık', 'sec.rat-off': 'kapalı',
      'log.empty': 'günlük boş', 'rec.empty': 'kurtarma yok',
      't.err': 'Sunucu kullanılamıyor', 't.err-gen': 'Hata', 't.action-ok': 'Tamam 🐾',
      'inv.need': 'Mesh davet kodunu yapıştırın', 'inv.bad': 'davet aurora://invite gibi görünmüyor — kodu kontrol edin',
      'inv.add-ok': 'Düğüm mesha eklendi 🕸️', 'inv.add-err': 'Bağlanılamadı', 'inv.leave-none': 'Ayrılacak düğüm yok',
      'inv.leave-ok': 'Düğümler silindi, meshten çıkıldı 🕸️', 'inv.leave-err': 'Ayrılma hatası', 'inv.regen-ok': 'Davet yenilendi 🔄',
      'inv.regen-err': 'Başarısız', 'inv.copy-ok': 'Davet kopyalandı 🔗', 'inv.empty': 'Davet henüz yok',
      'inv.topology': 'Topoloji güncellendi 🕸️',
      'set.saved': 'Ayarlar kaydedildi 🐾', 'set.save-err': 'Kaydetme hatası',
      'sec.need-token': 'Jetonu girin', 'sec.accept': 'Jeton kabul edildi, panel açıldı 🛡️', 'sec.reject': 'Jeton reddedildi (401)',
      'sec.logout': 'Çıkış yapıldı', 'sec.rotate-ok': 'Reality anahtarları değiştirildi 🔄', 'sec.rotate-na': 'Döndürme bu sürümde yok',
      'upd.run-ok': 'Kontrol başlatıldı (arka plan)', 'upd.check-err': 'Kontrol hatası', 'upd.apply-ok': 'Güncelleme başlatıldı ⬆️',
      'upd.apply-err': 'Başlatılamadı', 'upd.admin': 'Güncelleme kanalı yönetim panelinde yönetilir 🐾',
      'plans.admin': 'Planlar yönetim panelinde yönetilir 🐾', 'plans.buy': 'Plan «', 'plans.buy2': '» — satın alma yönetim panelinde 🐾',
      'feat.admin': 'Mağaza bu sürümde yok 🐾', 'feat.buy': 'Özellik «', 'feat.buy2': '» — vitrin herkese açık sürümde 🐾',
      'vpn.on': 'VPN açıldı 🌀', 'vpn.off': 'VPN kapatıldı', 'vpn.err': 'Hata', 'rot.ok': 'Anahtar değiştirildi 🎲', 'rot.err': 'Değiştirilemedi',
      'pool.refresh': 'Havuz güncellendi 🔄', 'pool.check': 'Anahtar kontrolü arka planda 🧪', 'mesh.ping': 'Mesh ping başlatıldı 📡',
      'mesh.policy-saved': 'Hub politikası kaydedildi 🎛',
      'copy.link-ok': 'Bağlantı kopyalandı 📋', 'copy.link-na': 'Bağlantı henüz yok', 'ru.done': 'Kontrol bitti 🇷🇺',
      'ru.run': 'Kontrol başlatıldı', 'ru.failonly': '💀 Yalnızca sorunlar', 'ru.failonly-on': '💀 Yalnızca sorunlar ✓',
      'tg.restarted': 'TG-WS yeniden başlatıldı ✈️', 'tg.restart-err': 'Yeniden başlatma hatası',
      'fmt.kb': 'KB', 'fmt.mb': 'MB', 'fmt.gb': 'GB', 'fmt.ul': 'Sınırsız', 'fmt.per-mo': '/ay',
      'fmt.s': ' sn', 'fmt.min': ' dk', 'fmt.h': ' sa', 'fmt.d': ' g',
      'dash.mode': 'Mod', 'dash.ip': 'Çıkış IP', 'dash.conns': 'Bağlantılar', 'dash.traffic': 'Trafik ↓ / ↑', 'dash.mesh-nodes': 'Mesh düğümü', 'dash.plan': 'Tarife',
      'upd.details': 'Detaylar', 'upd.now': 'Güncelle', 'w.proxy': 'Proxy durumu', 'w.check-ru': 'Kontrol et',
      'keys.uri-ph': 'vless://… linkini yapıştır (Reality)', 'keys.add': 'Kendi anahtarın', 'keys.clean': 'Ölüleri temizle', 'keys.src': 'github + kendi',
      'th.tag': 'Etiket', 'th.source': 'Kaynak', 'th.status': 'Durum', 'th.ping': 'Ping', 'th.exit': 'Çıkış IP', 'th.sites': 'Sites',
      'dev.head': 'Ağdaki cihazlar', 'th.device': 'Cihaz', 'th.conn': 'Conn', 'th.dl': '↓ İndirilen', 'th.ul': '↑ Yüklenen',
      'cx.head': 'Dış bağlantı', 'cx.hint': 'Proxy\'nuz için hazır vless-link. v2rayN / v2rayNG / NekoBox\'a yapıştırın — trafik her yerden bu sunucudan geçer.', 'cx.addr': 'Adres', 'cx.port': 'Port', 'cx.uuid': 'UUID', 'cx.sni': 'SNI',
      'ru.partial': 'kısmen', 'ru.hint': 'Rus kaynaklarının sunucudan doğrudan (VPN\'siz) erişilebilirliği. Segment çalışıyorsa — RU siteleri proxiesiz açılır.', 'ru.ok': 'Erişilebilir', 'ru.bad': 'Sorunlar', 'ru.med': 'Medyan', 'ru.ts': 'Kontrol edildi',
      'ru.check-now': 'Şimdi kontrol et', 'th.domain': 'Alan adı', 'th.time': 'Süre',
      'tgws.head': 'Telegram WS-proxy', 'tgws.proc': 'İşlem', 'tgws.secret': 'Sır', 'tgws.restart': 'TG-WS\'yi yeniden başlat',
      'mj.head': 'Mesh ağına bağlan', 'mj.p': 'Proxy\'nuz özel Aurora mesh ağının parçası olabilir. Bu, diğer katılımcıların özel konumlarına erişim, otomatik engel atlatma ve yedek rotalar sağlar.',
      'mj.invite-ph': 'Mesh invite kodunu yapıştır (örn.: aurora-home-a1b2c3d4)', 'mj.join': 'Bağlan', 'mj.st': 'Mesh durumu', 'mj.name': 'Mesh adı', 'mj.role': 'Rol',
      'mj.nodes': 'Erişilebilir düğüm', 'mj.ping': 'Hub pingi', 'mj.enc': 'Şifreleme', 'mj.what': 'Mesh ne sağlar',
      'mj.leave': 'Mesh\'ten ayrıl', 'mj.regen': 'Invite\'i güncelle', 'mj.pol': 'Hub politikası', 'mj.pol-hint': 'Hub sunucusu, mesh istemcilerinin gördüğü sekmeleri kontrol eder. Bu sunucunun invite\'ıyla bağlanan istemciler politikayı otomatik uygular (15 sn\'de bir günceller).',
      'mj.master': 'Sunucu hub\'dır, istemci görünürlüğünü kontrol eder', 'mj.show-mesh': 'İstemcilere «Mesh ağı» sekmesini göster', 'mj.show-subs': 'İstemcilere «Mağaza» sekmesini göster',
      'mt.hint': 'Proxy\'nuz (merkezde) ve diğer mesh katılımcılarının düğümleri. Trafik onlardan geçiyorsa bağlantılar aktiftir.',
      'mrt.hint': 'Hangi trafiğin hangi düğümden internete çıktığı kuralları. Sıra yukarıdan aşağıya.', 'th.what': 'Ne', 'th.via': 'Nereye', 'th.proto': 'Protokol',
      'sp.head': 'Tarifeler', 'sp.hint': 'Proxy işlevlerinin temel seti. Tek tıkla yükseltme, anında uygulanır, bağlantılar kesilmez.', 'sp.loading': 'tarifeler yükleniyor…', 'sp.comp': 'Tarife içeriği', 'th.func': 'İşlev', 'th.val': 'Değer',
      'sf.instant': '+ anında etkinleşir',
      'sb.head': 'Ödeme ve uzatma', 'sb.hint': 'Aktif tarife, süre ve ödeme geçmişi. Tek tıkla uzatma.', 'sb.plan': 'Mevcut tarife', 'sb.until': 'Geçerlilik', 'sb.buy': 'Uzat / tarife değiştir', 'sb.hist': 'Ödeme geçmişi',
      'th.date': 'Tarih', 'th.desc': 'Açıklama', 'th.sum': 'Tutar',
      'upd.apply': 'Şimdi güncelle', 'upd.auto': 'Otomatik güncelleme', 'upd.auto-hint': 'Güncelleme GitHub sürümlerinden yapılır. İkili indirilir, doğrulanır, atomik değiştirilir — proxy birkaç saniyede yeniden başlar.',
      'upd.src': 'Güncelleme kaynağı', 'th.param': 'Parametre', 'upd.repo': 'Depo', 'upd.sig': 'İmza kontrolü', 'upd.rollback': 'Hata durumunda geri dönüş',
      'upd.check-now': 'Şimdi kontrol et', 'upd.stable': 'stable — yalnız kararlılar', 'upd.rc': 'rc — sürüm adayları', 'upd.nightly': 'nightly — gece sürümleri',
      'upd.mode-auto': 'Otomatik güncelleme açık', 'upd.mode-notify': 'Yalnız bildir', 'upd.mode-off': 'Kontrol etme',
      'ver.head': 'Sürüm geçmişi',
      'set.head': 'Sunucu parametreleri', 'set.host': 'Host', 'set.port': 'Xray portu', 'set.ver': 'Sürüm', 'set.uptime': 'Çalışma süresi',
      'set.common': 'Genel', 'set.mesh': 'Mesh', 'set.name-ph': 'Sunucu adı', 'set.meshid-ph': 'Mesh ID', 'set.copy-invite': 'Invite kopyala',
      'sec.hint': 'Panel admin tokeni ve harici Reality anahtarları. Canlı konfigürasyonu değiştirir.', 'sec.panel': 'Panel', 'sec.tok-ph': 'Admin tokeni (Bearer) — POST /api/* için gerekli', 'sec.acc-v': 'Erişim', 'sec.pbk-ph': 'genel anahtar', 'sec.rotate': 'Anahtar döndür',
      'log.head': 'Sistem günlüğü', 'log.loading': 'yükleniyor…', 'log.refresh': 'Yenile', 'log.download': 'İndir', 'rclog.head': 'Recovery günlüğü',
      'th.node': 'Düğüm', 'th.region': 'Bölge', 'th.route': 'Güzergâh', 'sec.tok': 'Admin tokeni', 'sec.reality': 'Reality',
      'theme.sun': '🌙', 'theme.moon': '☀️'
    },
    pt: {
      'pol.head': 'Política do serviço', 'pol.readOnly': 'Ver', 'pol.accept': 'Aceito os termos', 'ru.regions': 'Segmentos', 'ru.custom-ph': 'Domínios personalizados separados por vírgulas (opcional)',
      'dash.manage': 'Gestão', 'pool.refresh-btn': 'Atualizar chaves', 'pool.check-btn': 'Verificar chaves', 'mesh.ping-btn': 'Ping mesh',
      'nav.dash': 'Painel', 'nav.keys': 'Chaves', 'nav.devices': 'Dispositivos',
      'nav.connect': 'Acesso externo', 'nav.rusegment': 'Segmento RU', 'nav.tgws': 'TG-WS',
      'nav.mesh': 'Rede mesh', 'nav.mesh-join': 'Conectar', 'nav.mesh-topo': 'Topologia', 'nav.mesh-routes': 'Rotas',
      'nav.shop': 'Loja', 'nav.shop-plans': 'Planos', 'nav.shop-features': 'Recursos', 'nav.shop-billing': 'Pagamentos',
      'nav.update': 'Atualização', 'nav.versions': 'Versões', 'nav.settings': 'Servidor', 'nav.security': 'Segurança', 'nav.logs': 'Logs',
      'nav.group.home': 'Proxy doméstico', 'nav.group.upd': 'Atualizações', 'nav.group.set': 'Configurações',
      'g.you': 'Você', 'g.yours': 'seu', 'status.on': 'online', 'status.off': 'offline', 'status.warn': 'instável',
      'status.online': 'ativo', 'status.stopped': 'parado', 'status.active': 'ativo', 'status.dead': 'morto',
      'status.bad': 'ruim', 'status.slow': 'lento', 'status.noip': 'noip', 'status.ok': 'ok', 'status.final': 'final',
      'status.direct': 'direto', 'status.enabled': 'habilitado', 'status.disabled': 'desabilitado',
      'btn.vpn-off': '🌀 Ativar VPN', 'btn.vpn-on': '🌀 VPN ativa', 'btn.rotate': '🎲 Trocar chave', 'btn.choose': '💎 Escolher',
      'btn.copy': '📋 Copiar', 'btn.save': 'Salvar', 'btn.login': '🔑 Entrar', 'btn.logout': 'Sair',
      'k.keys': 'chaves: ', 'k.empty': 'ainda sem chaves', 'k.mine': 'própria', 'k.github': 'github',
      'k.add-ok': 'Chave adicionada 🐾', 'k.add-err': 'Falha ao adicionar', 'k.need-vless': 'É necessário um link vless://',
      'k.active-ok': 'ativa 🐾', 'k.active-err': 'Não foi possível ativar', 'k.clean-ok': 'Chaves mortas removidas 🐾',
      'k.set-active': 'Tornar ativa',
      'd.empty': 'ainda sem dispositivos',
      'c.on': 'habilitado', 'c.off': 'desabilitado', 'c.server': 'servidor', 'c.qr-na': 'QR indisponível', 'c.qr-na-off': 'QR off-line indisponível',
      'c.secret-hint': 'Os segredos só são visíveis localmente. Informe o token X-Auth do painel, se ativado.',
      'ru.empty': 'verificação ainda não feita', 'ru.avail': 'disponível', 'ru.unavail': 'indisponível', 'ru.all': 'todos os domínios disponíveis ✅',
      'upd.avail': 'disponível', 'upd.cur': 'atual', 'upd.msg-avail': 'Atualização disponível', 'upd.msg-cur': 'Versão atual instalada',
      'upd.checked': 'Verificado: ',
      'w.mesh-nodes': 'Nós de mesh:', 'w.mesh-exit': 'saída por', 'w.hub': 'hub', 'w.mesh-none': 'Mesh não conectado. Convite na aba «Conectar».',
      'w.plan': 'Plano ativo:', 'w.ru': 'Domínios RU:', 'w.ru-ok': 'disponíveis',
      'mesh.connected': 'conectado', 'mesh.not': 'não conectado', 'mesh.member': 'membro', 'mesh.hub': 'hub',
      'mesh.no-nodes': 'sem nós — adicione o primeiro', 'mesh.node': 'nó',
      'routes.empty': 'ainda sem rotas', 'routes.active': 'ativo', 'routes.off': 'desligado',
      'plans.na': 'planos indisponíveis nesta versão', 'plans.traffic': 'Tráfego:', 'plans.devices': 'Dispositivos:', 'plans.keys': 'Chaves:',
      'plans.free': 'Grátis', 'plans.per-mo': '/mês', 'plans.current': 'atual',
      'bill.empty': 'ainda sem pagamentos',
      'sec.on': 'habilitado', 'sec.off': 'desabilitado', 'sec.access': 'Somente LAN: ', 'sec.da': 'sim', 'sec.no': 'não', 'sec.blk': 'bloquear',
      'sec.rat': 'on', 'sec.rat-off': 'off',
      'log.empty': 'log vazio', 'rec.empty': 'sem recuperações',
      't.err': 'Servidor indisponível', 't.err-gen': 'Erro', 't.action-ok': 'Pronto 🐾',
      'inv.need': 'Cole o código de convite do mesh', 'inv.bad': 'convite não parece aurora://invite — verifique o código',
      'inv.add-ok': 'Nó adicionado ao mesh 🕸️', 'inv.add-err': 'Não foi possível conectar', 'inv.leave-none': 'Nenhum nó para desconectar',
      'inv.leave-ok': 'Nós removidos, saiu do mesh 🕸️', 'inv.leave-err': 'Erro de desconexão', 'inv.regen-ok': 'Convite renovado 🔄',
      'inv.regen-err': 'Falhou', 'inv.copy-ok': 'Convite copiado 🔗', 'inv.empty': 'Convite ainda indisponível',
      'inv.topology': 'Topologia atualizada 🕸️',
      'set.saved': 'Configurações salvas 🐾', 'set.save-err': 'Erro ao salvar',
      'sec.need-token': 'Digite o token', 'sec.accept': 'Token aceito, painel desbloqueado 🛡️', 'sec.reject': 'Token rejeitado (401)',
      'sec.logout': 'Sessão encerrada', 'sec.rotate-ok': 'Chaves Reality rotacionadas 🔄', 'sec.rotate-na': 'Rotação indisponível nesta versão',
      'upd.run-ok': 'Verificação iniciada (fundo)', 'upd.check-err': 'Erro de verificação', 'upd.apply-ok': 'Atualização iniciada ⬆️',
      'upd.apply-err': 'Não foi possível iniciar', 'upd.admin': 'O canal de atualização é gerido no painel de administração 🐾',
      'plans.admin': 'Os planos são geridos no painel de administração 🐾', 'plans.buy': 'Plano «', 'plans.buy2': '» — compra no painel de administração 🐾',
      'feat.admin': 'Loja indisponível nesta versão 🐾', 'feat.buy': 'Recurso «', 'feat.buy2': '» — vitrine na versão pública 🐾',
      'vpn.on': 'VPN ativada 🌀', 'vpn.off': 'VPN desativada', 'vpn.err': 'Erro', 'rot.ok': 'Chave rotacionada 🎲', 'rot.err': 'Não foi possível rotacionar',
      'pool.refresh': 'Pool atualizado 🔄', 'pool.check': 'Verificação de chaves em segundo plano 🧪', 'mesh.ping': 'Ping de mesh iniciado 📡',
      'mesh.policy-saved': 'Política do hub salva 🎛',
      'copy.link-ok': 'Link copiado 📋', 'copy.link-na': 'Link ainda indisponível', 'ru.done': 'Verificação concluída 🇷🇺',
      'ru.run': 'Verificação iniciada', 'ru.failonly': '💀 Somente problemas', 'ru.failonly-on': '💀 Somente problemas ✓',
      'tg.restarted': 'TG-WS reiniciado ✈️', 'tg.restart-err': 'Erro de reinicialização',
      'fmt.kb': 'KB', 'fmt.mb': 'MB', 'fmt.gb': 'GB', 'fmt.ul': 'Ilimitado', 'fmt.per-mo': '/mês',
      'fmt.s': ' s', 'fmt.min': ' min', 'fmt.h': ' h', 'fmt.d': ' d',
      'dash.mode': 'Modo', 'dash.ip': 'IP de saída', 'dash.conns': 'Conexões', 'dash.traffic': 'Tráfego ↓ / ↑', 'dash.mesh-nodes': 'Nós mesh', 'dash.plan': 'Plano',
      'upd.details': 'Detalhes', 'upd.now': 'Atualizar', 'w.proxy': 'Estado do proxy', 'w.check-ru': 'Verificar',
      'keys.uri-ph': 'vless://… cole seu link (Reality)', 'keys.add': 'Adicionar chave', 'keys.clean': 'Limpar mortas', 'keys.src': 'github + minhas',
      'th.tag': 'Tag', 'th.source': 'Origem', 'th.status': 'Status', 'th.ping': 'Ping', 'th.exit': 'IP de saída', 'th.sites': 'Sites',
      'dev.head': 'Dispositivos na rede', 'th.device': 'Dispositivo', 'th.conn': 'Conn', 'th.dl': '↓ Baixado', 'th.ul': '↑ Enviado',
      'cx.head': 'Conexão externa', 'cx.hint': 'Link vless pronto para o seu proxy. Cole no v2rayN / v2rayNG / NekoBox — o tráfego passará por este servidor de qualquer lugar.', 'cx.addr': 'Endereço', 'cx.port': 'Porta', 'cx.uuid': 'UUID', 'cx.sni': 'SNI',
      'ru.partial': 'parcial', 'ru.hint': 'Disponibilidade de recursos russos diretamente do servidor (sem VPN). Se o segmento funciona — os sites RU abrem sem proxy.', 'ru.ok': 'Disponível', 'ru.bad': 'Problemas', 'ru.med': 'Mediana', 'ru.ts': 'Verificado',
      'ru.check-now': 'Verificar agora', 'th.domain': 'Domínio', 'th.time': 'Tempo',
      'tgws.head': 'Proxy WS do Telegram', 'tgws.proc': 'Processo', 'tgws.secret': 'Segredo', 'tgws.restart': 'Reiniciar TG-WS',
      'mj.head': 'Entrar na rede mesh', 'mj.p': 'Seu proxy pode fazer parte da rede mesh privada Aurora. Isso dá acesso a localizações exclusivas de outros membros, desvio automático de bloqueios e rotas de reserva.',
      'mj.invite-ph': 'Cole o código invite do mesh (ex.: aurora-home-a1b2c3d4)', 'mj.join': 'Conectar', 'mj.st': 'Estado do mesh', 'mj.name': 'Nome do mesh', 'mj.role': 'Papel',
      'mj.nodes': 'Nós disponíveis', 'mj.ping': 'Ping ao hub', 'mj.enc': 'Criptografia', 'mj.what': 'O que o mesh dá',
      'mj.leave': 'Sair do mesh', 'mj.regen': 'Atualizar invite', 'mj.pol': 'Política do hub', 'mj.pol-hint': 'O servidor hub controla quais abas os clientes do mesh veem. Clientes conectados por invite deste servidor aplicam a política automaticamente (atualização a cada 15 s).',
      'mj.master': 'Servidor é hub, controla a visibilidade dos clientes', 'mj.show-mesh': 'Mostrar a aba “Rede mesh” aos clientes', 'mj.show-subs': 'Mostrar a aba “Loja” aos clientes',
      'mt.hint': 'Seu proxy (no centro) e os nós de outros membros do mesh. As conexões estão ativas se o tráfego passa por eles.',
      'mrt.hint': 'Regras de qual tráfego sai para a internet via qual nó. Ordem de cima para baixo.', 'th.what': 'O quê', 'th.via': 'Onde', 'th.proto': 'Protocolo',
      'sp.head': 'Planos', 'sp.hint': 'Conjunto básico de funções do proxy. Upgrade em um clique, aplicado na hora, sem perder conexões.', 'sp.loading': 'carregando planos…', 'sp.comp': 'Conteúdo do plano', 'th.func': 'Função', 'th.val': 'Valor',
      'sf.instant': '+ ativam na hora',
      'sb.head': 'Pagamento e renovação', 'sb.hint': 'Plano ativo, validade e histórico de pagamentos. Renovação em um clique.', 'sb.plan': 'Plano atual', 'sb.until': 'Válido até', 'sb.buy': 'Renovar / mudar plano', 'sb.hist': 'Histórico de pagamentos',
      'th.date': 'Data', 'th.desc': 'Descrição', 'th.sum': 'Valor',
      'upd.apply': 'Atualizar agora', 'upd.auto': 'Auto-atualização', 'upd.auto-hint': 'A atualização vem dos releases do GitHub. O binário é baixado, verificado, substituído atomicamente — o proxy reinicia em alguns segundos.',
      'upd.src': 'Origem da atualização', 'th.param': 'Parâmetro', 'upd.repo': 'Repositório', 'upd.sig': 'Verificação de assinatura', 'upd.rollback': 'Reversão em falha',
      'upd.check-now': 'Verificar agora', 'upd.stable': 'stable — apenas estáveis', 'upd.rc': 'rc — candidatos a release', 'upd.nightly': 'nightly — builds noturnos',
      'upd.mode-auto': 'Auto-atualização ativada', 'upd.mode-notify': 'Apenas notificar', 'upd.mode-off': 'Não verificar',
      'ver.head': 'Histórico de versões',
      'set.head': 'Parâmetros do servidor', 'set.host': 'Host', 'set.port': 'Porta Xray', 'set.ver': 'Versão', 'set.uptime': 'Uptime',
      'set.common': 'Geral', 'set.mesh': 'Mesh', 'set.name-ph': 'Nome do servidor', 'set.meshid-ph': 'ID do mesh', 'set.copy-invite': 'Copiar invite',
      'sec.hint': 'Token do painel admin e chaves Reality externas. Muda a config ao vivo.', 'sec.panel': 'Painel', 'sec.tok-ph': 'Token admin (Bearer) — necessário para POST /api/*', 'sec.acc-v': 'Acesso', 'sec.pbk-ph': 'chave pública', 'sec.rotate': 'Rotacionar chaves',
      'log.head': 'Log do sistema', 'log.loading': 'carregando…', 'log.refresh': 'Atualizar', 'log.download': 'Baixar', 'rclog.head': 'Diário do recovery',
      'th.node': 'Nó', 'th.region': 'Região', 'th.route': 'Rota', 'sec.tok': 'Token admin', 'sec.reality': 'Reality',
      'theme.sun': '🌙', 'theme.moon': '☀️'
    },
    zh: {
      'pol.head': '服务政策', 'pol.readOnly': '查看', 'pol.accept': '我接受条款', 'ru.regions': '分段', 'ru.custom-ph': '自定义域名，逗号分隔（可选）',
      'dash.manage': '管理', 'pool.refresh-btn': '更新密钥', 'pool.check-btn': '检查密钥', 'mesh.ping-btn': '网格ping',
      'nav.dash': '概览', 'nav.keys': '密钥', 'nav.devices': '设备',
      'nav.connect': '外部访问', 'nav.rusegment': 'RU 段', 'nav.tgws': 'TG-WS',
      'nav.mesh': 'Mesh 网络', 'nav.mesh-join': '连接', 'nav.mesh-topo': '拓扑', 'nav.mesh-routes': '路由',
      'nav.shop': '商店', 'nav.shop-plans': '套餐', 'nav.shop-features': '功能', 'nav.shop-billing': '支付',
      'nav.update': '更新', 'nav.versions': '版本', 'nav.settings': '服务器', 'nav.security': '安全', 'nav.logs': '日志',
      'nav.group.home': '家用代理', 'nav.group.upd': '更新', 'nav.group.set': '设置',
      'g.you': '您', 'g.yours': '您的', 'status.on': '在线', 'status.off': '离线', 'status.warn': '不稳定',
      'status.online': '运行中', 'status.stopped': '已停止', 'status.active': '活动', 'status.dead': '已失效',
      'status.bad': '差', 'status.slow': '慢', 'status.noip': '无IP', 'status.ok': '正常', 'status.final': '最终',
      'status.direct': '直连', 'status.enabled': '已启用', 'status.disabled': '已禁用',
      'btn.vpn-off': '🌀 开启VPN', 'btn.vpn-on': '🌀 VPN开启', 'btn.rotate': '🎲 更换密钥', 'btn.choose': '💎 选择',
      'btn.copy': '📋 复制', 'btn.save': '保存', 'btn.login': '🔑 登录', 'btn.logout': '退出',
      'k.keys': '密钥：', 'k.empty': '暂无密钥', 'k.mine': '自有', 'k.github': 'github',
      'k.add-ok': '密钥已添加 🐾', 'k.add-err': '添加失败', 'k.need-vless': '需要 vless:// 链接',
      'k.active-ok': '活动 🐾', 'k.active-err': '无法激活', 'k.clean-ok': '已删除失效密钥 🐾',
      'k.set-active': '设为活动',
      'd.empty': '暂无设备',
      'c.on': '已启用', 'c.off': '已禁用', 'c.server': '服务器', 'c.qr-na': '二维码不可用', 'c.qr-na-off': '离线二维码不可用',
      'c.secret-hint': '密钥仅本地可见。已启用面板 X-Auth 令牌时请输入。',
      'ru.empty': '尚未检查', 'ru.avail': '可用', 'ru.unavail': '不可用', 'ru.all': '所有域名均可访问 ✅',
      'upd.avail': '可用', 'upd.cur': '最新', 'upd.msg-avail': '有可用更新', 'upd.msg-cur': '已安装最新版本',
      'upd.checked': '已检查：',
      'w.mesh-nodes': 'Mesh节点：', 'w.mesh-exit': '出口', 'w.hub': '集线器', 'w.mesh-none': 'Mesh 未连接。邀请在「连接」选项卡中。',
      'w.plan': '活动套餐：', 'w.ru': 'RU 域名：', 'w.ru-ok': '可用',
      'mesh.connected': '已连接', 'mesh.not': '未连接', 'mesh.member': '成员', 'mesh.hub': '集线器',
      'mesh.no-nodes': '没有节点 — 请添加第一个', 'mesh.node': '节点',
      'routes.empty': '暂无路由', 'routes.active': '活动', 'routes.off': '关闭',
      'plans.na': '此版本暂无套餐', 'plans.traffic': '流量：', 'plans.devices': '设备：', 'plans.keys': '密钥：',
      'plans.free': '免费', 'plans.per-mo': '/月', 'plans.current': '当前',
      'bill.empty': '暂无支付记录',
      'sec.on': '已启用', 'sec.off': '已禁用', 'sec.access': '仅局域网：', 'sec.da': '是', 'sec.no': '否', 'sec.blk': '阻止',
      'sec.rat': '开', 'sec.rat-off': '关',
      'log.empty': '日志为空', 'rec.empty': '无恢复记录',
      't.err': '服务器不可用', 't.err-gen': '错误', 't.action-ok': '完成 🐾',
      'inv.need': '粘贴 mesh 邀请码', 'inv.bad': '邀请不像 aurora://invite — 请检查代码',
      'inv.add-ok': '节点已加入 mesh 🕸️', 'inv.add-err': '连接失败', 'inv.leave-none': '没有要断开的节点',
      'inv.leave-ok': '节点已移除，已退出 mesh 🕸️', 'inv.leave-err': '断开错误', 'inv.regen-ok': '邀请已更新 🔄',
      'inv.regen-err': '失败', 'inv.copy-ok': '邀请已复制 🔗', 'inv.empty': '邀请尚不可用',
      'inv.topology': '拓扑已更新 🕸️',
      'set.saved': '设置已保存 🐾', 'set.save-err': '保存错误',
      'sec.need-token': '输入令牌', 'sec.accept': '令牌已接受，面板已解锁 🛡️', 'sec.reject': '令牌被拒绝 (401)',
      'sec.logout': '已退出', 'sec.rotate-ok': 'Reality 密钥已轮换 🔄', 'sec.rotate-na': '此版本不支持轮换',
      'upd.run-ok': '已开始检查（后台）', 'upd.check-err': '检查错误', 'upd.apply-ok': '更新已启动 ⬆️',
      'upd.apply-err': '无法启动', 'upd.admin': '更新渠道在管理面板中管理 🐾',
      'plans.admin': '套餐在管理面板中管理 🐾', 'plans.buy': '套餐「', 'plans.buy2': '」— 在管理面板购买 🐾',
      'feat.admin': '此版本商店不可用 🐾', 'feat.buy': '功能「', 'feat.buy2': '」— 公开版展示 🐾',
      'vpn.on': 'VPN已开启 🌀', 'vpn.off': 'VPN已关闭', 'vpn.err': '错误', 'rot.ok': '密钥已轮换 🎲', 'rot.err': '轮换失败',
      'pool.refresh': '密钥池已更新 🔄', 'pool.check': '后台密钥检查已启动 🧪', 'mesh.ping': 'Mesh 节点已发起 📡',
      'mesh.policy-saved': '集线器策略已保存 🎛',
      'copy.link-ok': '链接已复制 📋', 'copy.link-na': '链接尚不可用', 'ru.done': '检查完成 🇷🇺',
      'ru.run': '检查已启动', 'ru.failonly': '💀 仅问题', 'ru.failonly-on': '💀 仅问题 ✓',
      'tg.restarted': 'TG-WS 已重启 ✈️', 'tg.restart-err': '重启错误',
      'fmt.kb': 'KB', 'fmt.mb': 'MB', 'fmt.gb': 'GB', 'fmt.ul': '无限', 'fmt.per-mo': '/月',
      'fmt.s': ' 秒', 'fmt.min': ' 分钟', 'fmt.h': ' 小时', 'fmt.d': ' 天',
      'dash.mode': '模式', 'dash.ip': '出口 IP', 'dash.conns': '连接数', 'dash.traffic': '流量 ↓ / ↑', 'dash.mesh-nodes': 'Mesh 节点', 'dash.plan': '套餐',
      'upd.details': '详情', 'upd.now': '更新', 'w.proxy': '代理状态', 'w.check-ru': '检查',
      'keys.uri-ph': 'vless://… 粘贴你的链接（Reality）', 'keys.add': '添加密钥', 'keys.clean': '清除失效', 'keys.src': 'github + 自有',
      'th.tag': '标签', 'th.source': '来源', 'th.status': '状态', 'th.ping': 'Ping', 'th.exit': '出口 IP', 'th.sites': 'Sites',
      'dev.head': '网络中的设备', 'th.device': '设备', 'th.conn': '连接', 'th.dl': '↓ 下载', 'th.ul': '↑ 上传',
      'cx.head': '外部连接', 'cx.hint': '现成的 vless 链接。粘贴到 v2rayN / v2rayNG / NekoBox — 流量将从任何地方经过这台服务器。', 'cx.addr': '地址', 'cx.port': '端口', 'cx.uuid': 'UUID', 'cx.sni': 'SNI',
      'ru.partial': '部分', 'ru.hint': '从服务器直连访问俄罗斯资源（不带 VPN）。如果网段正常 — RU 网站无需代理即可打开。', 'ru.ok': '可用', 'ru.bad': '问题', 'ru.med': '中位数', 'ru.ts': '已检查',
      'ru.check-now': '立即检查', 'th.domain': '域名', 'th.time': '时间',
      'tgws.head': 'Telegram WS 代理', 'tgws.proc': '进程', 'tgws.secret': '密钥', 'tgws.restart': '重启 TG-WS',
      'mj.head': '加入 Mesh 网络', 'mj.p': '你的代理可以成为私有 Aurora Mesh 网络的一部分。这提供其他成员专属位置、自动绕过封锁和备用路由。',
      'mj.invite-ph': '粘贴 Mesh 邀请码（例如：aurora-home-a1b2c3d4）', 'mj.join': '连接', 'mj.st': 'Mesh 状态', 'mj.name': 'Mesh 名称', 'mj.role': '角色',
      'mj.nodes': '可用节点', 'mj.ping': '到中心的延迟', 'mj.enc': '加密', 'mj.what': 'Mesh 带来什么',
      'mj.leave': '退出 Mesh', 'mj.regen': '更新邀请', 'mj.pol': '中心策略', 'mj.pol-hint': '中心服务器控制客户端看到哪些标签页。通过此服务器邀请连接的客户端自动应用策略（每 15 秒更新一次）。',
      'mj.master': '服务器是中心，控制客户端的可见性', 'mj.show-mesh': '向客户端显示“Mesh 网络”标签页', 'mj.show-subs': '向客户端显示“商店”标签页',
      'mt.hint': '你的代理（中心）和 Mesh 其他成员的节点。如果流量经过它们，连接就是活动的。',
      'mrt.hint': '哪些流量通过哪个节点出网的规则。从上到下的顺序。', 'th.what': '什么', 'th.via': '去向', 'th.proto': '协议',
      'sp.head': '套餐方案', 'sp.hint': '代理功能的基础套件。一键升级，即时生效，不中断连接。', 'sp.loading': '加载中…', 'sp.comp': '套餐内容', 'th.func': '功能', 'th.val': '数值',
      'sf.instant': '+ 即时启用',
      'sb.head': '支付与续费', 'sb.hint': '当前套餐、有效期和支付记录。一键续费。', 'sb.plan': '当前套餐', 'sb.until': '有效至', 'sb.buy': '续费 / 更换套餐', 'sb.hist': '支付记录',
      'th.date': '日期', 'th.desc': '描述', 'th.sum': '金额',
      'upd.apply': '立即更新', 'upd.auto': '自动更新', 'upd.auto-hint': '更新来自 GitHub 发布版。二进制下载、验证、原子替换 — 代理几秒后重启。',
      'upd.src': '更新来源', 'th.param': '参数', 'upd.repo': '仓库', 'upd.sig': '签名验证', 'upd.rollback': '失败时回滚',
      'upd.check-now': '立即检查', 'upd.stable': 'stable — 仅稳定版', 'upd.rc': 'rc — 候选版本', 'upd.nightly': 'nightly — 夜间构建',
      'upd.mode-auto': '自动更新已开启', 'upd.mode-notify': '仅通知', 'upd.mode-off': '不检查',
      'ver.head': '版本历史',
      'set.head': '服务器参数', 'set.host': '主机', 'set.port': 'Xray 端口', 'set.ver': '版本', 'set.uptime': '运行时间',
      'set.common': '通用', 'set.mesh': 'Mesh', 'set.name-ph': '服务器名称', 'set.meshid-ph': 'Mesh ID', 'set.copy-invite': '复制邀请',
      'sec.hint': '面板管理员令牌和外部 Reality 密钥。修改会作用于实时配置。', 'sec.panel': '面板', 'sec.tok-ph': '管理员令牌（Bearer）— POST /api/* 需要', 'sec.acc-v': '访问', 'sec.pbk-ph': '公钥', 'sec.rotate': '轮换密钥',
      'log.head': '系统日志', 'log.loading': '加载中…', 'log.refresh': '刷新', 'log.download': '下载', 'rclog.head': '恢复日志',
      'th.node': '节点', 'th.region': '地区', 'th.route': '路由', 'sec.tok': '管理员令牌', 'sec.reality': 'Reality',
      'theme.sun': '🌙', 'theme.moon': '☀️'
    },
    ar: {
      'pol.head': 'سياسة الخدمة', 'pol.readOnly': 'عرض', 'pol.accept': 'أوافق على الشروط', 'ru.regions': 'القطاعات', 'ru.custom-ph': 'نطاقات مخصصة مفصولة بفواصل (اختياري)',
      'dash.manage': 'إدارة', 'pool.refresh-btn': 'تحديث المفاتيح', 'pool.check-btn': 'فحص المفاتيح', 'mesh.ping-btn': 'بنج الشبكة',
      'nav.dash': 'لوحة التحكم', 'nav.keys': 'المفاتيح', 'nav.devices': 'الأجهزة',
      'nav.connect': 'الوصول الخارجي', 'nav.rusegment': 'قطاع RU', 'nav.tgws': 'TG-WS',
      'nav.mesh': 'شبكة ميش', 'nav.mesh-join': 'الاتصال', 'nav.mesh-topo': 'الطوبولوجيا', 'nav.mesh-routes': 'المسارات',
      'nav.shop': 'المتجر', 'nav.shop-plans': 'الباقات', 'nav.shop-features': 'الميزات', 'nav.shop-billing': 'المدفوعات',
      'nav.update': 'التحديث', 'nav.versions': 'الإصدارات', 'nav.settings': 'الخادم', 'nav.security': 'الأمان', 'nav.logs': 'السجلات',
      'nav.group.home': 'بروكسي المنزلي', 'nav.group.upd': 'التحديثات', 'nav.group.set': 'الإعدادات',
      'g.you': 'أنت', 'g.yours': 'الخاص بك', 'status.on': 'متصل', 'status.off': 'غير متصل', 'status.warn': 'غير مستقر',
      'status.online': 'يعمل', 'status.stopped': 'متوقف', 'status.active': 'نشط', 'status.dead': 'ميت',
      'status.bad': 'سيء', 'status.slow': 'بطيء', 'status.noip': 'noip', 'status.ok': 'موافق', 'status.final': 'نهائي',
      'status.direct': 'مباشر', 'status.enabled': 'مفعّل', 'status.disabled': 'معطّل',
      'btn.vpn-off': '🌀 تفعيل VPN', 'btn.vpn-on': '🌀 VPN مفعل', 'btn.rotate': '🎲 تبديل المفتاح', 'btn.choose': '💎 اختيار',
      'btn.copy': '📋 نسخ', 'btn.save': 'حفظ', 'btn.login': '🔑 دخول', 'btn.logout': 'خروج',
      'k.keys': 'المفاتيح: ', 'k.empty': 'لا توجد مفاتيح بعد', 'k.mine': 'خاصة', 'k.github': 'github',
      'k.add-ok': 'تمت إضافة المفتاح 🐾', 'k.add-err': 'فشل الإضافة', 'k.need-vless': 'مطلوب رابط vless://',
      'k.active-ok': 'نشط 🐾', 'k.active-err': 'تعذر التفعيل', 'k.clean-ok': 'تم حذف المفاتيح الميتة 🐾',
      'k.set-active': 'جعله نشطًا',
      'd.empty': 'لا توجد أجهزة بعد',
      'c.on': 'مفعّل', 'c.off': 'معطّل', 'c.server': 'الخادم', 'c.qr-na': 'QR غير متاح', 'c.qr-na-off': 'QR غير متاح دون اتصال',
      'c.secret-hint': 'الأسرار مرئية محليًا فقط. أدخل رمز X-Auth للوحة إذا كان مفعّلاً.',
      'ru.empty': 'لم يتم الفحص بعد', 'ru.avail': 'متاح', 'ru.unavail': 'غير متاح', 'ru.all': 'جميع النطاقات متاحة ✅',
      'upd.avail': 'متاح', 'upd.cur': 'محدّث', 'upd.msg-avail': 'تحديث متاح', 'upd.msg-cur': 'تم تثبيت الإصدار الحالي',
      'upd.checked': 'تم الفحص: ',
      'w.mesh-nodes': 'عقد الشبكة:', 'w.mesh-exit': 'الخروج عبر', 'w.hub': 'المحور', 'w.mesh-none': 'الشبكة غير متصلة. الدعوة في تبويب «الاتصال».',
      'w.plan': 'الباقة النشطة:', 'w.ru': 'نطاقات RU:', 'w.ru-ok': 'متاحة',
      'mesh.connected': 'متصل', 'mesh.not': 'غير متصل', 'mesh.member': 'عضو', 'mesh.hub': 'محور',
      'mesh.no-nodes': 'لا توجد عقد — أضف الأولى', 'mesh.node': 'عقدة',
      'routes.empty': 'لا توجد مسارات بعد', 'routes.active': 'نشط', 'routes.off': 'معطل',
      'plans.na': 'الباقات غير متاحة في هذا الإصدار', 'plans.traffic': 'المرور:', 'plans.devices': 'الأجهزة:', 'plans.keys': 'المفاتيح:',
      'plans.free': 'مجاني', 'plans.per-mo': '/شهر', 'plans.current': 'الحالية',
      'bill.empty': 'لا توجد مدفوعات بعد',
      'sec.on': 'مفعّل', 'sec.off': 'معطّل', 'sec.access': 'LAN فقط: ', 'sec.da': 'نعم', 'sec.no': 'لا', 'sec.blk': 'حظر',
      'sec.rat': 'تفعيل', 'sec.rat-off': 'تعطيل',
      'log.empty': 'السجل فارغ', 'rec.empty': 'لا توجد عمليات استعادة',
      't.err': 'الخادم غير متاح', 't.err-gen': 'خطأ', 't.action-ok': 'تم 🐾',
      'inv.need': 'الصق رمز دعوة الشبكة', 'inv.bad': 'الدعوة لا تشبه aurora://invite — تحقق من الرمز',
      'inv.add-ok': 'تمت إضافة العقدة إلى الشبكة 🕸️', 'inv.add-err': 'تعذر الاتصال', 'inv.leave-none': 'لا توجد عقد لفصلها',
      'inv.leave-ok': 'تمت إزالة العقد، خرجت من الشبكة 🕸️', 'inv.leave-err': 'خطأ في الفصل', 'inv.regen-ok': 'تم تجديد الدعوة 🔄',
      'inv.regen-err': 'فشل', 'inv.copy-ok': 'تم نسخ الدعوة 🔗', 'inv.empty': 'الدعوة غير متاحة بعد',
      'inv.topology': 'تم تحديث الطوبولوجيا 🕸️',
      'set.saved': 'تم حفظ الإعدادات 🐾', 'set.save-err': 'خطأ في الحفظ',
      'sec.need-token': 'أدخل الرمز', 'sec.accept': 'تم قبول الرمز، فُتحت اللوحة 🛡️', 'sec.reject': 'تم رفض الرمز (401)',
      'sec.logout': 'تم تسجيل الخروج', 'sec.rotate-ok': 'تم تدوير مفاتيح Reality 🔄', 'sec.rotate-na': 'التدوير غير متاح في هذا الإصدار',
      'upd.run-ok': 'بدأ الفحص (في الخلفية)', 'upd.check-err': 'خطأ في الفحص', 'upd.apply-ok': 'بدأ التحديث ⬆️',
      'upd.apply-err': 'تعذر البدء', 'upd.admin': 'قناة التحديث تدار في لوحة الإدارة 🐾',
      'plans.admin': 'الباقات تدار في لوحة الإدارة 🐾', 'plans.buy': 'الباقة «', 'plans.buy2': '» — الشراء في لوحة الإدارة 🐾',
      'feat.admin': 'المتجر غير متاح في هذا الإصدار 🐾', 'feat.buy': 'الميزة «', 'feat.buy2': '» — واجهة في الإصدار العام 🐾',
      'vpn.on': 'تم تفعيل VPN 🌀', 'vpn.off': 'تم إيقاف VPN', 'vpn.err': 'خطأ', 'rot.ok': 'تم تدوير المفتاح 🎲', 'rot.err': 'تعذر التدوير',
      'pool.refresh': 'تم تحديث المجموعة 🔄', 'pool.check': 'فحص المفاتيح في الخلفية 🧪', 'mesh.ping': 'بدأ فحص الشبكة 📡',
      'mesh.policy-saved': 'تم حفظ سياسة المحور 🎛',
      'copy.link-ok': 'تم نسخ الرابط 📋', 'copy.link-na': 'الرابط غير متاح بعد', 'ru.done': 'اكتمل الفحص 🇷🇺',
      'ru.run': 'بدأ الفحص', 'ru.failonly': '💀 المشاكل فقط', 'ru.failonly-on': '💀 المشاكل فقط ✓',
      'tg.restarted': 'تمت إعادة تشغيل TG-WS ✈️', 'tg.restart-err': 'خطأ في إعادة التشغيل',
      'fmt.kb': 'كيلوبايت', 'fmt.mb': 'ميجابايت', 'fmt.gb': 'гигабайт', 'fmt.ul': 'غير محدود', 'fmt.per-mo': '/شهر',
      'fmt.s': ' ث', 'fmt.min': ' د', 'fmt.h': ' س', 'fmt.d': ' يوم',
      'dash.mode': 'الوضع', 'dash.ip': 'IP الخروج', 'dash.conns': 'الاتصالات', 'dash.traffic': 'الحركة ↓ / ↑', 'dash.mesh-nodes': 'عقد الشبكة', 'dash.plan': 'الخطة',
      'upd.details': 'التفاصيل', 'upd.now': 'تحديث', 'w.proxy': 'حالة البروكسي', 'w.check-ru': 'تحقق',
      'keys.uri-ph': 'vless://… الصق رابطك (Reality)', 'keys.add': 'إضافة مفتاح', 'keys.clean': 'إزالة الميتة', 'keys.src': 'github + الخاصة',
      'th.tag': 'الوسم', 'th.source': 'المصدر', 'th.status': 'الحالة', 'th.ping': 'بينغ', 'th.exit': 'IP الخروج', 'th.sites': 'Sites',
      'dev.head': 'الأجهزة في الشبكة', 'th.device': 'الجهاز', 'th.conn': 'الاتصال', 'th.dl': '↓ تم التنزيل', 'th.ul': '↑ تم الرفع',
      'cx.head': 'اتصال خارجي', 'cx.hint': 'رابط vless جاهز لبروكسيك. الصقه في v2rayN / v2rayNG / NekoBox — ستمر الحركة عبر هذا الخادم من أي مكان.', 'cx.addr': 'العنوان', 'cx.port': 'المنفذ', 'cx.uuid': 'UUID', 'cx.sni': 'SNI',
      'ru.partial': 'جزئي', 'ru.hint': 'توفر الموارد الروسية مباشرة من الخادم (بدون VPN). إذا كان القطاع يعمل — تفتح مواقع RU بدون بروكسي.', 'ru.ok': 'متاح', 'ru.bad': 'مشاكل', 'ru.med': 'الوسيط', 'ru.ts': 'تم التحقق',
      'ru.check-now': 'تحقق الآن', 'th.domain': 'النطاق', 'th.time': 'الوقت',
      'tgws.head': 'بروكسي WS لتليجرام', 'tgws.proc': 'العملية', 'tgws.secret': 'السر', 'tgws.restart': 'إعادة تشغيل TG-WS',
      'mj.head': 'الانضمام لشبكة mesh', 'mj.p': 'يمكن لبروكسيك أن يكون جزءاً من شبكة Aurora mesh الخاصة. يمنح ذلك الوصول إلى مواقع حصرية لأعضاء آخرين، وتجاوز الحجب تلقائياً وطرق احتياطية.',
      'mj.invite-ph': 'الصق رمز دعوة mesh (مثال: aurora-home-a1b2c3d4)', 'mj.join': 'اتصال', 'mj.st': 'حالة mesh', 'mj.name': 'اسم mesh', 'mj.role': 'الدور',
      'mj.nodes': 'العقد المتاحة', 'mj.ping': 'البنغ إلى المحور', 'mj.enc': 'التشفير', 'mj.what': 'ماذا يقدم mesh',
      'mj.leave': 'مغادرة mesh', 'mj.regen': 'تحديث الدعوة', 'mj.pol': 'سياسة المحور', 'mj.pol-hint': 'يتحكم خادم المحور في التبويبات التي يراها عملاء mesh. العملاء المتصلون بدعوة هذا الخادم يطبقون السياسة تلقائياً (تحديث كل 15 ثانية).',
      'mj.master': 'الخادم هو المحور ويتحكم في رؤية العملاء', 'mj.show-mesh': 'إظهار تبويب "شبكة mesh" للعملاء', 'mj.show-subs': 'إظهار تبويب "المتجر" للعملاء',
      'mt.hint': 'بروكسيك (في المركز) وعقد أعضاء mesh الآخرين. الاتصالات نشطة إذا مرت الحركة عبرها.',
      'mrt.hint': 'قواعد أي حركة تخرج للإنترنت عبر أي عقدة. الترتيب من الأعلى للأسفل.', 'th.what': 'ماذا', 'th.via': 'إلى أين', 'th.proto': 'البروتوكول',
      'sp.head': 'الخطط', 'sp.hint': 'مجموعة أساسية من وظائف البروكسي. ترقية بنقرة واحدة، تُطبق فوراً، دون فقدان الاتصالات.', 'sp.loading': 'جارٍ تحميل الخطط…', 'sp.comp': 'محتوى الخطة', 'th.func': 'الوظيفة', 'th.val': 'القيمة',
      'sf.instant': '+ تُفعّل فوراً',
      'sb.head': 'الدفع والتجديد', 'sb.hint': 'الخطة النشطة وصلاحيتها وسجل الدفعات. التجديد بنقرة واحدة.', 'sb.plan': 'الخطة الحالية', 'sb.until': 'صالحة حتى', 'sb.buy': 'تجديد / تغيير الخطة', 'sb.hist': 'سجل الدفعات',
      'th.date': 'التاريخ', 'th.desc': 'الوصف', 'th.sum': 'المبلغ',
      'upd.apply': 'تحديث الآن', 'upd.auto': 'تحديث تلقائي', 'upd.auto-hint': 'يتم التحديث من إصدارات GitHub. يُنزل الملف، يُتحقق منه، يُستبدل ذرياً — يعاد تشغيل البروكسي خلال ثوانٍ.',
      'upd.src': 'مصدر التحديث', 'th.param': 'المعامل', 'upd.repo': 'المستودع', 'upd.sig': 'التحقق من التوقيع', 'upd.rollback': 'تراجع عند الفشل',
      'upd.check-now': 'تحقق الآن', 'upd.stable': 'stable — المستقرة فقط', 'upd.rc': 'rc — مرشحو الإصدار', 'upd.nightly': 'nightly — بنى ليلية',
      'upd.mode-auto': 'التحديث التلقائي مفعل', 'upd.mode-notify': 'إشعار فقط', 'upd.mode-off': 'لا تتحقق',
      'ver.head': 'سجل الإصدارات',
      'set.head': 'معاملات الخادم', 'set.host': 'المضيف', 'set.port': 'منفذ Xray', 'set.ver': 'الإصدار', 'set.uptime': 'مدة التشغيل',
      'set.common': 'عام', 'set.mesh': 'Mesh', 'set.name-ph': 'اسم الخادم', 'set.meshid-ph': 'معرّف mesh', 'set.copy-invite': 'نسخ الدعوة',
      'sec.hint': 'رمز لوحة الإدارة ومفاتيح Reality الخارجية. يغيّر الإعداد الحي.', 'sec.panel': 'اللوحة', 'sec.tok-ph': 'رمز المسؤول (Bearer) — مطلوب لـ POST /api/*', 'sec.acc-v': 'الوصول', 'sec.pbk-ph': 'المفتاح العام', 'sec.rotate': 'تدوير المفاتيح',
      'log.head': 'سجل النظام', 'log.loading': 'جارٍ التحميل…', 'log.refresh': 'تحديث', 'log.download': 'تنزيل', 'rclog.head': 'سجل الاسترداد',
      'th.node': 'العقدة', 'th.region': 'المنطقة', 'th.route': 'المسار', 'sec.tok': 'رمز المسؤول', 'sec.reality': 'Reality',
      'theme.sun': '🌙', 'theme.moon': '☀️'
    },
    hi: {
      'pol.head': 'सेवा नीति', 'pol.readOnly': 'देखें', 'pol.accept': 'मैं शर्तें स्वीकार करता हूँ', 'ru.regions': 'सेगमेंट', 'ru.custom-ph': 'कस्टम डोमेन, अल्पविराम से अलग (वैकल्पिक)',
      'dash.manage': 'प्रबंधन', 'pool.refresh-btn': 'कुंजियाँ अपडेट करें', 'pool.check-btn': 'कुंजियाँ जाँचें', 'mesh.ping-btn': 'मेश पिंग',
      'nav.dash': 'डैशबोर्ड', 'nav.keys': 'कुंजियाँ', 'nav.devices': 'डिवाइस',
      'nav.connect': 'बाहरी पहुँच', 'nav.rusegment': 'RU सेगमेंट', 'nav.tgws': 'TG-WS',
      'nav.mesh': 'मेश नेटवर्क', 'nav.mesh-join': 'कनेक्ट', 'nav.mesh-topo': 'टोपोलॉजी', 'nav.mesh-routes': 'रूट',
      'nav.shop': 'दुकान', 'nav.shop-plans': 'योजनाएँ', 'nav.shop-features': 'सुविधाएँ', 'nav.shop-billing': 'भुगतान',
      'nav.update': 'अपडेट', 'nav.versions': 'संस्करण', 'nav.settings': 'सर्वर', 'nav.security': 'सुरक्षा', 'nav.logs': 'लॉग',
      'nav.group.home': 'घरेलू प्रॉक्सी', 'nav.group.upd': 'अपडेट', 'nav.group.set': 'सेटिंग्स',
      'g.you': 'आप', 'g.yours': 'आपका', 'status.on': 'ऑनलाइन', 'status.off': 'ऑफ़लाइन', 'status.warn': 'अस्थिर',
      'status.online': 'चालू', 'status.stopped': 'रोका गया', 'status.active': 'सक्रिय', 'status.dead': 'मृत',
      'status.bad': 'खराब', 'status.slow': 'धीमा', 'status.noip': 'noip', 'status.ok': 'ठीक', 'status.final': 'अंतिम',
      'status.direct': 'सीधा', 'status.enabled': 'सक्षम', 'status.disabled': 'अक्षम',
      'btn.vpn-off': '🌀 VPN चालू करें', 'btn.vpn-on': '🌀 VPN चालू', 'btn.rotate': '🎲 कुंजी बदलें', 'btn.choose': '💎 चुनें',
      'btn.copy': '📋 कॉपी', 'btn.save': 'सहेजें', 'btn.login': '🔑 लॉगिन', 'btn.logout': 'लॉगआउट',
      'k.keys': 'कुंजियाँ: ', 'k.empty': 'अभी कोई कुंजी नहीं', 'k.mine': 'मेरी', 'k.github': 'github',
      'k.add-ok': 'कुंजी जोड़ी गई 🐾', 'k.add-err': 'जोड़ना विफल', 'k.need-vless': 'vless:// लिंक आवश्यक है',
      'k.active-ok': 'सक्रिय 🐾', 'k.active-err': 'सक्रिय नहीं कर सके', 'k.clean-ok': 'मृत कुंजियाँ हटाई गईं 🐾',
      'k.set-active': 'सक्रिय करें',
      'd.empty': 'अभी कोई डिवाइस नहीं',
      'c.on': 'सक्षम', 'c.off': 'अक्षम', 'c.server': 'सर्वर', 'c.qr-na': 'QR उपलब्ध नहीं', 'c.qr-na-off': 'QR ऑफ़लाइन उपलब्ध नहीं',
      'c.secret-hint': 'गुप्त कुंजियाँ केवल स्थानीय रूप से दिखती हैं। सक्षम होने पर पैनल X-Auth टोकन दें।',
      'ru.empty': 'जाँच अभी नहीं हुई', 'ru.avail': 'उपलब्ध', 'ru.unavail': 'अनुपलब्ध', 'ru.all': 'सभी डोमेन उपलब्ध ✅',
      'upd.avail': 'उपलब्ध', 'upd.cur': 'नवीनतम', 'upd.msg-avail': 'अपडेट उपलब्ध', 'upd.msg-cur': 'नवीनतम संस्करण स्थापित',
      'upd.checked': 'जाँचा गया: ',
      'w.mesh-nodes': 'मेश नोड:', 'w.mesh-exit': 'निकास', 'w.hub': 'हब', 'w.mesh-none': 'मेश कनेक्ट नहीं। निमंत्रण «कनेक्ट» टैब में है।',
      'w.plan': 'सक्रिय योजना:', 'w.ru': 'RU डोमेन:', 'w.ru-ok': 'उपलब्ध',
      'mesh.connected': 'कनेक्टेड', 'mesh.not': 'कनेक्ट नहीं', 'mesh.member': 'सदस्य', 'mesh.hub': 'हब',
      'mesh.no-nodes': 'कोई नोड नहीं — पहला जोड़ें', 'mesh.node': 'नोड',
      'routes.empty': 'अभी कोई रूट नहीं', 'routes.active': 'सक्रिय', 'routes.off': 'बंद',
      'plans.na': 'इस बिल्ड में योजनाएँ उपलब्ध नहीं', 'plans.traffic': 'ट्रैफ़िक:', 'plans.devices': 'डिवाइस:', 'plans.keys': 'कुंजियाँ:',
      'plans.free': 'मुफ़्त', 'plans.per-mo': '/माह', 'plans.current': 'वर्तमान',
      'bill.empty': 'अभी कोई भुगतान नहीं',
      'sec.on': 'सक्षम', 'sec.off': 'अक्षम', 'sec.access': 'केवल LAN: ', 'sec.da': 'हाँ', 'sec.no': 'नहीं', 'sec.blk': 'ब्लॉक',
      'sec.rat': 'चालू', 'sec.rat-off': 'बंद',
      'log.empty': 'लॉग खाली है', 'rec.empty': 'कोई पुनर्प्राप्ति नहीं',
      't.err': 'सर्वर अनुपलब्ध', 't.err-gen': 'त्रुटि', 't.action-ok': 'हो गया 🐾',
      'inv.need': 'मेश निमंत्रण कोड चिपकाएँ', 'inv.bad': 'निमंत्रण aurora://invite नहीं लगता — कोड जाँचें',
      'inv.add-ok': 'नोड मेश में जोड़ा गया 🕸️', 'inv.add-err': 'कनेक्ट नहीं हो सका', 'inv.leave-none': 'डिस्कनेक्ट करने के लिए कोई नोड नहीं',
      'inv.leave-ok': 'नोड हटाए गए, मेश छोड़ा 🕸️', 'inv.leave-err': 'डिस्कनेक्ट त्रुटि', 'inv.regen-ok': 'निमंत्रण नवीनीकृत 🔄',
      'inv.regen-err': 'विफल', 'inv.copy-ok': 'निमंत्रण कॉपी किया 🔗', 'inv.empty': 'निमंत्रण अभी उपलब्ध नहीं',
      'inv.topology': 'टोपोलॉजी अपडेट हुई 🕸️',
      'set.saved': 'सेटिंग्स सहेजी गईं 🐾', 'set.save-err': 'सहेजने में त्रुटि',
      'sec.need-token': 'टोकन दर्ज करें', 'sec.accept': 'टोकन स्वीकृत, पैनल अनलॉक 🛡️', 'sec.reject': 'टोकन अस्वीकृत (401)',
      'sec.logout': 'लॉगआउट हो गया', 'sec.rotate-ok': 'Reality कुंजियाँ रोटेट हुईं 🔄', 'sec.rotate-na': 'इस बिल्ड में रोटेशन उपलब्ध नहीं',
      'upd.run-ok': 'जाँच शुरू (पृष्ठभूमि)', 'upd.check-err': 'जाँच त्रुटि', 'upd.apply-ok': 'अपडेट शुरू ⬆️',
      'upd.apply-err': 'शुरू नहीं हो सका', 'upd.admin': 'अपडेट चैनल एडमिन पैनल में प्रबंधित होता है 🐾',
      'plans.admin': 'योजनाएँ एडमिन पैनल में प्रबंधित होती हैं 🐾', 'plans.buy': 'योजना «', 'plans.buy2': '» — खरीद एडमिन पैनल में 🐾',
      'feat.admin': 'इस बिल्ड में दुकान उपलब्ध नहीं 🐾', 'feat.buy': 'सुविधा «', 'feat.buy2': '» — सार्वजनिक बिल्ड में शोकेस 🐾',
      'vpn.on': 'VPN चालू 🌀', 'vpn.off': 'VPN बंद', 'vpn.err': 'त्रुटि', 'rot.ok': 'कुंजी रोटेट हुई 🎲', 'rot.err': 'रोटेट नहीं हो सकी',
      'pool.refresh': 'पूल अपडेट हुआ 🔄', 'pool.check': 'पृष्ठभूमि में कुंजी जाँच 🧪', 'mesh.ping': 'मेश पिंग शुरू 📡',
      'mesh.policy-saved': 'हब नीति सहेजी गई 🎛',
      'copy.link-ok': 'लिंक कॉपी किया 📋', 'copy.link-na': 'लिंक अभी उपलब्ध नहीं', 'ru.done': 'जाँच पूर्ण 🇷🇺',
      'ru.run': 'जाँच शुरू', 'ru.failonly': '💀 केवल समस्याएँ', 'ru.failonly-on': '💀 केवल समस्याएँ ✓',
      'tg.restarted': 'TG-WS पुनः आरंभ ✈️', 'tg.restart-err': 'पुनः आरंभ त्रुटि',
      'fmt.kb': 'KB', 'fmt.mb': 'MB', 'fmt.gb': 'GB', 'fmt.ul': 'असीमित', 'fmt.per-mo': '/माह',
      'fmt.s': ' से', 'fmt.min': ' मिनट', 'fmt.h': ' घंटे', 'fmt.d': ' दिन',
      'dash.mode': 'मोड', 'dash.ip': 'एग्ज़िट IP', 'dash.conns': 'कनेक्शन', 'dash.traffic': 'ट्रैफ़िक ↓ / ↑', 'dash.mesh-nodes': 'Mesh नोड', 'dash.plan': 'प्लान',
      'upd.details': 'विवरण', 'upd.now': 'अपडेट', 'w.proxy': 'प्रॉक्सी स्थिति', 'w.check-ru': 'जाँचें',
      'keys.uri-ph': 'vless://… अपना लिंक पेस्ट करें (Reality)', 'keys.add': 'अपनी कुंजी', 'keys.clean': 'मृत हटाएँ', 'keys.src': 'github + अपनी',
      'th.tag': 'टैग', 'th.source': 'स्रोत', 'th.status': 'स्थिति', 'th.ping': 'Ping', 'th.exit': 'एग्ज़िट IP', 'th.sites': 'Sites',
      'dev.head': 'नेटवर्क में डिवाइस', 'th.device': 'डिवाइस', 'th.conn': 'Conn', 'th.dl': '↓ डाउनलोड', 'th.ul': '↑ अपलोड',
      'cx.head': 'बाहरी कनेक्शन', 'cx.hint': 'आपके प्रॉक्सी के लिए तैयार vless-लिंक। इसे v2rayN / v2rayNG / NekoBox में पेस्ट करें — ट्रैफ़िक कहीं से भी इस सर्वर से होकर जाएगा।', 'cx.addr': 'पता', 'cx.port': 'पोर्ट', 'cx.uuid': 'UUID', 'cx.sni': 'SNI',
      'ru.partial': 'आंशिक', 'ru.hint': 'रूसी संसाधनों की सीधी उपलब्धता सर्वर से (VPN के बिना)। यदि सेगमेंट काम करता है — RU साइटें प्रॉक्सी के बिना खुलती हैं।', 'ru.ok': 'उपलब्ध', 'ru.bad': 'समस्याएँ', 'ru.med': 'माध्य', 'ru.ts': 'जाँचा गया',
      'ru.check-now': 'अभी जाँचें', 'th.domain': 'डोमेन', 'th.time': 'समय',
      'tgws.head': 'Telegram WS-प्रॉक्सी', 'tgws.proc': 'प्रक्रिया', 'tgws.secret': 'गुप्त', 'tgws.restart': 'TG-WS पुनः आरंभ',
      'mj.head': 'Mesh नेटवर्क से जुड़ें', 'mj.p': 'आपका प्रॉक्सी निजी Aurora mesh नेटवर्क का हिस्सा हो सकता है। यह अन्य सदस्यों के विशेष स्थानों, स्वचालित ब्लॉक-बायपास और बैकअप रूट्स तक पहुँच देता है।',
      'mj.invite-ph': 'Mesh इन्वाइट कोड पेस्ट करें (जैसे: aurora-home-a1b2c3d4)', 'mj.join': 'कनेक्ट', 'mj.st': 'Mesh स्थिति', 'mj.name': 'Mesh नाम', 'mj.role': 'भूमिका',
      'mj.nodes': 'उपलब्ध नोड', 'mj.ping': 'हब तक ping', 'mj.enc': 'एन्क्रिप्शन', 'mj.what': 'Mesh क्या देता है',
      'mj.leave': 'Mesh छोड़ें', 'mj.regen': 'इन्वाइट अपडेट', 'mj.pol': 'हब नीति', 'mj.pol-hint': 'हब सर्वर नियंत्रित करता है कि mesh क्लाइंट कौन-से टैब देखते हैं। इस सर्वर के इन्वाइट से जुड़े क्लाइंट स्वचालित रूप से नीति लागू करते हैं (हर 15 सेकंड अपडेट)।',
      'mj.master': 'सर्वर हब है, क्लाइंट की दृश्यता नियंत्रित करता है', 'mj.show-mesh': 'क्लाइंट्स को “Mesh नेटवर्क” टैब दिखाएँ', 'mj.show-subs': 'क्लाइंट्स को “स्टोर” टैब दिखाएँ',
      'mt.hint': 'आपका प्रॉक्सी (केंद्र में) और अन्य mesh सदस्यों के नोड। कनेक्शन सक्रिय हैं यदि ट्रैफ़िक उनसे होकर जाता है।',
      'mrt.hint': 'नियम कि कौन-सा ट्रैफ़िक किस नोड से इंटरनेट जाता है। क्रम ऊपर से नीचे।', 'th.what': 'क्या', 'th.via': 'कहाँ', 'th.proto': 'प्रोटोकॉल',
      'sp.head': 'प्लान', 'sp.hint': 'प्रॉक्सी सुविधाओं का मूल सेट। एक क्लिक में अपग्रेड, तुरंत लागू, कनेक्शन बिना खोए।', 'sp.loading': 'प्लान लोड हो रहे…', 'sp.comp': 'प्लान सामग्री', 'th.func': 'सुविधा', 'th.val': 'मान',
      'sf.instant': '+ तुरंत सक्रिय होते हैं',
      'sb.head': 'भुगतान और नवीनीकरण', 'sb.hint': 'सक्रिय प्लान, अवधि और भुगतान इतिहास। एक क्लिक में नवीनीकरण।', 'sb.plan': 'वर्तमान प्लान', 'sb.until': 'मान्य तक', 'sb.buy': 'नवीनीकरण / प्लान बदलें', 'sb.hist': 'भुगतान इतिहास',
      'th.date': 'दिनांक', 'th.desc': 'विवरण', 'th.sum': 'राशि',
      'upd.apply': 'अभी अपडेट करें', 'upd.auto': 'ऑटो-अपडेट', 'upd.auto-hint': 'अपडेट GitHub रिलीज़ से होता है। बाइनरी डाउनलोड, सत्यापित, परमाणु रूप से बदली जाती है — प्रॉक्सी कुछ सेकंड में पुनः आरंभ हो जाता है।',
      'upd.src': 'अपडेट स्रोत', 'th.param': 'पैरामीटर', 'upd.repo': 'रिपॉज़िटरी', 'upd.sig': 'हस्ताक्षर जाँच', 'upd.rollback': 'विफलता पर रोलबैक',
      'upd.check-now': 'अभी जाँचें', 'upd.stable': 'stable — केवल स्थिर', 'upd.rc': 'rc — रिलीज़ उम्मीदवार', 'upd.nightly': 'nightly — रात्रि बिल्ड',
      'upd.mode-auto': 'ऑटो-अपडेट चालू', 'upd.mode-notify': 'केवल सूचित करें', 'upd.mode-off': 'जाँच न करें',
      'ver.head': 'संस्करण इतिहास',
      'set.head': 'सर्वर पैरामीटर', 'set.host': 'होस्ट', 'set.port': 'Xray पोर्ट', 'set.ver': 'संस्करण', 'set.uptime': 'अपटाइम',
      'set.common': 'सामान्य', 'set.mesh': 'Mesh', 'set.name-ph': 'सर्वर नाम', 'set.meshid-ph': 'Mesh ID', 'set.copy-invite': 'इन्वाइट कॉपी',
      'sec.hint': 'पैनल admin टोकन और बाहरी Reality कुंजियाँ। लाइव कॉन्फ़िग बदलता है।', 'sec.panel': 'पैनल', 'sec.tok-ph': 'Admin टोकन (Bearer) — POST /api/* के लिए आवश्यक', 'sec.acc-v': 'पहुँच', 'sec.pbk-ph': 'सार्वजनिक कुंजी', 'sec.rotate': 'कुंजी रोटेट',
      'log.head': 'सिस्टम लॉग', 'log.loading': 'लोड हो रहा…', 'log.refresh': 'रिफ़्रेश', 'log.download': 'डाउनलोड', 'rclog.head': 'रिकवरी जर्नल',
      'th.node': 'नोड', 'th.region': 'क्षेत्र', 'th.route': 'रूट', 'sec.tok': 'Admin टोकन', 'sec.reality': 'Reality',
      'theme.sun': '🌙', 'theme.moon': '☀️'
    }
  };
  function langNow() {
    var l = 'ru';
    try { l = localStorage.getItem(LS.lang) || 'ru'; } catch (e) { }
    return (I18N[l] ? l : 'ru');
  }
  function _t(k) {
    var dict = I18N[langNow()];
    if (dict && dict[k] !== undefined) return dict[k];
    return (I18N.ru[k] !== undefined) ? I18N.ru[k] : k;
  }
  function applyLang() {
    var l = langNow();
    var el = $('lang-sel');
    if (el) el.value = l;
    document.documentElement.setAttribute('dir', (l === 'ar') ? 'rtl' : 'ltr');
    Array.prototype.forEach.call(document.querySelectorAll('[data-i18n]'), function (n) {
      n.textContent = _t(n.getAttribute('data-i18n'));
    });
    Array.prototype.forEach.call(document.querySelectorAll('[data-i18n-placeholder]'), function (n) {
      n.placeholder = _t(n.getAttribute('data-i18n-placeholder'));
    });
    initTabMeta();
    renderAll(V.S || {});
    var theme = document.documentElement.getAttribute('data-theme');
    $('theme-btn').textContent = (theme === 'dark' ? _t('theme.sun') : _t('theme.moon'));
  }
  function setLang(l) {
    if (!I18N[l]) l = 'ru';
    try { localStorage.setItem(LS.lang, l); } catch (e) { }
    applyLang();
  }

  function $(id) { return document.getElementById(id); }
  function _ruOk(r) { return !!r && (r.ok === true || (r.code && r.code > 0)); }
  function esc(s) {
    return (s == null ? '' : String(s)).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function fmtB(n) {
    if (n == null || isNaN(n)) return '0';
    n = +n;
    if (n < 1024) return n + ' Б';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' КБ';
    if (n < 1073741824) return (n / 1048576).toFixed(1) + ' МБ';
    return (n / 1073741824).toFixed(2) + ' ГБ';
  }
  function fmtNum(n) { return (n == null || isNaN(n)) ? '–' : String(n); }
  function fmtTs(s) {
    if (s == null || !s) return '–';
    s = +s;
    if (s < 60) return Math.round(s) + ' с';
    if (s < 3600) return Math.floor(s / 60) + ' мин';
    if (s < 86400) return Math.floor(s / 3600) + ' ч';
    return Math.floor(s / 86400) + ' д';
  }
  function fmtDate(ts) {
    if (!ts) return '–';
    var d = new Date(+ts * 1000), p = function (x) { return x < 10 ? '0' + x : '' + x; };
    return d.getDate() + '.' + p(d.getMonth() + 1) + '.' + d.getFullYear() + ' ' + p(d.getHours()) + ':' + p(d.getMinutes());
  }
  function bytesPlan(n) { return (n == null || n <= 0) ? 'Безлимит' : fmtB(n) + '/мес'; }
  function median(arr) {
    var a = (arr || []).filter(function (x) { return x != null && x > 0; }).map(Number).sort(function (a, b) { return a - b; });
    if (!a.length) return null;
    var m = Math.floor(a.length / 2);
    return a.length % 2 ? a[m] : Math.round((a[m - 1] + a[m]) / 2);
  }
  function toast(msg, ok) {
    var t = $('toast');
    if (!t) return;
    t.textContent = msg;
    t.className = 'show' + (ok ? '' : ' err');
    clearTimeout(t._tm);
    t._tm = setTimeout(function () { t.className = ''; }, 2500);
  }
  function secTok() { return localStorage.getItem(LS.sec) || ''; }
  function authHdr() {
    var h = { 'Content-Type': 'application/json', 'X-Aurora-Request': '1' };
    var p = sessionStorage.getItem('aurora_token') || '';
    if (p) h['X-Auth'] = p;
    var t = secTok();
    if (t) h['Authorization'] = 'Bearer ' + t;
    var f = sessionStorage.getItem(LS.tfa) || '';
    if (f) h['X-2FA'] = f;
    return h;
  }
  function getJSON(url) {
    return fetch(url, { cache: 'no-store', headers: authHdr() }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) {
        if (!r.ok && !j.error) j.error = 'HTTP_' + r.status;
        return j;
      });
    }).catch(function () { return { error: 'network' }; });
  }
  function postJSON(url, data) {
    var body = data ? JSON.stringify(data) : '';
    return fetch(url, { method: 'POST', headers: authHdr(), body: body })
      .then(function (r) {
        return r.json().catch(function () { return {}; }).then(function (j) {
          if (!r.ok) {
            j = j && typeof j === 'object' ? j : {};
            j.ok = false;
            j.error = j.error || ('HTTP ' + r.status);
          }
          return j;
        });
      })
      .catch(function () { return { ok: false, error: 'network error' }; });
  }

  /* ================= STATE ================= */
  function loadState(soft) {
    getJSON('/api/state').then(function (j) {
      V.S = j || {};
      renderAll(soft);
      if (j.setup_complete === false) setupShow();
    }).catch(function () { if (!soft) toast('Сервер недоступен', false); });
  }

  function renderAll(soft) {
    var S = V.S || {};
    if (!Object.keys(S).length) return;
    applyFlags(S);
    renderHero(S);
    renderPills();
    renderKeys(S);
    renderDevices(S);
    renderConnect(S);
    renderRu(S);
    renderRegions(S);
    renderPolicy(S);
    renderUpdateDash(S);
    renderWidgets(S);
    renderMeshPolicy(S);
  }

  function renderHero(S) {
    var nm = (S.server_name && S.server_name !== '-') ? S.server_name : 'Aurora';
    $('hero-title').textContent = nm;
    $('hero-sub').textContent = 'v' + (S.version || '—') + ' · ' + (S.version_name || '');
    var on = !!S.vpn_mode;
    $('hero-badge').textContent = on ? 'VPN' : 'DIRECT';
    $('hero-badge').className = 'badge ' + (on ? 'on' : 'off');
    $('btn-vpn').textContent = on ? _t('btn.vpn-on') : _t('btn.vpn-off');
    var commState = S.comm && S.comm.state ? String(S.comm.state) : '';
    $('btn-vpn').disabled = commState === 'syncing' || commState === 'loading' || commState === 'running';
    $('mode').textContent = S.mesh_nodes ? (on ? 'VPN + mesh' : 'Direct') : (on ? 'VPN' : 'Direct');
    $('egress').textContent = (S.egress_ip && S.egress_ip !== '-') ? S.egress_ip : '–';
    $('conns').textContent = S.conns != null ? fmtNum(S.conns) : '–';
    $('traffic').textContent = (S.up != null || S.traffic_up != null) ? fmtB(S.down || S.traffic_down || 0) + ' / ' + fmtB(S.up || S.traffic_up || 0) : '–';
    $('mesh-count').textContent = S.mesh_nodes != null ? fmtNum(S.mesh_nodes) : '0';
    $('side-version').textContent = 'v' + (S.version || '—');
  }

  function renderPills() {
    var S = V.S || {};
    var vpn = $('pill-vpn');
    vpn.className = 'pill ' + (S.vpn_mode ? 'on' : 'off') + ' hide-sm';
    $('pill-vpn-t').textContent = S.vpn_mode ? 'VPN' : 'DIRECT';
    $('pill-mesh').style.display = (S.show_mesh === false) ? 'none' : '';
    $('pill-plan').style.display = (S.show_subs === false) ? 'none' : '';
    if (V.SUBS && V.SUBS.plans && V.SUBS.default) {
      $('pill-plan').textContent = '💎 ' + V.SUBS.default;
    }
  }

  /* ================= KEYS ================= */
  function renderKeys(S) {
    var rows = $('keyrows');
    if (!rows) return;
    var ks = S.keys || [];
    $('keyinfo').textContent = _t('k.keys') + ks.length;
    if (!ks.length) { rows.innerHTML = '<tr><td colspan="7"><div class="empty"><span class="ic">🔑</span>' + _t('k.empty') + '</div></td></tr>'; return; }
    var h = '';
    ks.forEach(function (k) {
      var stCls = 'st-dim', stTxt = '—';
      if (k.is_active) { stCls = 'st-act'; stTxt = _t('status.active'); }
      else if (k.dead) { stCls = 'st-dead'; stTxt = _t('status.dead'); }
      else if (k.status === 'bad') { stCls = 'st-dead'; stTxt = _t('status.bad'); }
      else if (k.status === 'noip') { stCls = 'st-dim'; stTxt = _t('status.noip'); }
      else if (k.status === 'slow') { stCls = 'st-slow'; stTxt = _t('status.slow'); }
      else if (k.status === 'ok') { stCls = 'st-ok'; stTxt = _t('status.ok'); }
      var src = (k.source === 'my' || k.source === 'manual') ? '<span class="chip st-gold">' + _t('k.mine') + '</span>' : '<span class="chip st-dim">' + _t('k.github') + '</span>';
      var act = k.is_active ? ''
        : '<button class="btn small icon" data-act="key-activate" data-tag="' + esc(k.tag) + '" title="' + _t('k.set-active') + '">▶</button>';
      h += '<tr class="' + (k.is_active ? 'tr-active' : k.dead ? 'tr-dead' : '') + '">'
        + '<td class="mono">' + esc(k.tag) + '</td>'
        + '<td>' + src + '</td>'
        + '<td><span class="chip ' + stCls + '">' + stTxt + '</span></td>'
        + '<td class="mono">' + (k.ping_ms ? Math.round(k.ping_ms) + ' мс' : '–') + '</td>'
        + '<td class="mono">' + esc(k.exit_ip || '–') + '</td>'
        + '<td class="mono">' + (k.sites_ok != null ? fmtNum(k.sites_ok) : '–') + '</td>'
        + '<td style="text-align:right">' + act + '</td>'
        + '</tr>';
    });
    rows.innerHTML = h;
  }

  /* ================= DEVICES ================= */
  function renderDevices(S) {
    var rows = $('devrows');
    if (!rows) return;
    var dv = S.devices || {};
    var ds = (Array.isArray(dv) ? dv : Object.keys(dv).map(function (ip) { var d = dv[ip]; d.ip = ip; return d; }));
    if (!ds.length) { rows.innerHTML = '<tr><td colspan="5"><div class="empty"><span class="ic">📱</span>' + _t('d.empty') + '</div></td></tr>'; return; }
    var h = '';
    ds.forEach(function (d) {
      h += '<tr>'
        + '<td><span class="dot' + (d.on ? ' on' : '') + '"></span>' + esc(d.name || '—') + '</td>'
        + '<td class="mono">' + esc(d.ip || '–') + '</td>'
        + '<td class="mono">' + fmtNum(d.conns) + '</td>'
        + '<td class="mono">' + fmtB(d.download || 0) + '</td>'
        + '<td class="mono">' + fmtB(d.upload || 0) + '</td>'
        + '</tr>';
    });
    rows.innerHTML = h;
  }

  /* ================= CONNECT ================= */
  function renderConnect(S) {
    var x = S.vless_ext;
    var link = x && x.link ? x.link : null;
    var flag = $('cx-flag');
    if (!x) { $('cx-flag-wrap').innerHTML = ''; return; }
    flag.textContent = link ? _t('c.on') : _t('c.off');
    flag.className = 'badge ' + (link ? 'on' : 'off');
    $('cx-link').value = link || '';
    $('cx-host').textContent = x.host || (x.link ? '' : '–');
    $('cx-port').textContent = x.port != null ? x.port : '–';
    $('cx-uuid').textContent = x.uuid || '–';
    $('cx-sni').textContent = x.sni || '–';
    $('cx-hint-port').textContent = x.port != null ? x.port : '–';
    $('cx-hint-host').textContent = S.server_name || _t('c.server');
    var q = $('cx-qr');
    q.innerHTML = '';
    if (link) {
      if (typeof qrcode !== 'undefined') { var c = document.createElement('canvas'); c.width = 150; c.height = 150; q.appendChild(c); try { qrcode.toCanvas(c, link); } catch (e) { q.innerHTML = '<div class="qr-ph">' + _t('c.qr-na') + '</div>'; } }
      else { q.innerHTML = '<div class="qr-ph">' + _t('c.qr-na-off') + '</div>'; }
    } else {
      q.innerHTML = '<div class="qr-ph">' + _t('c.secret-hint') + '</div>';
    }
  }

  /* ================= RU SEGMENT ================= */
  function pullRu() {
    getJSON('/api/state').then(function (j) { if (j && j.rusegment) V.RU = j.rusegment; renderRu(j || {}); });
  }
  function renderRu(S) {
    var ru = (S && S.rusegment) || V.RU;
    var rows = $('rurows');
    if (!rows) return;
    var items = (ru && ru.results) || [];
    if (!items.length) {
      rows.innerHTML = '<tr><td colspan="5"><div class="empty"><span class="ic">🇷🇺</span>' + _t('ru.empty') + '</div></td></tr>';
      return;
    }
    var ok = 0, bad = 0, med = median(items.map(function (r) { return r.ms; }));
    items.forEach(function (r) { var o = _ruOk(r); if (o) ok++; else bad++; });
    $('ru-ok').textContent = ok + '/' + items.length;
    $('ru-bad').textContent = bad;
    $('ru-med').textContent = med != null ? med + ' мс' : '–';
    $('ru-ts').textContent = fmtDate(ru.ts);
    var h = '';
    items.forEach(function (r) {
      var o = _ruOk(r);
      if (CFG.ruFailOnly && o) return;
      var stCls = o ? 'st-ok' : 'st-dead';
      var stTxt = o ? _t('ru.avail') : _t('ru.unavail');
      h += '<tr>'
        + '<td>' + esc(r.host || r.domain || '–') + '</td>'
        + '<td class="mono">' + esc(r.ip || '–') + '</td>'
        + '<td class="mono">' + (r.code ? r.code : '–') + '</td>'
        + '<td class="mono">' + (r.ms != null ? Math.round(r.ms) + ' мс' : '–') + '</td>'
        + '<td><span class="chip ' + stCls + '">' + stTxt + '</span></td>'
        + '</tr>';
    });
    rows.innerHTML = h || '<tr><td colspan="5"><div class="empty">' + _t('ru.all') + '</div></td></tr>';
  }

  /* ================= POLICY + REGIONS ================= */
  function renderPolicy(S) {
    var t = $('policy-text');
    if (t) t.textContent = S.policy_text || '';
    var rev = $('policy-rev');
    if (rev) rev.textContent = 'rev ' + (S.policy_rev || 0);
    var need = !!(S.policy_rev && S.policy_rev > (S.policy_accepted_rev || 0));
    if (!$('policy-screen')) return;
    if (S.setup_complete === false) {
      $('policy-screen').style.display = 'none';
      return;
    }
    if (need && !CFG.policyOnce) {
      CFG.policyOnce = true;
      $('policy-screen').style.display = '';
    }
    var ab = $('policy-accept-btn');
    if (ab) ab.style.display = need ? '' : 'none';
  }
  function renderRegions(S) {
    var sel = $('rg-sel');
    if (!sel) return;
    var arr = (S.regions && S.regions.length) ? S.regions : [{ id: 'ru', flag: '🇷🇺', title: _t('nav.rusegment') }];
    var picked = S.segment_regions && S.segment_regions.length ? S.segment_regions : ['ru'];
    sel.innerHTML = arr.map(function (r) {
      return '<option value="' + esc(r.id) + '"' + (picked.indexOf(r.id) !== -1 ? ' selected' : '') + '>' + esc(r.flag + ' ' + r.title) + '</option>';
    }).join('');
    var title = S.segment_title || _t('nav.rusegment');
    var rg = $('rg-title');
    if (rg) rg.innerHTML = S.segment_flag ? (S.segment_flag + ' ' + esc(title)) : esc(title);
    var lb = document.querySelector('#nav button[data-t="rusegment"] .lb');
    if (lb && S.segment_title) lb.textContent = S.segment_title;
  }

  /* ================= UPDATE DASH ================= */
  function loadUpdate() {
    getJSON('/api/update/status').then(function (j) {
      j = j || {};
      V.UPD = j;
       var avail = j.update === true || (j.latest && j.current && j.latest !== j.current);
      $('du-cur').textContent = j.current || '—';
      $('du-new').textContent = j.latest || '—';
      $('du-msg').textContent = j.msg || '';
      $('dash-update').style.display = avail ? '' : 'none';
      $('side-upd').style.display = avail ? '' : 'none';
      $('upd-cur').textContent = j.current || '—';
      $('upd-new').textContent = j.latest || '—';
      $('upd-state-b').textContent = avail ? _t('upd.avail') : _t('upd.cur');
      $('upd-msg').textContent = j.msg || (avail ? _t('upd.msg-avail') : _t('upd.msg-cur'));
      $('upd-repo').textContent = j.repo || '–';
      $('upd-last').textContent = _t('upd.checked') + fmtDate(j.ts);
      var s = j.state || '';
      $('upd-state-b').className = 'badge gold';
    });
  }
  function renderUpdateDash() { loadUpdate(); }

  /* ================= VERSIONS ================= */
  function loadVersions() {
    getJSON('/api/versions').then(function (j) {
      j = j || {};
      V.VERS = j;
      var arr = j.versions || [];
      var box = $('ver-list');
      if (!box) return;
      box.innerHTML = arr.map(function (x) {
        return '<div class="ver-item" style="padding:10px 18px;border-bottom:1px solid var(--line);display:flex;gap:10px;align-items:center;font-size:13px">' +
          '<span class="badge">v' + esc(x.v || '') + '</span>' +
          '<b style="flex:1">' + esc(x.name || '') + '</b>' +
          '<span class="muted mono" style="font-size:12px">' + esc(x.date || '') + '</span></div>';
      }).join('') || '<div class="empty" style="padding:18px;color:var(--muted);font-size:13px">' + _t('log.empty') + '</div>';
    });
  }

  /* ================= WIDGETS ================= */
  function renderWidgets(S) {
    var s = V.MESH;
    if (s && s.nodes) {
      var on = s.nodes.filter(function (n) { return n.status === 'online' || n.on; }).length;
      $('w-mesh-st').textContent = s.nodes.length ? (on + '/' + s.nodes.length + ' ' + _t('status.online')) : '—';
      $('w-mesh-body').innerHTML = s.nodes.length ? (_t('w.mesh-nodes') + ' <b>' + s.nodes.length + '</b> · ' + _t('w.mesh-exit') + ' <b>' + esc(s.hub_name || (s.name || _t('w.hub'))) + '</b>') : _t('w.mesh-none');
      $('w-mesh-st').className = 'badge ' + (s.nodes.length ? 'on' : 'warn');
    }
    if (V.SUBS && V.SUBS.plans && V.SUBS.default) {
      $('plan-st').textContent = V.SUBS.default;
      $('plan-name').textContent = V.SUBS.default;
      $('w-plan-body').innerHTML = _t('w.plan') + ' <b>' + esc(V.SUBS.default) + '</b>'
        + (V.SUBS.expires ? ' · до ' + fmtDate(V.SUBS.expires) : '');
    }
    $('w-proxy-st').textContent = S.vpn_mode ? _t('status.online') : _t('status.direct');
    $('w-proxy-st').className = 'badge ' + (S.vpn_mode ? 'ok' : 'warn');
    $('w-key').textContent = S.vless_now || '—';
    $('w-exit').textContent = (S.egress_ip && S.egress_ip !== '-') ? S.egress_ip : '—';
    var ru = (S && S.rusegment) || V.RU;
    if (ru && ru.results && ru.results.length) {
      var ok = ru.results.filter(function (r) { return _ruOk(r); }).length;
      $('w-ru-st').textContent = ok + '/' + ru.results.length;
      $('w-ru-st').className = 'badge ' + (ok === ru.results.length ? 'ok' : 'warn');
      $('w-ru-body').innerHTML = _t('w.ru') + ' <b>' + ru.results.length + '</b>, ' + _t('w.ru-ok') + ' <b>' + ok + '</b>.';
    }
  }

  /* ================= MESH ================= */
  function loadMesh() {
    getJSON('/api/mesh').then(function (j) {
      if (!j) return;
      V.MESH = j;
      var nodes = V.MESH.nodes = V.MESH.nodes || [];
      var hub = nodes.filter(function (n) { return n.role === 'hub' || n.id === 'hub' || n.self; })[0];
      $('mesh-join-st').textContent = nodes.length ? _t('mesh.connected') : _t('mesh.not');
      $('mesh-join-st').className = 'badge ' + (nodes.length ? 'on' : 'warn');
      $('mesh-join-st').style.display = '';
      $('mi-name').textContent = esc((hub && (hub.name || hub.host)) || j.name || 'aurora');
      $('mi-role').textContent = hub && hub.role ? hub.role : (nodes.length ? _t('mesh.member') : '—');
      $('mi-nodes').textContent = fmtNum(nodes.length);
      $('mi-ping').textContent = hub && hub.ping_ms ? Math.round(hub.ping_ms) + ' мс' : '–';
      $('mi-enc').textContent = 'Reality';
      $('meshid').value = j.invite || '';
      $('mesh-topo-name').textContent = esc((hub && hub.name) || j.name || 'меш');
      renderMeshNodes(nodes, hub);
      renderMeshSvg(nodes, hub);
      renderWidgets(V.S || {});
    });
  }
  function renderMeshNodes(nodes, hub) {
    var rows = $('mesh-nodes');
    if (!rows) return;
    if (!nodes.length) { rows.innerHTML = '<tr><td colspan="5"><div class="empty"><span class="ic">🕸️</span>' + _t('mesh.no-nodes') + '</div></td></tr>'; return; }
    var h = '';
    nodes.forEach(function (n) {
      var on = n.status === 'online' || n.on;
      var stCls = on ? 'st-ok' : (n.status === 'warn' ? 'st-slow' : 'st-dim');
      var stTxt = on ? _t('status.on') : (n.status === 'warn' ? _t('status.warn') : _t('status.off'));
      h += '<tr>'
        + '<td><span class="dot' + (on ? ' on' : '') + '"></span>' + esc(n.name || n.id || '—') + ' <span class="chip st-act">' + esc(n.region || '—') + '</span></td>'
        + '<td class="mono">' + esc((n.role === 'hub' || n.id === 'hub') ? _t('mesh.hub') : '') + '</td>'
        + '<td><span class="chip ' + stCls + '">' + stTxt + '</span></td>'
        + '<td class="mono">' + (n.ping_ms ? Math.round(n.ping_ms) + ' мс' : '–') + '</td>'
        + '<td><button class="btn small ghost" data-act="nav" data-tab="mesh-routes">🧭</button></td>'
        + '</tr>';
    });
    rows.innerHTML = h;
  }
  function renderMeshSvg(nodes, hub) {
    var box = $('mesh-svg');
    if (!box) return;
    var svg = box.querySelector('svg');
    if (!svg) return;
    var cx = 400, cy = 170, R = 170;
    var others = nodes.filter(function (n) { return !(n.role === 'hub' || n.id === 'hub' || n.self); }).slice(0, 8);
    var h = '<path class="mesh-link yours" d="M' + cx + ',' + cy + ' L' + cx + ',' + (cy + 12) + '"/>';
    others.forEach(function (n, i) {
      var a = -Math.PI / 2 + (i / Math.max(others.length, 1)) * 2 * Math.PI;
      var x = cx + R * Math.cos(a), y = cy + R * Math.sin(a);
      var on = n.status === 'online' || n.on;
      h += '<path class="mesh-link' + (on ? ' active' : '') + '" d="M' + cx + ',' + cy + ' L' + x + ',' + y + '"/>';
      var col = on ? 'var(--ok)' : 'var(--bad)';
      var lbl = (n.name || n.id || _t('mesh.node')) + (n.region ? ' · ' + n.region : '');
      h += '<g class="mesh-node" data-label="' + esc(lbl) + '" color="' + col + '">'
        + '<circle cx="' + x.toFixed(1) + '" cy="' + y.toFixed(1) + '" r="13" fill="' + col + '"/>'
        + '<text x="' + x.toFixed(1) + '" y="' + (y + 26).toFixed(1) + '">' + esc(lbl.substr(0, 22)) + '</text></g>';
    });
    h += '<g class="mesh-node" color="var(--primary)">'
      + '<circle cx="' + cx + '" cy="' + cy + '" r="22" fill="var(--primary)" opacity=".15"/>'
      + '<circle cx="' + cx + '" cy="' + cy + '" r="14" fill="var(--primary)"/>'
      + '<text x="' + cx + '" y="' + (cy + 34) + '">🏠 ' + esc((hub && (hub.name || hub.host)) || _t('g.you')) + '</text></g>';
    svg.setAttribute('viewBox', '0 0 800 340');
    svg.innerHTML = h;
    Array.prototype.forEach.call(svg.querySelectorAll('.mesh-node[data-label]'), function (el) {
      el.addEventListener('click', function () {
        toast(el.getAttribute('data-label') || '', true);
      });
    });
  }

  /* ================= ROUTES ================= */
  function loadRoutes() {
    getJSON('/api/routes').then(function (j) {
      j = j || {};
      V.ROUTES = j;
      var rows = $('mesh-routes');
      if (!rows) return;
      var rr = j.rows || [];
      if (!rr.length) { rows.innerHTML = '<tr><td colspan="6"><div class="empty"><span class="ic">🧭</span>' + _t('routes.empty') + '</div></td></tr>'; return; }
      var h = '';
      rr.forEach(function (r, i) {
        var stCls = r.status === 'final' ? 'st-act' : (r.status === 'active' ? 'st-ok' : 'st-dim');
        var stTxt = r.status === 'final' ? _t('status.final') : (r.status === 'active' ? _t('routes.active') : _t('routes.off'));
        h += '<tr>'
          + '<td class="mono">#' + (i + 1) + '</td>'
          + '<td class="mono">' + esc(r.what || r.match || '—') + '</td>'
          + '<td class="mono">' + esc(r.target || r.tag || '—') + '</td>'
          + '<td class="mono">' + esc(r.inbound || '—') + '</td>'
          + '<td class="mono">' + esc(r.kind || '—') + '</td>'
          + '<td><span class="chip ' + stCls + '">' + stTxt + '</span></td>'
          + '</tr>';
      });
      rows.innerHTML = h;
    });
  }

  /* ================= SUBS / SHOP ================= */
  function loadSubs() {
    getJSON('/api/subs/list').then(function (j) {
      j = j || {};
      V.SUBS = j;
      renderPlans(j);
      renderBilling(j);
      renderPlanWidget(j);
      if (j.error) {
        V.STATS = { error: j.error };
        renderBilling(j);
        return;
      }
      getJSON('/api/stats').then(function (s) {
        V.STATS = s && !s.error ? s : { error: (s && s.error) || 'stats' };
        renderBilling(j);
        renderPlanWidget(j);
      });
      var d = document.querySelector('#subs-count');
      if (d && j.total !== undefined) d.textContent = j.total;
    });
  }
  function renderPlans(j) {
    var grid = $('plans-grid');
    var load = $('plans-loading');
    if (!grid) return;
    var pl = j.plans || {};
    var def = j.default || 'free';
    load.style.display = 'none';
    var ids = Object.keys(pl);
    if (!ids.length) {
      $('plans-loading').style.display = '';
      $('plans-loading').innerHTML = '<span class="empty"><span class="ic">💎</span>' + _t('plans.na') + '</span>';
      return;
    }
    var order = { free: 0, basic: 1, prem: 2, premium: 2 };
    ids.sort(function (a, b) { return (order[a] != null ? order[a] : 9) - (order[b] != null ? order[b] : 9); });
    var h = '';
    ids.forEach(function (id) {
      var p = pl[id] || {};
      var hot = id === 'prem' || id === 'premium' || p.hot;
      var cur = id === def;
      var feats = [];
      if (p.bytes !== undefined) feats.push({ t: _t('plans.traffic') + bytesPlan(p.bytes), no: false });
      if (p.devices) feats.push({ t: _t('plans.devices') + p.devices, no: false });
      if (p.keys) feats.push({ t: _t('plans.keys') + p.keys, no: false });
      (p.features || []).forEach(function (f) { feats.push({ t: f, no: false }); });
      (p.features_no || []).forEach(function (f) { feats.push({ t: f, no: true }); });
      var priceTxt = p.price != null ? (p.price === 0 ? _t('plans.free') : +p.price + ' ₽') : '—';
      h += '<div class="plan' + (hot ? ' hot' : '') + (cur ? ' current' : '') + '">'
        + '<h3>' + esc(p.name || id) + (cur ? ' <span class="chip st-act">' + _t('plans.current') + '</span>' : '') + '</h3>'
        + '<div class="price">' + priceTxt + '<small>' + _t('plans.per-mo') + '</small></div>'
        + '<ul>' + feats.map(function (f) { return '<li' + (f.no ? ' class="no"' : '') + '>' + esc(f.t) + '</li>'; }).join('') + '</ul>'
        + '<button class="btn' + (hot ? ' gold' : '') + '" data-act="plan-buy" data-plan-id="' + esc(id) + '">' + _t('btn.choose') + '</button>'
        + '</div>';
    });
    grid.innerHTML = h;
  }
  function renderPlanWidget(j) {
    var cur = j.default || 'free';
    if (j.plans) { $('plan-st').textContent = cur; var pn = (j.plans[cur] || {}).name || cur; $('plan-name').textContent = pn; $('pill-plan').textContent = '💎 ' + cur; }
    var active = (j.subs || []).find(function (s) { return s.access_ok === true || s.access_status === 'ok'; });
    $('w-plan-body').innerHTML = _t('w.plan') + ' <b>' + esc(active ? (active.plan || cur) : cur) + '</b>'
      + (active && active.expires ? ' · до ' + fmtDate(active.expires) : '');
  }
  function renderBilling(j) {
    var cur = j.default || 'free';
    var subs = j.subs || [];
    var active = subs.find(function (s) { return s.access_ok === true || s.access_status === 'ok'; });
    var stats = V.STATS && !V.STATS.error ? V.STATS : null;
    var payments = (stats && (Array.isArray(stats.payments) ? stats.payments : (Array.isArray(stats.recent_payments) ? stats.recent_payments : []))) || [];
    $('bill-plan').textContent = active ? (active.plan || cur) : cur;
    $('bill-until').textContent = active && active.expires ? fmtDate(active.expires) : '—';
    $('bill-traffic').textContent = (active && active.used_bytes != null)
      ? fmtB(active.used_bytes) + (active.limit_bytes ? ' / ' + fmtB(active.limit_bytes) : '')
      : (j.used_bytes != null ? fmtB(j.used_bytes) : '—');
    $('bill-active').textContent = stats && stats.active != null ? String(stats.active) : String(subs.filter(function (s) { return s.access_ok === true || s.access_status === 'ok'; }).length);
    $('bill-income').textContent = stats && stats.income_month != null ? fmtNum(stats.income_month) + ' ₽' : '—';
    $('bill-traffic-month').textContent = stats && stats.traffic_month != null ? fmtB(stats.traffic_month) : '—';
    var rows = $('bill-rows');
    if (!rows) return;
    if (!payments.length) { rows.innerHTML = '<tr><td colspan="4"><div class="empty"><span class="ic">💳</span>' + _t('bill.empty') + '</div></td></tr>'; return; }
    rows.innerHTML = payments.map(function (p) {
      var date = p.paid_at || p.created_at || 0;
      var desc = p.plan_name || p.plan || p.name || '—';
      if (p.name && p.plan_name) desc += ' · ' + p.name;
      var amount = p.amount != null ? fmtNum(p.amount) + (p.currency ? ' ' + p.currency : '') : '—';
      var status = p.operation || p.state || 'paid';
      return '<tr>'
        + '<td class="mono">' + (date ? fmtDate(date) : '—') + '</td>'
        + '<td class="mono">' + esc(desc) + '</td>'
        + '<td class="mono">' + esc(amount) + '</td>'
        + '<td class="mono">' + esc(status) + '</td>'
        + '</tr>';
    }).join('');
  }

  /* ================= TGWS ================= */
  function loadTG() {
    getJSON('/api/tgws/status').then(function (j) {
      j = j || {};
      V.TG = j;
      $('tg-on').textContent = j.running ? _t('status.online') : _t('status.stopped');
      $('tg-on').className = 'badge ' + (j.running ? 'ok' : 'off');
      $('tg-port').textContent = j.port != null ? j.port : '–';
      $('tg-sec').textContent = j.secret_ok ? '✓' : '–';
      var q = $('tg-qr');
      q.innerHTML = '';
      if (j.link) {
        if (typeof qrcode !== 'undefined') { var c = document.createElement('canvas'); c.width = 150; c.height = 150; q.appendChild(c); try { qrcode.toCanvas(c, j.link); } catch (e) { q.innerHTML = '<div class="qr-ph">' + _t('c.qr-na') + '</div>'; } }
        else { q.innerHTML = '<div class="qr-ph">' + _t('c.qr-na-off') + '</div>'; }
      }
    });
  }

  /* ================= SETTINGS ================= */
  function loadSettings() {
    getJSON('/api/settings').then(function (j) {
      j = j || {};
      var s = j.settings || {};
      V.SET = s;
      $('set-host').textContent = s.host || (V.S ? V.S.server_name : '') || '–';
      $('set-port').textContent = (V.S && V.S.xray_port != null) ? V.S.xray_port : '–';
      $('set-ver').textContent = 'v' + (s.version || '—') + (s.version_name ? ' ' + s.version_name : '');
      $('set-up').textContent = fmtTs(s.uptime);
      var nm = (s.server_name && s.server_name !== '-') ? s.server_name : '';
      $('set-name').value = nm;
      var stMesh = $('set-st-mesh');
      if (stMesh) { stMesh.textContent = (s.show_mesh !== false) ? _t('sec.on') : _t('sec.off'); stMesh.className = 'chip ' + ((s.show_mesh !== false) ? 'st-ok' : 'st-dim'); }
      var stSubs = $('set-st-subs');
      if (stSubs) { stSubs.textContent = (s.show_subs !== false) ? _t('sec.on') : _t('sec.off'); stSubs.className = 'chip ' + ((s.show_subs !== false) ? 'st-ok' : 'st-dim'); }
    });
  }

  /* ================= SECURITY ================= */
  function loadSecurity() {
    getJSON('/api/security').then(function (j) {
      j = j || {};
      V.SEC = j;
       $('sec-en').textContent = j.enabled ? _t('sec.on') : _t('sec.off');
       $('sec-en').className = j.enabled ? 'ok' : 'bad';
       var tfa = $('sec-2fa');
       if (tfa) { tfa.textContent = j.twofa ? _t('sec.on') : _t('sec.off'); tfa.className = j.twofa ? 'ok' : 'bad'; }
       var a = j.access || {};
      $('sec-acc').textContent = _t('sec.access') + (a.lan_only ? _t('sec.da') : _t('sec.no')) + ' · сканеры: ' + (a.block_scanners ? _t('sec.blk') : _t('sec.no')) + ' · rate-limit: ' + (a.rate_limit ? _t('sec.rat') : _t('sec.rat-off'));
      $('sec-pbk').value = (j.pbk || '–') + (j.sid ? ' · sid=' + j.sid : '');
      var has = !!secTok();
      $('sec-token').value = has ? '' : $('sec-token').value;
      $('sec-logout').style.display = has ? '' : 'none';
     }).catch(function () {
       $('sec-en').textContent = '—';
       $('sec-acc').textContent = '—';
       $('sec-2fa').textContent = '—';
       $('sec-2fa').className = 'v mono';
     });
  }

  /* ================= LOGS ================= */
  function loadLog() {
    getJSON('/api/log').then(function (j) {
      j = j || {};
      var lines = j.lines || [];
      var box = $('log');
      box.innerHTML = lines.map(function (l) { return esc(l); }).join('\n') || _t('log.empty');
      box.scrollTop = box.scrollHeight;
      $('log-count').textContent = lines.length;
    });
    getJSON('/api/recovery/log').then(function (j) {
      j = j || {};
      var lines = j.lines || j.log || [];
      var box = $('rclog');
      box.innerHTML = lines.map(function (l) { return esc(l); }).join('\n') || _t('rec.empty');
      box.scrollTop = box.scrollHeight;
      $('rclog-count').textContent = lines.length;
    });
  }

  /* ================= NAV ================= */
  var TABS = {};
  var TB_META = {};
  function navTo(t) {
    CFG.tab = t;
    Array.prototype.forEach.call(document.querySelectorAll('.tab'), function (s) { s.classList.remove('show'); });
    var tab = $('t-' + t);
    if (tab) tab.classList.add('show');
    Array.prototype.forEach.call(document.querySelectorAll('#nav button'), function (b) {
      b.classList.toggle('on', b.getAttribute('data-t') === t);
    });
    var meta = TB_META[t] || { ic: '📊', lb: 'Обзор' };
    $('tb-icon').textContent = meta.ic;
    $('tb-name').textContent = meta.lb;
    var side = $('side');
    if (side && side.classList.contains('open')) side.classList.remove('open');
    loadTab(t);
  }
  function initTabMeta() {
    Array.prototype.forEach.call(document.querySelectorAll('#nav button[data-t]'), function (b) {
      var t = b.getAttribute('data-t');
      TB_META[t] = { ic: (b.querySelector('.ic') || {}).textContent || '', lb: (b.querySelector('.lb') || {}).textContent || t };
    });
  }
  function loadTab(t) {
    if (t === 'logs') loadLog();
    if (t === 'update' || t === 'versions') { loadUpdate(); if (t === 'versions') loadVersions(); }
    if (t.indexOf('mesh') === 0 || t === 'mesh-topo' || t === 'mesh-routes') { loadMesh(); if (t === 'mesh-routes') loadRoutes(); }
    if (t === 'shop-plans' || t === 'shop-billing') loadSubs();
    if (t === 'settings') loadSettings();
    if (t === 'security') loadSecurity();
    if (t === 'tgws') loadTG();
  }

  /* ================= ACTIONS (window globals) ================= */
  window.navTo = navTo;
  window.setLang = setLang;
  window.toast = toast;
  window.setActive = function (tag) {
    postJSON('/api/keys/active', { tag: tag }).then(function (j) {
      toast((j && j.ok) ? 'Ключ ' + tag + ' активен 🐾' : ((j && j.error) || 'Не удалось активировать'), !!(j && j.ok));
      loadState(true);
    });
  };
  window.keyAdd = function () {
    var v = ($('keyuri').value || '').trim();
    if (!/^vless:\/\//i.test(v)) { toast(_t('k.need-vless'), false); return; }
    postJSON('/api/keys/add', { uri: v }).then(function (j) {
      toast((j && j.ok) ? _t('k.add-ok') : ((j && j.error) || _t('k.add-err')), !!(j && j.ok));
      if (j && j.ok) { $('keyuri').value = ''; loadState(true); }
    });
  };
  window.keyClean = function () {
    postJSON('/api/keys/cleanup', {}).then(function (j) {
      toast((j && j.ok) ? _t('k.clean-ok') : ((j && j.error) || _t('t.err-gen')), !!(j && j.ok));
      loadState(true);
    });
  };
  window.cxCopy = function () {
    var l = $('cx-link').value;
    if (!l) { toast(_t('copy.link-na'), false); return; }
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(l).then(function () { toast(_t('copy.link-ok'), true); });
    else { l.select(); document.execCommand('copy'); toast(_t('copy.link-ok'), true); }
  };
  window.ruCheck = function () {
    postJSON('/api/rusegment/check', {}).then(function (j) {
      if (j && j.rows) V.RU = j;
      else V.RU = j;
      renderRu(V.S || {});
      toast((j && (j.ok || j.done)) ? _t('ru.done') : _t('ru.run'), true);
      setTimeout(function () { getJSON('/api/state').then(function (st) { if (st && st.rusegment) { V.RU = st.rusegment; renderRu(st); } }); }, 2500);
    });
  };
  window.ruToggleFail = function () {
    CFG.ruFailOnly = !CFG.ruFailOnly;
    var b = $('ru-failonly');
    b.classList.toggle('primary', CFG.ruFailOnly);
    b.textContent = CFG.ruFailOnly ? _t('ru.failonly-on') : _t('ru.failonly');
    renderRu(V.S || {});
  };
  window.policyShow = function (ro) {
    if (V.S && V.S.setup_complete === false) return;
    var s = $('policy-screen');
    if (!s) return;
    s.style.display = '';
    var ab = $('policy-accept-btn');
    if (!V.S || !(V.S.policy_rev > (V.S.policy_accepted_rev || 0))) {
      if (ab) ab.style.display = 'none';
    } else if (ab) {
      ab.style.display = '';
    }
  };
  window.policyAccept = function () {
    var S = V.S || {};
    postJSON('/api/policy/accept', { rev: (S.policy_rev || 0) }).then(function (j) {
      if (j && j.ok) {
        CFG.policyOnce = true;
        $('policy-screen').style.display = 'none';
        toast('OK 🐾', true);
        loadState(true);
      } else {
        toast((j && j.error) || _t('t.err-gen'), false);
      }
    });
  };
  window.regionsSave = function () {
    var sel = $('rg-sel');
    var picked = [];
    if (sel) Array.prototype.forEach.call(sel.options, function (o) { if (o.selected) picked.push(o.value); });
    postJSON('/api/rusegment/region', {
      regions: picked.length ? picked : ['ru'],
      custom: ($('rg-custom') && $('rg-custom').value || '').trim()
    }).then(function (j) {
      toast((j && j.ok) ? _t('set.saved') : ((j && j.error) || _t('set.save-err')), !!(j && j.ok));
      if (j && j.ok) loadState(true);
    });
  };
  window.tgRestart = function () {
    postJSON('/api/tgws/restart', {}).then(function (j) {
      toast((j && j.ok) ? _t('tg.restarted') : ((j && j.error) || _t('tg.restart-err')), !!(j && j.ok));
      setTimeout(loadTG, 1500);
    });
  };
  window.meshJoin = function () {
    var v = ($('mesh-invite').value || '').trim();
    if (!v) { toast(_t('inv.need'), false); return; }
    if (v.indexOf('aurora://invite?') !== 0) { toast(_t('inv.bad'), false); return; }
    postJSON('/api/mesh/join', { invite: v, name: '', region: '' }).then(function (j) {
      toast((j && j.ok) ? _t('inv.add-ok') : ((j && j.error) || _t('inv.add-err')), !!(j && j.ok));
      loadMesh(); loadState(true);
    });
  };
  window.meshLeave = function () {
    var nodes = (V.MESH && V.MESH.nodes) || [];
    var others = nodes.filter(function (n) { return !(n.role === 'hub' || n.id === 'hub' || n.self); });
    if (!others.length) { toast(_t('inv.leave-none'), false); return; }
    var done = 0, fail = 0;
    others.forEach(function (n) {
      postJSON('/api/mesh/node/remove', { id: n.id }).then(function (j) {
        if (j && j.ok) done++; else fail++;
        if (done + fail === others.length) {
          toast(done ? _t('inv.leave-ok') : _t('inv.leave-err'), !!done);
          loadMesh();
        }
      });
    });
  };
  window.meshRegen = function () {
    postJSON('/api/mesh/regenerate', {}).then(function (j) {
      toast((j && j.ok) ? _t('inv.regen-ok') : ((j && (j.error || j.invite)) ? 'Invite: ' + (j.invite || j.error) : _t('inv.regen-err')), !!j);
      loadMesh();
    });
  };
  window.meshRefresh = function () { loadMesh(); toast(_t('inv.topology'), true); };
  window.inviteCopy = function () {
    var v = $('meshid').value || (V.MESH && V.MESH.invite) || '';
    if (!v) { toast(_t('inv.empty'), false); return; }
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(v).then(function () { toast(_t('inv.copy-ok'), true); });
    else toast(_t('inv.copy-ok'), true);
  };
  window.settingsSave = function () {
    var nm = ($('set-name').value || '').trim();
    postJSON('/api/settings/save', { server_name: nm }).then(function (j) {
      toast((j && j.ok) ? _t('set.saved') : ((j && j.error) || _t('set.save-err')), !!(j && j.ok));
      loadState(true);
    });
  };
  window.secLogin = function () {
    var v = ($('sec-token').value || '').trim() || secTok();
    if (!v) { toast(_t('sec.need-token'), false); return; }
    var pin = ($('sec-pin').value || '').trim();
    if (pin) sessionStorage.setItem(LS.tfa, pin);
    else sessionStorage.removeItem(LS.tfa);
    localStorage.setItem(LS.sec, v);
    postJSON('/api/update/check', {}).then(function (j) {
      if (j && j.ok !== false) {
        toast(_t('sec.accept'), true);
        $('sec-token').value = '';
        $('sec-logout').style.display = '';
        loadSecurity();
      } else {
        localStorage.removeItem(LS.sec);
        sessionStorage.removeItem(LS.tfa);
        toast((j && j.error) || _t('sec.reject'), false);
      }
    });
  };
  window.secTwofaEnable = function () {
    var pin = ($('sec-pin').value || '').trim();
    if (!pin) { toast('Введите PIN 2FA', false); return; }
    if (!secTok()) { toast(_t('sec.need-token'), false); return; }
    postJSON('/api/security/twofa', { pin: pin }).then(function (j) {
      if (j && j.ok) {
        sessionStorage.setItem(LS.tfa, pin);
        $('sec-pin').value = '';
        toast((j.msg || '2FA включена'), true);
        loadSecurity();
      } else toast((j && j.error) || '2FA не включена', false);
    });
  };
  window.secTwofaDisable = function () {
    if (!secTok()) { toast(_t('sec.need-token'), false); return; }
    postJSON('/api/security/twofa', { pin: '' }).then(function (j) {
      if (j && j.ok) {
        sessionStorage.removeItem(LS.tfa);
        $('sec-pin').value = '';
        toast((j.msg || '2FA выключена'), true);
        loadSecurity();
      } else toast((j && j.error) || '2FA не выключена', false);
    });
  };
  window.secLogout = function () {
    localStorage.removeItem(LS.sec);
    sessionStorage.removeItem(LS.tfa);
    $('sec-logout').style.display = 'none';
    $('sec-2fa').textContent = '—';
    $('sec-2fa').className = 'v mono';
    toast(_t('sec.logout'), true);
  };
  window.secRotate = function () {
    postJSON('/api/security/vless/rotate', {}).then(function (j) {
      toast((j && j.ok) ? _t('sec.rotate-ok') : ((j && j.error) || _t('sec.rotate-na')), !!(j && j.ok));
      securityLoad();
    });
  };
  function securityLoad() { loadSecurity(); loadState(true); }
  window.loadLog = loadLog;
  window.checkUpdate = function () {
    postJSON('/api/update/check', {}).then(function (j) {
      toast((j && j.ok) ? _t('upd.run-ok') : ((j && j.error) || _t('upd.check-err')), !!(j && j.ok));
      setTimeout(loadUpdate, 2000);
    });
  };
  window.startUpdate = function () {
    postJSON('/api/update/apply', {}).then(function (j) {
      toast((j && j.ok) ? _t('upd.apply-ok') : ((j && j.error) || _t('upd.apply-err')), !!(j && j.ok));
      setTimeout(function () { getJSON('/api/update/status').then(loadUpdate); }, 2500);
    });
  };
  window.updSave = function () {
    toast(_t('upd.admin'), true);
  };
  window.buyPlan = function (id) {
    toast(id ? (_t('plans.buy') + id + _t('plans.buy2')) : _t('plans.admin'), true);
  };
  window.buyFeature = function (id) {
    toast(id ? (_t('feat.buy') + id + _t('feat.buy2')) : _t('feat.admin'), true);
  };

  var SETUP = { step: 0, values: {}, shown: false };
  function setupError(message) {
    var el = $('setup-error');
    if (!el) return;
    el.textContent = message || '';
    el.style.display = message ? '' : 'none';
  }
  function setupPort(key, value) {
    var base = (SETUP.prefill && SETUP.prefill[key]) || '';
    if (!value || value === base) return '';
    return Number(value);
  }

  function setupRead() {
    return {
      lang: $('setup-lang') ? $('setup-lang').value : 'ru',
      theme: $('setup-theme') ? $('setup-theme').value : '',
      policy_accepted: !!($('setup-policy-ok') && $('setup-policy-ok').checked),
      name: $('setup-name') ? $('setup-name').value.trim() : '',
      password: $('setup-password') ? $('setup-password').value : '',
      pin: $('setup-pin') ? $('setup-pin').value.trim() : '',
      lan_only: !!($('setup-lan') && $('setup-lan').checked),
      block_scanners: !!($('setup-scanners') && $('setup-scanners').checked),
      rate_limit: !!($('setup-rate') && $('setup-rate').checked),
      ui_port: $('setup-ui-port') ? $('setup-ui-port').value.trim() : '',
      xray_port: $('setup-xray-port') ? $('setup-xray-port').value.trim() : '',
      xray_api_port: $('setup-xray-api-port') ? $('setup-xray-api-port').value.trim() : '',
      tgws_port: $('setup-tgws-port') ? $('setup-tgws-port').value.trim() : '',
      mesh_invite: $('setup-mesh') ? $('setup-mesh').value.trim() : '',
      setup_token: $('setup-token') ? $('setup-token').value.trim() : ''
    };
  }

  function setupValidate(all) {
    var d = setupRead();
    if (all || SETUP.step === 0) {
      if (!$('setup-theme') || !d.theme) return 'Выберите тему';
      if (!d.policy_accepted) return 'Примите условия использования';
    }
    if ((all || SETUP.step === 1) && (!d.name || d.name.length > 80)) return 'Имя сервера: 1–80 символов';
    if ((all || SETUP.step === 2) && (d.password.length < 12 || d.password.length > 256 || /\s/.test(d.password))) return 'Пароль: 12–256 символов без пробелов';
    if ((all || SETUP.step === 3) && !/^[0-9]{6}$/.test(d.pin)) return 'PIN: 6 цифр';
    if (all || SETUP.step === 5) {
      var used = {};
      var fields = [
        ['ui_port', 'Панель'], ['xray_port', 'Xray'],
        ['xray_api_port', 'Xray API'], ['tgws_port', 'TG-WS']
      ];
      for (var i = 0; i < fields.length; i++) {
        var raw = d[fields[i][0]];
        if (raw === '') continue;
        var n = Number(raw);
        if (!isFinite(n) || Math.floor(n) !== n || n < 1 || n > 65535) return fields[i][1] + ': порт 1–65535';
        if (used[n]) return 'Порты должны различаться';
        used[n] = true;
      }
    }
    if (d.mesh_invite && d.mesh_invite.indexOf('aurora://invite?') !== 0) {
      return 'Invite: нужен формат aurora://invite?...';
    }
    return '';
  }

  function setupRender() {
    var step = SETUP.step;
    var pr = $('setup-progress');
    if (pr) pr.textContent = (step + 1) + '/7';
    Array.prototype.forEach.call(document.querySelectorAll('[data-setup-step]'), function (n) {
      n.style.display = Number(n.getAttribute('data-setup-step')) === step ? '' : 'none';
    });
    $('setup-back').style.display = step === 0 ? 'none' : '';
    var last = step === 6;
    $('setup-next').style.display = last ? 'none' : '';
    $('setup-finish').style.display = last ? '' : 'none';
  }

  function setupShow() {
    if (!V.S || V.S.setup_complete !== false) return;
    if (SETUP.shown) return;
    SETUP.shown = true;
    SETUP.step = 0;
    var lang = $('setup-lang'); if (lang) lang.value = langNow();
    var th = $('setup-theme'); if (th) th.value = 'light';
    var pol = $('setup-policy-text'); if (pol) pol.textContent = V.S.policy_text || '';
    var pok = $('setup-policy-ok');
    if (pok) pok.checked = !!(V.S.policy_rev && (V.S.policy_accepted_rev || 0) >= V.S.policy_rev);
    var nm = $('setup-name'); if (nm && !nm.value) nm.value = V.S.server_name || '';
    var lan = $('setup-lan'); if (lan) lan.checked = true;
    var sc = $('setup-scanners'); if (sc) sc.checked = true;
    var rate = $('setup-rate'); if (rate) rate.checked = true;
    var up = $('setup-ui-port'); if (up) up.value = V.S.ui_port || 8890;
    var xp = $('setup-xray-port'); if (xp) xp.value = V.S.xray_port || 8899;
    var ap = $('setup-xray-api-port'); if (ap) ap.value = V.S.xray_api_port || 8897;
    var tp = $('setup-tgws-port'); if (tp) tp.value = V.S.tgws_port || 443;
    SETUP.prefill = {
      ui_port: up ? up.value : '',
      xray_port: xp ? xp.value : '',
      xray_api_port: ap ? ap.value : '',
      tgws_port: tp ? tp.value : ''
    };
    $('setup-screen').style.display = '';
    setupRender();
  }

  function setupFinish() {
    var d = setupRead();
    var err = setupValidate(true);
    if (err) { $('setup-error').textContent = err; return; }
    $('setup-error').textContent = '';
    $('setup-finish').disabled = true;
    postJSON('/api/setup/complete', {
      server_name: d.name,
      password: d.password,
      pin: d.pin,
      policy_rev: (V.S && V.S.policy_rev) || 0,
      ui_port: setupPort('ui_port', d.ui_port),
      xray_port: setupPort('xray_port', d.xray_port),
      xray_api_port: setupPort('xray_api_port', d.xray_api_port),
      tgws_port: setupPort('tgws_port', d.tgws_port),
      lan_only: d.lan_only,
      block_scanners: d.block_scanners,
      rate_limit: d.rate_limit,
      mesh_invite: d.mesh_invite,
      setup_token: d.setup_token
    }).then(function (r) {
      if (!r || r.ok !== true) throw new Error((r && r.error) || 'Ошибка');
      try {
        sessionStorage.setItem('aurora_pin', d.pin);
        sessionStorage.setItem('aurora_token', d.password);
        sessionStorage.setItem(LS.tfa, d.pin);
      } catch (e) { }
      $('setup-screen').style.display = 'none';
      toast(r.restart_required ? 'Мяу! Порты применятся после перезапуска службы' : 'Мяу! Настройка завершена');
      setTimeout(function () { location.reload(); }, 800);
    }).catch(function (e) {
      $('setup-error').textContent = (e && e.message) || 'Ошибка';
    }).then(function () {
      $('setup-finish').disabled = false;
    });
  }

  function setupNext() {
    var d = setupRead();
    var err = setupValidate();
    if (err) { $('setup-error').textContent = err; return; }
    $('setup-error').textContent = '';
    if (SETUP.step === 0 && V.S && V.S.policy_rev && (V.S.policy_accepted_rev || 0) < V.S.policy_rev) {
      $('setup-next').disabled = true;
      postJSON('/api/policy/accept', { rev: V.S.policy_rev }).then(function (r) {
        if (!r || r.ok !== true) throw new Error((r && r.error) || 'Ошибка');
        V.S.policy_accepted_rev = V.S.policy_rev;
        V.S.policy_required = false;
        SETUP.step = Math.min(6, SETUP.step + 1);
        setupRender();
      }).catch(function (e) {
        $('setup-error').textContent = (e && e.message) || 'Ошибка';
      }).then(function () {
        $('setup-next').disabled = false;
      });
      return;
    }
    SETUP.step = Math.min(6, SETUP.step + 1);
    setupRender();
  }

  function setupBack() { setupError(''); SETUP.step = Math.max(0, SETUP.step - 1); setupRender(); }

  var ACTS = {
    nav: function (t) { navTo(t.getAttribute('data-tab')); },
    toast: function (t) { toast(t.getAttribute('data-msg') || '', true); },
    lang: function (t, ev) { setLang(((ev && ev.target && ev.target.value) || t.value || 'ru')); },
    'key-activate': function (t) { window.setActive(t.getAttribute('data-tag') || ''); },
    'plan-buy': function (t) { var id = t.getAttribute('data-plan-id'); if (id) window.buyPlan(id); else window.buyPlan(); },
    'policy-open': function (t) { window.policyShow(t.getAttribute('data-force') === '1'); },
    'policy-accept': function () { window.policyAccept(); },
    'update-start': function () { window.startUpdate(); },
    'update-save': function () { window.updSave(); },
    'update-check': function () { window.checkUpdate(); },
    'key-add': function () { window.keyAdd(); },
    'key-clean': function () { window.keyClean(); },
    'cx-copy': function () { window.cxCopy(); },
    'regions-save': function () { window.regionsSave(); },
    'ru-check': function () { window.ruCheck(); },
    'ru-toggle-fail': function () { window.ruToggleFail(); },
    'tgws-restart': function () { window.tgRestart(); },
    'mesh-join': function () { window.meshJoin(); },
    'mesh-leave': function () { window.meshLeave(); },
    'mesh-regen': function () { window.meshRegen(); },
    'mesh-refresh': function () { window.meshRefresh(); },
    'mesh-policy-save': function () { window.meshPolicySave(); },
    'settings-save': function () { window.settingsSave(); },
    'invite-copy': function () { window.inviteCopy(); },
    'sec-login': function () { window.secLogin(); },
    'sec-logout': function () { window.secLogout(); },
    'sec-2fa-on': function () { window.secTwofaEnable(); },
    'sec-2fa-off': function () { window.secTwofaDisable(); },
    'sec-rotate': function () { window.secRotate(); },
    'log-load': function () { window.loadLog(); }
  };
  function actTarget(ev) {
    var node = ev && ev.target;
    return (node && node.closest) ? node.closest('[data-act]') : null;
  }
  function actDispatch(ev) {
    var t = actTarget(ev);
    if (!t) return;
    var fn = ACTS[t.getAttribute('data-act')];
    if (!fn) return;
    if (ev.type === 'click') ev.preventDefault();
    fn(t, ev);
  }
  function bindActions() {
    document.addEventListener('click', actDispatch);
    document.addEventListener('change', actDispatch);
    $('btn-vpn') && ($('btn-vpn').onclick = function () {
      var on = !(V.S && V.S.vpn_mode);
      postJSON('/api/vpn_mode', { on: on }).then(function (j) {
        toast((j && j.ok) ? (on ? _t('vpn.on') : _t('vpn.off')) : ((j && j.error) || _t('t.err-gen')), !!(j && j.ok));
        setTimeout(function () { loadState(true); }, on ? 3000 : 1200);
      });
    });
    $('btn-rotate') && ($('btn-rotate').onclick = function () {
      postJSON('/api/rotate', {}).then(function (j) {
        toast((j && j.ok) ? _t('rot.ok') : ((j && j.error) || _t('rot.err')), !!(j && j.ok));
        setTimeout(function () { loadState(true); }, 3000);
      });
    });
    $('btn-refresh') && ($('btn-refresh').onclick = function () {
      postJSON('/api/keys/refresh', {}).then(function (j) {
        toast((j && j.ok) ? _t('pool.refresh') : ((j && j.error) || _t('t.err-gen')), !!(j && j.ok));
        setTimeout(function () { loadState(true); }, 1200);
      });
    });
    $('btn-check') && ($('btn-check').onclick = function () {
      postJSON('/api/keys/check', {}).then(function (j) {
        toast((j && j.ok) ? _t('pool.check') : ((j && j.error) || _t('t.err-gen')), true);
      });
    });
    $('btn-ping-mesh') && ($('btn-ping-mesh').onclick = function () {
      postJSON('/api/mesh/ping', {}).then(function (j) {
        toast((j && j.ok) ? _t('mesh.ping') : ((j && j.error) || _t('t.err-gen')), !!(j && j.ok));
        setTimeout(loadMesh, 2500);
      });
    });
    $('theme-btn') && ($('theme-btn').onclick = function () {
      var cur = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
      document.documentElement.setAttribute('data-theme', cur);
      localStorage.setItem(LS.theme, cur);
      $('theme-btn').textContent = cur === 'dark' ? '🌙' : '☀️';
    });
    $('menu-btn') && ($('menu-btn').onclick = function () { $('side').classList.toggle('open'); });
    $('setup-back') && ($('setup-back').onclick = setupBack);
    $('setup-next') && ($('setup-next').onclick = setupNext);
    $('setup-finish') && ($('setup-finish').onclick = setupFinish);
    Array.prototype.forEach.call(document.querySelectorAll('#nav button[data-t]'), function (b) {
      b.onclick = function () { navTo(b.getAttribute('data-t')); };
    });
  }
  function setVis(el, on) { if (el) el.style.display = on ? '' : 'none'; }
  function applyFlags(S) {
    var meshOn = (S.show_mesh !== false);
    var subsOn = (S.show_subs !== false);
    setVis($('g-mesh'), meshOn);
    setVis($('meshm'), meshOn);
    setVis($('dash-mesh-widget'), meshOn);
    setVis($('btn-ping-mesh'), meshOn);
    setVis($('pill-mesh'), meshOn);
    var wm = $('w-mesh-st');
    if (wm) setVis(wm.parentElement, meshOn);
    setVis($('g-shop'), subsOn);
    setVis($('planm'), subsOn);
    setVis($('dash-plan-widget'), subsOn);
    setVis($('pill-plan'), subsOn);
  }
  function renderMeshPolicy(S) {
    var card = $('mesh-policy-card');
    if (S.mesh_master) {
      if (card) setVis(card, true);
      if (!$('m-master') || !$('m-show-mesh') || !$('m-show-subs')) return;
      $('m-master').checked = !!S.mesh_master;
      $('m-show-mesh').checked = (S.show_mesh !== false);
      $('m-show-subs').checked = (S.show_subs !== false);
    } else if (card) {
      setVis(card, false);
    }
  }
  window.meshPolicySave = function () {
    postJSON('/api/settings/save', {
      mesh_master: $('m-master').checked,
      show_mesh: $('m-show-mesh').checked,
      show_subs: $('m-show-subs').checked
    }).then(function (j) {
      toast((j && j.ok) ? _t('mesh.policy-saved') : ((j && j.error) || _t('set.save-err')), !!(j && j.ok));
    });
  };

  function init() {
    try {
      var th = localStorage.getItem(LS.theme) || 'dark';
      document.documentElement.setAttribute('data-theme', th);
      $('theme-btn').textContent = th === 'dark' ? '🌙' : '☀️';
    } catch (e) { }
    initTabMeta();
    applyLang();
    bindActions();
    loadState();
    var subsTask = loadSubs();
    if (subsTask && typeof subsTask.then === 'function') {
      subsTask.then(function () { return 0; });
    }
    loadUpdate();
    setInterval(function () { loadState(true); }, 5000);
    setInterval(function () { loadUpdate(); }, 30000);
    setInterval(function () { if (CFG.tab === 'logs') loadLog(); }, 10000);
    setInterval(function () { if (CFG.tab === 'shop-plans' || CFG.tab === 'shop-billing') loadSubs(); }, 15000);
    var orig = loadState;
    loadState = function (soft) { orig(soft); };
  }
  document.addEventListener('DOMContentLoaded', init);
})();