'use strict';
let S = null;
let tab = 'status';
const $ = (id) => document.getElementById(id);

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

function toast(msg, ok) {
  const t = $('toast');
  t.textContent = msg;
  t.classList.toggle('err', !ok);
  t.classList.add('show');
  clearTimeout(toast._h);
  toast._h = setTimeout(() => t.classList.remove('show'), 2500);
}

function api(path, data, cb) {
  fetch('/api/' + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data || {})
  })
    .then((r) => r.json())
    .then((j) => {
      if (j && j.error) toast('ошибка: ' + j.error, false);
      else if (j && j.ok === false) toast('ошибка: ' + ((j && j.msg) || 'нет ответа'), false);
      else toast('Мяу! Готово 🐾', true);
      if (cb) cb(j);
    })
    .catch(() => toast('ошибка сети', false));
}

function fmt(n) {
  n = Number(n) || 0;
  if (n >= 1e9) return (n / 1e9).toFixed(2) + ' GB';
  if (n >= 1e6) return (n / 1e6).toFixed(1) + ' MB';
  if (n >= 1e3) return (n / 1e3).toFixed(1) + ' KB';
  return n + ' B';
}

const CHIP = {
  ok: ['st-ok', 'OK'],
  '': ['st-dim', ''],
  unchecked: ['st-dim', 'НЕ ПРОВЕРЕН'],
  bad: ['st-dead', 'BAD'],
  noip: ['st-dim', 'БЕЗ IP'],
  dead: ['st-dead', 'DEAD'],
  slow: ['st-slow', 'SLOW']
};
function chip(s) {
  const c = CHIP[s] || CHIP.unchecked;
  return '<span class="chip ' + c[0] + '">' + c[1] + '</span>';
}

function toggleVpn() {
  const on = !(S && S.vpn_mode);
  api('vpn_mode', { on: on }, (j) => {
    if (j && j.ok) setTimeout(refresh, 1500);
  });
}

function keyAct(tag) {
  if (!S || !S.vpn_mode) return toast('Сначала включите VPN', false);
  api('keys/active', { tag: tag }, refresh);
}

function keyDel(tag) {
  const k = (S && S.keys || []).find((x) => x.tag === tag);
  if (!k) return toast('ключ не найден', false);
  const uri = k.uri || (k.host + ':' + k.port);
  api('keys/remove', { uri: uri }, refresh);
}

function keyAdd() {
  const uri = ($('keyuri').value || '').trim();
  if (!uri) return toast('Вставьте vless:// ссылку', false);
  api('keys/add', { uri: uri }, (j) => {
    $('keyuri').value = '';
    setTimeout(refresh, 1500);
  });
}

function keyClean() {
  if (!confirm('Удалить мёртвые github-ключи?\n(без выходного IP / пинг > 500мс / в блеклисте)\nСвои ключи не тронутся.')) return;
  api('keys/cleanup', {}, (j) => {
    const n = (j && j.removed) || 0;
    if (n) toast('Мяу! Мёртвых убрано: ' + n + ' 🐾', true);
    setTimeout(refresh, 1200);
  });
}

function render() {
  if (!S) return;
  $('mode').textContent = S.vpn_mode ? 'VPN' : 'Прямой';
  const hb = $('hero-badge');
  if (hb) {
    hb.textContent = S.vpn_mode ? 'VPN' : 'DIRECT';
    hb.className = 'badge ' + (S.vpn_mode ? 'on' : 'off');
  }
  $('vless').textContent = S.vless_now || '-';
  $('egress').textContent = S.egress_ip || '-';
  $('conns').textContent = S.conns != null ? S.conns : 0;
  $('traffic').textContent = fmt(S.down) + ' / ' + fmt(S.up);
  const btn = $('btn-vpn');
  btn.textContent = (S.vpn_mode ? '🌀 VPN' : '🔌 Прямой');
  const hero = $('hero-title');
  const sub = $('hero-sub');
  if (S.vpn_mode && (S.egress_ip && S.egress_ip !== '-')) {
    hero.textContent = 'Прокси работает 🐈';
    sub.innerHTML = 'Aurora v' + esc(S.version) + (S.version_name ? ' «' + esc(S.version_name) + '»' : '') + ' · выход <b>' + esc(S.egress_ip) + '</b> · порт 8899';
  } else if (S.vpn_mode) {
    hero.textContent = 'Котик спит 😴';
    sub.innerHTML = 'Aurora v' + esc(S.version) + (S.version_name ? ' «' + esc(S.version_name) + '»' : '') + ' · канал поднимается';
  } else {
    hero.textContent = 'Прямой режим 🌐';
    sub.innerHTML = 'Aurora v' + esc(S.version) + (S.version_name ? ' «' + esc(S.version_name) + '»' : '') + ' · без VPN';
  }
  const deadN = (S.keys || []).filter((k) => k.dead || k.status === 'dead' || k.status === 'slow' || k.status === 'bad').length;
  $('keyinfo').textContent = 'ключей: ' + (S.keys_total || 0) + (deadN ? ' · 💀 мёртвых: ' + deadN : ' · всё живо 🐈');
  renderKeys();
  renderDevices();
  renderTGWS();
  renderConnect();
  renderRu();
  renderSecurity();
  renderUpdate();
  renderDock();
}

/* ——— док-бар: процесс загрузки/проверки ключей ——— */
function renderDock() {
  const c = (S && S.comm) || {};
  const keys = (S && S.keys) || [];
  const done = keys.filter((k) => k.status && k.status !== 'unchecked').length;
  const pct = keys.length ? Math.round((done / keys.length) * 100) : 0;
  const cnt = { ok: 0, bad: 0, noip: 0, slow: 0 };
  keys.forEach((k) => { if (cnt[k.status] != null) cnt[k.status]++; });

  let faze = 'idle';
  let msg = 'Все котики на месте';
  if (c.state === 'loading') { faze = 'loading'; msg = c.msg || 'Загружаю ключи с GitHub…'; }
  else if (c.state === 'running') { faze = 'checking'; msg = c.msg || ('Проверено ' + done + ' из ' + keys.length + '…'); }
  else if (c.state === 'syncing') { faze = 'syncing'; msg = c.msg || 'Синхронизирую с xray…'; }
  else if (c.state === 'done') {
    faze = 'done';
    msg = /check done/.test(c.msg || '') ? 'Проверка завершена' : (c.msg || 'Готово');
  }

  const d = $('dock');
  if (!d) return;
  d.dataset.faze = faze;
  $('dock-faze').textContent = msg;
  $('dock-fill').style.width = pct + '%';
  $('dock-pct').textContent = (faze === 'checking' || pct > 0) ? pct + '%' : '';
  $('dock-mascot').textContent = faze === 'checking' ? '🐈⬛' : (faze === 'loading' ? '🐾' : '🐱');
  $('dock-stats').innerHTML =
    '<span class="ok">✓' + cnt.ok + '</span>' +
    '<span class="bad">✗' + cnt.bad + '</span>' +
    '<span class="noip">∅' + cnt.noip + '</span>' +
    '<span class="slow">⚠' + cnt.slow + '</span>';
}

function dockToggle() {
  const d = $('dock');
  if (!d) return;
  d.classList.toggle('open');
  const c = (S && S.comm) || {};
  $('dock-detail').textContent = (c.msg || '—') +
    '\nключей: ' + ((S && S.keys_total) || 0) +
    (S && S.vless_now ? '\nvless: ' + S.vless_now : '') +
    (S && S.egress_ip ? ' · egress: ' + S.egress_ip : '');
}

function renderKeys() {
  const rows = $('keyrows');
  const keys = (S && S.keys || []).slice(0, 40);
  if (!keys.length) {
    rows.innerHTML = '<tr><td colspan="7" class="empty"><span class="ic">🐾</span>Здесь пока ни одного котика… <br>Нажми «Обновить из GitHub»</td></tr>';
    return;
  }
  rows.innerHTML = keys.map((k) => {
    const name = k.tag || k.host || '?';
    const st = k.dead ? 'dead' : k.status;
    const cls = k.is_active ? 'tr-active' : (st === 'dead' || st === 'slow' || st === 'bad' || k.dead ? 'tr-dead' : '');
    const ping = k.ping_ms != null ? Math.round(k.ping_ms) : null;
    const pingHtml = ping == null ? '-' : (ping > 500 ? '<span class="chk-die">' + ping + 'ms</span>' : ping + 'ms');
    return '<tr class="' + cls + '">' +
      '<td><b>' + esc(name) + '</b>' + (k.is_active ? ' 🐈' : '') + (k.dead ? ' 💀' : '') + '</td>' +
      '<td>' + esc(k.source || '-') + '</td>' +
      '<td>' + (k.is_active ? '<span class="chip st-act">АКТИВЕН</span>' : chip(st)) +
        (k.dead ? ' <span class="chip st-dead">БЛ:' + esc(k.dead) + '</span>' : '') + '</td>' +
      '<td class="mono">' + pingHtml + '</td>' +
      '<td class="mono">' + esc(k.exit_ip || '-') + '</td>' +
      '<td>' + (k.sites_ok || 0) + '</td>' +
      '<td><button class="btn small" title="Активировать ключ" onclick="keyAct(\'' + esc(name) + '\')">🔀</button> ' +
      '<button class="btn small" title="Удалить ключ" onclick="keyDel(\'' + esc(name) + '\')">🗑</button></td>' +
      '</tr>';
  }).join('');
}

function renderDevices() {
  const rows = $('devrows');
  const d = (S && S.devices) || {};
  const arr = Object.keys(d).map((ip) => d[ip]).sort((a, b) => (b.conns || 0) - (a.conns || 0));
  if (!arr.length) {
    rows.innerHTML = '<tr><td colspan="5" class="empty"><span class="ic">😿</span>Устройств пока не видно</td></tr>';
    return;
  }
  rows.innerHTML = arr.map((x) => {
    const ip = x.ip || '-';
    const dot = (x.conns || 0) > 0 ? 'dot on' : 'dot';
    return '<tr>' +
      '<td><span class="' + dot + '"></span>' + esc(x.name || '—') + '</td>' +
      '<td class="mono">' + esc(ip) + '</td>' +
      '<td>' + (x.conns || 0) + '</td>' +
      '<td class="mono">' + fmt(x.download || 0) + '</td>' +
      '<td class="mono">' + fmt(x.upload || 0) + '</td>' +
      '</tr>';
  }).join('');
}

function renderTGWS() {
  const t = (S && S.tgws) || {};
  $('tg-on').textContent = t.running ? 'running 🐈' : 'стоп';
  $('tg-on').parentElement.className = 'stat';
  $('tg-port').textContent = t.port_open ? (t.port || 443) + ' открыт' : (t.port || 443) + ' закрыт';
  $('tg-sec').textContent = t.secret_ok ? 'секрет ok' : 'секрет?';
  const qr = $('tg-qr');
  if (t.link) {
    qr.innerHTML = '<img src="https://api.qrserver.com/v1/create-qr-code/?size=220x220&data=' +
      encodeURIComponent(t.link) +
      '" alt="QR"><div class="qr-link mono">' + esc(t.link) + '</div>';
  } else {
    qr.innerHTML = '<span class="empty">секрета нет</span>';
  }
}

function renderConnect() {
  const x = (S && S.vless_ext) || {};
  const on = !!(x && x.enabled && x.link);
  const flag = $('cx-flag');
  if (flag) {
    flag.textContent = on ? 'активно' : 'выключено';
    flag.className = 'badge ' + (on ? 'on' : 'off');
  }
  $('cx-host').textContent = x.host || '-';
  $('cx-port').textContent = x.port || '-';
  $('cx-uuid').textContent = x.uuid || '-';
  $('cx-sni').textContent = x.sni || '-';
  const input = $('cx-link');
  const qr = $('cx-qr');
  if (on) {
    input.value = x.link;
    qr.innerHTML = '<img src="https://api.qrserver.com/v1/create-qr-code/?size=260x260&data=' +
      encodeURIComponent(x.link) +
      '" alt="QR"><div class="qr-link mono">' + esc(x.link) + '</div>';
  } else {
    input.value = '';
    qr.innerHTML = '<span class="empty">состояние выключено</span>';
  }
}

function cxCopy() {
  const input = $('cx-link');
  if (!input.value) return toast('ссылки нет', false);
  input.select();
  input.setSelectionRange(0, 99999);
  try { document.execCommand('copy'); toast('Ссылка скопирована 🐾', true); }
  catch (e) { toast('не удалось скопировать', false); }
}

/* ——— ру-сегмент: доступность RU-доменов напрямую ——— */
let RU_FAILONLY = false;

function ruCls(code) {
  if (code >= 200 && code < 300) return 'ok';       /* 2xx — норма */
  if (code >= 300 && code < 400) return 'redir';    /* 3xx — редирект, тоже норм */
  if (code >= 400 && code < 500) return 'reach';    /* 4xx — сайт ответил (антибот/403) */
  if (code >= 500) return 'err';                    /* 5xx — серверная ошибка */
  return 'dead';                                    /* -1/0 — нет ответа */
}

function ruCheck() {
  const ru = (S && S.rusegment) || {};
  if (ru.running) { toast('⏳ Уже идёт проверка', true); return; }
  api('rusegment/check', {}, (j) => {
    if (j && j.error) { toast('ошибка: ' + j.error, false); return; }
    toast('Мяу! Проверка запущена 🐾', true);
    setTimeout(refresh, 1200);
  });
}

function ruToggleFail() {
  RU_FAILONLY = !RU_FAILONLY;
  const b = $('ru-failonly');
  if (b) b.className = RU_FAILONLY ? 'btn primary small' : 'btn small';
  renderRu();
}
function ruSetFail(on) {
  RU_FAILONLY = on;
  const b = $('ru-failonly');
  if (b) b.className = on ? 'btn primary small' : 'btn small';
}

function ruMed(arr) {
  if (!arr || !arr.length) return null;
  const a = arr.slice().sort((x, y) => x - y);
  const m = a.length >> 1;
  return a.length % 2 ? a[m] : Math.round((a[m - 1] + a[m]) / 2);
}

function renderRu() {
  const ru = (S && S.rusegment) || {};
  const rows = $('rurows');
  const flag = $('ru-flag');
  const run = $('ru-run');
  const failb = $('ru-failonly');
  const emptyRow = '<tr class="empty"><td colspan="5"><span class="ic">🌍</span>Данные появятся после проверки</td></tr>';
  const res = (ru && ru.results) || [];
  if (run) { run.disabled = !!ru.running; run.textContent = ru.running ? '🔄 Проверяю…' : '🧪 Проверить сейчас'; }
  if (failb) failb.className = RU_FAILONLY ? 'btn primary small' : 'btn small';
  /* бейдж: 4 состояния */
  if (flag) {
    if (ru.running) { flag.textContent = 'проверяю…'; flag.className = 'badge on' + (res.length ? '' : ''); }
    else if (!res.length) { flag.textContent = 'не проверено'; flag.className = 'badge off'; }
    else {
      const okN = res.filter((r) => ruCls(r.code) !== 'dead' && ruCls(r.code) !== 'err').length;
      if (okN === res.length) { flag.textContent = 'всё ок'; flag.className = 'badge on'; }
      else if (okN > 0) { flag.textContent = okN + '/' + res.length + ' доступно'; flag.className = 'badge warn'; }
      else { flag.textContent = 'недоступен'; flag.className = 'badge off'; }
    }
  }
  /* сводка-метрики */
  const mets = {
    mn: ru.running ? null : ruMed(res.filter((r) => r.ms != null).map((r) => r.ms)),
    ts: ru.ts ? new Date(ru.ts * 1000).toLocaleTimeString() : null
  };
  const okN = ru.running ? null : res.filter((r) => ruCls(r.code) !== 'dead' && ruCls(r.code) !== 'err').length;
  const badN = ru.running ? null : res.filter((r) => ruCls(r.code) === 'dead' || ruCls(r.code) === 'err').length;
  const setT = (id, v, extra) => { const e = $(id); if (e) { e.textContent = v; if (extra) e.style.color = extra; } };
  setT('ru-ok', okN == null ? '–' : okN + ' / ' + res.length, okN != null && okN === res.length ? 'var(--success)' : (okN != null && okN > 0 ? 'var(--warning)' : 'var(--danger)'));
  setT('ru-bad', badN == null ? '–' : badN, badN != null && badN > 0 ? 'var(--danger)' : '');
  setT('ru-med', mets.mn == null ? '–' : mets.mn + 'ms');
  setT('ru-ts', mets.ts || (ru.running ? 'идёт…' : 'ещё не проверено'));
  if (!$('ru-med')) {
    /* на случай старой разметки — метрики воткнуты в таблицу не будут */
  }
  if (!res.length) {
    rows.innerHTML = ru.running ? '<tr class="empty"><td colspan="5"><span class="ic">🐾</span>Котики проверяют ру-сегмент…</td></tr>' : emptyRow;
    return;
  }
  const list = RU_FAILONLY ? res.filter((r) => { const c = ruCls(r.code); return c === 'dead' || c === 'err'; }).sort((a, b) => (b.ms || 0) - (a.ms || 0)) : res;
  rows.innerHTML = list.map((r) => {
    const c = ruCls(r.code);
    const ok = c !== 'dead' && c !== 'err';
    const cls = c === 'dead' ? 'tr-dead' : (c === 'err' ? '' : '');
    const codeTxt = r.code === -1 ? 'недоступен' : (r.code === 0 ? 'нет ответа' : r.code);
    const chip = c === 'ok' ? '<span class="chip st-ok">OK</span>'
      : c === 'redir' ? '<span class="chip st-dim">РЕДИРЕКТ</span>'
      : c === 'reach' ? '<span class="chip st-ok">ДОСТУПЕН</span>'
      : c === 'err' ? '<span class="chip st-slow">ОШИБКА</span>'
      : '<span class="chip st-dead">НЕТ ОТВЕТА</span>';
    const msPing = r.ms != null && r.ms > 800 ? '<span style="color:var(--danger);font-weight:800">' + r.ms + 'ms</span>' : (r.ms != null ? r.ms + 'ms' : '-');
    return '<tr class="' + cls + '">' +
      '<td><b>' + esc(r.host) + '</b>' + (ok ? ' 🐈' : ' 💀') + '</td>' +
      '<td class="mono">' + esc(r.ip || '-') + '</td>' +
      '<td class="mono">' + esc(codeTxt) + '</td>' +
      '<td class="mono">' + msPing + '</td>' +
      '<td>' + chip + '</td>' +
      '</tr>';
  }).join('');
}

/* ——— безопасность: админ-токен ——— */
const SEC_STATE = { enabled: null, masked: '' };

function renderSecurity() {
  fetch('/api/security/status')
    .then((r) => r.json())
    .then((j) => {
      SEC_STATE.enabled = !!(j && j.enabled);
      SEC_STATE.masked = (j && j.masked) || '';
      const en = $('sec-en');
      en.textContent = SEC_STATE.enabled ? 'включена 🔒' : 'выключена';
      en.className = 'v ' + (SEC_STATE.enabled ? '' : 'dim');
      $('sec-tok').textContent = SEC_STATE.masked;
    })
    .catch(() => {});
}

function secRotate() {
  api('security/rotate', {}, () => {
    toast('Токен ротирован 🔑');
    renderSecurity();
  });
}

/* ——— обновление ——— */
function renderUpdate() {
  fetch('/api/update/status')
    .then((r) => r.json())
    .then((j) => {
      if (!j) return;
      $('up-cur').textContent = j.current || '-';
      $('up-lat').textContent = j.latest ? (j.update ? ('доступна v' + j.latest) : ('v' + j.latest + ' (актуально)')) : (j.repo || 'не настроено');
      $('up-ts').textContent = j.ts ? new Date(j.ts * 1000).toLocaleString() : 'ещё не проверялась';
      const apply = $('btn-up-apply');
      if (apply) apply.disabled = !(j.ok && j.update);
    })
    .catch(() => {});
}

function upCheck() {
  api('update/check', {}, () => {
    toast('Проверка выполнена 🔍');
    renderUpdate();
  });
}

function upApply() {
  if (!confirm('Установить обновление? Сервер кратко перезапустится.')) return;
  toast('Устанавливаю… сервер перезапустится 📥');
  api('update/apply', {}, () => {});
}

function refresh() {
  fetch('/api/state')
    .then((r) => r.json())
    .then((j) => { S = j; render(); })
    .catch(() => {});
}

function loadLog() {
  fetch('/api/log')
    .then((r) => r.json())
    .then((j) => {
      const box = $('log');
      if (!j || !j.lines || !j.lines.length) {
        box.innerHTML = '<span class="empty"><span class="ic">🗒️</span>записей пока нет</span>';
        return;
      }
      box.textContent = j.lines.slice(-22).join('\n');
    })
    .catch(() => {});
  fetch('/api/recovery/log')
    .then((r) => r.json())
    .then((j) => {
      const box = $('rclog');
      if (!j || !j.log || !j.log.length) {
        box.innerHTML = '<span class="empty"><span class="ic">🛟</span>восстановлений не было</span>';
        return;
      }
      box.textContent = j.log.slice(-8).map((e) => {
        const t = new Date((e.ts || 0) * 1000).toLocaleTimeString();
        return '[' + t + '] [' + (e.kind || '?') + '] ' + (e.msg || '');
      }).join('\n');
    })
    .catch(() => {});
}

function init() {
  const STORE = 'aurora-theme';
  const saved = localStorage.getItem(STORE) || 'dark';
  document.documentElement.setAttribute('data-theme', saved);
  $('theme-btn').textContent = saved === 'dark' ? '🌙' : '☀️';
  $('theme-btn').onclick = () => {
    const next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem(STORE, next);
    $('theme-btn').textContent = next === 'dark' ? '🌙' : '☀️';
  };

  document.querySelectorAll('#nav button').forEach((b) => {
    b.onclick = () => {
      tab = b.dataset.t;
      document.querySelectorAll('#nav button').forEach((x) => x.classList.toggle('on', x === b));
      document.querySelectorAll('.tab').forEach((x) => x.classList.toggle('show', x.id === 't-' + tab));
      refresh();
    };
  });

  $('btn-vpn').onclick = toggleVpn;
  $('btn-rotate').onclick = () => api('rotate', {}, refresh);
  $('btn-refresh').onclick = () => api('keys/refresh', {}, refresh);
  $('btn-check').onclick = () => api('keys/check', {}, refresh);

  refresh();
  loadLog();
  setInterval(refresh, 5000);
  setInterval(loadLog, 8000);
}

document.addEventListener('DOMContentLoaded', init);
