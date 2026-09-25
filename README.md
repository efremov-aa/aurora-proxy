# 🐱 Aurora — VPN-прокси сервер с панелью 🐾

> Мяу! Я — **Aurora**, тёплый котик-прокси. Собственный VPN-сервер на **Xray (VLESS Reality)**
> с веб-панелью в нежно-розово-мятной гамме, Telegram WS-прокси, автозагрузкой ключей с GitHub,
> ротацией по живым ключам, RU-байпасом и мониторингом устройств. Лапки мягкие, туннель — быстрый. 🐾

![mascot](https://img.shields.io/badge/mascot-%F0%9F%90%B1-pink)
![python](https://img.shields.io/badge/python-3.12%20stdlib-blue)
![xray](https://img.shields.io/badge/xray-v26.9.9-blue)
![version](https://img.shields.io/badge/version-1.9.3-pink)
![tests](https://img.shields.io/badge/tests-34%20regression%20suites-blue)
![i18n](https://img.shields.io/badge/i18n-10%20languages-blue)

**Версия:** `VERSION=1.9.3`, `VERSION_NAME=Кот-глашатай` · **Политика:** ревизия 2 (обязательна при первом запуске)

## Содержание

- [📥 Загрузка](#-загрузка)
- [🐾 Что умеет](#-что-умеет)
- [🗂 Структура](#-структура)
- [🚀 Запуск](#-запуск)
- [⚙️ Настройка через env](#️-настройка-через-env)
- [🔌 API (выборка)](#-api-выборка)
- [🧪 Тесты](#-тесты)
- [🛡 Безопасность и приватность](#-безопасность-и-приватность)
- [📝 Замечания и известные проблемы](#-замечания-и-известные-проблемы)

## 📥 Загрузка

Архивы, установщик и список изменений — в [Release v1.9.3 «Кот-глашатай»](https://github.com/efremov-aa/aurora-proxy/releases).

| Ассет | Что внутри |
|---|---|
| `Aurora-v1.9.3-linux.zip` | Linux-версия: модули, `ui/`, `proxy/`, `Dockerfile`, `docker-compose.yml`, systemd-юниты |
| `Aurora-v1.9.3-windows.zip` | Windows-версия (папка `windows/`): те же модули + `bin/`, `nssm/`, `installer/`, `download_xray.ps1` |
| `Aurora-Setup-1.9.3.exe` 🪟 | **Установщик для Windows**: ставит Aurora как службу **NSSM «Aurora»**, xray и TG-WS внутри, авто-обновление |
| `*.sig` | Подпись Ed25519 каждого ассета — авто-обновление откажется принимать неподписанный файл 🐾 |

Проверено: подпись релизов валидна end-to-end (Ed25519, fingerprint `ca4f87c9999e0282…`), скачанный
с GitHub архив побайтно равен проверенному локальному.

## 🐾 Что умеет

**Канал и ключи**

- 🌐 **VLESS Reality** — xray mixed на `:8899`, встроенный пул реальных ключей, ротация по
  *фактическому* egress (выходной IP проверяется запросом, не «на глаз»).
- 🔑 **Автозагрузка ключей** — пул тянется с публичного GitHub-списка
  `barry-far/V2ray-Config` (`Splitted-By-Protocol/vless.txt`), фильтруется только по Reality-строкам
  (наличие `pbk`); несобираемые строки отбрасываются ещё на входе.
- 🛡 **Чёрный список** — `autodead_noip / autodead_conn / autodead_ping / user_removed`.
  Ключ без выходного IP считается мёртвым (правило владельца), удалённые руками ключи не воскрешаются.
- 🇷🇺 **RU-байпас** — российские домены (~1370) идут напрямую даже при включённом VPN: список с GitHub,
  кэш и статический фолбэк. Google/YouTube **всегда** в туннеле.
- 🧲 **Circuit-breaker** — не отвечающий кандидат уводится на `direct` без ручного рестарта xray.

**Панель и Telegram**

- 🏠 **Веб-панель `:8890`** — статус, ключи (обновить / проверить / добавить свой / удалить),
  устройства с трафиком и группировкой по префиксам IP, сортировка и скрытие колонок,
  Telegram WS-прокси, «Ру-сегмент», док-бар прогресса, магазин и меш-сеть.
- ✈️ **Telegram WS-прокси `:443`** — секрет не в argv и не в journal: расшифровывается во временный
  файл с `umask 077`, передаётся в прокси через **FD 3**, файл сразу удаляется.
- 📱 **Внешний VLESS-Reality `:8443`** (опционально) — готовая ссылка + локальный QR для подключения извне.
- 🔄 **Авто-восстановление** — лимит / регион / соединение: ротация VLESS при VPN ON, при VPN OFF — пропуск.
- 🌍 **Языки** — интерфейс на 10 языках (ru, en, es, de, fr, tr, pt, zh, ar, hi), тёмная/светлая тема,
  выбор языка сохраняется в браузере.

**Windows-сборка**

- 🪟 Авто-детект локального и публичного IP, телеметрия через `netstat`, авто-генерация VLESS-секретов,
  авто-heal TG-WS, скрытые окна консоли у всех дочерних процессов, служба NSSM «Aurora».

**Сеть-меш и подписки (по команде главного сервера)**

- 🕸 **Меш-сеть** — узлы в ролях `hub`/`node`, подписанный одноразовый **invite** (proof вместо
  токена, защита от повторного использования), политика главного сервера раздаёт флаги видимости.
- 🛒 **Подписки** — тарифы, лимиты трафика/устройств/ключей, счётчик по xray API, оплата и продление.
- 🚫 **Жёсткое правило для GitHub-сборок:** быть главным сервером **невозможно** — `mesh_master`
  намертво `False`, вкладки «Меш» и «Магазин» скрыты, пока головной сервер не пришлёт команду.
  Даже без подписки узел входит в группу (через него подключаются, сам — нет).
- 🧲 **BitTorrent → direct**: торрент-трафик эта сборка никогда не гонит через VPN (sniffing включён).

**Политика и защита**

- 📜 **Политика первого запуска** — ревизия 2, показывается до входа в панель, принятие фиксируется;
  при смене ревизии политика запрашивается заново.
- 🔏 **Шифрование AURORA2** (ChaCha20-Poly1305) для настроек, статусов, блеклиста, меша, админ-токена
  и TG-WS-секрета; ключ — `data/.aurora_key`, права 0600/0700, бэкап старого формата AURORA1 мигрируется.
- ✍️ **Подпись обновлений** — релиз подписывается Ed25519, авто-обновление fail-closed: неподписанный
  или испорченный файл не применяется (проверка digest + SHA-256 + `.sig`).
- 🧹 **CSP без inline-JS** — все кнопки работают через `data-act` allowlist, `script-src 'unsafe-inline'`
  и `script-src-attr` запрещены, добавлены HSTS/nosniff/frame-ancestors/Referrer-Policy.
- 🔍 **Read-scope проекции** — недоверенному клиенту/LAN отдаются маскированные данные,
  сырые логи, меш, TGWS, ключи и настройки — только доверенному админу.
- 🌐 **Опциональный TLS** — `AURORA_TLS_CERT`/`AURORA_TLS_KEY` поднимают HTTPS и HSTS.

## 🗂 Структура

```
aurora/
├── run.py            # точка входа: треды, фоновые циклы, HTTP-сервер
├── config.py         # настройки, state, env, порты, политика, RU-домены
├── api.py            # HTTP API и веб-панель (/api/state, /api/keys/*, /api/setup/*, ...)
├── core.py           # сборка xray.json, рестарт xray, ротация, circuit-breaker, egress
├── pool.py           # пул ключей + блеклист (data/keys.json|status.json|dead.json)
├── source.py         # GitHub-источники, keytest (TCP-пинг + egress через temp-xray)
├── crypt.py          # шифрование хранилищ AURORA2 (ChaCha20-Poly1305) + миграция AURORA1
├── security.py       # admin-токен панели (env AURORA_ADMIN_TOKEN, rate-limit)
├── updater.py        # авто-обновление с GitHub Releases
├── release_sign.py   # Ed25519: подпись и проверка ассетов
├── mesh.py           # меш-сеть: узлы, invite, политика главного сервера
├── subs.py           # подписки: тарифы, лимиты, счётчик трафика, оплата
├── telemetry.py      # устройства и трафик (ss/netstat), delta→cumulative
├── tgws.py           # Telegram WS-прокси: секрет, статус, ссылка
├── rusegment.py      # проверка доступности российских ресурсов
├── recovery.py       # авто-восстановление (limit/region/conn)
├── ui.py             # отдача static-файлов панели
├── ui/               # index.html, app.js, style.css, qr.js (локальный QR)
├── proxy/            # исходники TG-WS-прокси (Python): tg_ws_proxy.py, bridge.py, balancer.py, ...
├── tests/            # 34 регрессионных harness-а (test_*.py), запускаются из корня
├── data/             # данные (НЕ в репо): ключи, статусы, блеклист, настройки, .aurora_key
├── xray.json         # конфиг xray (генерится автоматически)
├── Dockerfile        # образ (XRAY_MANAGE=proc)
├── docker-compose.yml
├── .env.example      # пример переменных окружения
├── aurora.service    # systemd-юнит Aurora
├── xray.service      # systemd-юнит xray
├── tg-ws-proxy.service # systemd-юнит TG-WS-прокси
└── run_tgws.sh       # runner TG-WS (секрет через FD 3)
```

Windows-зеркало — в `windows/` (те же модули + `bin/`, `nssm/`, `installer/`, `download_xray.ps1`),
подробности в [`windows/README-windows.md`](windows/README-windows.md).

## 🚀 Запуск

### Вариант 1 — Docker (рекомендуется)

```bash
cp .env.example .env      # заполните AURORA_HOST и, при желании, VLESS-ключи
docker compose up -d --build
```

Публикуются панель `:8890` и API xray `:8897`; mixed-прокси `:8899` и внешний VLESS `:8443` — нет.
Данные — в томе `./data`. Xray уже встроен (v26.9.9 + geoip/geosite), управление — `XRAY_MANAGE=proc`.
**TG-WS в Docker-варианте не запускается**, порт `:443` не публикуется: Telegram WS-прокси живёт только
в режиме systemd (`run_tgws.sh` + `tg-ws-proxy.service`).

### Вариант 2 — Linux-сервер с systemd

1. Нужен **Python 3.12+** (только стандартная библиотека) и **xray v26.9.9**
   (бинар `xray` в `$HOME` или в папке проекта, рядом `geoip.dat`/`geosite.dat`).
2. Скопируйте папку в `/home/youruser/aurora/`.
3. `systemctl --user enable --now aurora` (см. `aurora.service`); `xray.service` и
   `tg-ws-proxy.service` — из репозитория, `run_tgws.sh` — для TG-прокси.
4. Откройте `http://<host>:8890/` — при первом запуске появится мастер настройки и политика.

> Управление xray на сервере — `XRAY_MANAGE=systemctl` (по умолчанию), в Docker — `proc`.

### Вариант 3 — Windows 🪟

Скачайте `Aurora-Setup-1.9.3.exe` и запустите: ставится служба **NSSM «Aurora»** (автозапуск,
авто-рестарт, логи в `%LOCALAPPDATA%\Aurora\service.log`). Альтернатива — ручная установка из
`windows/README-windows.md` (`nssm\install_service.bat`, `download_xray.ps1`).

При первом запуске мастер спрашивает язык/тему, имя сервера, пароль админа, PIN 2FA и — по желанию —
лимиты LAN/сканеров/rate. Порты, VLESS, TG-WS и секреты главного сервера в мастере не вводятся.

## ⚙️ Настройка через env

| Переменная | По умолчанию | Описание |
|---|---|---|
| `AURORA_HOST` | `127.0.0.1` | адрес/домен сервера для внешних ссылок (VLESS, `tg://proxy`) |
| `AURORA_WHITE_IP` | пусто | «белый» IP провайдера — фильтр, не засчитывается как выход VPN |
| `AURORA_DATA_DIR` | `<base>/data` | каталог данных |
| `AURORA_UI_PORT` | `8890` | порт веб-панели |
| `AURORA_XRAY_PORT` | `8899` | mixed-вход xray (http+socks) |
| `AURORA_XRAY_API_PORT` | `8897` | докодемо-API xray (статистика трафика) |
| `AURORA_TGWS_PORT` | `443` | порт Telegram WS-прокси (systemd-режим; Docker-порт не публикуется; 1443 блокировался РКН снаружи) |
| `AURORA_TGWS_RUNTIME_DIR` | `%t/aurora-tgws` | каталог временного runtime-секрета TG-WS |
| `AURORA_ADMIN_TOKEN` | пусто | admin-токен панели (Bearer для POST `/api/*`; пусто — выключено) |
| `AURORA_VLESS_ENABLED` | `false` | включить внешний VLESS-Reality `:8443` |
| `AURORA_VLESS_PORT` | `8443` | порт внешнего VLESS |
| `AURORA_VLESS_HOST` | пусто | публичный host для ссылки/QR (fallback — `AURORA_HOST`) |
| `AURORA_VLESS_UUID` | пусто | UUID клиента (`uuidgen`) |
| `AURORA_VLESS_PRIVATE_KEY` / `AURORA_VLESS_PUBLIC_KEY` | пусто | пара x25519 (`xray x25519`) |
| `AURORA_VLESS_SHORT_ID` | пусто | shortId Reality (hex, чётной длины) |
| `AURORA_VLESS_SNI` | `www.microsoft.com` | SNI прикрытия Reality |
| `AURORA_VLESS_FLOW` | `xtls-rprx-vision` | flow для VLESS |
| `AURORA_SETUP_TOKEN` | пусто | токен LAN-привязки при первом запуске (claim) |
| `AURORA_ALLOW_PRIVATE_LINK` | `0` | разрешить приватные (LAN) адреса в mesh-ссылках |
| `AURORA_MESH_MASTER_ID` | пусто | идентификатор узла-главного в меше (≥32 байт) |
| `AURORA_MESH_POLICY_KEY` | пусто | ключ подписи mesh-политики (≥32 байта) |
| `AURORA_TLS_CERT` / `AURORA_TLS_KEY` | пусто | сертификат/ключ HTTPS и HSTS |
| `AURORA_UPDATE_REPO` | `efremov-aa/aurora-proxy` | репозиторий авто-обновления |
| `XRAY_MANAGE` | `systemctl` | `systemctl` (сервер) или `proc` (Docker) |

> ⚠️ Меш требует `AURORA_MESH_POLICY_KEY` и `AURORA_MESH_MASTER_ID`; без них invite не выдаётся
> (503, а не ошибка авторизации).

## 🔌 API (выборка)

- `GET /api/state` — полное состояние (ключи, egress, VLESS-тег, устройства, comm, версии).
- `GET /api/policy` — текст политики и ревизия; `POST /api/policy/accept {rev}` — принять.
- `POST /api/setup {…}` — завершение первого запуска (только loopback, атомарно).
- `POST /api/vpn_mode {on:true|false}` — включить/выключить VPN-канал.
- `POST /api/keys/refresh` — обновить ключи с GitHub (фоново, ответ мгновенный).
- `POST /api/keys/check` — проверить все ключи (TCP + egress), мёртвые в блеклист.
- `POST /api/keys/add {uri}` / `POST /api/keys/remove {uri}` / `POST /api/keys/active {tag}` / `POST /api/rotate`.
- `GET /api/plans`, `POST /api/subs/purchase`, `GET /api/subs/list`, `POST /api/subs/apply` — магазин и подписки.
- `GET /api/mesh/policy`, `POST /api/mesh/node/add`, `POST /api/mesh/regenerate` — меш-сеть.
- `POST /api/tgws/restart`, `POST /api/rusegment/check` — обслуживание каналов.
- `GET /api/log`, `GET /api/recovery/log`, `GET /api/tgws/status`.
- `GET /api/security/status` — состояние admin-токена (`enabled` + маска); `POST /api/security/rotate` — новый токен.
- `GET /api/update/status|check|apply` — состояние, проверка и применение авто-обновления.

Ошибки `POST` возвращаются с кодом **400** и полем `error`; UI это учитывает.

## 🧪 Тесты

В репозитории **34 регрессионных harness-а** в папке `tests/` (`tests/test_*.py`), каждый печатает свой маркер
(`A0xx_…_OK`, `BILLING_REGRESSION_OK`, `BLOCKED_FLOW_OK`, …) и падает с ненулевым кодом при ошибке.
Запускать из корня репозитория:

```bash
python tests/test_a062_update_signature.py   # A062_UPDATE_SIGNATURE_OK — подпись обновлений
python tests/test_a068_ui_csp.py             # A068_UI_CSP_OK — CSP без inline-JS
python tests/test_a074_subs_contract.py      # подписки: покупка/продление/очередь/лимиты
python tests/test_billing.py                 # BILLING_REGRESSION_OK
python tests/test_comm_flow.py               # COMM_FLOW_ALL_OK (~30 с)
python tests/test_blocked.py                 # BLOCKED_FLOW_OK — бан-лист ключей
python tests/test_cleanup.py                 # CLEANUP_FLOW_OK — чистка пула
```

Полный прогон всех harness-ов разом (вспомогательным скриптом-обвязкой) заканчивается строкой
`ALL_LOCAL_TEST_SCRIPTS_OK`. Перед сборкой релиза прогоняются также `py_compile` всех модулей
и `node --check` для `ui/app.js` и `ui/qr.js`.

## 🛡 Безопасность и приватность

- Ключи, настройки, статусы, блеклист, меш и TG-WS-секрет — в зашифрованных хранилищах AURORA2.
- Панель: admin-токен + 2FA (PIN), rate-limit неудачных попыток, защита от чужих `Host`/`Origin`,
  раздельные проекции для LAN и внешних клиентов.
- Никаких ключей, токенов и паролей в репозитории: всё через env и `data/` (в `.gitignore`).
- Политика (ревизия 2) принимается до первого входа; в ней же — пункт о сотрудничестве
  с правоохранительными органами по официальному письменному запросу.
- Aurora не является анонимайзером и не обходит закон. Соблюдайте законы своей страны и правила
  провайдеров.

## 📝 Замечания и известные проблемы

- 🪟 **Windows 1.9.3: каталог данных.** NSSM-переменная `AppEnvironmentExtra` не доходит до
  frozen-процесса, поэтому установщик 1.9.3 пишет данные в `Aurora\_internal\data` вместо
  `%LOCALAPPDATA%\Aurora`. Это ломает обновление «поверх» и удаление (ошибка 145). Исправление —
  кандидат в **1.9.4**; до него при обновлении переносите каталог данных вручную.
- 🌐 **Egress проверяется только по HTTP**: HTTPS-проба через прокси даёт ложный SSL EOF.
  Факт: `curl --proxy http://127.0.0.1:8899 http://api.ipify.org`.
- 🔁 **Источники ключей статичны**: список `barry-far` обновляется редко, при каждом refresh
  приходят «те же» ключи. В Aurora это не цикл: бан-лист не даёт им вернуться, а фильтр по `pbk`
  отсекает несобираемые строки.
- 🐾 **Публичная сборка** не содержит приватных ключей владельца, станции Yandex и её кук —
  всё вынесено в env/`data/`.
- 🕸 **Меш и магазин скрыты** до команды главного сервера (см. выше) — так и задумано.
