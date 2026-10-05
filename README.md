# 🐱 Aurora — тёплый котик с VLESS Reality и общей меш-сетью 🐾

> Мяу! Я **Aurora**, тёплый розово-мятный котик. У меня мягкие лапки, честный хвост
> (наружу не показываю) и три ипостаси:
>
> - 🐾 **свой прокси** — VLESS Reality, пул живых ключей, ротация по *настоящему* выходному IP;
> - 🐾 **своя Aurora** — веб-панель, стабильные ключи, устройства, Telegram WS-прокси и «свои сайты»;
> - 🐾 **общая меш-сеть** — я умею ждать друзей, играть с ними в общей группе, переписываться и
>   разговаривать.
>
> 🐾 **Честно:** Aurora — **не VPN-сервис**, **не анонимайзер** и **не обход белых списков**.
> Ядро — свой прокси, панель, общая меш-сеть, чат и голос — бесплатно. Дополнительные **услуги
> самой Aurora** можно купить: это расширения и режимы для **твоей** Aurora, а не VPN и не
> обход белых списков. Туннель, ключи и панель — твои. Никаких продаж VPN в этой сборке нет.

![mascot](https://img.shields.io/badge/mascot-%F0%9F%90%B1-pink)
![python](https://img.shields.io/badge/python-3.12%20stdlib-blue)
![xray](https://img.shields.io/badge/xray-v26.9.9-blue)
![version](https://img.shields.io/badge/version-1.10.0-pink)

**Версия:** `VERSION=1.10.0`, `VERSION_NAME=Кот-вольный` · **Политика:** ревизия 2 (принимается при первом запуске)

---

## 📥 Загрузка

Мяу! Всё лежит в [Release v1.10.0 «Кот-вольный»](https://github.com/efremov-aa/aurora-proxy/releases).

| Ассет | Что внутри |
|---|---|
| `Aurora-v1.10.0-linux.zip` | Linux-версия: модули, `ui/`, `proxy/`, `Dockerfile`, `docker-compose.yml`, systemd-юниты |
| `Aurora-v1.10.0-windows.zip` | Windows-версия (папка `windows/`): те же модули + `bin/`, `nssm/`, `installer/`, `download_xray.ps1` |
| `Aurora-Setup-1.10.0.exe` 🪟 | **Установщик для Windows**: ставит Aurora как службу **NSSM «Aurora»**, xray и TG-WS внутри, авто-обновление |
| `*.sig` | Подпись Ed25519 каждого ассета: авто-обновление не примет неподписанный файл 🐾 |

Подпись релизов проверена подписно: Ed25519, fingerprint `ca4f87c9999e0282…`. Скачанный архив
побайтно равен локальному.

## 🐾 Что я умею бесплатно

| Что | Как это работает |
|---|---|
| 🐾 Свой прокси | VLESS Reality, xray mixed на `:8899`, пул живых ключей, ротация по фактическому egress |
| 🐾 Своя Aurora | панель `:8890`, стабильные ключи и ссылка для своих устройств |
| 🐾 Общая меш-сеть | узлы в ролях `hub`/`node`, подписанный одноразовый invite (proof вместо токена) |
| 🐾 До 5 mesh-клиентов для игр | групповая L3-подсеть `10.<группа>.<узел>.1`, прямой UDP-канал и рель с честной плашкой «через рель, +N мс» |
| 🐾 Чат и голос | внутри общей сети, без отдельной подписки и без счётчиков |

Ни квот по трафику, ни лимита устройств, ни сроков. Ключи и xray — твои, панель — твоя,
хвост наружу не торчит.

## 🐾 Дополнительные услуги Aurora

Да, некоторые дополнительные штуки для Aurora продаются. Но это **не VPN**, **не подписка на прокси**
и **не обход белых списков**. Я не продаю VPN, не продаю доступ к чужим сетям и не даю возможности
обхода белых списков. Платно — только то, что умеет **сама Aurora**: расширения и режимы для твоей
панели, твоего прокси и твоей меш-сети.

- 🧩 **Плагины и расширение для браузера** — блокируют рекламу и трекеры, включают RU-режим прямо
  в браузере и дают режимы «только этот сайт / глобально / выкл».
- 📺 **Трансляция экрана и видео** — между твоими устройствами, без чужих серверов.
- 👥 **Друзья без ограничения** — бесплатно у Aurora пять игровых mesh-клиентов, а платно лимита нет:
  сколько друзей подключишь, столько и играешь. Работает **только для твоих друзей** и **только через
  наши клиенты**, чужие сети и чужие устройства эта услуга не открывает.
- 🏠 **NAT-доступ только к своей Aurora** — если ты за серым IP/NAT, клиент доходит до **твоего** узла
  и никуда больше. Чужие Aurora эта штука не открывает.
- 🌍 **«Сайты, которые не любят прокси»** — список доменов, которые открываются напрямую, вместо
  старых «белых списков». Это **не обход белых списков**, а переключение режима для сайтов,
  которые не любят прокси.

> Мяу. Ещё раз: покупка доп. услуг не делает Aurora VPN и не даёт обхода белых списков.
> Она просто расширяет то, что уже есть у тебя.

## 🔮 Как я работаю

**Канал и ключи**

- 🌐 **VLESS Reality** — xray mixed на `:8899`, встроенный пул реальных ключей, ротация по
  *фактическому* egress (выходной IP проверяется запросом).
- 🔑 **Автозагрузка ключей** — пул тянется с публичного GitHub-списка
  `barry-far/V2ray-Config` (`Splitted-By-Protocol/vless.txt`) и фильтруется только по Reality-строкам
  (наличие `pbk`).
- 🛡 **Чёрный список** — `autodead_noip / autodead_conn / autodead_ping / user_removed`.
  Ключ без выходного IP считается мёртвым.
- 🌍 **«Свои сайты»** — сайты, которые не любят прокси, идут напрямую с твоего белого IP.
  Это **не обход белых списков**: Aurora просто переключает режим на `direct` для таких доменов.
  Google/YouTube **всегда** через прокси.
- 🧲 **Circuit-breaker** — не отвечающий кандидат уводится на `direct` без ручного рестарта xray.

**Панель и Telegram**

- 🏠 **Веб-панель `:8890`** — статус, ключи (обновить / проверить / добавить свой / удалить),
  устройства с трафиком и группировкой по префиксам IP, Telegram WS-прокси, «Ру-сегмент»,
  док-бар прогресса и меш-сеть.
- ✈️ **Telegram WS-прокси `:443`** — секрет не в argv и не в журнале: расшифровывается во временный
  файл с `umask 077`, передаётся прокси через **FD 3**, файл сразу удаляется.
- 📱 **Внешний VLESS-Reality `:8443`** (опционально) — готовая ссылка и локальный QR для подключения извне.
- 🔄 **Авто-восстановление** — лимит / регион / соединение: ротация VLESS при включённом прокси-канале,
  при выключенном — пропуск.
- 🌍 **Языки** — интерфейс на 10 языках (ru, en, es, de, fr, tr, pt, zh, ar, hi), тёмная и светлая тема,
  выбор языка живёт в браузере.

**Windows-сборка 🪟**

- 🪟 Авто-детект локального и публичного IP, телеметрия через `netstat`, авто-генерация VLESS-секретов,
  авто-heal TG-WS, скрытые окна консоли у всех дочерних процессов, служба NSSM «Aurora».

**Меш-сеть**

- 🕸 **Узлы и invite** — роли `hub`/`node`, подписанный одноразовый **invite** (proof вместо токена,
  защита от повторного использования). Здесь можно играть с друзьями.
- 🧲 **BitTorrent → direct** — торрент-трафик эта сборка никогда не гонит через прокси (sniffing включён).
- 🚫 **Тарифов и лимитов на сам прокси нет.**

**Политика и защита**

- 📜 **Политика первого запуска** — ревизия 2, показывается до входа в панель, принятие фиксируется.
- 🔏 **Шифрование AURORA2** (ChaCha20-Poly1305) для настроек, статусов, блеклиста, меша, админ-токена
  и TG-WS-секрета; ключ — `data/.aurora_key`, права 0600/0700, старый формат AURORA1 мигрируется.
- ✍️ **Подпись обновлений** — релиз подписывается Ed25519, авто-обновление fail-closed.
- 🧹 **CSP без inline-JS** — все кнопки работают через `data-act` allowlist, добавлены HSTS, nosniff,
  frame-ancestors, Referrer-Policy.
- 🔍 **Read-scope проекции** — недоверенному клиенту или LAN отдаются маскированные данные.
- 🌐 **Опциональный TLS** — `AURORA_TLS_CERT`/`AURORA_TLS_KEY` поднимают HTTPS и HSTS.

## 🗂 Мои внутренности

```
aurora/
├── run.py            # точка входа: треды, фоновые циклы, HTTP-сервер
├── config.py         # настройки, state, env, порты, политика, RU-домены
├── api.py            # HTTP API и веб-панель
├── core.py           # сборка xray.json, рестарт xray, ротация, circuit-breaker, egress
├── pool.py           # пул ключей + блеклист
├── source.py         # GitHub-источники, keytest
├── crypt.py          # шифрование хранилищ AURORA2 + миграция AURORA1
├── security.py       # admin-токен панели, rate-limit
├── updater.py        # авто-обновление с GitHub Releases
├── release_sign.py   # Ed25519: подпись и проверка ассетов
├── meshsignal.py    # сигналинг mesh для клиентов: offer/answer/ICE, чат и голос
├── mesh.py           # меш-сеть: узлы, invite, политика
├── telemetry.py      # устройства и трафик (ss/netstat)
├── tgws.py           # Telegram WS-прокси
├── rusegment.py      # проверка доступности российских ресурсов
├── recovery.py       # авто-восстановление
├── ui.py             # отдача static-файлов панели
├── ui/               # index.html, app.js, style.css, qr.js
├── proxy/            # исходники TG-WS-прокси
├── data/             # данные (НЕ в репо): ключи, статусы, блеклист, настройки, .aurora_key
├── xray.json         # конфиг xray (генерится автоматически)
├── Dockerfile
├── docker-compose.yml
├── .env.example
├── aurora.service
├── xray.service
├── tg-ws-proxy.service
└── run_tgws.sh
```

Windows-зеркало — в `windows/` (те же модули + `bin/`, `nssm/`, `installer/`, `download_xray.ps1`).

## 🚀 Как меня запустить

### Вариант 1 — Docker (рекомендуется)

```bash
cp .env.example .env
docker compose up -d --build
```

Публикуются панель `:8890` и dokodemo-API xray `:8897`; mixed-прокси `:8899` и внешний VLESS `:8443` — нет.
Данные — в томе `./data`. Xray уже встроен (v26.9.9 + geoip/geosite), управление — `XRAY_MANAGE=proc`.
**TG-WS в Docker-варианте не запускается**, порт `:443` не публикуется: Telegram WS-прокси живёт только
в режиме systemd (`run_tgws.sh` + `tg-ws-proxy.service`). Порт задаётся env `AURORA_TGWS_PORT`,
но Docker-порт не публикуется.

### Вариант 2 — Linux-сервер с systemd

1. Нужен **Python 3.12+** (только стандартная библиотека) и **xray v26.9.9**.
2. Скопируйте папку в `/home/youruser/aurora/`.
3. `systemctl --user enable --now aurora`; `xray.service` и `tg-ws-proxy.service` — из репозитория.
4. Откройте `http://<host>:8890/` — при первом запуске появится мастер настройки и политика.

> Управление xray на сервере — `XRAY_MANAGE=systemctl`, в Docker — `proc`.

### Вариант 3 — Windows 🪟

Скачайте `Aurora-Setup-1.10.0.exe` и запустите: ставится служба **NSSM «Aurora»**.
Данные — в `%LOCALAPPDATA%\Aurora`. Альтернатива — ручная установка из `windows/README-windows.md`.

## ⚙️ Мои настройки через env

| Переменная | По умолчанию | Описание |
|---|---|---|
| `AURORA_HOST` | `127.0.0.1` | адрес/домен сервера для внешних ссылок |
| `AURORA_WHITE_IP` | пусто | «белый» IP провайдера — фильтр, не засчитывается как выход прокси |
| `AURORA_DATA_DIR` | `<base>/data` | каталог данных |
| `AURORA_UI_PORT` | `8890` | порт веб-панели |
| `AURORA_XRAY_PORT` | `8899` | mixed-вход xray (http+socks) |
| `AURORA_XRAY_API_PORT` | `8897` | dokodemo-API xray |
| `AURORA_TGWS_PORT` | `443` | порт Telegram WS-прокси |
| `AURORA_TGWS_RUNTIME_DIR` | `%t/aurora-tgws` | каталог временного runtime-секрета TG-WS |
| `AURORA_ADMIN_TOKEN` | пусто | admin-токен панели |
| `AURORA_VLESS_ENABLED` | `false` | включить внешний VLESS-Reality `:8443` |
| `AURORA_VLESS_PORT` | `8443` | порт внешнего VLESS |
| `AURORA_VLESS_HOST` | пусто | публичный host для ссылки/QR |
| `AURORA_VLESS_UUID` | пусто | UUID клиента |
| `AURORA_VLESS_PRIVATE_KEY` / `AURORA_VLESS_PUBLIC_KEY` | пусто | пара x25519 |
| `AURORA_VLESS_SHORT_ID` | пусто | shortId Reality |
| `AURORA_VLESS_SNI` | `www.microsoft.com` | SNI прикрытия Reality |
| `AURORA_VLESS_FLOW` | `xtls-rprx-vision` | flow для VLESS |
| `AURORA_SETUP_TOKEN` | пусто | токен LAN-привязки при первом запуске |
| `AURORA_ALLOW_PRIVATE_LINK` | `0` | разрешить приватные адреса в mesh-ссылках |
| `AURORA_MESH_MASTER_ID` | пусто | идентификатор узла-главного в меше |
| `AURORA_MESH_POLICY_KEY` | пусто | ключ подписи mesh-политики |
| `AURORA_TLS_CERT` / `AURORA_TLS_KEY` | пусто | сертификат/ключ HTTPS и HSTS |
| `AURORA_UPDATE_REPO` | `efremov-aa/aurora-proxy` | репозиторий авто-обновления |
| `XRAY_MANAGE` | `systemctl` | `systemctl` или `proc` (Docker) |

> ⚠️ Меш требует `AURORA_MESH_POLICY_KEY` и `AURORA_MESH_MASTER_ID`; без них invite не выдаётся (503).

## 🔌 Мой API

- `GET /api/state` — полное состояние.
- `GET /api/policy` — текст политики и ревизия; `POST /api/policy/accept {rev}` — принять.
- `POST /api/setup {…}` — завершение первого запуска (только loopback).
- `POST /api/keys/refresh` — обновить ключи с GitHub.
- `POST /api/keys/check` — проверить все ключи (TCP + egress), мёртвые в блеклист.
- `POST /api/keys/add {uri}` / `POST /api/keys/remove {uri}` / `POST /api/keys/active {tag}` / `POST /api/rotate`.
- `GET /api/mesh/policy`, `POST /api/mesh/node/add`, `POST /api/mesh/regenerate` — меш-сеть.
- `POST /api/tgws/restart`, `POST /api/rusegment/check` — обслуживание каналов.
- `GET /api/log`, `GET /api/recovery/log`, `GET /api/tgws/status`.
- `GET /api/security/status`; `POST /api/security/rotate`.
- `GET /api/update/status|check|apply`.

Ошибки `POST` возвращаются с кодом **400** и полем `error`; UI это учитывает.

## 🧪 Мои проверки

🐾 Папки с тестами в репозитории нет — владелец убрал её с сайта, чтобы сборка выглядела чисто.
Локально проверки остались и гоняются каждую правку.

**Что проверяется (по группам):**

- хранилище и шифрование: `test_a031_storage.py`, `test_a029_storage_validation.py`,
  `test_a030_crypt_storage.py`;
- подпись релизов и авто-обновление: `test_a062_update_signature.py`;
- контракт Docker-варианта: `test_a035_docker_contract.py`;
- версия и названия релизов: `test_a042_version.py`;
- границы доступа, CSRF, TLS: `test_a058_boundary.py`, `test_a061_transport.py`,
  `test_a063_public_host.py`, `test_a073_read_scope.py`;
- панель без inline-JS: `test_a068_ui_csp.py`;
- устройство = ключ и инструкции подключения: `test_a110_mykeys.py`;
- релей-туннель между узлами: `test_a160_relay_tunnel.py`;
- меш-реестр, ключи, recovery, телеметрия, RU-сегмент: `test_a064_mesh_invite.py`,
  `test_a041_vless.py`, `test_a032_recovery.py`, `test_a034_telemetry.py`,
  `test_a033_direct.py`, `test_a043_bt.py`.

**Полный прогон разом** — обвязкой, которая заканчивается строкой `ALL_LOCAL_TEST_SCRIPTS_OK`.

```bash
python tests/test_a068_ui_csp.py       # A068_UI_CSP_OK
python tests/test_a042_version.py      # A042_VERSION_CONTRACT_OK
python tests/test_a160_relay_tunnel.py # A160_RELAY_TUNNEL_OK
```

И быстрая проверка синтаксиса:

```bash
python -m py_compile api.py config.py core.py crypt.py extgate.py mesh.py \
    meshtunnel.py pool.py recovery.py run.py subs.py telemetry.py tgws.py updater.py
node --check ui/app.js && node --check ui/qr.js
```

🛡 Ни одна проверка не ходит в сеть: всё считается офлайн, на заглушках и копиях конфигов.

## 🛡 Моя безопасность

- Ключи, настройки, статусы, блеклист, меш и TG-WS-секрет лежат в зашифрованных хранилищах AURORA2.
- Панель: admin-токен + 2FA (PIN), rate-limit неудачных попыток, защита от чужих `Host`/`Origin`,
  раздельные проекции для LAN и внешних клиентов.
- Политика (ревизия 2) принимается до первого входа.
- Aurora — **не VPN-сервис**, не анонимайзер и не обход законов. Соблюдайте законы своей страны
  и правила провайдеров.

## ⚖️ Честно о законах

Мяу! Я котик, а не юрист, и это не юридическая консультация.

- **Я не VPN, не анонимайзер и не средство обхода блокировок.** Aurora — твой локальный прокси: ключи, панель, меш-сеть.
- **Я не продаю и не рекламирую VPN-доступ и обход блокировок** — ни в README, ни в панели, ни в боте.
- **Законы — твои.** Aurora не помогает ищемь запрещённое и не торгует чужим трафиком; соблюдай законам своей страны.

> 🐾 Простое правило: за своё пользование своими ключами и своей панелью ты не платишь никому.
> Платится только Aurora за дополнительные возможности — и только свои.

## 📝 Замечания и честные грабли

- 🐾 **В 1.10.0 никаких подписок на VPN.** Вкладка тарифов удалена, покупка закрыта гейтом (403).
  Ядро (свой прокси, своя Aurora, общая меш-сеть, чат и голос) осталось бесплатным — без квот и счётчиков.
- 🪟 **Каталог данных установщика (1.10.0).** При установленном приложении каталог данных по умолчанию —
  `%LOCALAPPDATA%\Aurora`. Если у вас стоял 1.9.3 — перенесите старый каталог
  `Aurora\_internal\data` в `%LOCALAPPDATA%\Aurora` один раз руками.
- 🌐 **Egress проверяется только по HTTP**: HTTPS-проба через прокси даёт ложный SSL EOF.
  Факт: `curl --proxy http://127.0.0.1:8899 http://api.ipify.org`.
- 🔁 **Источники ключей статичны**: список `barry-far` обновляется редко. Бан-лист не даёт ключам
  вернуться, а фильтр по `pbk` отсекает несобираемые строки.
- 🐾 **Публичная сборка** не содержит приватных ключей владельца.

## 🧭 Решения и дорожная карта

Подробный документ — **ROADMAP.md**. Коротко:

- **Три независимых контура:** прокси (VLESS Reality + панель) и игровой mesh-контур. Туннель
  головного сервера слушает **только loopback** (`51821`/`51822`/`51823`) и наружу не выходит.
- **Игровой контур** — групповая L3-подсеть `10.<группа>.<узел>.1`. Группы изолированы, маршрут `/16`
  внутри группы обязателен, рель отправляет кадр только пиру с совпадающим адресом назначения.
- **Диагностика не пишет каждые 5 секунд.** Строка пишется при смене состояния или по таймеру:
  100 циклов без изменений дают 2 строки вместо 100.
- **Ключ без валидного выходного IP выводится из ротации** — канал без выхода бесполезен.
- **Время в инструментах переводится в UTC**: хосты живут в разных зонах, и логи нельзя сшивать
  «как есть» без пересчёта.

🐾 Ни один пункт из раздела «В будущих обновлениях» в ROADMAP.md нельзя считать выполненным,
пока он там не отмечен как реализованный. Мяу!

---

# 🇬🇧 English

# 🐱 Aurora — a warm kitty with VLESS Reality and a shared mesh network 🐾

> Meow! I am **Aurora**, a warm pink-and-mint proxy kitty. I have soft paws, an honest tail
> (I don’t show it outside), and three forms:
>
> - 🐾 **my own proxy** — VLESS Reality, a pool of live keys, rotation by the *real* egress IP;
> - 🐾 **my own Aurora** — web panel, stable keys, devices, Telegram WS proxy, and “own sites”;
> - 🐾 **shared mesh network** — I can wait for friends, play with them in a shared group,
>   chat, and talk.
>
> 🐾 **Honestly:** Aurora is **not a VPN service**, **not an anonymizer**, and **not a whitelist
> bypass**. The core — your proxy, panel, shared mesh, chat, and voice — is free. Additional
> **Aurora services** can be purchased: they are extensions and modes for **your** Aurora, not a VPN
> and not a whitelist bypass. The keys, panel, and tunnel are yours. There are no VPN sales in this build.

## 🐾 What I can do for free

| What | How it works |
|---|---|
| 🐾 Own proxy | VLESS Reality, xray mixed on `:8899`, live key pool, rotation by actual egress |
| 🐾 Own Aurora | panel `:8890`, stable keys, and a link for your devices |
| 🐾 Shared mesh network | nodes in `hub`/`node` roles, signed one-time invite (proof instead of token) |
| 🐾 Up to 5 mesh clients for games | group L3 subnet `10.<group>.<node>.1`, direct UDP channel, and relay with an honest “via relay, +N ms” badge |
| 🐾 Chat and voice | inside the shared network, with no separate subscription and no counters |

No traffic quotas, no device limits, no expiry dates. The keys and xray are yours, the panel is yours,
and the tail does not stick out.

## 🐾 Additional Aurora services

Yes, some extra Aurora features are sold. But this is **not a VPN**, **not a proxy subscription**,
and **not a whitelist bypass**. I don’t sell VPN, I don’t sell access to foreign networks, and I don’t
provide whitelist bypass. Paid features are only what **Aurora itself** can do: extensions and modes
for your panel, your proxy, and your mesh.

- 🧩 **Plugins and browser extension** — block ads and trackers, enable RU mode inside the browser,
  and switch modes “this site only / global / off.”
- 📺 **Screen and video streaming** — between your devices, without third-party servers.
- 👥 **Friends without limits** — Aurora gives you five game mesh clients for free, and paid there is no
  limit: connect as many friends as you like. It works **only for your friends** and **only through our
  clients**; it does not open foreign networks or other people’s devices.
- 🏠 **NAT access only to your own Aurora** — if you’re behind a gray IP/NAT, the client reaches
  **your** node and nowhere else. It does not open other people’s Auroras.
- 🌍 **“Sites that don’t like proxies”** — a list of domains opened directly, instead of the old
  “whitelists.” This is **not whitelist bypass**; it’s mode switching for sites that dislike proxies.

> Meow. Once again: buying extra services does not make Aurora a VPN and does not provide whitelist
> bypass. It only extends what you already have.

## 🔮 How I work

**Channel and keys**

- 🌐 **VLESS Reality** — xray mixed on `:8899`, built-in pool of real keys, rotation by
  *actual* egress (the exit IP is checked by request).
- 🔑 **Key autoload** — the pool is pulled from the public GitHub list
  `barry-far/V2ray-Config` (`Splitted-By-Protocol/vless.txt`) and filtered only by Reality lines
  (presence of `pbk`).
- 🛡 **Blacklist** — `autodead_noip / autodead_conn / autodead_ping / user_removed`.
  A key without an exit IP is considered dead.
- 🌍 **“Own sites”** — sites that don’t like proxies go direct via your white IP.
  This is **not whitelist bypass**: Aurora simply switches the mode to `direct` for such domains.
  Google/YouTube are **always** through the proxy.
- 🧲 **Circuit-breaker** — a non-responding candidate is moved to `direct` without manual xray restart.

**Panel and Telegram**

- 🏠 **Web panel `:8890`** — status, keys (refresh / check / add your own / remove),
  devices with traffic and grouping by IP prefixes, Telegram WS proxy, “RU segment”,
  progress dock, and mesh network.
- ✈️ **Telegram WS proxy `:443`** — the secret is not in argv and not in the log: it is decrypted into
  a temporary file with `umask 077`, passed to the proxy via **FD 3**, and the file is deleted immediately.
- 📱 **External VLESS-Reality `:8443`** (optional) — a ready link and local QR for external connections.
- 🔄 **Auto-recovery** — limit / region / connection: VLESS rotation when the proxy channel is on,
  skipped when it is off.
- 🌍 **Languages** — interface in 10 languages (ru, en, es, de, fr, tr, pt, zh, ar, hi), dark and light
  theme, language choice lives in the browser.

**Windows build 🪟**

- 🪟 Auto-detect local and public IP, telemetry via `netstat`, auto-generate VLESS secrets,
  auto-heal TG-WS, hidden console windows for all child processes, NSSM “Aurora” service.

**Mesh network**

- 🕸 **Nodes and invite** — `hub`/`node` roles, signed one-time **invite** (proof instead of token,
  protection against reuse). Here you can play with friends.
- 🧲 **BitTorrent → direct** — this build never routes torrent traffic through the proxy (sniffing is on).
- 🚫 **No plans or limits for the proxy itself.**

**Policy and protection**

- 📜 **First-run policy** — revision 2, shown before entering the panel, acceptance is recorded.
- 🔏 **AURORA2 encryption** (ChaCha20-Poly1305) for settings, statuses, blacklist, mesh, admin token,
  and TG-WS secret; key — `data/.aurora_key`, permissions 0600/0700, old AURORA1 format is migrated.
- ✍️ **Update signature** — the release is signed with Ed25519, auto-update is fail-closed.
- 🧹 **CSP without inline JS** — all buttons work via the `data-act` allowlist; HSTS, nosniff,
  frame-ancestors, Referrer-Policy are added.
- 🔍 **Read-scope projections** — masked data is returned to untrusted clients or LAN.
- 🌐 **Optional TLS** — `AURORA_TLS_CERT`/`AURORA_TLS_KEY` enable HTTPS and HSTS.

## ⚖️ Honestly about the law

Meow. I’m a kitty, not a lawyer, and this is not legal advice.

- **I am not a VPN, not an anonymizer, and not a blocking-circumvention tool.** Aurora is your own local
  proxy: keys, panel, mesh.
- **I don’t sell or advertise VPN access or block circumvention** — not in the README, not in the
  panel, not in the bot.
- **Laws are yours.** Aurora doesn’t help you look for anything forbidden and doesn’t trade in
  someone else’s traffic; follow the laws of your country.

> 🐾 One simple rule: you don’t pay anyone for using your own keys and your own panel.
> You only ever pay Aurora for extra features — and only for yourself.

## 📝 Notes and honest gotchas

- 🐾 **In 1.10.0 there are no VPN subscriptions.** The pricing tab is removed, purchase is closed
  by a gate (403). The core (own proxy, own Aurora, shared mesh network, chat, and voice) remains free —
  without quotas or counters.
- 🪟 **Installer data directory (1.10.0).** When the app is installed, the default data directory is
  `%LOCALAPPDATA%\Aurora`. If you had 1.9.3 — move the old
  `Aurora\_internal\data` directory to `%LOCALAPPDATA%\Aurora` once, manually.
- 🌐 **Egress is checked via HTTP only**: an HTTPS probe through the proxy gives a false SSL EOF.
  Fact: `curl --proxy http://127.0.0.1:8899 http://api.ipify.org`.
- 🔁 **Key sources are static**: the `barry-far` list updates rarely. The ban list prevents keys from
  returning, and the `pbk` filter cuts out unbuildable lines.
- 🐾 **The public build** does not contain the owner’s private keys.

## 🧭 Decisions and roadmap

Detailed document — **ROADMAP.md**. Briefly:

- **Three independent contours:** proxy (VLESS Reality + panel) and game mesh contour. The head server
  tunnel listens **only on loopback** (`51821`/`51822`/`51823`) and does not go outside.
- **Game contour** — group L3 subnet `10.<group>.<node>.1`. Groups are isolated, the `/16` route inside
  the group is mandatory, the relay sends a frame only to a peer with a matching destination address.
- **Diagnostics do not write every 5 seconds.** A line is written on state change or by timer:
  100 unchanged cycles produce 2 lines instead of 100.
- **A key without a valid exit IP is removed from rotation** — a channel without an exit is useless.
- **Time in tools is converted to UTC**: hosts live in different zones, and logs cannot be stitched
  “as is” without recalculation.

🐾 No item from the “Future updates” section in ROADMAP.md can be considered done until it is marked
there as implemented. Meow!