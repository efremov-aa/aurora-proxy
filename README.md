# 🐱 Aurora — VPN-прокси сервер с панелью 🐾

Собственный прокси-сервер на базе **Xray (VLESS Reality)** с веб-панелью, Telegram WS-прокси,
автозагрузкой ключей с GitHub, ротацией по живым ключам, RU-байпасом и мониторингом устройств.

![кот](https://img.shields.io/badge/mascot-%F0%9F%90%B1-pink)
![python](https://img.shields.io/badge/python-3.12-blue)
![xray](https://img.shields.io/badge/xray-v26.9.9-blue)
![version](https://img.shields.io/badge/version-1.9.2%20%C2%AB%D0%9A%D0%BE%D1%82-%D0%BF%D0%BE%D1%87%D0%B8%D0%BD%D1%89%D0%B8%D0%BA%C2%BB-pink)

> Мяу! Готово 🐾 — панель в стиле Neko: тёплые кошачьи тона, тосты «Мяу! Готово 🐾».

## Содержание

- [📥 Загрузка](#-загрузка)
- [✨ Возможности](#-возможности)
- [🗂 Структура](#-структура)
- [🚀 Запуск](#-запуск)
- [⚙️ Настройка через env](#️-настройка-через-env)
- [🔌 API (выборка)](#-api-выборка)
- [🧪 Тесты](#-тесты)
- [📝 Замечания](#-замечания)

## 📥 Загрузка

Архивы и список изменений — в [Release v1.9.2](https://github.com/efremov-aa/aurora-proxy/releases):

- **`Aurora-v1.9.2-linux.zip`** — Linux-версия: исходники + `Dockerfile`/`docker-compose.yml`
  (Docker, `XRAY_MANAGE=proc`) или развёртывание на сервере с systemd (`aurora.service` и юниты).
- **`Aurora-v1.9.2-windows.zip`** — Windows-версия (папка `windows/`): авто-детект локального и
  публичного IP, телеметрия через `netstat`, служба **NSSM «Aurora»** (`nssm/install_service.bat`),
  бинарь xray ставится скриптом `download_xray.ps1`. Подробности — в `windows/README-windows.md`.

Версия для обеих платформ: `VERSION=1.9.2`, `VERSION_NAME=Кот-починщик`.

## ✨ Возможности

- **VLESS Reality** 🌐 — xray mixed на `:8899`, встроенный пул реальных ключей, ротация по
  реальному egress (выходной IP проверяется фактом, не «на глаз»).
- **Автозагрузка ключей** 🔑 — пул тянется с публичного GitHub-списка
  `barry-far/V2ray-Config` (`Splitted-By-Protocol/vless.txt`), фильтруется только по Reality-строкам
  (наличие `pbk`), мёртвые ключи уходят в блеклист и больше не возвращаются.
- **Чёрный список** 🛡️ — `autodead_noip / autodead_conn / autodead_ping / user_removed`.
  Ключ без выходного IP считается мёртвым (правило пользователя).
- **RU-байпас** 🇷🇺 — российские домены идут напрямую даже при включённом VPN; список (~1370 доменов)
  грузится с GitHub с кэшем и статическим фолбэком. Google/YouTube всегда в туннеле.
- **Веб-панель `:8890`** 🏠 — статус, ключи (обновить/проверить/добавить свой/удалить), устройства с
  трафиком, Telegram WS-прокси, «Ру-сегмент» (проверка доступности РФ-ресурсов), док-бар прогресса.
- **Telegram WS-прокси `:443`** ✈️ — секрет генерится и хранится в `data/tg_secret.txt`.
- **Внешний VLESS-Reality `:8443`** 📱 (опционально) — готовая ссылка + QR для подключения извне.
- **Авто-восстановление** 🔄 — лимит/регион/соединение: ротация vless при VPN ON, при VPN OFF — пропуск.
- **Админ-токен** 🛡️ — защита панели: env `AURORA_ADMIN_TOKEN` либо `data/admin_secret.json`
  (ротация на вкладке «Безопасность»), rate-limit неудачных попыток.

## 🗂 Структура

```
aurora/
├── run.py            # точка входа (запускает треды и HTTP-сервер)
├── config.py         # настройки, state, env-переменные
├── pool.py           # пул ключей + блеклист (data/keys.json|status.json|dead.json)
├── source.py         # GitHub-источники, keytest (TCP-пинг + egress через temp-xray)
├── core.py           # сборка xray.json, старт/рестарт xray, ротация, watch
├── api.py            # HTTP API (/api/state, /api/keys/*, /api/vpn_mode, ...)
├── ui.py             # загрузка static-файлов панели
├── ui/               # index.html, app.js, style.css, qr.js (локальный QR)
├── security.py       # admin-токен панели (env AURORA_ADMIN_TOKEN, rate-limit)
├── telemetry.py      # устройства (conns + трафик) по /proc и ss
├── tgws.py           # Telegram WS-прокси (секрет, статус, ссылка)
├── recovery.py       # авто-восстановление (limit/region/conn)
├── rusegment.py      # проверка доступности российских ресурсов
├── data/             # данные (НЕ в репо): keys/status/dead.json, settings.json
├── xray.json         # конфиг xray (генерится автоматически)
├── aurora.service    # systemd-unit (режим systemctl)
└── Dockerfile        # образ (режим proc)
```

## 🚀 Запуск

### Вариант 1 — Docker (рекомендуется)

```bash
cp .env.example .env    # заполните AURORA_HOST и при желании VLESS-ключи
docker compose up -d --build
```

Порты Docker: панель `:8890`, API `:8897`; mixed-прокси `:8899` и внешний VLESS `:8443`
не публикуются по умолчанию. Данные — в томе `./data`.

TG-WS в Docker-варианте не запускается и порт `:443` не публикуется. Telegram WS-прокси
запускается только в режиме systemd через `run_tgws.sh` и `tg-ws-proxy.service`.
TG-WS запускается только через systemd. Секрет хранится encrypted в `data/tg_secret.txt`; runner расшифровывает его во временный файл с `umask 077`, открывает FD 3, удаляет файл и передаёт FD 3 прокси. Секрет не попадает в argv или journal.
`AURORA_TGWS_RUNTIME_DIR` — каталог для временного runtime-секрета TG-WS; Docker TG-WS не запускает.

Xray в образ уже встроен (v26.9.9 + geoip/geosite). Управление xray — режим `XRAY_MANAGE=proc`
(подпроцесс), systemd/юниты в контейнере не нужны.

### Вариант 2 — на сервере с systemd

1. Установите **python 3.12+** (только stdlib) и **xray v26.9.9** (бинар `xray` в `$HOME` или в папке проекта,
   рядом — `geoip.dat`/`geosite.dat`).
2. Скопируйте папку в `/home/youruser/aurora/`.
3. `systemctl --user enable --now aurora` (см. `aurora.service`);
   `xray.service`, `tg-ws-proxy.service` — из репозитория, `run_tgws.sh` для TG-прокси.

> Режим управления xray на сервере — `XRAY_MANAGE=systemctl` (по умолчанию), в Docker — `proc`.

## ⚙️ Настройка через env

| Переменная | По умолчанию | Описание |
|---|---|---|
| `AURORA_HOST` | `127.0.0.1` | адрес/домен сервера для внешних ссылок (vless, tg://proxy) |
| `AURORA_WHITE_IP` | пусто | «белый» IP провайдера — фильтр, не засчитывается как выход VPN |
| `AURORA_VLESS_ENABLED` | `false` | включить внешний VLESS-Reality `:8443` |
| `AURORA_VLESS_UUID` / `AURORA_VLESS_PRIVATE_KEY` / `AURORA_VLESS_PUBLIC_KEY` | пусто | генерация: `xray x25519` для пары ключей, `uuidgen` для UUID |
| `AURORA_VLESS_SNI` | `www.microsoft.com` | SNI прикрытия Reality |
| `XRAY_MANAGE` | `systemctl` | `systemctl` (сервер) или `proc` (Docker) |
| `AURORA_DATA_DIR` | `<base>/data` | каталог данных |
| `AURORA_TGWS_PORT` | `443` | порт Telegram WS-прокси в режиме systemd; Docker-порт не публикуется |
| `AURORA_TGWS_RUNTIME_DIR` | `%t/aurora-tgws` | runtime-каталог для временного секрета TG-WS; Docker TG-WS не запускает |
| `AURORA_ADMIN_TOKEN` | пусто | admin-токен панели (Bearer для POST `/api/*`; пусто — выключено) |

## 🔌 API (выборка)

- `GET /api/state` — полное состояние (ключи, egress, vless-тег, устройства, comm).
- `POST /api/vpn_mode {on:true|false}` — включить/выключить VPN-канал.
- `POST /api/keys/refresh` — обновить ключи с GitHub (фоново).
- `POST /api/keys/check` — проверить все ключи (TCP + egress), мёртвые в блеклист.
- `POST /api/keys/add {uri}` — добавить свой ключ.
- `POST /api/keys/remove {uri}` / `POST /api/keys/active {tag}` / `POST /api/rotate`.
- `POST /api/tgws/restart` — рестарт Telegram WS-прокси.
- `POST /api/rusegment/check` — проверка ру-сегмента.
- `GET /api/log`, `GET /api/recovery/log`, `GET /api/tgws/status`.
- `GET /api/security/status` — состояние admin-токена (`enabled` + маска); `POST /api/security/rotate` — новый токен.

## 🧪 Тесты

```bash
python test_blocked.py     # BLOCKED_FLOW_OK
python test_cleanup.py     # CLEANUP_FLOW_OK
python test_comm_flow.py   # COMM_FLOW_ALL_OK (занимает ~30с)
```

## 📝 Замечания

- HTTPS-проба через прокси даёт ложный SSL EOF — проверка egress **только по HTTP**:
  `curl --proxy http://127.0.0.1:8899 http://api.ipify.org`.
- Источники ключей обновляются каждые ~15 минут (workflow репозитория barry-far), список
  статичный — при каждом refresh приходят «те же» ключи; в Aurora это не цикл: бан-лист
  dead-ключей не даёт им вернуться, а pbk-фильтр отсекает несобираемые строки.
- Публичная версия не содержит приватных ключей пользователя, станции Yandex и её кук —
  всё зашитое **удалено** и вынесено в env.
