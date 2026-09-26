# 🐱 Aurora — Windows-сборка v1.9.4 «Кот-привратник» 🐾

> Мяу! Та же кошка, только на Windows: те же модули, что и в Linux/Docker-версии, но под Windows-службу
> **NSSM «Aurora»**. Окна консоли не вылезают, IP определяется сам, обновление подписано. 🐾

![mascot](https://img.shields.io/badge/mascot-%F0%9F%90%B1-pink)
![version](https://img.shields.io/badge/version-1.9.4-pink)
![windows](https://img.shields.io/badge/windows-10%2F11%20x64-blue)

Основа — публичный репозиторий [`aurora-proxy`](https://github.com/efremov-aa/aurora-proxy)
(Linux/Docker). Общее описание возможностей, политики и переменных окружения — в
[корневом README](../README.md); здесь только отличия Windows-сборки. 🐾

## 📥 Установка (рекомендуется)

1. Скачайте **`Aurora-Setup-1.9.4.exe`** из [Releases](https://github.com/efremov-aa/aurora-proxy/releases)
   и запустите от администратора.
2. Установщик собирает `Aurora.exe` + `_internal\` (xray v26.9.9, geoip/geosite, `wintun.dll`,
   `tg-ws-proxy.exe`, nssm, `ui\`), ставит службу **NSSM «Aurora»** (автозапуск, авто-рестарт) и
   запускает её скрыто.
3. Откройте `http://<ваш-IP>:8890/` — мастер первого запуска: язык и тема, имя сервера, пароль
   админа, PIN 2FA, лимиты LAN/сканеров/rate. Порты, VLESS, TG-WS и секреты главного сервера
   в мастере **не вводятся**.

> 🪟 **Каталог данных (1.9.4).** NSSM-переменная `AURORA_DATA_DIR` не доходит до frozen-процесса,
> поэтому в **1.9.3** данные клались в `Aurora\_internal\data` вместо `%LOCALAPPDATA%\Aurora` —
> это ломало обновление «поверх» и удаление (ошибка 145). В **1.9.4** исправлено в сборке: для
> установленного приложения каталог данных по умолчанию — `%LOCALAPPDATA%\Aurora`
> (`xray.json`, `keys.json`, `settings.json`, `tg_secret.txt`, логи). Если у вас стоял 1.9.3 —
> перенесите старый `Aurora\_internal\data` в `%LOCALAPPDATA%\Aurora` один раз руками.
> Подробности — в [корневом README](../README.md#-замечания-и-известные-проблемы).

## 🛠 Установка вручную (для разработчиков)

```
1. powershell -ExecutionPolicy Bypass -File download_xray.ps1     # xray.exe + geoip/geosite в bin\
2. pip install -r requirements.txt
3. nssm\install_service.bat                                       # от администратора
```

Служба **Aurora** (автозапуск, рестарт при падении) запускает `pythonw run.py`.
Требования: Windows 10/11 x64, Python 3.8+ (**Add to PATH**), xray v26.9.9 в `bin\`.
Удаление: `nssm\uninstall_service.bat`.

## 🐾 Что умеет Windows-сборка

- 🌐 xray **VLESS Reality**: mixed-вход `:8899`, автозагрузка ключей с GitHub
  (`barry-far Splitted-By-Protocol/vless.txt`, пре-фильтр только Reality `pbk`).
- 🏠 Панель `:8890`: ключи, устройства (телеметрия через `netstat`), ру-сегмент, TG-WS,
  подключение извне, магазин и меш-сеть (по команде главного сервера).
- 🛡 Бан-лист ключей (`autodead_conn/noip/ping`, `user_removed`) — мёртвые не возвращаются.
- 🇷🇺 RU-байпас: российские домены напрямую, Google/YouTube — в туннель.
- 📱 Внешний VLESS-Reality `:8443` (опционально, через env `AURORA_VLESS_*`), авто-генерация
  секретов и локальный QR для подключения извне.
- 🕵 Авто-определение локального и публичного IP — для внешней ссылки подключения.
- 🔄 Восстановление канала: ротация VLESS при VPN ON, при VPN OFF — пропуск.
- ✈️ TG-WS-прокси с секретом через FD0 (`--secret-fd 0`) — секрет не попадает в argv и журнал.
- 🕶 Все дочерние процессы (xray, netstat, taskkill, TG-WS) запускаются со скрытыми окнами.
- 🌐 Интерфейс на 10 языках, тёмная/светлая тема, шифрование хранилищ AURORA2 (ChaCha20-Poly1305).
- 🔏 Авто-обновление с GitHub: ассет сверяется по digest + SHA-256 + подписи Ed25519 (`.sig`),
  неподписанный файл не применяется (fail-closed).

## 🚪 Порты

| Порт | Назначение |
|---|---|
| 8890 | Веб-панель Aurora |
| 8899 | xray mixed (proxy-вход) |
| 8897 | xray API (dokodemo, 127.0.0.1) |
| 443 | Telegram WS-прокси |
| 8443 | Внешний VLESS-Reality (опц.) |
| 19876+ | keytest (проверка ключей) |

Порты переопределяются env: `AURORA_UI_PORT`, `AURORA_XRAY_PORT`, `AURORA_XRAY_API_PORT`,
`AURORA_TGWS_PORT`. Firewall-правила создаются автоматически.

## ⚙️ Настройка

Файл `.env` рядом с `run.py` или переменные окружения (полный список — в `.env.example`
в корне репозитория). Чаще всего меняют:

- `AURORA_HOST` — внешний адрес для ссылок (по умолчанию авто-детект локального IP);
- `AURORA_WHITE_IP` — «белый» IP (не засчитывается как egress VPN), по умолчанию пусто;
- `AURORA_VLESS_ENABLED=false`, `AURORA_VLESS_UUID`, `AURORA_VLESS_PRIVATE_KEY`,
  `AURORA_VLESS_PUBLIC_KEY`, `AURORA_VLESS_SNI`, `AURORA_VLESS_FLOW` — внешний Reality-вход `:8443`;
- `XRAY_MANAGE=proc` — xray управляется как подпроцесс (на Windows по умолчанию).

## 🩺 Проверка

```
curl --proxy http://127.0.0.1:8899 http://api.ipify.org
```

Метод **HTTP**: HTTPS-проба через прокси может давать ложный SSL EOF. Если в `http://<ip>:8890/`
всё хорошо, а IP совпадает с выходным — кошка работает. 🐾
