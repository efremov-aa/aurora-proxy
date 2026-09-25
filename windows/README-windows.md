# Aurora Proxy — Windows (сборка v1.9.1 «Кот-крепость»)

Прокси-сервер VLESS Reality с веб-панелью для Windows. Основа — тот же код, что в публичном репозитории
`aurora-proxy` (Linux/Docker); здесь он адаптирован под Windows-сервис NSSM.

## Возможности

- xray VLESS Reality — mixed-вход :8899, автонастройка ключей с GitHub (barry-far `Splitted-By-Protocol/vless.txt`, пре-фильтр только Reality `pbk`)
- Веб-панель :8890 (ключи, устройства, ру-сегмент, TG-WS, подключение извне)
- Чёрный список (`autodead_conn/noip/ping`, `user_removed`) — мёртвые ключи не возвращаются
- RU-байпас: российские домены идут напрямую, остальное — в туннель
- Внешний VLESS-Reality :8443 (опционально, через env `AURORA_VLESS_*`)
- Авто-определение локального и публичного IP (для внешней ссылки подключения)
- Восстановление канала: ротация VLESS при VPN ON, при VPN OFF — пропуск

## Требования

- Windows 10/11 x64
- Python 3.8+ (python.org, **Add to PATH**)
- Библиотека `tg-ws-proxy` (`pip install -r requirements.txt`)
В комплекте `bin\tg-ws-proxy.exe` поддерживает FD; секрет передаётся через stdin FD0 (`--secret-fd 0`) и никогда не передаётся через argv.
- Xray для Windows: `xray.exe` + `geoip.dat` + `geosite.dat` (+ `wintun.dll`) в папке `bin\`

## Установка

1. Скачайте xray в `bin\`:
   ```
   powershell -ExecutionPolicy Bypass -File download_xray.ps1
   ```
2. Установите зависимости + службу (запуск `nssm\install_service.bat` от администратора):
   ```
   powershell -ExecutionPolicy Bypass -File nssm\setup.ps1
   ```
   либо вручную: `pip install -r requirements.txt` → `nssm\install_service.bat`.

Служба **Aurora** (автозапуск, рестарт при падении) запускает `pythonw run.py`.

## Порты

| Порт  | Назначение                       |
|-------|----------------------------------|
| 8890  | Веб-панель Aurora                |
| 8899  | xray mixed (proxy-вход)          |
| 8897  | xray API (dokodemo 127.0.0.1)    |
| 443   | TG-WS proxy                       |
| 8443  | Внешний VLESS-Reality (опц.)      |
| 19876+| keytest (проверка ключей)        |

## Настройка

Создайте рядом файл `.env` (или переменные окружения) — см. `.env.example` в корне репозитория:
- `AURORA_HOST` — внешний/ваш адрес для ссылок (по умолчанию авто-детект локального IP)
- `AURORA_WHITE_IP` — ваш «белый» IP (не засчитывается как egress VPN), по умолчанию пусто
- `AURORA_VLESS_ENABLED=false`, `AURORA_VLESS_UUID`, `AURORA_VLESS_PRIVATE_KEY`, `AURORA_VLESS_PUBLIC_KEY`, `AURORA_VLESS_SNI`, `AURORA_VLESS_FLOW` — внешний Reality-вход :8443
- `XRAY_MANAGE=proc` — xray управляется как подпроцесс (на Windows по умолчанию)

## Проверка

```
curl --proxy http://127.0.0.1:8899 http://api.ipify.org
```
(метод HTTP; HTTPS через прокси может давать ложный SSL EOF)

## Удаление

```
nssm\uninstall_service.bat
```
