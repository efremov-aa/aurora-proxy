# Aurora v1.0 — конфигурация ядра.
# Всё, что меняется между деплоями: пути, порты, источники ключей, режимы.

import json
import os
import subprocess
import sys
import threading
import time

# Windows: флаг CREATE_NO_WINDOW скрывает окна консоли дочерних процессов
# (xray run/keytest/statsquery/netstat/netsh/taskkill/tg-ws-proxy и т.п.).
HIDE_FLAG = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0

VERSION = "1.9.0"
VERSION_NAME = "Кот-правозащитник"
APP_NAME = "Aurora"

# История версий для вкладки «Версии» (v, имя, дата).
VERSION_HISTORY = (
    ("1.9.0", "Кот-правозащитник", "24.09.2026"),
    ("1.8.0", "Кот-именитый", "24.09.2026"),
    ("1.7.0", "Кот-дипломат", "24.09.2026"),
    ("1.6.0", "Кот-банкир", "24.09.2026"),
    ("1.5.0", "Кот в мешке", "24.09.2026"),
    ("1.4.0", "Подписки", "22.09.2026"),
    ("1.3.1", "Мур-апдейт", "22.09.2026"),
    ("1.3.0", "Mesh", "22.09.2026"),
    ("1.2.0", "Windows-fix", "19.09.2026"),
    ("1.1.0", "Свежая рыба", "19.09.2026"),
)

# --- политика сервиса (GitHub-сборки: первая страница — правила) ---
# POLICY_REV меняется ТОЛЬКО при изменении POLICY_TEXT.
# REV > принятого => панель снова требует принять политику (после обновления).
POLICY_REV = 2
POLICY_TEXT = """ПОЛИТИКА И ПРАВИЛА ПРОЕКТА AURORA «Кот в законе»

1. НАЗНАЧЕНИЕ
Aurora — персональный VPN/прокси-сервер. Установка и использование подразумевают
полное согласие с настоящей политикой. Если вы не согласны — не устанавливайте.

2. РАЗРЕШЕНО
- подключать собственные устройства (телефоны, планшеты, ПК, телевизоры);
- использовать прокси в личных целях: приватность, доступ к заблокированным
  сайтам, безопасные подключения в общественных сетях;
- привлекать в свою сеть (меш) друзей с их согласия и на тех же правилах.

3. ЗАПРЕЩЕНО
- раздавать доступ посторонним без явного согласия владельца сервера;
- использовать канал для DDoS, массового сканирования, покупки запрещённого,
  кражи данных, мошенничества и любых нарушений закона;
- обходить лимиты тарифов, маскировать свой трафик против владельца сервера;
- продавать/перепродавать ключи и подписки без разрешения владельца;
- вмешиваться в работу серверного ПО или панели управления.

4. ОБЯЗАТЕЛЬСТВА ВЛАДЕЛЬЦА СЕРВЕРА
- шифровать хранимые данные (подписки, ключи) и ограничивать доступ к файлам;
- не передавать персональные данные клиентов третьим лицам без оснований;
- немедленно уведомлять клиентов об изменении правил.
При изменении текста политики ревизия увеличивается, и при следующем запуске
панель снова запросит принятие — это обязательное условие продолжения работы.

5. СОТРУДНИЧЕСТВО С ПРАВООХРАНИТЕЛЬНЫМИ ОРГАНАМИ
Владелец гарантирует анонимность и конфиденциальность ВСЕГДА — до момента
нарушения закона. По официальному письменному запросу правоохранительных
органов (в т.ч. по официальным каналам связи) владелец обязан предоставить
все имеющиеся данные об абоненте (адрес, логи, тайминг и т.п.).
При нарушении закона любой страны владелец обязан сотрудничать
с правоохранительными органами. Без официального запроса данные не передаются.

6. ОГРАНИЧЕНИЕ ОТВЕТСТВЕННОСТИ
Сервер предоставляется «как есть». Владелец не отвечает за доступность сторонних
ресурсов, за действия клиентов сети и за последствия нарушения настоящих правил.

7. СОГЛАСИЕ
Нажатие кнопки «Принять» на панели управления означает безоговорочное принятие
настоящей политики для всего оборудования, подключённого к серверу."""

_BOOT_TS = time.time()   # время старта процесса (для /api/settings.uptime)

# --- авто-обновление (GitHub Releases) ---
# Обязательное: публичная сборка всегда обновляется с этого репо.
# Локальное отключение/обход НЕ предусмотрен (управляется только политикой релизов).
UPDATE_REPO = "efremov-aa/aurora-proxy"
UPDATE_CHECK_INTERVAL = 15 * 60  # проверка признаков обновления каждые 15 минут

# --- пути (относительно корня проекта) ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("AURORA_DATA_DIR", os.path.join(BASE_DIR, "data"))
XRAY_CONFIG = os.path.join(BASE_DIR, "xray.json")
LOG_FILE = os.path.join(BASE_DIR, "aurora.log")

os.makedirs(DATA_DIR, exist_ok=True)

if getattr(sys, "frozen", False):
    # в frozen-бандле BASE_DIR указывает на _internal (read-only при Program Files) —
    # журнал и xray.json переносим в каталог данных пользователя (AURORA_DATA_DIR)
    XRAY_CONFIG = os.path.join(DATA_DIR, "xray.json")
    LOG_FILE = os.path.join(DATA_DIR, "aurora.log")

# --- подписки (продаваемые VLESS-ключи клиентам) ---
SUBS_FILE = os.path.join(DATA_DIR, "subs.json")
SUBS_PLANS_FILE = os.path.join(DATA_DIR, "plans.json")
AUTO_REFRESH_INTERVAL = 1800   # фоновый цикл обновления github-ключей (сек)

SUBS_PLANS = {
    "free": {"name": "Бесплатный", "price": 0, "bytes": 10 * 1024 ** 3, "days": 30,
             "devices": 1, "keys": 1,
             "features": ["1 устройство", "10 ГБ трафика", "Базовая локация 🇷🇺"],
             "features_no": ["Меш-сеть", "Внешний доступ извне", "Приоритетная поддержка"]},
    "basic": {"name": "Базовый", "price": 399, "bytes": 100 * 1024 ** 3, "days": 30,
              "devices": 3, "keys": 2,
              "features": ["3 устройства", "100 ГБ трафика", "Все локации + 🇩🇪 🇳🇱",
                           "Меш-сеть", "Внешний доступ извне"],
              "features_no": ["Приоритетная поддержка"]},
    "prem": {"name": "Премиум", "price": 799, "bytes": 0, "days": 30,
             "devices": 10, "keys": 5,
             "features": ["10 устройств", "Безлимит трафика", "Все локации + эксклюзив",
                          "Меш-сеть + приоритет", "Внешний доступ извне",
                          "Приоритетная поддержка 24/7"],
             "features_no": []},
}
SUBS_PLAN_DEFAULT = "free"
SUBS_MASK_UUID = True  # в UI показывать маскированные uuid подключений

# --- порты (конфигурируются через env AURORA_*_PORT; дефолты совместимы с сервером) ---
UI_PORT = int(os.environ.get("AURORA_UI_PORT", "8890"))            # панель Aurora
XRAY_PORT = int(os.environ.get("AURORA_XRAY_PORT", "8899"))        # mixed-вход xray (http+socks)
XRAY_API_PORT = int(os.environ.get("AURORA_XRAY_API_PORT", "8897"))  # докодемо-API xray (статистика)
TGWS_PORT = int(os.environ.get("AURORA_TGWS_PORT", "443"))        # Telegram WS-прокси (443; 1443 блокировался РКН снаружи)

# --- сеть (значения из env, дефолты безопасны) ---
# На Windows локальный адрес авто-определяется (для внешних ссылок/QR).
_DETECT_LOCK = threading.Lock()
_PUBLIC = {"ip": None, "ts": 0.0}
_PUBLIC_TTL_S = 3600.0


def _detect_local_ip():
    """Локальный IP машины (UDP-трюк без реального трафика)."""
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and not ip.startswith("127."):
            return ip
    except OSError:
        pass
    return "127.0.0.1"


def _fetch_public_ip():
    """Публичный IP через ipify (без прокси)."""
    import urllib.request
    try:
        with urllib.request.urlopen("https://api.ipify.org?format=json", timeout=5) as r:
            return json.loads(r.read().decode("utf-8")).get("ip", "")
    except Exception:
        return ""


def get_public_ip():
    """Публичный IP с TTL-кэшем (для внешних ссылок/QR)."""
    import time as _t
    now = _t.time()
    if _PUBLIC["ip"] and (now - _PUBLIC["ts"]) < _PUBLIC_TTL_S:
        return _PUBLIC["ip"]
    with _DETECT_LOCK:
        if _PUBLIC["ip"] and (_t.time() - _PUBLIC["ts"]) < _PUBLIC_TTL_S:
            return _PUBLIC["ip"]
        ip = _fetch_public_ip()
        if ip:
            _PUBLIC["ip"] = ip
            _PUBLIC["ts"] = _t.time()
        return _PUBLIC["ip"] or ""


def refresh_public_ip_async():
    """Фоновое обновление публичного IP (на старте)."""
    def _bg():
        try:
            get_public_ip()
        except Exception:
            pass
    threading.Thread(target=_bg, daemon=True).start()


VM_HOST = os.environ.get("AURORA_HOST", "") or _detect_local_ip()  # адрес сервера для внешних ссылок/QR
WHITE_IP = os.environ.get("AURORA_WHITE_IP", "")      # белый IP провайдера — фильтр «не выход VPN»

# --- источники github-ключей ---
# Репо barry-far/V2ray-Config: файлы регенерируются workflow main.yml каждые 15 минут.
GITHUB_SOURCES = ["https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt"]

# --- ру-байпас: RU-домены уходят на direct (без VPN) ---
# Базовый список (актуально навсегда: обновления ПО, ключевые RU-сервисы).
# При недоступности github-источников используется ТОЛЬКО он.
RU_DOMAINS_STATIC = [
    "github.com", "githubusercontent.com", "raw.githubusercontent.com",
    "github.io", "huggingface.co", "hf-mirror.com",
    "pypi.org", "files.pythonhosted.org", "npmjs.org",
    "registry.npmjs.org", "crates.io", "static.crates.io",
    "nuget.org", "download.visualstudio.microsoft.com", "dotnet.microsoft.com",
    "pypi.python.org", "files.pythonhosted.org",
    "jetbrains.com", "download.jetbrains.com", "plugins.jetbrains.com",
    "opencode.ai",
    "yandex.ru", "ya.ru", "vk.com", "ok.ru", "mail.ru", "vk.ru",
    "rutube.ru", "gosuslugi.ru", "mos.ru", "kremlin.ru", "gov.ru",
]

# Списки с github для расширения базового набора (плейн-домены ИЛИ domain:...).
RU_DOMAINS_SOURCES = [
    "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/whitelist.txt",
    "https://raw.githubusercontent.com/UnRKN/ru-blocklist/refs/heads/main/ru-blocklist-domain.txt",
]

# Кэш загруженного списка (TTL 900с; при сбое = пустой, работает фолбэк).
RU_DOMAINS_TTL_S = 900
RU_DOMAINS_LOCK = threading.Lock()
RU_DOMAINS_CACHE = {"list": [], "ts": 0.0}

# --- лимиты ---
MAX_USER_KEYS = 120       # максимум ключей в пуле (60 -> 120: большая выборка из 2529 reality-ключей)
MAX_PING_MS = 700        # выше = ключ мёртв (правило юзера: >700мс мёртвый)
EGRESS_TTL_S = 60         # кэш egress
ROTATE_COOLDOWN_S = 180.0 # демпф ротации
VPN_KEYS_N = 4            # сколько ключей попадает в xray.json при VPN ON

# --- внешнее подключение (VLESS-Reality inbound :8443) ---
# На Windows/публичной сборке ключи генерируются автоматически при первом старте
# (см. ensure_vless()): uuid + пара x25519 через `xray x25519`, сохраняются в data/vless_public.json.
# Вручную можно переопределить через env AURORA_VLESS_* (см. README/.env.example).
VLESS_PUBLIC = {
    "enabled": os.environ.get("AURORA_VLESS_ENABLED", "true").lower() != "false",
    "port": int(os.environ.get("AURORA_VLESS_PORT", "8443")),
    "host": os.environ.get("AURORA_VLESS_HOST", "127.0.0.1"),
    "uuid": os.environ.get("AURORA_VLESS_UUID", ""),
    "private_key": os.environ.get("AURORA_VLESS_PRIVATE_KEY", ""),
    "public_key": os.environ.get("AURORA_VLESS_PUBLIC_KEY", ""),
    "short_id": os.environ.get("AURORA_VLESS_SHORT_ID", ""),
    "sni": os.environ.get("AURORA_VLESS_SNI", "www.microsoft.com"),
    "flow": os.environ.get("AURORA_VLESS_FLOW", "xtls-rprx-vision"),
}

_VLESS_FILE = os.path.join(DATA_DIR, "vless_public.json")


def _gen_vless_material():
    """uuid + пара x25519 через `xray x25519`. Возвращает (uuid, priv, pub) или None."""
    import subprocess
    import uuid as _uuid
    xbin = os.path.join(BASE_DIR, "bin", "xray.exe")
    if not os.path.exists(xbin):
        xbin = os.path.join(BASE_DIR, "xray")
    if not os.path.exists(xbin):
        return None
    try:
        out = subprocess.run([xbin, "x25519"], capture_output=True, text=True,
                             timeout=10, creationflags=HIDE_FLAG).stdout
    except Exception:
        return None
    priv = pub = ""
    for ln in out.splitlines():
        if ln.startswith("PrivateKey:"):
            priv = ln.split(":", 1)[1].strip()
        elif ln.startswith("PublicKey:"):
            pub = ln.split(":", 1)[1].strip()
    if not priv or not pub:
        return None
    return str(_uuid.uuid4()), priv, pub


def ensure_vless():
    """Авто-включение внешнего VLESS: env -> сохранённый -> автогенерация. Возвращает VLESS_PUBLIC."""
    global VLESS_PUBLIC
    if VLESS_PUBLIC.get("enabled") and VLESS_PUBLIC.get("uuid") and VLESS_PUBLIC.get("private_key"):
        return VLESS_PUBLIC
    saved = {}
    try:
        with open(_VLESS_FILE, "r", encoding="utf-8") as f:
            saved = json.load(f)
    except (OSError, ValueError):
        saved = {}
    if saved.get("uuid") and saved.get("private_key") and saved.get("public_key"):
        VLESS_PUBLIC = {
            "enabled": True,
            "port": int(saved.get("port", VLESS_PUBLIC.get("port", 8443))),
            "host": saved.get("host", VLESS_PUBLIC.get("host", "127.0.0.1")),
            "uuid": saved["uuid"],
            "private_key": saved["private_key"],
            "public_key": saved["public_key"],
            "short_id": saved.get("short_id", ""),
            "sni": saved.get("sni", VLESS_PUBLIC.get("sni", "www.microsoft.com")),
            "flow": saved.get("flow", VLESS_PUBLIC.get("flow", "xtls-rprx-vision")),
        }
        return VLESS_PUBLIC
    made = _gen_vless_material()
    if not made:
        log("vless: xray недоступен, внешний VLESS не сгенерирован")
        return VLESS_PUBLIC
    _uuid, priv, pub = made
    VLESS_PUBLIC = {
        "enabled": True,
        "port": VLESS_PUBLIC.get("port", 8443),
        "host": VLESS_PUBLIC.get("host", "127.0.0.1"),
        "uuid": _uuid,
        "private_key": priv,
        "public_key": pub,
        "short_id": "",
        "sni": VLESS_PUBLIC.get("sni", "www.microsoft.com"),
        "flow": VLESS_PUBLIC.get("flow", "xtls-rprx-vision"),
    }
    try:
        with open(_VLESS_FILE + ".tmp", "w", encoding="utf-8") as f:
            json.dump(VLESS_PUBLIC, f, indent=2)
        os.replace(_VLESS_FILE + ".tmp", _VLESS_FILE)
    except OSError:
        pass
    log("vless: внешний VLESS сгенерирован (%s:%d)" % (VLESS_PUBLIC["host"], VLESS_PUBLIC["port"]))
    return VLESS_PUBLIC


def open_firewall(ports=None):
    """Windows: netsh правила для наших портов (best-effort, ошибки игнорируются).

    ports: явный список портов; по умолчанию UI/XRAY/XRAY_API/TGWS/VLESS(8443).
    """
    if os.name != "nt":
        return
    import subprocess
    _ports = list(ports) if ports else [
        UI_PORT, XRAY_PORT, XRAY_API_PORT, TGWS_PORT,
        int(VLESS_PUBLIC.get("port", 8443)),
    ]
    seen = {}
    ordered = []
    for p in _ports:
        if p in seen:
            continue
        seen[p] = 1
        ordered.append(p)
    for p in ordered:
        try:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 "name=Aurora_%d" % p, "dir=in", "action=allow",
                 "protocol=TCP", "localport=%d" % p],
                capture_output=True, timeout=10, creationflags=HIDE_FLAG)
        except Exception:
            pass
    log("firewall: правила добавлены для портов %s" % ",".join(str(p) for p in ordered))

# --- агент ПК (recovery, команды) ---
AGENT_TOKEN = ""
AGENT_UPDATE_URL = ""
AGENT_UPDATE_VERSION = ""

# --- настройки (сохранение в data/settings.json) ---
_LOCK = threading.RLock()   # RLock: set() берёт лок, save_settings берёт вложенно
_SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")

_SETTINGS_DEFAULTS = {
    "vpn_mode": True,        # True = VPN активен (final = лучший ключ), False = прямой
    "auto_recovery": True,   # авто-восстановление канала через агента
    "continue_text": "",     # текст при отправке continue
    "ui_token": "",          # X-Auth-токен панели (пусто = как раньше, секреты видны в LAN)
    # --- v1.4.0: сервер / меш / безопасность ---
    "server_name": "Home",       # имя сервера (хаб меша)
    "auto_refresh": True,        # автообновление github-ключей фоновым циклом
    "lan_only": False,           # панель: loopback + LAN (дефолт выключен для публичного деплоя)
    "block_scanners": False,     # 403 на шаблонные пути сканеров/ботов
    "rate_limit": True,          # демпфер 600 req/min на не-loopback IP
    "mesh_id": "mesh-aurora-home",  # идентификатор меша (invite-ссылка)
    "mesh_token": "",            # токен invite (генерируется при первом запросе)
    "twofa": False,              # требовать X-2FA на POST /api/*
    "ui_pin": "",                # пин 2FA (заголовок X-2FA)
    "show_mesh": False,          # показывать вкладку «Меш-сеть» в панели (ТОЛЬКО по команде мастера)
    "show_subs": False,          # показывать вкладку «Магазин» в панели (ТОЛЬКО по команде мастера)
    "mesh_master": False,        # головной сервер: раздаёт политику видимости клиентам меша
    "policy_rev_accepted": 0,    # принятая ревизия политики (0 = не принимал)
    "segment_title": "",         # своё название сегмента монитора (пусто = авто)
    "segment_regions": [],       # выбранные регионы (ru/global/eu/asia)
    "segment_custom": "",        # пользовательские домены (по одному на строку)
    # --- v1.8.0: гологоловной сервер (master) / авто-джойн / замок тестового сервера ---
    "master_addr": "",           # URL головного сервера (напр. http://10.1.136.56:5053)
    "master_token": "",          # секрет регистрации у головного (выдаёт головной)
    "auto_join": False,          # при старте регистрироваться в меше головного (авто-джуin)
    "master_only": False,        # замок: подключиться/использовать может только головной
    # --- windows: белый список (белый IP + кастомные домены на direct) ---
    "white_ip": "",          # белый IP провайдера (переопределяет env AURORA_WHITE_IP)
    "bypass_domains": [],    # кастомный белый список доменов, идущих на direct (в дополнение к RU-байпасу)
}

_settings = dict(_SETTINGS_DEFAULTS)

# --- разделяемые runtime-состояния (фоновые треды пишут, web читает) ---
STATE = {
    "conns": 0,
    "devices": {},          # {ip: {name, conns, upload, download}}
    "up": 0,
    "down": 0,
    "tgws": {"running": False, "port_open": False, "secret_ok": False},
    "comm": {"state": "idle", "msg": ""},
    "vless_now": "-",
    "egress_ip": "-",
    "final_mode": "direct",
    "rusegment": {"running": False, "results": [], "ts": 0},
}
STATE_LOCK = threading.Lock()

LOG_LOCK = threading.Lock()


def log(msg):
    """Единая запись в лог (время + сообщение), потокобезопасно."""
    ts = _ts()
    with LOG_LOCK:
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write("[%s] %s\n" % (ts, msg))
        except OSError:
            pass


def log_tail(n=40):
    """Последние n строк LOG_FILE (для /api/log). Возвращает список строк."""
    try:
        with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
        return lines[-n:]
    except OSError:
        return []


# --- RU-байпас: загрузка списка доменов (фолбэк на статический) ---
def _normalize_ru_line(line):
    """Из сырой строки github-списка -> домен без префикса domain: (или None)."""
    line = line.strip().lower()
    if not line or line.startswith(("#", "!", "//")):
        return None
    if line.startswith("domain:"):
        d = line[len("domain:"):].strip()
        return d or None
    if line.startswith("*.") or line.startswith("."):
        d = line.lstrip("*.")
        return d or None
    if " " in line or "/" in line:
        return None
    return line


def _fetch_ru_sources():
    """Скачивает RU_DOMAINS_SOURCES с github, возвращает список доменов."""
    import urllib.request
    domains = []
    seen = {}
    for url in RU_DOMAINS_SOURCES:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Aurora/1.0"})
            with urllib.request.urlopen(req, timeout=20) as r:
                body = r.read().decode("utf-8", errors="replace")
            for ln in body.splitlines():
                d = _normalize_ru_line(ln)
                if d and d not in seen:
                    seen[d] = 1
                    domains.append(d)
        except Exception as e:
            log("ru-bypass: источник %s недоступен: %s" % (url, e))
    return domains


def ru_domains():
    """Актуальный список RU-доменов для байпаса (кэш TTL + фолбэк на статику)."""
    now = time.time()
    with RU_DOMAINS_LOCK:
        cached = RU_DOMAINS_CACHE["list"]
        if cached and now - RU_DOMAINS_CACHE["ts"] < RU_DOMAINS_TTL_S:
            return cached
    fetched = _fetch_ru_sources()
    with RU_DOMAINS_LOCK:
        # фолбэк: при пустой загрузке — статический минимум
        merged = fetched if fetched else list(RU_DOMAINS_STATIC)
        # дедуп цельном (static мог прийти первым)
        seen = {}
        final = []
        for d in merged + RU_DOMAINS_STATIC:
            if d and d not in seen:
                seen[d] = 1
                final.append(d)
        RU_DOMAINS_CACHE["list"] = final
        RU_DOMAINS_CACHE["ts"] = now
        log("ru-bypass: доменов %d (%s)" % (
            len(final), "github" if fetched else "static fallback"))
    return RU_DOMAINS_CACHE["list"]


# --- сегменты монитора (t-rusegment): регионы + свои домены ---
REGIONS = {
    "ru": {"title": "Ру-сегмент", "flag": "🇷🇺", "domains": [
        "yandex.ru", "ya.ru", "vk.com", "ok.ru", "mail.ru", "rambler.ru",
        "lenta.ru", "rbc.ru", "gazeta.ru", "kommersant.ru", "rg.ru",
        "kremlin.ru", "gosuslugi.ru", "gov.ru", "sberbank.ru", "tinkoff.ru",
        "avito.ru", "ozon.ru", "wildberries.ru", "kinopoisk.ru", "rutube.ru",
        "matchtv.ru", "kp.ru", "mos.ru",
    ]},
    "global": {"title": "Международный сегмент", "flag": "🌐", "domains": [
        "google.com", "youtube.com", "wikipedia.org", "github.com",
        "cloudflare.com", "mozilla.org", "openai.com", "netflix.com",
        "amazon.com", "reddit.com", "x.com", "instagram.com",
        "microsoft.com", "apple.com", "stackoverflow.com", "medium.com",
    ]},
    "eu": {"title": "ЕС-сегмент", "flag": "🇪🇺", "domains": [
        "bbc.com", "dw.com", "lemonde.fr", "elpais.com", "ilpost.it",
        "france24.com", "rtve.es", "europarl.europa.eu", "rtl.be", "oe24.at",
    ]},
    "asia": {"title": "Азия", "flag": "🌏", "domains": [
        "baidu.com", "alibaba.com", "taobao.com", "tmall.com",
        "naver.com", "yahoo.co.jp", "rakuten.co.jp", "kakaku.com",
        "sina.com.cn", "line.me",
    ]},
}


def _seg_line_to_domain(line):
    """Нормализация строки списка доменов (переиспользует _normalize_ru_line)."""
    d = _normalize_ru_line(line)
    if not d or "." not in d:
        return None
    return d


def segment_regions():
    """Выбранные регионы списком (только существующие в REGIONS)."""
    raw = get("segment_regions") or ["ru"]
    if isinstance(raw, str):
        raw = [raw]
    out = []
    for r in raw:
        if r in REGIONS and r not in out:
            out.append(r)
    return out or ["ru"]


def segment_title():
    """Название вкладки монитора: своё или авто (один регион — его имя, иначе флаги)."""
    own = (get("segment_title") or "").strip()
    if own:
        return own
    sel = segment_regions()
    if len(sel) == 1 and REGIONS.get(sel[0], {}).get("title"):
        return REGIONS[sel[0]]["title"]
    flags = [REGIONS[r]["flag"] for r in sel]
    return "Сегмент" if not flags else " ".join(flags) + " сегмент"


def segment_flag():
    """Флаг/эмодзи вкладки монитора (регионы, иначе глобус)."""
    sel = segment_regions()
    if len(sel) == 1:
        return REGIONS[sel[0]].get("flag", "🌐")
    return "🌐"


# --- v1.8.0: рандомное уникальное имя сервера ---
_NAME_ADJ = ["Мур", "Барс", "Снеж", "Рыж", "Полос", "Тих", "Быстр", "Хит", "Добр", "Гром"]
_NAME_NOUN = ["кот", "барсик", "мурзик", "лео", "тишка", "снежок", "рыжик", "марс", "симба", "том"]


def random_server_name(taken=None, tries=20):
    """Случайное имя сервера, не пересекающееся с уже существующими (taken)."""
    import secrets
    seen = {str(x or "").strip().lower() for x in (taken or [])}
    for _ in range(tries):
        name = "%s-%s-%s" % (
            _NAME_ADJ[secrets.randbelow(len(_NAME_ADJ))],
            _NAME_NOUN[secrets.randbelow(len(_NAME_NOUN))],
            secrets.token_hex(2),
        )
        if name.lower() not in seen:
            return name
    return "Aurora-%s" % secrets.token_hex(3)


def segment_domains():
    """Домены монитора: выбранные регионы + пользовательские домены (custom)."""
    domains = []
    for r in segment_regions():
        for d in REGIONS[r]["domains"]:
            if d not in domains:
                domains.append(d)
    custom = (get("segment_custom") or "").strip()
    if custom:
        for ln in custom.splitlines():
            d = _seg_line_to_domain(ln)
            if d and d not in domains:
                domains.append(d)
    return domains


def policy_required():
    """True, пока не принята актуальная ревизия политики (после обновления — снова True)."""
    try:
        acc = int(get("policy_rev_accepted", 0) or 0)
    except (TypeError, ValueError):
        acc = 0
    return POLICY_REV > acc


def _ts():
    import datetime
    return datetime.datetime.now().strftime("%H:%M:%S")


# --- настройки ---
def load_settings():
    """Читает data/settings.json (выживают только известные ключи)."""
    global _settings, WHITE_IP
    try:
        with open(_SETTINGS_FILE, "r", encoding="utf-8") as f:
            raw = json.load(f)
        merged = dict(_SETTINGS_DEFAULTS)
        merged.update({k: raw[k] for k in raw if k in _SETTINGS_DEFAULTS})
        _settings = merged
        if merged.get("white_ip"):
            WHITE_IP = merged["white_ip"].strip()
    except (OSError, ValueError):
        _settings = dict(_SETTINGS_DEFAULTS)


def save_settings():
    """Атомарно пишет настройки в data/settings.json."""
    tmp = _SETTINGS_FILE + ".tmp"
    with _LOCK:
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(_settings, f, indent=2, ensure_ascii=False)
            os.replace(tmp, _SETTINGS_FILE)
        except OSError as e:
            log("settings: не удалось сохранить: %s" % e)


def reset_settings():
    """Сброс настроек к значениям по умолчанию (кнопка «Сбросить всё»)."""
    global _settings
    with _LOCK:
        _settings = dict(_SETTINGS_DEFAULTS)
    save_settings()
    log("settings: сброшены к значениям по умолчанию")


# --- тарифы: переопределение из data/plans.json (редактор тарифов в UI) ---
_SUBS_PLANS_LOCK = threading.RLock()


def save_plans():
    """Сохраняет текущие SUBS_PLANS в data/plans.json (атомарно)."""
    with _SUBS_PLANS_LOCK:
        tmp = SUBS_PLANS_FILE + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(SUBS_PLANS, f, indent=2, ensure_ascii=False)
            os.replace(tmp, SUBS_PLANS_FILE)
        except OSError as e:
            log("plans: не удалось сохранить: %s" % e)


def _load_plans_override():
    """Переопределение тарифов из data/plans.json (валидные планы перезаписывают)."""
    try:
        if not os.path.exists(SUBS_PLANS_FILE):
            return
        with open(SUBS_PLANS_FILE, "r", encoding="utf-8") as f:
            raw = json.load(f)
        valid = {}
        need = ("name", "price", "bytes", "days", "devices", "keys")
        for k, v in raw.items():
            if isinstance(v, dict) and all(x in v for x in need):
                # мержим с дефолтом: features/features_no не обязательны в json,
                # но сохраняем, если заданы (иначе описание тарифа теряется)
                base = dict(SUBS_PLANS.get(k, {}))
                base.update(v)
                valid[k] = base
        if valid:
            SUBS_PLANS.update(valid)
            log("plans: тарифы переопределены из data/plans.json (%d)" % len(valid))
    except (OSError, ValueError) as e:
        log("plans: не читается plans.json: %s" % e)


def get(key, default=None):
    return _settings.get(key, default)


def set(key, value):
    with _LOCK:                  # защита от RuntimeError при параллельном save_settings
        _settings[key] = value
    save_settings()


def update_state_sub(key, **kw):
    """Атомарный апдейт вложенного словаря STATE (напр. tgws) под локом."""
    with STATE_LOCK:
        STATE.setdefault(key, {}).update(kw)


def update_state(**kw):
    """Безопасное обновление /api/state-словаря."""
    with STATE_LOCK:
        STATE.update(kw)


def get_state():
    with STATE_LOCK:
        return dict(STATE)


def state_fields():
    """Плоская копия STATE для JSON-ответа."""
    return get_state()


# Переопределение тарифов из data/plans.json — в конце модуля (после log()).
_load_plans_override()


# --- белый список (белый IP + кастомные домены на direct) ---
def get_white_ip():
    """Белый IP провайдера: settings override -> env -> ''."""
    v = (_settings.get("white_ip") or "").strip()
    return v or (os.environ.get("AURORA_WHITE_IP", "") or "").strip()


def set_white_ip(ip):
    """Сохраняет белый IP в настройки (и обновляет WHITE_IP). Возвращает новый IP."""
    global WHITE_IP
    WHITE_IP = (ip or "").strip()
    _settings["white_ip"] = WHITE_IP
    save_settings()
    return WHITE_IP


def get_bypass_domains():
    """Кастомный белый список доменов (direct-байпас)."""
    return list(_settings.get("bypass_domains") or [])


def set_bypass_domains(domains):
    """Сохраняет список кастомных доменов (direct-байпас). Возвращает сохранённый список."""
    clean = []
    seen = {}
    for d in domains or []:
        d = str(d).strip().lower()
        if d and d not in seen and not d.startswith(("http://", "https://", "www.")):
            seen[d] = 1
            clean.append(d)
    _settings["bypass_domains"] = clean
    save_settings()
    return clean