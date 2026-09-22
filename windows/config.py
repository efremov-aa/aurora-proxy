# Aurora v1.0 — конфигурация ядра.
# Всё, что меняется между деплоями: пути, порты, источники ключей, режимы.

import json
import os
import threading
import time

VERSION = "1.3.0"
VERSION_NAME = "Mesh"
APP_NAME = "Aurora"

# --- пути (относительно корня проекта) ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("AURORA_DATA_DIR", os.path.join(BASE_DIR, "data"))
XRAY_CONFIG = os.path.join(BASE_DIR, "xray.json")
LOG_FILE = os.path.join(BASE_DIR, "aurora.log")

os.makedirs(DATA_DIR, exist_ok=True)

# --- порты (конфигурируются через env AURORA_*_PORT; дефолты совместимы с сервером) ---
UI_PORT = int(os.environ.get("AURORA_UI_PORT", "8890"))            # панель Aurora
XRAY_PORT = int(os.environ.get("AURORA_XRAY_PORT", "8899"))        # mixed-вход xray (http+socks)
XRAY_API_PORT = int(os.environ.get("AURORA_XRAY_API_PORT", "8897"))  # докодемо-API xray (статистика)
TGWS_PORT = int(os.environ.get("AURORA_TGWS_PORT", "443"))        # Telegram WS-прокси (443; 1443 блокировался РКН)

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
MAX_PING_MS = 500        # выше = ключ мёртв (правило юзера: >500мс мёртвый)
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
        out = subprocess.run([xbin, "x25519"], capture_output=True, text=True, timeout=10).stdout
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
                capture_output=True, timeout=10)
        except Exception:
            pass
    log("firewall: правила добавлены для портов %s" % ",".join(str(p) for p in ordered))

# --- агент ПК (recovery, команды) ---
AGENT_TOKEN = ""
AGENT_UPDATE_URL = ""
AGENT_UPDATE_VERSION = ""

# --- настройки (сохранение в data/settings.json) ---
_LOCK = threading.Lock()
_SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")

_SETTINGS_DEFAULTS = {
    "vpn_mode": True,        # True = VPN активен (final = лучший ключ), False = прямой
    "auto_recovery": True,   # авто-восстановление канала через агента
    "continue_text": "",     # текст при отправке continue
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
        if _settings.get("white_ip"):
            WHITE_IP = _settings["white_ip"].strip()
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


def get(key, default=None):
    return _settings.get(key, default)


def set(key, value):
    _settings[key] = value
    save_settings()


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
