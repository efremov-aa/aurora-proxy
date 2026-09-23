# Aurora v1.0 — конфигурация ядра.
# Всё, что меняется между деплоями: пути, порты, источники ключей, режимы.

import json
import os
import threading
import time

VERSION = "1.6.0"
VERSION_NAME = "Меш и Магазин"
APP_NAME = "Aurora"

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

# --- порты (привязаны к клиентским устройствам, НЕ менять без запроса) ---
UI_PORT = 8890            # панель Aurora
XRAY_PORT = 8899          # mixed-вход xray (http+socks)
XRAY_API_PORT = 8897      # докодемо-API xray (статистика)
TGWS_PORT = int(os.environ.get("AURORA_TGWS_PORT", "443"))  # Telegram WS-прокси (443; 1443 блокировался РКН снаружи)

# --- сеть (значения из env, дефолты безопасны/пустые) ---
VM_HOST = os.environ.get("AURORA_HOST", "127.0.0.1")    # адрес сервера для внешних ссылок/QR
WHITE_IP = os.environ.get("AURORA_WHITE_IP", "")        # белый IP провайдера — фильтр «не выход VPN»

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
# Отключено по умолчанию. Заполните свои ВСЕ поля через env AURORA_VLESS_* (см. README/.env.example),
# иначе register_public_inbound() вернёт False и внешний inbound не создастся.
VLESS_PUBLIC = {
    "enabled": os.environ.get("AURORA_VLESS_ENABLED", "").lower() == "true",
    "port": int(os.environ.get("AURORA_VLESS_PORT", "8443")),
    "host": os.environ.get("AURORA_VLESS_HOST", "127.0.0.1"),
    "uuid": os.environ.get("AURORA_VLESS_UUID", ""),
    "private_key": os.environ.get("AURORA_VLESS_PRIVATE_KEY", ""),
    "public_key": os.environ.get("AURORA_VLESS_PUBLIC_KEY", ""),
    "short_id": os.environ.get("AURORA_VLESS_SHORT_ID", ""),
    "sni": os.environ.get("AURORA_VLESS_SNI", "www.microsoft.com"),
    "flow": os.environ.get("AURORA_VLESS_FLOW", "xtls-rprx-vision"),
}

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
    "show_mesh": True,           # показывать вкладку «Меш-сеть» в панели
    "show_subs": True,           # показывать вкладку «Магазин» в панели
    "mesh_master": False,        # головной сервер: раздаёт политику видимости клиентам меша
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
    global _settings
    try:
        with open(_SETTINGS_FILE, "r", encoding="utf-8") as f:
            raw = json.load(f)
        merged = dict(_SETTINGS_DEFAULTS)
        merged.update({k: raw[k] for k in raw if k in _SETTINGS_DEFAULTS})
        _settings = merged
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