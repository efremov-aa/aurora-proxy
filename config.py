# Aurora v1.0 — конфигурация ядра.
# Всё, что меняется между деплоями: пути, порты, источники ключей, режимы.

import base64
import binascii
import ipaddress
import json
import os
import re
import threading
import time
import urllib.parse
import urllib.request
import uuid

VERSION = "1.9.3"
VERSION_NAME = "Кот-глашатай"
APP_NAME = "Aurora"

# История версий для вкладки «Версии» (v, имя, дата).
# ВАЖНО: без дублей — иначе вкладка показывает одну версию несколько раз.
VERSION_HISTORY = (
    ("1.9.3", "Кот-глашатай", "25.09.2026"),
    ("1.9.2", "Кот-починщик", "25.09.2026"),
    ("1.9.1", "Кот-крепость", "25.09.2026"),
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

# Описания версий для вкладки «Версии» (v -> текст). Показываются в панели.
VERSION_NOTES = {
    "1.9.3": "Глашатай выходит на площадь: тарифы, оплата и продление теперь прямо в Telegram-боте. Браузерное "
                                  "расширение стало дружелюбнее, а в панели — понятный состав тарифов и дополнительных возможностей.",
    "1.9.2": "Починщик подлатал авто-обновление: теперь оно аккуратнее переносит файлы и не спотыкается на разных "
                                  "дисках. Для Windows появился установщик Aurora-Setup — быстрый старт без лишних движений.",
    "1.9.1": "Крепость укрепила стены: релизы и хранилище под надёжной защитой, приглашения в сеть — безопаснее, "
                                  "права доступа — строже. Первый запуск стал понятным мастером, а интерфейс — чище и спокойнее.",
    "1.9.0": "Правозащитник обновил политику и правила. Некоторые разделы теперь открываются только после команды "
                                  "головного сервера — так в сети больше порядок.",
    "1.8.0": "Именитый сам выбирает имя и вступает в сеть. Появился тестовый узел, а вкладки «Меш» и «Магазин» "
                                  "стали видны с головного сервера.",
    "1.7.0": "Дипломат вынес политику на первую страницу с историей версий, спрятал секреты под замкок и добавил "
                                  "раздел «Защита». Русский сегмент и регионы — под рукой.",
    "1.6.0": "Банкир построил меш-сеть и магазин тарифов: статистика, топология, маршруты, безопасность — всё в "
                                  "одном месте.",
    "1.5.0": "Кот в мешке принёс подписки с оплатой и продлением, счётчик трафика, лимиты и управление "
                                  "устройствами.",
    "1.4.0": "Появились тарифы free/basic/prem, маскирование ключей и внешний защищённый профиль.",
    "1.3.1": "Мур-апдейт сделал авто-обновление обязательным и заботливым: Linux и Windows получают свежие версии "
                                  "сами.",
    "1.3.0": "Mesh принёс защищённое подключение, раздел безопасности, авто-обновление и проверку версий.",
    "1.2.0": "Windows-fix навёл порядок: подключение по внутреннему IP, авто-генерация профиля, локальный QR, "
                                  "авто-восстановление порта, настройки через переменные окружения и правила брандмауэра.",
    "1.1.0": "Свежая рыба улучшила умный фильтр ключей, добавила лимит в 120 ключей и честный исходящий IP."
}

# Заголовок вкладки «Версии» — в стиле маскота (общий для всех языков).
VERSION_CHRONICLE = {
    "title": "🐾 Хроники "
             "кота-маскота Aurora",
    "sub": "Каждый релиз — "
           "новая глава: "
           "кот взрослеет, "
           "учится, охраняет "
           "и приносит подарки.",
}


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

# --- периметр plaintext-файлов Xray/keytest (A-072) ---
# Формат xray.json/keytest-конфигов менять нельзя (требование xray), поэтому
# секреты в них защищаются правами доступа: POSIX 0600 (файл) / 0700 (каталог),
# Windows DACL — владелец + SYSTEM + Administrators, наследование отключено.
PLAINTEXT_FILE_MODE = 0o600
PLAINTEXT_DIR_MODE = 0o700

# --- авто-обновление (GitHub Releases) ---
# Обязательное: публичная сборка всегда обновляется с этого репо.
# Локальное отключение/обход НЕ предусмотрен (управляется только политикой релизов).
UPDATE_REPO = "efremov-aa/aurora-proxy"
# Пиннированный Ed25519-ключ подписи релизов (fail-closed: без ключа обновление не ставится)
UPDATE_PUBKEY = "6159031f0fd9ab6c5074f9bef99f5ac125df75e05bdeaa772860236fb85e3371"
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
SUBS_EXTRAS_FILE = os.path.join(DATA_DIR, "extras.json")
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

# --- дополнительные возможности Aurora (витрина «Дополнительные возможности») ---
# Каталог платных доп. услуг поверх тарифа. Показывается в панели, покупка — в Telegram-боте.
# A-109: цены и описания витрины задаёт ТОЛЬКО головной сервер.
# Клиентский дефолт пуст — реальный прайс приходит по меш-политике
# (mesh._policy_loop) и хранится в data/extras.json.
SUBS_EXTRAS = {}
_EXTRAS_SOURCE = "local"
_EXTRAS_GOOD = {}
_EXTRAS_LOCK = threading.RLock()
_EXTRAS_ID_RE = re.compile(r"^[a-z0-9_-]{1,40}$")


def extras_source():
    """Откуда взят текущий прайс витрины: local (заглушка) или master."""
    return _EXTRAS_SOURCE


def _validate_extras(raw):
    """Строгая проверка каталога витрины: dict позиций, максимум 32 штуки."""
    if not isinstance(raw, dict):
        return None
    out = {}
    for key, value in list(raw.items())[:32]:
        if not isinstance(key, str) or not isinstance(value, dict):
            return None
        kid = key.strip().lower()
        if not _EXTRAS_ID_RE.match(kid):
            return None
        name = str(value.get("name") or "").strip()
        if not name or len(name) > 120:
            return None
        try:
            price = int(value.get("price") or 0)
        except (TypeError, ValueError):
            return None
        if price < 0 or price > 1000000:
            return None
        out[kid] = {"name": name,
                    "price": price,
                    "unit": str(value.get("unit") or "").strip()[:40],
                    "note": str(value.get("note") or "").strip()[:400]}
    return out or None


def save_extras(extras, buy_url=None):
    """Принять каталог витрины от головного сервера и сохранить его локально."""
    global SUBS_EXTRAS, BUY_URL, _EXTRAS_SOURCE, _EXTRAS_GOOD
    valid = _validate_extras(extras)
    if valid is None:
        log("extras: каталог мастера отклонён (неверный формат)")
        return False
    with _EXTRAS_LOCK:
        SUBS_EXTRAS.clear()
        SUBS_EXTRAS.update(valid)
        _EXTRAS_GOOD = {k: dict(v) for k, v in valid.items()}
        _EXTRAS_SOURCE = "master"
        payload = {"extras": {k: dict(v) for k, v in valid.items()}, "source": "master"}
        if isinstance(buy_url, str) and buy_url.strip():
            BUY_URL = buy_url.strip()[:200]
            payload["buy_url"] = BUY_URL
        try:
            import crypt
            crypt.save_json(SUBS_EXTRAS_FILE, payload)
        except Exception as exc:
            log("extras: не удалось сохранить каталог: %s" % exc)
            return False
    log("extras: прайс принят от мастера (%d позиций)" % len(SUBS_EXTRAS))
    return True


def load_extras():
    """Поднять сохранённый прайс мастера из data/extras.json при старте."""
    global SUBS_EXTRAS, BUY_URL, _EXTRAS_SOURCE, _EXTRAS_GOOD
    try:
        import crypt
        raw = crypt.load_bytes(SUBS_EXTRAS_FILE)
    except Exception:
        return False
    data = None
    if isinstance(raw, dict):
        data = raw
    elif isinstance(raw, (bytes, bytearray)):
        try:
            data = json.loads(raw.decode("utf-8"))
        except Exception:
            data = None
    if not isinstance(data, dict):
        return False
    source = data.get("extras")
    valid = _validate_extras(source if isinstance(source, dict) else data)
    if valid is None:
        with _EXTRAS_LOCK:
            SUBS_EXTRAS.clear()
            SUBS_EXTRAS.update(_EXTRAS_GOOD)
        return False
    with _EXTRAS_LOCK:
        SUBS_EXTRAS.clear()
        SUBS_EXTRAS.update(valid)
        _EXTRAS_GOOD = {k: dict(v) for k, v in valid.items()}
        _EXTRAS_SOURCE = str(data.get("source") or "master")
        if isinstance(data.get("buy_url"), str) and data["buy_url"].strip():
            BUY_URL = data["buy_url"].strip()[:200]
    return True


def save_catalog(plans=None, extras=None, buy_url=None):
    """Принять каталог мастера целиком: тарифы, витрина и ссылка оплаты."""
    ok = False
    if isinstance(plans, dict) and plans:
        ok = bool(save_plans(plans)) or ok
    if isinstance(extras, dict):
        ok = bool(save_extras(extras, buy_url)) or ok
    return ok

# --- порты (привязаны к клиентским устройствам, НЕ менять без запроса) ---
UI_PORT = int(os.environ.get("AURORA_UI_PORT", "8890"))  # панель Aurora
XRAY_PORT = int(os.environ.get("AURORA_XRAY_PORT", "8899"))  # mixed-вход xray (http+socks)
XRAY_API_PORT = int(os.environ.get("AURORA_XRAY_API_PORT", "8897"))  # докодемо-API xray (статистика)
TGWS_PORT = int(os.environ.get("AURORA_TGWS_PORT", "443"))  # Telegram WS-прокси (443; 1443 блокировался РКН снаружи)
BUY_BOT = (os.environ.get("AURORA_BUY_BOT", "@aurorahomevpn_bot").strip() or "@aurorahomevpn_bot")  # бот для оплаты тарифов
BUY_URL = "https://t.me/" + BUY_BOT.lstrip("@").strip("/")
# Браузерное расширение (MV3/DNR): хост прокси, режим RU-байпаса, версия правил.
RU_BYPASS = os.environ.get("AURORA_RU_BYPASS", "1").strip().lower() not in (
    "0", "false", "no", "off", "нет", "выкл")
RULES_VERSION = (os.environ.get("AURORA_RULES_VERSION", "1").strip() or "1")[:32]
EXT_HOST = os.environ.get("AURORA_EXT_HOST", "").strip()

# --- A-111: лицензионный гейт PRO-функций (цены и доступ - у мастера) ---
def _ext_int_env(name, default):
    """Целое из окружения, мусор и пусто -> значение по умолчанию."""
    try:
        value = int(str(os.environ.get(name, "") or default).strip())
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


EXT_MASTER_URL = os.environ.get("AURORA_EXT_MASTER", "http://10.1.0.238:8890").rstrip("/")
EXT_TOKEN = os.environ.get("AURORA_EXT_TOKEN", "").strip()          # token из device-ссылки
EXT_CREDENTIAL = os.environ.get("AURORA_EXT_CREDENTIAL", "").strip()  # credential из device-ссылки
EXT_CHECK_INTERVAL_S = _ext_int_env("AURORA_EXT_CHECK_INTERVAL", 3600)
EXT_OFFLINE_MAX_S = _ext_int_env("AURORA_EXT_OFFLINE_MAX_S", 72 * 3600)
EXT_TIMEOUT = _ext_int_env("AURORA_EXT_TIMEOUT", 10)
EXT_PRO_PLANS = os.environ.get("AURORA_EXT_PRO_PLANS", "").strip()  # пусто = все, кроме free

# --- A-161: архивы браузерного расширения (PRO-фича) ---
# Лежат в assets/ рядом с кодом; раздаёт их панель. Имя файла - только из
# белого списка ниже, путь из запроса никогда не подставляется.
EXT_ASSETS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")
EXT_PACKAGES = {}  # A-164: пакеты расширения раздаёт только головной
# сервер; в клиентской сборке их нет, /api/ext/license вернёт packages=[]




def ext_proxy_host():
    """Адрес прокси для расширения: AURORA_EXT_HOST -> VM_HOST -> 127.0.0.1."""
    for cand in (EXT_HOST, VM_HOST, ""):
        if cand and cand not in ("0.0.0.0", "::", "*"):
            return cand
    return "127.0.0.1"

# --- сеть (значения из env, дефолты безопасны/пустые) ---
VM_HOST = os.environ.get("AURORA_HOST", "127.0.0.1")    # адрес сервера для внешних ссылок/QR
WHITE_IP = os.environ.get("AURORA_WHITE_IP", "")        # белый IP провайдера — фильтр «не выход VPN»
_DIRECT_IP_LOCK = threading.Lock()
_DIRECT_IP_CACHE = {"ip": "", "ts": 0.0}
_DIRECT_IP_TTL_S = 300


def get_direct_ip(force=False):
    configured = str(WHITE_IP or "").strip()
    if configured:
        try:
            return str(ipaddress.ip_address(configured))
        except ValueError:
            return ""
    now = time.time()
    with _DIRECT_IP_LOCK:
        if not force and _DIRECT_IP_CACHE["ip"] and now - _DIRECT_IP_CACHE["ts"] < _DIRECT_IP_TTL_S:
            return _DIRECT_IP_CACHE["ip"]
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open("http://api.ipify.org?format=json", timeout=5) as response:
                value = json.loads(response.read().decode("utf-8")).get("ip", "")
            value = str(ipaddress.ip_address(str(value)))
            _DIRECT_IP_CACHE["ip"] = value
            _DIRECT_IP_CACHE["ts"] = time.time()
            return value
        except Exception:
            return ""

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
MAX_RU_SOURCE_BYTES = 4 * 1024 * 1024
MAX_RU_SOURCE_LINES = 200000
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
def _parse_port(value):
    if type(value) is int:
        return value if 1 <= value <= 65535 else None
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value.isdigit():
        return None
    value = int(value)
    return value if 1 <= value <= 65535 else None


def canonical_uuid(value):
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = uuid.UUID(value.strip())
    except (ValueError, AttributeError):
        return None
    if parsed.int == 0:
        return None
    return str(parsed)


def _valid_x25519(value):
    if not isinstance(value, str) or len(value) != 43:
        return False
    if any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for ch in value):
        return False
    try:
        raw = base64.urlsafe_b64decode(value + "=")
    except (ValueError, binascii.Error):
        return False
    if len(raw) != 32:
        return False
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") == value


def _valid_short_id(value):
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value:
        return ""
    if len(value) > 16 or len(value) % 2 or any(ch not in "0123456789abcdefABCDEF" for ch in value):
        return None
    return value.lower()


def _valid_sni(value):
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or any(ch in value for ch in "/?#@,; \t\r\n"):
        return None
    try:
        value = value.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    if not value or len(value) > 253 or "*" in value:
        return None
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+", value):
        return None
    return value


METADATA_HOSTS = frozenset((
    "169.254.169.254", "100.100.100.200", "168.63.129.16", "fd00:ec2::254",
))


def _read_setup_token():
    value = os.environ.get("AURORA_SETUP_TOKEN", "").strip()
    if len(value) < 16 or len(value) > 256:
        return ""
    if any(ch.isspace() or ord(ch) < 33 or ord(ch) > 126 for ch in value):
        return ""
    return value


SETUP_TOKEN = _read_setup_token()


def _private_links_allowed():
    return os.environ.get("AURORA_ALLOW_PRIVATE_LINK", "").lower() in ("1", "true", "yes", "on")


def _valid_public_host(value):
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or any(ch in value for ch in "/?#@,; \t\r\n"):
        return None
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    elif "[" in value or "]" in value:
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        try:
            value = value.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError:
            return None
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+", value):
            return None
        if value == "localhost" or value.endswith(".local") or value.endswith(".internal"):
            return None
        return value
    if str(address) in METADATA_HOSTS:
        return None
    if not address.is_global:
        private_ok = _private_links_allowed() and address.is_private and not address.is_loopback and not address.is_link_local and not address.is_unspecified and not address.is_multicast
        if not private_ok:
            return None
    return str(address)


def external_link_host(raw=None):
    for name in ("AURORA_VLESS_HOST", "AURORA_HOST"):
        if name in os.environ:
            return _valid_public_host(os.environ.get(name, "")) or ""
    if raw is None:
        raw = VLESS_PUBLIC
    if isinstance(raw, dict):
        host = _valid_public_host(raw.get("host", ""))
        if host:
            return host
    get_public_ip = globals().get("get_public_ip")
    if callable(get_public_ip):
        return _valid_public_host(get_public_ip() or "") or ""
    return ""


def _format_link_host(host):
    if not host:
        return ""
    try:
        if ipaddress.ip_address(host).version == 6:
            return "[%s]" % host
    except ValueError:
        pass
    return host


def vless_public(raw=None):
    if raw is None:
        raw = VLESS_PUBLIC
    if not isinstance(raw, dict):
        return {"enabled": False}
    enabled = raw.get("enabled") is True
    port = _parse_port(raw.get("port", 8443))
    out = {
        "enabled": enabled,
        "port": port if port is not None else 0,
        "host": external_link_host(raw),
        "uuid": canonical_uuid(raw.get("uuid")),
        "private_key": raw.get("private_key") if _valid_x25519(raw.get("private_key")) else "",
        "public_key": raw.get("public_key") if _valid_x25519(raw.get("public_key")) else "",
        "short_id": _valid_short_id(raw.get("short_id", "")),
        "sni": _valid_sni(raw.get("sni", "www.microsoft.com")),
        "flow": raw.get("flow") if raw.get("flow") == "xtls-rprx-vision" else None,
    }
    if not enabled or port is None or not out["uuid"] or not out["private_key"] or not out["public_key"] or out["short_id"] is None or not out["sni"] or not out["flow"]:
        out["enabled"] = False
    return out


VLESS_PUBLIC = {
    "enabled": os.environ.get("AURORA_VLESS_ENABLED", "").lower() == "true",
    "port": _parse_port(os.environ.get("AURORA_VLESS_PORT", "8443")) or 0,
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
    "mesh_tunnel": False,      # A-151: релей-туннель меш (по умолчанию выключен)
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
    # --- v1.7.0: политика сервиса + сегменты ---
    "policy_rev_accepted": 0,    # принятая ревизия политики (0 = не принимал)
    "segment_title": "",         # своё название сегмента монитора (пусто = авто)
    "segment_regions": [],       # выбранные регионы (ru/global/eu/asia)
    "segment_custom": "",        # пользовательские домены (по одному на строку)
    # --- v1.8.0: гологоловной сервер (master) / авто-джойн / замок тестового сервера ---
    "master_addr": "",           # URL головного сервера (напр. http://10.1.136.56:5053)
    "master_token": "",          # секрет регистрации у головного (выдаёт головной)
    "mesh_own_secret": "",       # секрет собственного mesh-узла
    "auto_join": False,          # при старте регистрироваться в меше головного (авто-джуin)
    "master_only": False,        # замок: подключиться/использовать может только головной
    "setup_complete": False,    # первый запуск public-сервера завершён
    "ui_port": UI_PORT,
    "xray_port": XRAY_PORT,
    "xray_api_port": XRAY_API_PORT,
    "tgws_port": TGWS_PORT,
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


class StorageDataError(ValueError):
    pass


def quarantine_file(path):
    source = os.path.abspath(path)
    if not os.path.isfile(source):
        return False
    index = 0
    while True:
        candidate = source + ".corrupt" if index == 0 else "%s.corrupt.%d" % (source, index)
        try:
            with open(source, "rb") as src:
                data = src.read()
            with open(candidate, "xb") as dst:
                dst.write(data)
                dst.flush()
                os.fsync(dst.fileno())
            try:
                import crypt

                crypt.restrict_file(candidate)
            except OSError:
                pass
            return True
        except FileExistsError:
            index += 1
        except OSError:
            return False


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
                raw_length = r.headers.get("Content-Length")
                if raw_length is not None:
                    if not str(raw_length).isdigit():
                        raise ValueError("invalid content length")
                    if int(raw_length) > MAX_RU_SOURCE_BYTES:
                        raise ValueError("ru source too large")
                data = r.read(MAX_RU_SOURCE_BYTES + 1)
                if len(data) > MAX_RU_SOURCE_BYTES:
                    raise ValueError("ru source too large")
                body = data.decode("utf-8")
                if len(body.splitlines()) > MAX_RU_SOURCE_LINES:
                    raise ValueError("too many ru source lines")
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


def _is_nonnegative_int(value):
    return type(value) is int and value >= 0


def _validate_ports(data):
    ports = {}
    for key in ("ui_port", "xray_port", "xray_api_port", "tgws_port"):
        value = data.get(key, _SETTINGS_DEFAULTS[key])
        if type(value) is not int or value < 1 or value > 65535:
            return None
        ports[key] = value
    values = list(ports.values())
    if any(values.count(value) > 1 for value in values):
        return None
    return ports


def _validate_settings(raw):
    if not isinstance(raw, dict):
        raise ValueError("root is not an object")
    bool_keys = (
        "vpn_mode", "auto_recovery", "auto_refresh", "lan_only",
        "block_scanners", "rate_limit", "twofa", "show_mesh", "show_subs",
        "mesh_master", "auto_join", "master_only", "setup_complete",
    )
    string_keys = (
        "continue_text", "ui_token", "server_name", "mesh_id", "mesh_token",
        "ui_pin", "segment_title", "segment_custom", "master_addr",
        "master_token", "mesh_own_secret",
    )
    list_keys = ("segment_regions",)
    for key in bool_keys:
        if key in raw and type(raw[key]) is not bool:
            raise ValueError("%s is not a boolean" % key)
    for key in string_keys:
        if key in raw and not isinstance(raw[key], str):
            raise ValueError("%s is not a string" % key)
    for key in list_keys:
        if key in raw and (not isinstance(raw[key], list)
                           or any(not isinstance(x, str) for x in raw[key])):
            raise ValueError("%s is not a string list" % key)
    if "policy_rev_accepted" in raw and not _is_nonnegative_int(raw["policy_rev_accepted"]):
        raise ValueError("policy_rev_accepted is not a nonnegative integer")
    if raw.get("ui_pin") and not re.fullmatch(r"[0-9]{6}", raw["ui_pin"]):
        raise ValueError("ui_pin must be six ASCII digits")
    if raw.get("ui_token") and not 12 <= len(raw["ui_token"]) <= 256:
        raise ValueError("ui_token length is invalid")
    merged = dict(_SETTINGS_DEFAULTS)
    merged.update({k: raw[k] for k in raw if k in _SETTINGS_DEFAULTS})
    if _validate_ports(merged) is None:
        raise ValueError("ports are invalid")
    return merged


def _storage_failure(path, reason):
    quarantine_file(path)
    raise StorageDataError("%s: %s" % (os.path.basename(path), reason))


def _apply_port_overrides(settings):
    global UI_PORT, XRAY_PORT, XRAY_API_PORT, TGWS_PORT
    ports = _validate_ports(settings)
    if ports is None:
        return False
    UI_PORT = ports["ui_port"]
    XRAY_PORT = ports["xray_port"]
    XRAY_API_PORT = ports["xray_api_port"]
    TGWS_PORT = ports["tgws_port"]
    return True


# --- настройки ---
def load_settings():
    """Читает data/settings.json (выживают только известные ключи)."""
    global _settings
    with _LOCK:
        import crypt
        missing = object()
        try:
            raw = crypt.load_json(_SETTINGS_FILE, default=missing)
        except crypt.StorageError as e:
            _storage_failure(_SETTINGS_FILE, str(e))
        if raw is missing:
            _settings = dict(_SETTINGS_DEFAULTS)
            if not _apply_port_overrides(_settings):
                raise ValueError("ports are invalid")
            return
        try:
            merged = _validate_settings(raw)
        except (TypeError, ValueError) as e:
            _storage_failure(_SETTINGS_FILE, str(e))
        try:
            crypt.save_json(_SETTINGS_FILE, merged)
        except (crypt.StorageError, OSError) as e:
            _storage_failure(_SETTINGS_FILE, str(e))
        if not _apply_port_overrides(merged):
            _storage_failure(_SETTINGS_FILE, "ports are invalid")
            return
        _settings = merged


def _persist_settings(value):
    import crypt
    crypt.save_json(_SETTINGS_FILE, value)


def save_settings():
    """Атомарно пишет настройки в data/settings.json."""
    with _LOCK:
        try:
            _persist_settings(_settings)
        except (crypt.StorageError, OSError) as e:
            log("settings: не удалось сохранить: %s" % e)
            return False
    return True


def reset_settings():
    """Сброс настроек к значениям по умолчанию (кнопка «Сбросить всё»)."""
    global _settings
    with _LOCK:
        candidate = dict(_SETTINGS_DEFAULTS)
        try:
            _persist_settings(candidate)
        except (crypt.StorageError, OSError) as e:
            log("settings: не удалось сохранить: %s" % e)
            return False
        _settings.clear()
        _settings.update(candidate)
    log("settings: сброшены к значениям по умолчанию")
    return True


# --- тарифы: переопределение из data/plans.json (редактор тарифов в UI) ---
_SUBS_PLANS_LOCK = threading.RLock()
_PLAN_FIELDS = ("name", "price", "bytes", "days", "devices", "keys")
_PLAN_LIST_FIELDS = ("features", "features_no")
_PLAN_NAME_MAX = 40
_PLAN_LIST_MAX = 100
_PLAN_ITEM_MAX = 80
_PLANS_GOOD = None


def _plan_id(value):
    if not isinstance(value, str) or not value or len(value) > 40:
        return False
    for ch in value:
        if not (("a" <= ch <= "z") or ("0" <= ch <= "9") or ch in "_-"):
            return False
    return True


def normalize_plan(plan_id, value, base=None):
    """Строгая нормализация тарифа (контракт головного сервера)."""
    if not _plan_id(plan_id):
        raise ValueError("invalid plan id")
    if not isinstance(value, dict):
        raise ValueError("invalid plan record")
    merged = dict(base or {})
    merged.update(value)
    if any(field not in merged for field in _PLAN_FIELDS):
        raise ValueError("missing plan fields")
    name = merged.get("name")
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= _PLAN_NAME_MAX:
        raise ValueError("invalid plan name")
    out = {"name": name.strip()}
    for field in ("price", "bytes", "days"):
        if not _is_nonnegative_int(merged.get(field)):
            raise ValueError("invalid plan field %s" % field)
        out[field] = int(merged[field])
    for field in ("devices", "keys"):
        if not _is_nonnegative_int(merged.get(field)) or int(merged[field]) < 1:
            raise ValueError("invalid plan field %s" % field)
        out[field] = int(merged[field])
    for field in _PLAN_LIST_FIELDS:
        if field not in merged:
            continue
        items = merged.get(field)
        if not isinstance(items, list) or len(items) > _PLAN_LIST_MAX:
            raise ValueError("invalid plan field %s" % field)
        clean = []
        for item in items:
            if not isinstance(item, str) or not 1 <= len(item) <= _PLAN_ITEM_MAX:
                raise ValueError("invalid plan field %s" % field)
            clean.append(item)
        out[field] = clean
    return out


def _plans_snapshot():
    return dict((key, dict(value)) for key, value in SUBS_PLANS.items()
                if isinstance(value, dict))


def save_plans(plans=None):
    """Сохраняет тарифы в data/plans.json (атомарно, шифрование AURORA2)."""
    with _SUBS_PLANS_LOCK:
        source = SUBS_PLANS if plans is None else plans
        if not isinstance(source, dict) or not source:
            raise ValueError("no plans")
        payload = {}
        for key, value in source.items():
            payload[key] = normalize_plan(key, value, base=SUBS_PLANS.get(key))
        if plans is not None:
            SUBS_PLANS.update(payload)
        try:
            import crypt
            crypt.save_json(SUBS_PLANS_FILE, payload)
        except Exception as e:
            log("plans: не удалось сохранить: %s" % e)
            return False
        return True


def _validate_plans(raw):
    if not isinstance(raw, dict):
        raise ValueError("root is not an object")
    valid = {}
    for key, value in raw.items():
        valid[key] = normalize_plan(key, value, base=SUBS_PLANS.get(key))
    return valid


def _load_plans_override():
    """Переопределение тарифов из data/plans.json (валидные планы перезаписывают)."""
    global _PLANS_GOOD
    try:
        import crypt
        raw = crypt.load_bytes(SUBS_PLANS_FILE)
    except (OSError, TypeError, ValueError) as e:
        _storage_failure(SUBS_PLANS_FILE, str(e))
        raw = None
    if raw is None:
        return
    try:
        valid = _validate_plans(json.loads(raw.decode("utf-8")))
    except (TypeError, ValueError, UnicodeDecodeError) as e:
        _storage_failure(SUBS_PLANS_FILE, str(e))
        valid = None
    with _SUBS_PLANS_LOCK:
        if valid:
            SUBS_PLANS.update(valid)
            _PLANS_GOOD = _plans_snapshot()
            log("plans: тарифы переопределены из data/plans.json (%d)" % len(valid))
        elif _PLANS_GOOD:
            SUBS_PLANS.clear()
            SUBS_PLANS.update(_PLANS_GOOD)
            log("plans: восстановлены последние корректные тарифы")
    if SUBS_PLAN_DEFAULT not in SUBS_PLANS:
        raise ValueError("default plan is missing")


# --- меш: общий ключ подписи приглашений/политики с головным сервером ---
MESH_POLICY_TTL_S = 120


def _read_mesh_policy_key():
    value = (os.environ.get("AURORA_MESH_POLICY_KEY") or "").strip()
    return value if len(value.encode("utf-8")) >= 32 else ""


def _read_mesh_master_id():
    value = (os.environ.get("AURORA_MESH_MASTER_ID") or "").strip()
    if not value or len(value) > 64:
        return ""
    for ch in value:
        if not (ch.isalnum() or ch in "._-"):
            return ""
    return value


MESH_POLICY_KEY = _read_mesh_policy_key()
MESH_MASTER_ID = _read_mesh_master_id()


def mesh_policy_key():
    return MESH_POLICY_KEY


def mesh_master_id():
    return MESH_MASTER_ID


def get(key, default=None):
    return _settings.get(key, default)


def set_many(values, strict=True):
    import crypt
    if not isinstance(values, dict):
        return False
    with _LOCK:
        candidate = dict(_settings)
        candidate.update(values)
        if strict:
            try:
                candidate = _validate_settings(candidate)
            except (TypeError, ValueError) as e:
                log("settings: невалидное значение: %s" % e)
                return False
        try:
            _persist_settings(candidate)
        except (crypt.StorageError, OSError) as e:
            log("settings: не удалось сохранить: %s" % e)
            return False
        _settings.clear()
        _settings.update(candidate)
    return True


def set(key, value):
    return set_many({key: value}, strict=key in _SETTINGS_DEFAULTS)


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

# --- A-151: релей-туннель между узлами меш (роль/адреса - из env) ---
# По умолчанию выключен: включается только приказом владельца.
# Секрет сети (AURORA_MESH_SECRET) в лог/конфиг/панель не попадает.
def _read_mesh_flag(name):
    v = (os.environ.get(name, "") or "").strip().lower()
    return v in ("1", "true", "yes", "on")


MESH_TUNNEL_ENV = _read_mesh_flag("AURORA_MESH_TUNNEL")
MESH_SECRET = (os.environ.get("AURORA_MESH_SECRET", "") or "").strip()
MESH_PUBLIC_ADDR = (os.environ.get("AURORA_MESH_PUBLIC_ADDR", "") or "").strip()
MESH_MASTER_ADDR = (os.environ.get("AURORA_MESH_MASTER_ADDR", "") or "").strip()
if MESH_TUNNEL_ENV:
    # env-переключатель для владельца сервера; значение всё равно живёт в settings.
    try:
        set("mesh_tunnel", True)
    except Exception:
        pass

_load_plans_override()
load_extras()