# Aurora v1.0 — ядро: сборка xray.json, старт/рестарт xray, ротация, watch.
# Принцип: final-тег — только живой ключ с реальным egress. VPN OFF -> direct.

import json
import os
import re
import socket
import subprocess
import threading
import time
import urllib.parse
import urllib.request

import config
import pool
import subs

XRAY_CONFIG_LOCK = threading.RLock()  # RLock: read-modify-write оборачивается этим локом целиком
EGRESS_LOCK = threading.Lock()
_ROTATE_LOCK = threading.Lock()
_MODE_LOCK = threading.Lock()  # сериализация sync/set_direct (гонка vpn ON->OFF)
_EGRESS_CACHE = {"ip": "-", "ts": 0.0}
_LAST_ROTATE = [0.0]
_WATCH_STOP = threading.Event()

# Как управлять xray: "systemctl" (по умолчанию) или "proc" (в Docker: xray — подпроцесс).
XRAY_MANAGE = os.environ.get("XRAY_MANAGE", "systemctl")
_XRAY_PROC = [None]  # Popen (режим proc)


def _xray_bin():
    cands = [
        os.path.join(os.path.expanduser("~"), "xray"),
        os.path.join(config.BASE_DIR, "xray"),
        "/usr/local/bin/xray",
    ]
    for c in cands:
        if os.path.exists(c):
            return c
    return None


def build_xray_config(final_tag):
    """Полный xray-конфиг. outbounds: [пул vless..., direct, block]."""
    if final_tag == "direct":
        tag = "direct"
    else:
        tag = final_tag
    outbounds = []
    keys = pool.get_keys()
    used_tags = set()
    for k in keys:
        ob = pool.build_outbound(k)
        if not ob:
            continue
        if ob["tag"] in used_tags:
            ob["tag"] = pool._tag_from_uri(k.get("uri", ""), k.get("host", ""))
            while ob["tag"] in used_tags:
                ob["tag"] += "-x"
        used_tags.add(ob["tag"])
        outbounds.append(ob)
        # final-ключ при коллизии переименован — routing должен идти на новое имя
        if tag != "direct" and ob["tag"] != tag and tag == k.get("tag"):
            tag = ob["tag"]
    # гарантируем наличие актуального direct/block
    outbounds.append({"tag": "direct", "protocol": "freedom",
                      "settings": {"domainStrategy": "UseIP"}})
    outbounds.append({"tag": "block", "protocol": "blackhole", "settings": {}})

    # Routing: RU-домены -> direct ПЕРВЫМ (без inboundTag — get_vless_now
    # берёт первое правило с http-in, оно должно остаться под VPN-тегом);
    # затем http-in/vless-in -> активный тег.
    http_rule = {"type": "field", "inboundTag": ["http-in"],
                 "network": "tcp,udp", "outboundTag": tag}
    rules = [http_rule]
    ru_bypass = config.ru_domains()
    if ru_bypass:
        rules.insert(0, {"type": "field",
                         "domain": ["domain:" + d for d in ru_bypass],
                         "outboundTag": "direct"})
    # Торрент-трафик на GitHub-сборках ВСЕГДА напрямую (правило юзера):
    # публичные сборки не гонят битторрент через туннель. Правило первым.
    rules.insert(0, {"type": "field", "protocol": ["bittorrent"],
                     "outboundTag": "direct"})

    cfg = {
        "log": {"loglevel": "warning", "access": "", "error": ""},
        "api": {"tag": "api-in", "services": ["StatsService"]},
        "policy": {"levels": {"0": {"statsUserUplink": True,
                                    "statsUserDownlink": True}}},
        "inbounds": [
            {"tag": "http-in", "listen": "0.0.0.0", "port": config.XRAY_PORT,
             "protocol": "http", "sniffing": {"enabled": True}},
            {"tag": "api-in", "listen": "127.0.0.1", "port": config.XRAY_API_PORT,
             "protocol": "dokodemo-door", "settings": {"address": "127.0.0.1"}},
        ],
        "outbounds": outbounds,
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": rules},
    }
    # Внешний VLESS-Reality inbound для подключения к прокси ИЗВНЕ.
    # При замке master_only сервер не раскрывает наружу входящий VLESS:
    # просочиться в этот сервер извне нельзя, работает только локальный http-in.
    vln = config.VLESS_PUBLIC
    master_locked = config.get("master_only", False)
    if vln.get("enabled") and vln.get("uuid") and not master_locked:
        # мастер-uuid (владелец сервера) + все активные подписочные клиенты
        clients = [{
            "id": vln["uuid"],
            "flow": vln.get("flow", "xtls-rprx-vision"),
        }]
        try:
            for cuuid in subs.build_client_list():
                clients.append({
                    "id": cuuid,
                    "email": cuuid,
                    "flow": vln.get("flow", "xtls-rprx-vision"),
                })
        except Exception:
            pass
        cfg["inbounds"].insert(1, {
            "tag": "vless-in",
            "listen": "0.0.0.0",
            "port": int(vln.get("port", 8443)),
            "protocol": "vless",
            "sniffing": {"enabled": True},
            "settings": {
                "clients": clients,
                "decryption": "none",
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": False,
                    "dest": (vln.get("sni") or vln.get("host", "www.microsoft.com")) + ":443",
                    "serverNames": [vln.get("sni") or vln.get("host", "www.microsoft.com")],
                    "privateKey": vln.get("private_key", ""),
                    "shortIds": [vln.get("short_id") or ""],
                },
            },
        })
        http_rule["inboundTag"] = ["http-in", "vless-in"]
    return cfg


def _read_config():
    try:
        with open(config.XRAY_CONFIG, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _write_config(cfg):
    with XRAY_CONFIG_LOCK:
        tmp = config.XRAY_CONFIG + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, config.XRAY_CONFIG)
            return True
        except OSError as e:
            config.log("core: запись xray.json не удалась: %s" % e)
            return False


def _port_open(port, timeout=1):
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        s.close()
        return True
    except OSError:
        return False


def _xray_proc_start():
    """Запуск xray как подпроцесса (режим proc для Docker)."""
    xbin = _xray_bin()
    if not xbin:
        config.log("core: xray-бинаря нет (proc)")
        return False
    if _XRAY_PROC[0] and _XRAY_PROC[0].poll() is None:
        return True
    try:
        _XRAY_PROC[0] = subprocess.Popen(
            [xbin, "run", "-c", config.XRAY_CONFIG],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError as e:
        config.log("core: proc-старт xray не удался: %s" % e)
        return False
    end = time.time() + 15
    while time.time() < end:
        if _port_open(config.XRAY_PORT):
            return True
        time.sleep(1)
    config.log("core: xray (proc) не поднял порт за 15с")
    return False


def _restart_xray():
    """Внешний перезапуск xray. Режим systemctl — `systemctl --user restart xray`,
    режим proc (Docker) — подпроцесс. Ждёт порт до 15с."""
    if XRAY_MANAGE == "proc":
        if _XRAY_PROC[0] and _XRAY_PROC[0].poll() is None:
            _XRAY_PROC[0].terminate()
            try:
                _XRAY_PROC[0].wait(timeout=8)
            except Exception:
                _XRAY_PROC[0].kill()
        _XRAY_PROC[0] = None
        return _xray_proc_start()
    try:
        subprocess.run(
            ["systemctl", "--user", "restart", "xray"],
            capture_output=True, timeout=20)
    except Exception:
        pass
    end = time.time() + 15
    while time.time() < end:
        if _port_open(config.XRAY_PORT):
            return True
        time.sleep(1)
    config.log("core: xray не поднял порт за 15с")
    return False


def sync():
    """Полная синхронизация: пул -> конфиг -> старт -> проверка egress.
    Возвращает (ok: bool, final: str). Под _MODE_LOCK: параллельный set_direct
    не может перезаписать результат после чтения vpn_mode."""
    with _MODE_LOCK:
        return _sync_impl()


def _sync_impl():
    config.update_state(comm={"state": "syncing", "msg": "синхронизация с xray..."})
    pool.dedupe()
    vpn = config.get("vpn_mode", True)
    active_key = pool.pick_final() if vpn else None
    final_tag = "direct"
    if vpn:
        if active_key:
            final_tag = active_key.get("tag") or "direct"
        else:
            final_tag = "direct"

    cfg = build_xray_config(final_tag)
    if not _write_config(cfg):
        config.update_state(vless_now="-", final_mode="direct",
                            comm={"state": "idle", "msg": ""})
        return False, "direct"
    if not _restart_xray():
        config.update_state(vless_now="-", final_mode="direct",
                            comm={"state": "idle", "msg": ""})
        return False, "direct"

    # egress-проверка активного канала (4 попытки — cold start Reality >8с)
    ip = None
    if final_tag != "direct":
        for i in range(1, 5):
            ip = egress_probe(timeout=10)
            if ip:
                break
            config.log("core: sync final=%s egress probe %d/4 не дал IP" % (final_tag, i))
            time.sleep(3)
        if not ip:
            config.log("core: final=%s БЕЗ egress, откат на direct" % final_tag)
            final_tag = "direct"
            cfg = build_xray_config("direct")
            _write_config(cfg)
            _restart_xray()
            config.update_state(vless_now="direct", final_mode="direct", egress_ip=config.WHITE_IP,
                                comm={"state": "idle", "msg": ""})
            return False, "direct"

    n_keys = len(pool.get_keys())
    config.log("core: sync: outbounds=%d final=%s user_keys=%d" % (
        len(cfg["outbounds"]) - 2, final_tag, n_keys))
    # при коллизии тег в xray.json мог быть переименован (-x) — в state пишем фактический
    if final_tag != "direct":
        final_tag = get_vless_now() or final_tag
    config.update_state(vless_now=final_tag, final_mode=final_tag,
                        egress_ip=ip or config.WHITE_IP,
                        comm={"state": "idle", "msg": ""})
    return True, final_tag


def egress_probe(timeout=10):
    """Фактический egress через живой порт xray. Возвращает IP или None.
    Только HTTP: HTTPS через CONNECT даёт SSL EOF (ложный провал)."""
    url = "http://api.ipify.org?format=json"
    try:
        handler = urllib.request.ProxyHandler({
            "http": "http://127.0.0.1:%d" % config.XRAY_PORT,
            "https": "http://127.0.0.1:%d" % config.XRAY_PORT,
        })
        opener = urllib.request.build_opener(handler)
        req = urllib.request.Request(url, headers={"User-Agent": "curl"})
        with opener.open(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", errors="replace")
        ip = json.loads(body).get("ip", "")
        if ip and ip not in ("", "-", config.WHITE_IP):
            return ip
    except Exception:
        return None
    return None


def egress_ip(force=False):
    """Кэш egress (TTL 60с)."""
    with EGRESS_LOCK:
        now = time.time()
        if force or now - _EGRESS_CACHE["ts"] > config.EGRESS_TTL_S:
            ip = egress_probe() or "-"
            _EGRESS_CACHE["ip"] = ip
            _EGRESS_CACHE["ts"] = now
        return _EGRESS_CACHE["ip"]


def get_vless_now():
    """Единственный источник правды активного тега — rule в xray.json."""
    cfg = _read_config()
    if not cfg:
        return "-"
    try:
        for rule in cfg.get("routing", {}).get("rules", []):
            if "http-in" in (rule.get("inboundTag") or []):
                return rule.get("outboundTag", "-")
    except Exception:
        pass
    return "-"


def set_direct():
    """Переключение final=direct (правки routing, vless-outbounds сохраняются).
    Под _MODE_LOCK: сериализация с sync при смене vpn_mode."""
    with _MODE_LOCK:
        return _set_direct_impl()


def _set_direct_impl():
    config.update_state(comm={"state": "syncing", "msg": "переключение в прямой режим..."})
    with XRAY_CONFIG_LOCK:  # read-modify-write целиком под локом (TOCTOU)
        cfg = _read_config()
        if not cfg:
            config.update_state(comm={"state": "idle", "msg": ""})
            return False
        for rule in cfg.get("routing", {}).get("rules", []):
            if "http-in" in (rule.get("inboundTag") or []):
                rule["outboundTag"] = "direct"
        if not _write_config(cfg):
            config.update_state(comm={"state": "idle", "msg": ""})
            return False
    if not _restart_xray():
        config.update_state(comm={"state": "idle", "msg": ""})
        return False
    config.update_state(vless_now="direct", final_mode="direct", egress_ip=config.WHITE_IP,
                        comm={"state": "idle", "msg": ""})
    config.log("core: final=direct (прямой режим)")
    return True


def apply_sub_clients():
    """Перезаписывает clients inbound vless-in в существующем xray.json
    (мастер + все активные подписочные uuid) и рестартует xray.
    ТОЛЬКО правка clients — routing/outbounds не трогаются (безопасно вживую).
    Возвращает (ok: bool, msg: str)."""
    if not (config.VLESS_PUBLIC.get("enabled") and config.VLESS_PUBLIC.get("uuid")):
        return False, "внешний inbound не настроен"
    clients = [{
        "id": config.VLESS_PUBLIC["uuid"],
        "flow": config.VLESS_PUBLIC.get("flow", "xtls-rprx-vision"),
    }]
    try:
        for cuuid in subs.build_client_list():
            clients.append({
                "id": cuuid,
                "email": cuuid,
                "flow": config.VLESS_PUBLIC.get("flow", "xtls-rprx-vision"),
            })
    except Exception:
        pass
    with XRAY_CONFIG_LOCK:
        cfg = _read_config()
        if not cfg:
            return False, "нет конфига"
        # статистика по пользователям нужна и для живого конфига (не только при sync)
        if "policy" not in cfg:
            cfg["policy"] = {"levels": {"0": {"statsUserUplink": True,
                                              "statsUserDownlink": True}}}
        done = False
        for inbound in cfg.get("inbounds", []):
            if inbound.get("tag") == "vless-in":
                inbound.setdefault("settings", {})["clients"] = clients
                done = True
                break
        if not done:
            return False, "vless-in не найден в xray.json"
        if not _write_config(cfg):
            return False, "write fail"
    if not _restart_xray():
        return False, "restart fail"
    config.log("core: vless-in clients обновлены (%d всего)" % len(clients))
    return True, "clients %d" % len(clients)


def set_active_tag(tag):
    """Переключение final на тег из xray.json (vless). Возвращает (ok, msg)."""
    config.update_state(comm={"state": "syncing", "msg": "переключение ключа..."})
    with XRAY_CONFIG_LOCK:  # read-modify-write целиком под локом (TOCTOU)
        cfg = _read_config()
        if not cfg:
            config.update_state(comm={"state": "idle", "msg": ""})
            return False, "нет конфига"
        tags = [o.get("tag") for o in cfg.get("outbounds", [])]
        if tag not in tags:
            config.update_state(comm={"state": "idle", "msg": ""})
            return False, "tag not in outbounds"
        prev = get_vless_now()
        if prev == tag:
            config.update_state(comm={"state": "idle", "msg": ""})
            return True, "already active"
        for rule in cfg.get("routing", {}).get("rules", []):
            if "http-in" in (rule.get("inboundTag") or []):
                rule["outboundTag"] = tag
        if not _write_config(cfg):
            config.update_state(comm={"state": "idle", "msg": ""})
            return False, "write fail"
    if not _restart_xray():
        config.update_state(comm={"state": "idle", "msg": ""})
        return False, "restart fail"
    ip = None
    for i in range(1, 5):  # 4 попытки, cold start Reality >8с
        ip = egress_probe(timeout=10)
        if ip:
            break
        time.sleep(3)
    if ip:
        config.update_state(vless_now=tag, final_mode=tag, egress_ip=ip,
                            comm={"state": "idle", "msg": ""})
        config.log("core: switch -> %s (egress %s)" % (tag, ip))
        return True, "egress %s" % ip
    # откат
    rollback = prev if prev in tags else "direct"
    with XRAY_CONFIG_LOCK:
        cfg = _read_config()  # перечитываем свежую версию (конфиг мог смениться)
        if cfg:
            for rule in cfg.get("routing", {}).get("rules", []):
                if "http-in" in (rule.get("inboundTag") or []):
                    rule["outboundTag"] = rollback
            _write_config(cfg)
    _restart_xray()
    config.update_state(vless_now=rollback, final_mode=rollback,
                        comm={"state": "idle", "msg": ""})
    config.log("core: no egress, rollback to %s" % rollback)
    return False, "no egress, rollback to %s" % rollback


def _rotate_guard():
    now = time.time()
    if now - _LAST_ROTATE[0] < config.ROTATE_COOLDOWN_S:
        return True  # в кулдауне — пропустить
    return False


def rotate():
    """Ротация: пробуем до 3 кандидатов с живым egress. Возвращает новый тег или None."""
    with _ROTATE_LOCK:  # guard + установка кулдауна атомарны (гонка watch+API)
        if _rotate_guard():
            config.log("core: rotate cooldown, skip")
            return None
        _LAST_ROTATE[0] = time.time()  # фиксируем сразу после прохода guard
    cur = get_vless_now()
    pool.dedupe()
    keys = pool.get_keys()
    # кандидаты: не текущий, с egress/IP
    cands = []
    for k in keys:
        if k.get("tag") == cur or pool.blocked(k.get("uri", "")):
            continue
        st = pool._STATUS.get(pool._norm_uri(k.get("uri", "")), {})
        ip = st.get("exit_ip", "-")
        if pool._good_ip(ip):
            cands.append(k)
    if not cands:  # фолбек: все живые, кроме текущего
        cands = [k for k in keys if k.get("tag") != cur and not pool.blocked(k.get("uri", ""))]
    cands = cands[:3]
    for k in cands:
        tag = k.get("tag")
        if not tag:
            continue
        ok, msg = set_active_tag(tag)
        if ok:
            config.log("core: rotate -> %s (%s)" % (tag, msg))
            return tag
    config.log("core: rotate: кандидаты мертвы")
    return None


# --- watchdog final ---
def _final_watch():
    """Каждые 120с: проверяет живой ли final, при смерти — sync/rotate."""
    while not _WATCH_STOP.is_set():
        if _WATCH_STOP.wait(120):
            break
        tag = get_vless_now()
        # VPN OFF -> просто наблюдаем
        if not config.get("vpn_mode", True):
            continue
        if tag in ("", "-", "direct", None):
            if pool.pick_final():
                config.log("core: final=direct при VPN ON, попытка восстановления")
                sync()
            else:
                config.log("core: живых кандидатов нет")
            continue
        # есть тег: проверяем TCP до хоста
        label = re.sub(r"-\d+$", "", tag.replace("vless-", ""))
        host = port = None
        for k in pool.get_keys():
            kh = k.get("host", "")
            if kh == label or kh.split(".")[0] == label:
                host, port = kh, k.get("port", 443)
                break
        if host:
            import source
            if not source._tcp_ping(host, port, timeout=5):
                config.log("core: final %s dead, rotate" % tag)
                if _rotate_guard():
                    continue
                rotate()
                continue
        # устойчивый None: одна проба = ложный rotate (cold start/flap 5-14с)
        ip = None
        for _attempt in range(3):
            ip = egress_probe(timeout=8)
            if ip:
                break
            time.sleep(3)
        if not ip:
            config.log("core: final %s БЕЗ egress (3 пробы), rotate" % tag)
            # честный egress: канал реально не отдаёт IP — не показываем устаревший кэш
            config.update_state(egress_ip="-")
            if _rotate_guard():
                continue
            rotate()
            continue
        # egress фактом жив — обновляем в state (анти-устаревание при кулдауне ротации)
        if config.get_state().get("egress_ip") != ip:
            config.update_state(egress_ip=ip)


def start_watch():
    t = threading.Thread(target=_final_watch, daemon=True)
    t.start()
    return t