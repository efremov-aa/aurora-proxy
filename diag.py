# Aurora A-1040 «Кот-смотритель» — самопроверка канала и замер скорости.
#
# Вкладка «Сервис» в панели: одна кнопка прогоняет проверки (прокси-порт,
# прямой выход, выход через прокси, egress, DNS, TG-WS, RU-сегмент, WARP,
# MASQUE), вторая — измеряет ping/загрузку/отдачу через тот же mixed-порт,
# что использует владелец. Всё в фоне: HTTP-поток панели не блокируется.

import json
import random
import socket
import threading
import time
import urllib.request

import config
import core
import masque
import tgws
import warp

_LOCK = threading.RLock()
_LAST = {"running": False, "ts": 0, "results": [], "ok": False}
_SPEED = {"running": False, "last": None, "history": []}
HISTORY_MAX = 12

PROBE_URLS = (
    "http://cp.cloudflare.com/generate_204",
    "http://www.msftconnecttest.com/connecttest",
    "http://example.com/",
)
PROXY_URL = "http://127.0.0.1:%d"
DOWN_BYTES = 5 * 1024 * 1024
UP_BYTES = 1024 * 1024


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _proxy_url():
    return PROXY_URL % config.XRAY_PORT


def _opener(proxy=False):
    handler = urllib.request.ProxyHandler(
        {"http": _proxy_url(), "https": _proxy_url()} if proxy else {})
    return urllib.request.build_opener(handler, _NoRedirect())


def _get(url, proxy=False, timeout=8, method="GET", data=None, headers=None):
    req = urllib.request.Request(url, data=data, method=method,
                                 headers=headers or {"User-Agent": "aurora-diag"})
    with _opener(proxy).open(req, timeout=timeout) as resp:
        body = resp.read()
        return resp.getcode() or 0, body
    return 0, b""


def _tcp_ok(host, port, timeout=3.0):
    t0 = time.time()
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True, int((time.time() - t0) * 1000)
    except OSError:
        return False, int((time.time() - t0) * 1000)


def _row(cid, name, ok, ms, detail="", critical=False):
    return {"id": cid, "name": str(name), "ok": bool(ok),
            "critical": bool(critical), "ms": int(ms or 0),
            "detail": str(detail or "")[:160]}


def _check_xray_port():
    ok, ms = _tcp_ok("127.0.0.1", config.XRAY_PORT)
    return _row("xray_port", "Порт прокси xray", ok, ms,
                "127.0.0.1:%d" % config.XRAY_PORT, critical=True)


def _check_direct():
    url = PROBE_URLS[0]
    t0 = time.time()
    try:
        code, _ = _get(url, proxy=False, timeout=6)
        ms = int((time.time() - t0) * 1000)
        return _row("direct", "Прямой выход (без прокси)", code in (200, 204),
                    ms, "HTTP %s" % code, critical=True)
    except Exception as e:
        return _row("direct", "Прямой выход (без прокси)", False,
                    int((time.time() - t0) * 1000),
                    "%s: %s" % (type(e).__name__, e), critical=True)


def _check_proxy():
    t0 = time.time()
    for url in PROBE_URLS:
        try:
            code, _ = _get(url, proxy=True, timeout=6)
            ms = int((time.time() - t0) * 1000)
            if code:
                return _row("proxy", "Выход через прокси", code in (200, 204),
                            ms, "HTTP %s · %s" % (code, url), critical=True)
        except Exception:
            continue
    return _row("proxy", "Выход через прокси", False,
                int((time.time() - t0) * 1000), "нет ответа", critical=True)


def _check_egress():
    t0 = time.time()
    # В осознанном прямом режиме выходного IP нет — это не поломка.
    if not config.get("vpn_mode", True):
        return _row("egress", "Выходной IP прокси", True, 0,
                    "прямой режим — прокси не используется")
    ip = core.egress_probe(timeout=8)
    ms = int((time.time() - t0) * 1000)
    white = str(config.WHITE_IP or "").strip()
    detail = ip or "не удалось определить"
    if ip and white and ip == white:
        detail += " · совпадает с белым IP"
    return _row("egress", "Выходной IP прокси", bool(ip), ms, detail,
                critical=True)


def _check_dns():
    t0 = time.time()
    try:
        socket.getaddrinfo("example.com", 80, socket.AF_INET)
        return _row("dns", "DNS", True, int((time.time() - t0) * 1000),
                    "example.com", critical=True)
    except Exception as e:
        return _row("dns", "DNS", False, int((time.time() - t0) * 1000),
                    "%s: %s" % (type(e).__name__, e), critical=True)


def _check_ipv6():
    t0 = time.time()
    try:
        socket.getaddrinfo("example.com", 80, socket.AF_INET6)
        return _row("ipv6", "IPv6", True, int((time.time() - t0) * 1000),
                    "есть адреса")
    except Exception:
        return _row("ipv6", "IPv6", True, int((time.time() - t0) * 1000),
                    "нет адресов (не ошибка)")


def _check_tgws():
    st = tgws.status()
    ok = bool(st.get("running")) and bool(st.get("port_open"))
    return _row("tgws", "Telegram WS-прокси", ok, 0,
                "процесс %s · порт %s" % (
                    "работает" if st.get("running") else "остановлен",
                    "открыт" if st.get("port_open") else "закрыт"))


def _check_rusegment():
    st = (config.get_state().get("rusegment") or {})
    rows = st.get("results") or []
    ok_n = sum(1 for r in rows if isinstance(r, dict) and (r.get("code") or 0) > 0)
    bad_n = len(rows) - ok_n
    if not rows:
        return _row("ru", "Ру-сегмент", True, 0, "ещё не проверялся")
    return _row("ru", "Ру-сегмент", bad_n == 0, 0,
                "доступно %d, проблем %d" % (ok_n, bad_n))


def _check_warp():
    st = warp.status()
    mode = str(st.get("mode") or "off")
    return _row("warp", "Резерв WARP", True, 0,
                "режим %s · конфигов %s" % (mode, st.get("count", 0)))


def _check_masque():
    st = masque.status()
    return _row("masque", "Резерв MASQUE", True, 0,
                "конфигов %s" % st.get("count", 0))


CHECKS = (
    _check_xray_port,
    _check_direct,
    _check_proxy,
    _check_egress,
    _check_dns,
    _check_ipv6,
    _check_tgws,
    _check_rusegment,
    _check_warp,
    _check_masque,
)


def _snapshot():
    with _LOCK:
        return json.loads(json.dumps(_LAST))


def status():
    """Состояние последней самопроверки для /api/diag."""
    snap = _snapshot()
    snap["ok"] = bool(snap.get("ok"))
    return snap


def start():
    """Запуск в фоне. Возвращает мгновенный ответ, результат — в status()."""
    with _LOCK:
        if _LAST["running"]:
            return {"ok": False, "msg": "проверка уже идёт"}
        _LAST["running"] = True
        _LAST["results"] = []
        _LAST["ts"] = 0
    threading.Thread(target=_worker, daemon=True).start()
    return {"ok": True, "msg": "проверка запущена"}


def _worker():
    results = []
    try:
        for check in CHECKS:
            try:
                row = check()
            except Exception as e:
                row = _row("error", check.__name__, False, 0,
                           "%s: %s" % (type(e).__name__, e))
            results.append(row)
            with _LOCK:
                _LAST["results"] = list(results)
    finally:
        with _LOCK:
            _LAST["running"] = False
            _LAST["ts"] = int(time.time())
            _LAST["results"] = results
            _LAST["ok"] = all(r.get("ok") for r in results
                              if r.get("critical"))
        config.log("diag: проверка завершена (%d проверок)" % len(results))


# --- замер скорости -------------------------------------------------------

def _speed_snapshot():
    with _LOCK:
        return json.loads(json.dumps(_SPEED))


def speed_status():
    return {"ok": True, "running": bool(_SPEED["running"]),
            "last": _speed_snapshot()["last"],
            "history": _speed_snapshot()["history"]}


def speed_start():
    with _LOCK:
        if _SPEED["running"]:
            return {"ok": False, "msg": "замер уже идёт"}
        _SPEED["running"] = True
    threading.Thread(target=_speed_worker, daemon=True).start()
    return {"ok": True, "msg": "замер запущен"}


def _ping_once(url):
    t0 = time.time()
    try:
        _get(url, proxy=True, timeout=6)
        return int((time.time() - t0) * 1000)
    except Exception:
        return None


def _measure_ping():
    best = None
    for url in PROBE_URLS:
        ms = _ping_once(url)
        if ms is not None and (best is None or ms < best):
            best = ms
    return best


def _measure_download():
    urls = ("https://speed.cloudflare.com/__down?bytes=%d" % DOWN_BYTES,
            "http://speed.cloudflare.com/__down?bytes=%d" % DOWN_BYTES)
    for url in urls:
        t0 = time.time()
        try:
            _, body = _get(url, proxy=True, timeout=30)
            seconds = time.time() - t0
            if len(body) >= 1024 and seconds > 0:
                return round(len(body) * 8 / seconds / 1_000_000.0, 2), \
                    "speed.cloudflare.com"
        except Exception:
            continue
    return None, ""


def _measure_upload():
    payload = bytes(random.getrandbits(8) for _ in range(min(65536, UP_BYTES)))
    # собираем тело нужного размера блоками, чтобы не держать в памяти мусор
    block = payload
    repeats = max(1, UP_BYTES // len(block))
    body = block * repeats
    url = "https://speed.cloudflare.com/__up"
    t0 = time.time()
    try:
        _get(url, proxy=True, timeout=30, method="POST", data=body,
             headers={"Content-Type": "application/octet-stream",
                      "User-Agent": "aurora-speed"})
        seconds = time.time() - t0
        if seconds > 0:
            return round(len(body) * 8 / seconds / 1_000_000.0, 2)
    except Exception:
        return None
    return None


def _speed_worker():
    result = {"ts": int(time.time()), "ping_ms": None,
              "down_mbps": None, "up_mbps": None, "target": "", "ok": False}
    try:
        result["ping_ms"] = _measure_ping()
        result["down_mbps"], result["target"] = _measure_download()
        result["up_mbps"] = _measure_upload()
        result["ok"] = bool(result["ping_ms"] is not None
                            and result["down_mbps"] is not None)
    finally:
        with _LOCK:
            _SPEED["running"] = False
            _SPEED["last"] = result
            if result.get("ok"):
                _SPEED["history"].append(result)
                del _SPEED["history"][:max(0, len(_SPEED["history"]) - HISTORY_MAX)]
        config.log("diag: замер скорости ping=%sМс ↓%s Мбит/с" % (
            result.get("ping_ms"), result.get("down_mbps")))
