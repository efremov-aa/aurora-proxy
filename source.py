# Aurora v1.0 — источники ключей: github-списки, парс vless://, live-проверка.
# Проверка не трогает рабочий xray: temp-конфиг на отдельном порту + реальный egress.

import os
import socket
import threading
import time
import urllib.parse
import urllib.request

import config
import pool

KEYTEST_PORT = 19876  # temp-xray для пробы ключей (отдельный, не мешает основному)
UA = "Aurora/1.0"


# ---- comm для док-бара: 'done' живёт TTL секунд, затем авто-возврат в idle.
# Guard по текущему state='done' защищает от затирания новой операции
# (loading/running/syncing), стартовавшей позже нашего таймера.
def _comm_done(msg, ttl=10):
    config.update_state(comm={"state": "done", "msg": msg})

    def _to_idle():
        time.sleep(ttl)
        if config.get_state().get("comm", {}).get("state") == "done":
            config.update_state(comm={"state": "idle", "msg": ""})
    threading.Thread(target=_to_idle, daemon=True).start()

# --- загрузка списков ---
def fetch_source(url, timeout=30):
    """Скачивает список ключей по URL; возвращает текст или None."""
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="replace")
    except Exception as e:
        config.log("source: fetch %s: %s" % (url, e))
        return None


def parse_vless_list(text):
    """Вытаскивает валидные vless:// URI из текста; возвращает список uri."""
    out = []
    for line in str(text).splitlines():
        line = line.strip()
        if line.startswith("vless://"):
            out.append(line.rstrip("#").strip())
    return out


def _key_from_uri(uri):
    """Разбирает vless-uri в dict-ключ или None. Reality-поля из query."""
    try:
        p = urllib.parse.urlparse(uri)
        if p.scheme != "vless" or not p.hostname:
            return None
        q = urllib.parse.parse_qs(p.query)

        def one(name, default=None):
            v = q.get(name)
            if isinstance(v, list):
                v = v[0] if v else None
            return v or default

        return {
            "uri": uri.rstrip("#").strip(),
            "tag": "",
            "host": p.hostname,
            "port": p.port or 443,
            "uuid": p.username or "",
            "pbk": one("pbk"),
            "sid": one("sid"),
            "fp": one("fp", "chrome"),
            "sni": one("sni"),
            "flow": one("flow", "xtls-rprx-vision"),
            "source": "github",
        }
    except Exception:
        return None


def refresh_from_github():
    """Скачивает все источники, мержит в пул (новые добавляет, старые оставляет)."""
    config.update_state(comm={"state": "loading", "msg": "загрузка ключей с github..."})
    pool.dedupe()
    before = len(pool.get_keys())
    total_new = 0
    for url in config.GITHUB_SOURCES:
        text = fetch_source(url)
        if not text:
            config.log("source: %s не дал данных" % url)
            continue
        uris = parse_vless_list(text)
        added = 0
        skipped = 0
        no_reality = 0
        for u in uris:
            key = _key_from_uri(u)
            if not key:
                continue
            if not key.get("pbk"):
                # без Reality build_outbound такой ключ не соберёт (xray v26.9.9) —
                # в пул не берём, чтобы не копить несобираемый мусор
                no_reality += 1
                continue
            r = pool.add_key(key)
            if r == "added":
                added += 1
            elif r == "blocked":
                # мёртвый ключ — в пул не возвращаем (правило юзера)
                skipped += 1
        total_new += added
        config.log("source: %s: %d uri (новых %d, в блоке пропущено %d, без reality %d)" % (
            url, len(uris), added, skipped, no_reality))
    after = len(pool.get_keys())
    _comm_done("github: добавлено %d ключей (всего %d)" % (total_new, after))
    config.log("source: всего в пуле %d (было %d, новых %d)" % (after, before, total_new))
    return total_new


# --- live-проверка ключа ---
def _tcp_ping(host, port, timeout=4):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except OSError:
        return False


def _tcp_ping_ms(host, port, timeout=4):
    """TCP-пинг с замером времени. Возвращает мс или None при недоступности."""
    t = time.time()
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return int((time.time() - t) * 1000)
    except OSError:
        return None


def _gen_keytest_config(key, port):
    """Temp-конфиг: один vless-outbound (только этот ключ) + direct; API на порту."""
    import json
    ob = pool.build_outbound(key)
    if not ob:
        return None
    cfg = {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "http-in",
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "http",
        }],
        "outbounds": [
            ob,
            {"protocol": "freedom", "tag": "direct",
             "settings": {"domainStrategy": "UseIP"}},
            {"protocol": "blackhole", "tag": "block"},
        ],
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": [
            {"type": "field", "inboundTag": ["http-in"], "outboundTag": ob["tag"]},
        ]},
    }
    return cfg


def _http_egress_check(port, timeout=8):
    """Реальный egress через temp-xray: HTTP+HTTPS ipify; белый IP отфильтрован."""
    for scheme in ("https", "http"):
        url = "%s://api.ipify.org?format=json" % scheme
        try:
            proxy = urllib.request.ProxyHandler({
                "http": "http://127.0.0.1:%d" % port,
                "https": "http://127.0.0.1:%d" % port,
            })
            opener = urllib.request.build_opener(proxy)
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with opener.open(req, timeout=timeout) as r:
                body = r.read().decode("utf-8", errors="replace")
            import json
            ip = json.loads(body).get("ip", "")
            if ip and ip not in ("", "-", config.WHITE_IP):
                return ip
        except Exception:
            continue
    return None


def _xray_bin():
    import glob
    cands = [
        os.path.join(os.path.expanduser("~"), "xray"),
        os.path.join(config.BASE_DIR, "xray"),
    ]
    for c in cands:
        if os.path.exists(c):
            return c
    return None


def keytest(key, timeout=15, port=None):
    """Полный тест: TCP -> keytest через temp-xray -> egress. Возвращает dict.
    port — уникальный temp-порт для xray (важно при параллельной проверке)."""
    import json
    import os
    import subprocess

    port = port or KEYTEST_PORT
    host = key.get("host")
    port_v = key.get("port") or 443
    uri = key.get("uri", "")

    host = key.get("host")
    port_v = key.get("port") or 443
    uri = key.get("uri", "")

    # TCP-пинг с реальным замером времени (это и есть ping_ms ключа)
    ping_ms = _tcp_ping_ms(host, port_v)
    if ping_ms is None:
        return {"status": "bad", "reason": "tcp-fail", "exit_ip": "-", "ping_ms": 9999}
    # правило юзера: > MAX_PING_MS (500мс) — ключ мёртвый
    if ping_ms > config.MAX_PING_MS:
        return {"status": "slow", "reason": "ping-high", "exit_ip": "-", "ping_ms": ping_ms}

    t0 = time.time()
    xbin = _xray_bin()
    if not xbin:
        return {"status": "noip", "reason": "no-xray-bin", "exit_ip": "-", "ping_ms": ping_ms}

    cfg = _gen_keytest_config(key, port)
    if not cfg:
        return {"status": "bad", "reason": "bad-config", "exit_ip": "-", "ping_ms": 9999}

    cfg_path = os.path.join(config.DATA_DIR, "keytest_cfg_%d.json" % port)
    try:
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f)
    except OSError:
        return {"status": "noip", "reason": "cfg-write-fail", "exit_ip": "-", "ping_ms": ping_ms}

    proc = None
    try:
        proc = subprocess.Popen([xbin, "run", "-c", cfg_path],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError:
        pass

    # ждём порт, затем egress-проба (не ждать завершения xray — он вечный)
    _wait_port(port, timeout=4)
    ip = _http_egress_check(port, timeout=8)
    try:
        if proc and proc.poll() is None:
            proc.terminate()
    except Exception:
        pass
    if ip:
        return {"status": "ok", "exit_ip": ip, "sites_ok": 1, "ping_ms": ping_ms}
    return {"status": "noip", "reason": "no-egress", "exit_ip": "-", "ping_ms": ping_ms}


def _wait_port(port, timeout=4):
    end = time.time() + timeout
    while time.time() < end:
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=0.5)
            s.close()
            return True
        except OSError:
            time.sleep(0.3)
    return False


# --- фоновый прогон проверки всех ключей ---
_CHECK_LOCK = threading.Lock()
_CHECK_RUNNING = [False]


def _check_running():
    return _CHECK_RUNNING[0]


def check_all(bg=True):
    """Проверяет все ключи пула (ThreadPoolExecutor), пишет статусы. В фоне или синхронно.
    Повторный вызов при уже идущей проверке — no-op (guard)."""
    with _CHECK_LOCK:
        if _CHECK_RUNNING[0]:
            if bg:
                return {"ok": False, "msg": "проверка уже идёт"}
            return False
        _CHECK_RUNNING[0] = True

    def run():
        try:
            from concurrent.futures import ThreadPoolExecutor
            keys = pool.get_keys()
            n = len(keys)
            config.update_state(comm={"state": "running", "msg": "проверка %d ключей..." % n})
            stats = {"total": n, "ok": 0, "bad": 0, "noip": 0, "slow": 0, "dead": 0}
            t0 = time.time()
            # каждый воркер-ключ получает СВОЙ temp-порт (иначе bind-конфликт на KEYTEST_PORT)
            def _kt(item):
                idx, k = item
                return keytest(k, port=KEYTEST_PORT + 1 + idx)
            with ThreadPoolExecutor(max_workers=8) as ex:
                futures = {ex.submit(_kt, (idx, k)): k for idx, k in enumerate(keys)}
                done_n = 0
                for fut in futures:
                    k = futures[fut]
                    try:
                        r = fut.result()
                    except Exception as e:
                        r = {"status": "bad", "reason": str(e), "exit_ip": "-", "ping_ms": 9999}
                    done_n += 1
                    # док-бар: живой прогресс проверки (не спамить — каждые 5 ключей)
                    if done_n % 5 == 0 or done_n == n:
                        config.update_state(comm={"state": "running",
                                                  "msg": "проверено %d из %d..." % (done_n, n)})
                    s = r.get("status")
                    if s == "ok":
                        stats["ok"] += 1
                        pool.status_mark(k["uri"], "ok", r.get("ping_ms", 0), r.get("exit_ip", "-"), r.get("sites_ok", 1))
                        # ключ ожил — снимаем ТОЛЬКО авто-блеклист, но НЕ user_removed (правило юзера: те не возвращаются)
                        if pool.dead_reason(k["uri"]) and pool.dead_reason(k["uri"]) != "user_removed":
                            pool.dead_remove(k["uri"])
                    elif s == "slow":
                        stats["slow"] += 1
                        stats["dead"] += 1
                        pool.status_mark(k["uri"], "slow", r.get("ping_ms", 0))
                        # правило юзера: >500мс — ключ мёртвый (в блеклист);
                        # «свои» (my/manual) в авто-блеклист НЕ попадают — удаляет только юзер вручную
                        if k.get("source") not in ("my", "manual"):
                            pool.dead_add(k["uri"], "autodead_ping")
                    else:
                        reason = r.get("reason", "unknown")
                        if reason == "tcp-fail":
                            stats["bad"] += 1
                            stats["dead"] += 1
                            pool.status_mark(k["uri"], "bad", r.get("ping_ms", 9999))
                            if k.get("source") not in ("my", "manual"):
                                pool.dead_add(k["uri"], "autodead_conn")
                        else:
                            stats["noip"] += 1
                            pool.status_mark(k["uri"], "noip", r.get("ping_ms", 0))
                            # Ключ TCP жив, но egress не дал — по правилу юзера «без
                            # выходного IP мёртвый». Блокируем в блеклисте, чтобы refresh
                            # не подливал его СНОВА как «новый» (цикл: refresh -> noip ->
                            # cleanup -> тот же refresh). Свои (my/manual) не трогаем.
                            if k.get("source") not in ("my", "manual"):
                                pool.dead_add(k["uri"], "autodead_noip")
            dt = int(time.time() - t0)
            msg = "check done: {total:%d, ok:%d, bad:%d, slow:%d, noip:%d, dead:%d} за %dс" % (
                stats["total"], stats["ok"], stats["bad"], stats["slow"], stats["noip"], stats["dead"], dt)
            _comm_done(msg)
            config.log("source: " + msg)
            # чистка мёртвых после проверки + подъём канала, если появился живой ключ
            try:
                removed = pool.cleanup()
                if removed:
                    config.log("source: cleanup убрал %d мёртвых после проверки" % removed)
            except Exception:
                pass
            try:
                if config.get("vpn_mode", True) and pool.pick_final():
                    import core
                    threading.Thread(target=core.sync, daemon=True).start()
                    config.log("source: живые ключи есть, поднимаю канал")
            except Exception:
                pass
            return stats
        finally:
            _CHECK_RUNNING[0] = False

    if bg:
        threading.Thread(target=run, daemon=True).start()
        return {"ok": True, "msg": "check started"}
    return run()
