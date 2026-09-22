# Aurora v1.0 — ру-сегмент: проверка доступности российских ресурсов напрямую.
# Вкладка «Ру-сегмент» показывает, работает ли RU-интернет без VPN
# (подключение с сервера напрямую, минуя xray-прокси).

import concurrent.futures
import socket
import threading
import time
import urllib.request

import config

# популярные российские ресурсы (по умолчанию)
RU_DOMAINS = [
    "yandex.ru", "ya.ru", "vk.com", "ok.ru", "mail.ru", "rambler.ru",
    "lenta.ru", "rbc.ru", "gazeta.ru", "kommersant.ru", "rg.ru",
    "kremlin.ru", "gosuslugi.ru", "gov.ru", "sberbank.ru", "tinkoff.ru",
    "avito.ru", "ozon.ru", "wildberries.ru", "kinopoisk.ru",
    "rutube.ru", "matchtv.ru", "kp.ru", "mos.ru",
]

_TIMEOUT = 6         # секунд на запрос
_MAX_WORKERS = 8     # параллельных проверок
_LOCK = threading.Lock()


def _probe(host):
    """Проверка одного домена напрямую (без прокси). HTTP-код + время + IP."""
    t0 = time.time()
    ip = ""
    try:
        # форсируем IPv4: на сервере нет гарантированного IPv6, HTTP проще по IPv4
        ip = socket.getaddrinfo(host, 80, socket.AF_INET)[0][4][0]
    except Exception:
        pass
    code = 0
    try:
        req = urllib.request.Request("http://" + host + "/",
                                     headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
            code = r.getcode() or 0
    except Exception as e:
        err = str(e)
        code = -1
    return {
        "host": host,
        "ip": ip,
        "code": code,
        "ms": int((time.time() - t0) * 1000),
    }


def check_all():
    """Прогон всех доменов. Обновляет config.STATE['rusegment']."""
    with _LOCK:
        if config.get_state().get("rusegment", {}).get("running"):
            return False
        st = config.get_state()
        st.setdefault("rusegment", {})["running"] = True
        config.update_state(rusegment=st["rusegment"])
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=_MAX_WORKERS) as ex:
        futs = {ex.submit(_probe, h): h for h in RU_DOMAINS}
        for fut in concurrent.futures.as_completed(futs):
            try:
                results.append(fut.result())
            except Exception:
                results.append({"host": futs[fut], "ip": "", "code": -1, "ms": 0})
    results.sort(key=lambda r: RU_DOMAINS.index(r["host"]) if r["host"] in RU_DOMAINS else 99)
    with _LOCK:
        st = config.get_state()
        st.setdefault("rusegment", {})
        st["rusegment"]["results"] = results
        st["rusegment"]["running"] = False
        st["rusegment"]["ts"] = time.time()
        config.update_state(rusegment=st["rusegment"])
    config.log("rusegment: проверено %d доменов" % len(results))
    return True


def start():
    """Первичный прогон в фоне при старте сервера."""
    t = threading.Thread(target=check_all, daemon=True)
    t.start()
    return t
