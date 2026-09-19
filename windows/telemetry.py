# Aurora v1.0 — телеметрия: устройства, соединения, трафик через ss//proc.

import os
import re
import subprocess
import threading
import time

import config

_POLL_LOCK = threading.Lock()


def _hex_to_ip(raw):
    """Адресс из /proc/net/tcp{,6} (HEX little-endian) -> IPv4/IPv6."""
    raw = raw.strip()
    if ":" not in raw:
        if len(raw) == 32:  # tcp6 с IPv4-mapped ::ffff: в HEX
            tail = raw[-8:]
            return ".".join(str(int(tail[i:i + 2], 16)) for i in (6, 4, 2, 0))
        if len(raw) == 8:   # tcp4
            return ".".join(str(int(raw[i:i + 2], 16)) for i in (6, 4, 2, 0))
        return raw
    # tcp6 с двоеточиями — оставляем как есть
    return raw


def _collect_conns_nt():
    """(total, {client_ip: count}) через netstat -ano (Windows)."""
    total = 0
    by_ip = {}
    ports = {config.XRAY_PORT, config.TGWS_PORT}
    try:
        out = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return total, by_ip
    for ln in out.splitlines():
        parts = ln.split()
        if len(parts) < 4:
            continue
        if parts[1] not in ("TCP", "TCP6"):
            continue
        if parts[3] != "ESTABLISHED":
            continue
        l = parts[2].rsplit(":", 1)
        r = parts[3].rsplit(":", 1) if False else (parts[2], "")
        # netstat: [Local Address, Foreign Address, State, PID]
        local = parts[2].strip("[]")
        foreign = parts[3].strip("[]")
        if ":" not in foreign:
            continue
        f_host, f_port = foreign.rsplit(":", 1)
        try:
            l_port = int(local.rsplit(":", 1)[1]) if ":" in local else 0
        except ValueError:
            continue
        if l_port not in ports:
            continue  # исходящее xray->VLESS
        ip = f_host.replace("::ffff:", "")
        if ip in ("127.0.0.1", "::1", "0.0.0.0"):
            continue
        total += 1
        by_ip[ip] = by_ip.get(ip, 0) + 1
    return total, by_ip


def _collect_conns():
    """(total, {client_ip: count}) по /proc/net/tcp{,6}, state=ESTABLISHED,
    локальный порт в наших или клиент локальной подсети."""
    if os.name == "nt":
        return _collect_conns_nt()
    ports = {config.XRAY_PORT, config.TGWS_PORT}
    total = 0
    by_ip = {}
    try:
        _octs = [int(o) for o in str(config.VM_HOST).split(".")]
        l_ip_hint = "".join("%02X" % o for o in reversed(_octs)).lower()  # IP в HEX (little-endian)
    except Exception:
        l_ip_hint = ""  # исходящие не отличаем — считается весь трафик на наши порты
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path, "r") as f:
                lines = f.readlines()[1:]
        except OSError:
            continue
        for ln in lines:
            parts = ln.split()
            if len(parts) < 4:
                continue
            state = parts[3]
            if state != "01":
                continue
            l_addr, l_port_hex = parts[1].split(":")
            r_addr, r_port_hex = parts[2].split(":")
            try:
                l_port = int(l_port_hex, 16)
            except ValueError:
                continue
            if l_ip_hint in l_addr and l_port in ports:
                continue  # исходящее соединение xray -> VLESS
            if l_port in ports:
                client = _hex_to_ip(r_addr)
                if client.startswith("127.") or client == "0.0.0.0":
                    continue
                total += 1
                by_ip[client] = by_ip.get(client, 0) + 1
    return total, by_ip


def _addr_port(body):
    """Адреса ip:port из тела ss-блока. Ловит и plain `1.2.3.4:port`,
    и IPv6-mapped `[::ffff:1.2.3.4]:port` (реальный IPv4 внутри скобок)."""
    res = []
    for m in re.finditer(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", body):
        e = m.end()
        if e < len(body) and body[e] == "]":
            mm = re.match(r"]:(\d+)", body[e:])
        elif e < len(body) and body[e] == ":":
            mm = re.match(r":(\d+)", body[e:])
        else:
            mm = None
        if mm:
            res.append((m.group(1), int(mm.group(1))))
    return res


def _collect_sock_stats():
    """Трафик per-device через ss -in (bytes_sent/bytes_received к peer IP).

    В блоке ss первый адрес — Local (наш сервер:порт), последний — Peer (клиент).
    Раньше брался первый адрес -> весь трафик копился на сервер, у клиентов 0.
    Считаем только соединения клиентов с нашими портами (local port in ports):
    исходящие xray->VLESS имеют эфемерный локальный порт и сюда не попадают."""
    if os.name == "nt":
        return {}, {}  # трафик per-device на Windows недоступен
    up = {}
    down = {}
    ports = {config.XRAY_PORT, config.TGWS_PORT}
    try:
        out = subprocess.run(["ss", "-in", "state", "established"],
                             capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return up, down
    cur_block = []
    for line in out.splitlines():
        if not line.strip():
            continue
        # ss: продолжение блока идёт с TAB, заголовок соединения — с 'tcp'
        if not line[:1].isspace():  # начало нового соединения
            cur_block = []
        cur_block.append(line)
        body = " ".join(cur_block)
        addrs = _addr_port(body)
        mb = re.search(r"bytes_sent:(\d+)", body)
        mr = re.search(r"bytes_received:(\d+)", body)
        if len(addrs) < 2 or not (mb or mr):
            continue
        l_port = addrs[0][1]
        if l_port not in ports:
            continue  # исходящее xray->VLESS или служебное
        ip = addrs[-1][0]  # peer (клиент)
        if ip.startswith("127.") or ip == "0.0.0.0":
            continue
        if mb:
            down[ip] = down.get(ip, 0) + int(mb.group(1))
        if mr:
            up[ip] = up.get(ip, 0) + int(mr.group(1))
    return up, down


def poll(loop=True):
    """Фоновый сбор: conns каждые 30с, трафик каждые 5с. Пишет в config.STATE."""
    cycles = 0
    while True:
        try:
            total, by_ip = _collect_conns()
            up, down = _collect_sock_stats()
            devices = {}
            names = DEVICE_NAMES
            for ip, cnt in by_ip.items():
                d = devices.setdefault(ip, {"ip": ip, "name": names.get(ip, ""), "conns": 0,
                                            "upload": 0, "download": 0})
                d["conns"] = cnt
                d["upload"] = up.get(ip, 0)
                d["download"] = down.get(ip, 0)
            total_up = sum(up.values())
            total_down = sum(down.values())
            config.update_state(conns=total, devices=devices, up=total_up, down=total_down)
        except Exception:
            pass
        if not loop:
            break
        cycles += 1
        # обновляем имена при старте и раз в ~10 циклов (5 мин)
        if cycles == 1 or cycles % 10 == 0:
            try:
                resolve_names()
            except Exception:
                pass
        time.sleep(30)


DEVICE_NAMES = {}

# Статические имена устройств (fallback, если reverse-DNS / ip neigh не дают).
# Заполните своими IP и именами, либо оставьте пустым — имена придут из DNS/ARP.
STATIC_NAMES = {
}


def resolve_names():
    """Имена устройств через ip neigh (MAC) и getent hosts (reverse-DNS .lan).
    На Windows — только статическая база STATIC_NAMES."""
    if os.name == "nt":
        if STATIC_NAMES:
            DEVICE_NAMES.update(dict(STATIC_NAMES))
        return
    names = dict(STATIC_NAMES)  # статика как база; ARP/getent перезаписывают
    try:
        out = subprocess.run(["ip", "neigh"], capture_output=True, text=True, timeout=8).stdout
        lines = out.splitlines()
    except Exception:
        lines = []
    mac_by_ip = {}
    for ln in lines:
        parts = ln.split()
        if len(parts) >= 5 and "lladdr" in parts:
            idx = parts.index("lladdr")
            mac_by_ip[parts[0]] = parts[idx + 1]
    for ip, mac in mac_by_ip.items():
        names[ip] = "устройство %s" % mac.replace(":", "")
    # reverse-DNS (работает для .lan)
    for ip in list(mac_by_ip):
        try:
            import subprocess
            r = subprocess.run(["getent", "hosts", ip], capture_output=True, text=True, timeout=4)
            if r.returncode == 0 and r.stdout.strip():
                parts = r.stdout.split()
                if len(parts) >= 2 and parts[1] != ip:
                    names[ip] = parts[1]
        except Exception:
            pass
    DEVICE_NAMES.update(names)