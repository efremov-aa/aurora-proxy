# Aurora v1.0 — телеметрия: устройства, соединения, трафик через ss//proc.

import re
import subprocess
import threading
import time

import config

_POLL_LOCK = threading.Lock()
_SERVICE_LOCK = threading.Lock()
_SERVICE_LAST_UP = {}
_SERVICE_LAST_DOWN = {}
_SERVICE_UP = {}
_SERVICE_DOWN = {}


def _service_ports():
    ports = {config.XRAY_PORT, config.TGWS_PORT}
    try:
        vless_port = int(getattr(config, "VLESS_PUBLIC", {}).get("port", 8443))
    except (TypeError, ValueError):
        vless_port = 0
    if 1 <= vless_port <= 65535:
        ports.add(vless_port)
    return ports


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


def _collect_conns():
    """(total, {client_ip: count}) по /proc/net/tcp{,6}, state=ESTABLISHED,
    локальный порт в наших или клиент локальной подсети."""
    ports = _service_ports()
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


def _parse_ss_block(block, ports):
    body = " ".join(block)
    addrs = _addr_port(body)
    if len(addrs) < 2:
        return None
    local = next(((ip, port) for ip, port in addrs if port in ports), None)
    if local is None:
        return None
    peer = next(((ip, port) for ip, port in reversed(addrs)
                 if (ip, port) != local), None)
    if peer is None:
        return None
    sent = re.search(r"bytes_sent:(\d+)", body)
    received = re.search(r"bytes_received:(\d+)", body)
    if not sent and not received:
        return None
    ip = peer[0]
    if ip.startswith("127.") or ip in ("0.0.0.0", "::"):
        return None
    return ip, int(sent.group(1)) if sent else 0, int(received.group(1)) if received else 0


def _collect_sock_stats():
    """Трафик per-device через ss -in (bytes_sent/bytes_received к peer IP)."""
    up = {}
    down = {}
    ports = _service_ports()
    try:
        out = subprocess.run(["ss", "-in", "state", "established"],
                             capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return up, down
    block = []
    for line in out.splitlines():
        if not line.strip():
            if block:
                item = _parse_ss_block(block, ports)
                if item:
                    ip, sent, received = item
                    down[ip] = down.get(ip, 0) + sent
                    up[ip] = up.get(ip, 0) + received
                block = []
            continue
        if not line[:1].isspace() and block:
            item = _parse_ss_block(block, ports)
            if item:
                ip, sent, received = item
                down[ip] = down.get(ip, 0) + sent
                up[ip] = up.get(ip, 0) + received
            block = []
        block.append(line)
    if block:
        item = _parse_ss_block(block, ports)
        if item:
            ip, sent, received = item
            down[ip] = down.get(ip, 0) + sent
            up[ip] = up.get(ip, 0) + received
    return up, down


def _traffic_deltas(current_up, current_down):
    delta_up = {}
    delta_down = {}
    with _SERVICE_LOCK:
        for ip, value in current_up.items():
            previous = _SERVICE_LAST_UP.get(ip, 0)
            delta_up[ip] = value - previous if value >= previous else value
            _SERVICE_LAST_UP[ip] = value
        for ip, value in current_down.items():
            previous = _SERVICE_LAST_DOWN.get(ip, 0)
            delta_down[ip] = value - previous if value >= previous else value
            _SERVICE_LAST_DOWN[ip] = value
    return delta_up, delta_down


def poll(loop=True):
    """Фоновый сбор: conns каждые 30с, трафик каждые 5с. Пишет в config.STATE."""
    cycles = 0
    while True:
        try:
            total, by_ip = _collect_conns()
            current_up, current_down = _collect_sock_stats()
            delta_up, delta_down = _traffic_deltas(current_up, current_down)
            with _SERVICE_LOCK:
                for ip, value in delta_up.items():
                    _SERVICE_UP[ip] = _SERVICE_UP.get(ip, 0) + value
                for ip, value in delta_down.items():
                    _SERVICE_DOWN[ip] = _SERVICE_DOWN.get(ip, 0) + value
                cumulative_up = dict(_SERVICE_UP)
                cumulative_down = dict(_SERVICE_DOWN)
            devices = {}
            names = DEVICE_NAMES
            for ip, cnt in by_ip.items():
                d = devices.setdefault(ip, {"ip": ip, "name": names.get(ip, ""), "conns": 0,
                                            "upload": 0, "download": 0})
                d["conns"] = cnt
                d["upload"] = cumulative_up.get(ip, 0)
                d["download"] = cumulative_down.get(ip, 0)
            total_up = sum(cumulative_up.values())
            total_down = sum(cumulative_down.values())
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
    """Имена устройств через ip neigh (MAC) и getent hosts (reverse-DNS .lan)."""
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
