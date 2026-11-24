# Aurora A-122 «Кот-диспетчер» — экспорт клиентских конфигов из панели.
#
# Владелец получает готовый профиль для подключения К ЭТОМУ серверу:
# v2rayN (ссылка vless://), sing-box (JSON), Clash.Meta (YAML). Источник —
# внешний VLESS-Reality :8443 (config.vless_public), тот же, что в панели
# «Внешний доступ». В профиль добавляется пометка, какой канал сейчас
# активен на сервере (VLESS-пул / MASQUE / WARP), чтобы было видно,
# куда реально пойдёт трафик после подключения.

import json
import urllib.parse

import config

FORMATS = ("v2rayn", "singbox", "clash")


def _link(v):
    host = config._format_link_host(v.get("host", ""))
    q = urllib.parse.urlencode({
        "encryption": "none",
        "security": "reality",
        "flow": v["flow"],
        "sni": v["sni"],
        "fp": "chrome",
        "pbk": v["public_key"],
        "sid": v["short_id"],
        "type": "tcp",
        "headerType": "none",
    })
    return "vless://%s@%s:%d?%s#Aurora-Out" % (v["uuid"], host, v["port"], q)


def _server_note():
    st = config.get_state() or {}
    final = str(st.get("final_mode") or "-")
    egress = str(st.get("egress_ip") or "-")
    if final in ("warp", "warp-noise"):
        channel = "резерв MASQUE/WARP"
    elif final and final != "direct":
        channel = "VLESS-пул"
    else:
        channel = "прямой выход"
    return "канал сервера: %s, egress %s" % (channel, egress)


def build(fmt):
    """Собрать профиль. Возвращает dict для API или бросает ValueError."""
    fmt = str(fmt or "").strip().lower()
    if fmt not in FORMATS:
        raise ValueError("неизвестный формат: нужен v2rayn, singbox или clash")
    v = config.vless_public()
    if not v.get("enabled") or not v.get("uuid"):
        raise ValueError("внешний VLESS выключен или не настроен (env AURORA_VLESS_*)")
    host = config._format_link_host(v.get("host", ""))
    if not host:
        raise ValueError("не задан адрес сервера для ссылки")
    link = _link(v)
    note = _server_note()
    name = "Aurora-Out"

    if fmt == "v2rayn":
        content = link
        filename = "aurora-v2rayn.txt"
    elif fmt == "singbox":
        outbound = {
            "type": "vless",
            "tag": name,
            "server": host,
            "server_port": int(v["port"]),
            "uuid": v["uuid"],
            "flow": v["flow"],
            "tls": {
                "enabled": True,
                "server_name": v["sni"],
                "utls": {"enabled": True, "fingerprint": "chrome"},
                "reality": {
                    "enabled": True,
                    "public_key": v["public_key"],
                    "short_id": v["short_id"],
                },
            },
        }
        cfg = {
            "log": {"level": "info"},
            "inbounds": [{"type": "mixed", "tag": "mixed-in",
                          "listen": "127.0.0.1", "listen_port": 2080}],
            "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
            "route": {"final": name},
        }
        content = json.dumps(cfg, ensure_ascii=False, indent=2)
        filename = "aurora-singbox.json"
    else:  # clash (Clash.Meta / mihomo)
        lines = [
            "# Aurora client profile (Clash.Meta / mihomo)",
            "# " + note,
            "mixed-port: 7890",
            "allow-lan: false",
            "mode: rule",
            "log-level: info",
            "proxies:",
            "  - name: \"%s\"" % name,
            "    type: vless",
            "    server: %s" % host,
            "    port: %d" % int(v["port"]),
            "    uuid: %s" % v["uuid"],
            "    network: tcp",
            "    udp: true",
            "    tls: true",
            "    flow: %s" % v["flow"],
            "    servername: %s" % v["sni"],
            "    client-fingerprint: chrome",
            "    reality-opts:",
            "      public-key: %s" % v["public_key"],
            "      short-id: %s" % v["short_id"],
            "proxy-groups:",
            "  - name: PROXY",
            "    type: select",
            "    proxies:",
            "      - \"%s\"" % name,
            "      - DIRECT",
            "rules:",
            "  - MATCH,PROXY",
        ]
        content = "\n".join(lines) + "\n"
        filename = "aurora-clash.yaml"

    return {"ok": True, "format": fmt, "filename": filename,
            "content": content, "link": link, "note": note}
