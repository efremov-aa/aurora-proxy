"""A-WARP-PUB: zapasnoy kanal Cloudflare WARP (klientskaya sborka).

Proizvodnoe ot _dom_v4_tmp/warp.py: khranenie cherez crypt (shifrovanne),
_wait_port bez parametra proc.

A-WARP: zapasnoy kanal Cloudflare WARP.

Konfig WARP ne generiruetsya na servere: s serverov Cloudflare-API ne dostupen
(TLS-фильтрация, endpoint warp_reg otvechaet 404, storonnie API generatora -
403). Vlasелец generiruet konfig na PK (stranica warp-generation) i zagruzhaet
ego cherez panel Aurora; modul tolko prinimaet, proverяet i podnimaet gotovyy
outbound.

Rezhimy (settings.warp_mode):
  off  - WARP ne ispolzuetsya (po umolchaniyu)
  auto - WARP vklyuchaetsya tolko kogda v pule NET zhivykh klyuchey
  on   - WARP vsegda vmesto klyuchey (ruchnoy rezhim)

Bez zagrouzhenogo konfiga modul ne deystvuet NIKOGDA: net outbound - net
kanala, i avtorezhim ne mozhet "vstanovit" WARP iz vozdukha.
"""

import json
import os
import re
import threading
import time

import config

WARP_FILE = os.path.join(config.DATA_DIR, "warp.json")
WARP_TAG = "warp"
NOISE_TAG = "warp-noise"
MODES = ("off", "auto", "on")
MAX_CONFIG_BYTES = 256 * 1024
PROBE_PORT = 19960
PROBE_TIMEOUT_S = 12

_LOCK = threading.RLock()
_CACHE = {"mtime": None, "value": None}
_LAST = {"ip": "-", "ts": 0.0, "reason": ""}

_B64_RE = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$")
_HOSTPORT_RE = re.compile(r"^[A-Za-z0-9._-]{1,253}:\d{1,5}$")


def _atomic_write_json(path, obj):
    """Fallback only; public build stores warp.json via crypt (encrypted)."""
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f)
    os.replace(tmp, path)


def mode():
    """Tekushhiy rezhim iz nastroyek, tolko iz belyh znacheniy."""
    value = str(config.get("warp_mode", "off") or "off").strip().lower()
    return value if value in MODES else "off"


def _b64_ok(value):
    return bool(_B64_RE.match(str(value or "")))


def _valid_warp_outbound(ob):
    """Fail-closed proverka odnogo outbound-a wireguard."""
    if not isinstance(ob, dict):
        return False, "outbound must be an object"
    if str(ob.get("protocol") or "").lower() != "wireguard":
        return False, "not a wireguard outbound"
    st = ob.get("settings")
    if not isinstance(st, dict):
        return False, "wireguard settings missing"
    if not _b64_ok(st.get("secretKey")):
        return False, "bad wireguard secretKey"
    peers = st.get("peers")
    if not isinstance(peers, list) or not peers:
        return False, "wireguard peers missing"
    for peer in peers:
        if not isinstance(peer, dict):
            return False, "bad peer"
        if not _b64_ok(peer.get("publicKey")):
            return False, "bad peer publicKey"
        if not _HOSTPORT_RE.match(str(peer.get("endpoint") or "")):
            return False, "bad peer endpoint"
    addresses = st.get("address")
    if not isinstance(addresses, list) or not addresses:
        return False, "wireguard address missing"
    return True, ""


def _valid_noise_outbound(ob):
    """noise-out = freedom s noises (maskirovka). Bez nego - ne zhiznennaya,
    no i ne kriticheskaya chast: tolko proverka formy."""
    if not isinstance(ob, dict):
        return False, "outbound must be an object"
    if str(ob.get("protocol") or "").lower() != "freedom":
        return False, "not a freedom outbound"
    noises = (ob.get("settings") or {}).get("noises")
    if not isinstance(noises, list) or not noises:
        return False, "no noises"
    return True, ""


def _clean_warp(ob):
    out = {
        "tag": WARP_TAG,
        "protocol": "wireguard",
        "settings": {
            "address": list(ob["settings"].get("address") or []),
            "mtu": int(ob["settings"].get("mtu") or 1280),
            "secretKey": str(ob["settings"]["secretKey"]),
            "peers": [{
                "allowedIPs": list(p.get("allowedIPs") or ["0.0.0.0/0", "::/0"]),
                "endpoint": str(p["endpoint"]),
                "publicKey": str(p["publicKey"]),
            } for p in ob["settings"]["peers"]],
        },
    }
    sockopt = ((ob.get("streamSettings") or {}).get("sockopt") or {})
    if isinstance(sockopt.get("dialerProxy"), str):
        out.setdefault("streamSettings", {})["sockopt"] = {"dialerProxy": NOISE_TAG}
    return out


def _clean_noise(ob):
    return {
        "tag": NOISE_TAG,
        "protocol": "freedom",
        "settings": {"noises": list((ob.get("settings") or {}).get("noises") or [])},
    }


def extract(cfg):
    """Dostayet warp + noise iz polyzovatel'skogo konfiga generatora.

    vozvrashchaet (warp_outbound|None, noise_outbound|None, error).
    """
    if isinstance(cfg, (bytes, bytearray)):
        raw = bytes(cfg)
        if len(raw) > MAX_CONFIG_BYTES:
            return None, None, "config too large"
        try:
            cfg = json.loads(raw.decode("utf-8"))
        except (TypeError, ValueError, UnicodeDecodeError):
            return None, None, "invalid json"
    elif isinstance(cfg, str):
        if len(cfg.encode("utf-8", "ignore")) > MAX_CONFIG_BYTES:
            return None, None, "config too large"
        try:
            cfg = json.loads(cfg)
        except (TypeError, ValueError):
            return None, None, "invalid json"
    if not isinstance(cfg, dict):
        return None, None, "config must be an object"
    outbounds = cfg.get("outbounds")
    if not isinstance(outbounds, list) or not outbounds:
        return None, None, "no outbounds in config"
    warp_ob = None
    noise_ob = None
    for ob in outbounds:
        if not isinstance(ob, dict):
            continue
        proto = str(ob.get("protocol") or "").lower()
        tag = str(ob.get("tag") or "")
        if proto == "wireguard" and warp_ob is None:
            warp_ob = ob
        elif proto == "freedom" and noise_ob is None and (tag == "noise-out"
                                                         or (isinstance(ob.get("settings"), dict)
                                                             and ob["settings"].get("noises"))):
            noise_ob = ob
    if warp_ob is None:
        return None, None, "no wireguard outbound"
    ok, reason = _valid_warp_outbound(warp_ob)
    if not ok:
        return None, None, reason
    if noise_ob is not None:
        ok, reason = _valid_noise_outbound(noise_ob)
        if not ok:
            noise_ob = None
    return _clean_warp(warp_ob), (_clean_noise(noise_ob) if noise_ob else None), ""


def install(raw):
    """Prinyal konfig ot vlaseltsa, sohranil tolko nuzhnoe."""
    warp_ob, noise_ob, reason = extract(raw)
    if warp_ob is None:
        return {"ok": False, "error": reason or "bad warp config"}
    outbounds = [warp_ob] + ([noise_ob] if noise_ob else [])
    peer = warp_ob["settings"]["peers"][0]
    payload = {
        "outbounds": outbounds,
        "endpoint": peer["endpoint"],
        "noise": bool(noise_ob),
        "ts": int(time.time()),
    }
    try:
        import crypt
        if hasattr(crypt, "save_json"):
            crypt.save_json(WARP_FILE, payload)
        else:
            _atomic_write_json(WARP_FILE, payload)
        try:
            os.chmod(WARP_FILE, 0o600)
        except OSError:
            pass
    except Exception as exc:  # crypt.StorageError, OSError, TypeError, ValueError
        return {"ok": False, "error": "save failed: %s" % str(exc)[:120]}
    with _LOCK:
        _CACHE["mtime"] = None
        _CACHE["value"] = None
    return {"ok": True, "endpoint": peer["endpoint"], "noise": bool(noise_ob)}


def clear():
    """Udalit zagruzhennyy konfig (vydacha rezerva obratno v keys)."""
    try:
        os.remove(WARP_FILE)
    except FileNotFoundError:
        pass
    except OSError as exc:
        return {"ok": False, "error": str(exc)[:120]}
    with _LOCK:
        _CACHE["mtime"] = None
        _CACHE["value"] = None
    return {"ok": True}


def load():
    """Zagruzhennye outbound'y WARP ili None. Kesh po mtime."""
    try:
        mtime = os.path.getmtime(WARP_FILE)
    except OSError:
        with _LOCK:
            _CACHE["mtime"] = None
            _CACHE["value"] = None
        return None
    with _LOCK:
        if _CACHE["mtime"] == mtime and _CACHE["value"] is not None:
            return copy_outbounds(_CACHE["value"])
        value = None
        try:
            raw = None
            try:
                import crypt
                if hasattr(crypt, "load_json"):
                    raw = crypt.load_json(WARP_FILE, None)
            except Exception:
                raw = None
            if raw is None:
                with open(WARP_FILE, "r", encoding="utf-8") as f:
                    raw = json.load(f)
            if isinstance(raw, dict) and isinstance(raw.get("outbounds"), list) \
                    and raw["outbounds"]:
                value = raw
        except Exception:
            value = None
        _CACHE["mtime"] = mtime
        _CACHE["value"] = value
    return copy_outbounds(value) if value else None


def copy_outbounds(value):
    try:
        return json.loads(json.dumps(value.get("outbounds") or []))
    except (TypeError, ValueError):
        return None


def endpoint():
    data = load()
    if not data:
        return ""
    return str(data[0].get("settings", {}).get("peers", [{}])[0].get("endpoint", "")) \
        if data[0].get("settings", {}).get("peers") else ""


def has_noise():
    data = load()
    return bool(data and len(data) > 1)


def active(alive_keys=0):
    """Aktiv li WARP prichyne: ruchnoy rezhim - vsegda, avto - tolko pustoy pul."""
    if mode() == "off":
        return False
    if not load():
        return False
    if mode() == "on":
        return True
    return int(alive_keys or 0) <= 0


def status():
    """Fakt sostoyaniya dlya paneli: chto zagruzheno, chej rezhim, posledniy vyhod."""
    data = load()
    with _LOCK:
        last_ip = _LAST["ip"]
        last_ts = _LAST["ts"]
        reason = _LAST["reason"]
    return {
        "loaded": bool(data),
        "mode": mode(),
        "active": active(),
        "endpoint": endpoint(),
        "noise": has_noise(),
        "egress": last_ip,
        "egress_ts": int(last_ts),
        "reason": reason,
    }


def record_probe(ip, reason=""):
    with _LOCK:
        _LAST["ip"] = str(ip or "-")
        _LAST["ts"] = time.time()
        _LAST["reason"] = str(reason or "")


def probe(timeout=PROBE_TIMEOUT_S, port=PROBE_PORT):
    """Fakticheskiy vyhod WARP cherez vremennyi xray (kak v source.keytest)."""
    import subprocess
    import source

    data = load()
    if not data:
        return {"ok": False, "error": "no warp config"}
    try:
        if not source._port_free(port):
            return {"ok": False, "error": "port-busy"}
        cfg = {
            "log": {"loglevel": "warning"},
            "inbounds": [{"tag": "http-in", "listen": "127.0.0.1",
                          "port": port, "protocol": "http"}],
            "outbounds": data + [
                {"protocol": "freedom", "tag": "direct",
                 "settings": {"domainStrategy": "UseIP"}},
                {"protocol": "blackhole", "tag": "block"},
            ],
            "routing": {"domainStrategy": "IPIfNonMatch", "rules": [
                {"type": "field", "inboundTag": ["http-in"], "outboundTag": WARP_TAG},
            ]},
        }
        cfg_path = os.path.join(config.DATA_DIR, "warp_probe_%d.json" % port)
        fd = os.open(cfg_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(cfg, f)
    except (OSError, TypeError, ValueError) as exc:
        return {"ok": False, "error": "cfg: %s" % str(exc)[:100]}
    xbin = None
    proc = None
    try:
        xbin = source._xray_bin()
        if not xbin:
            return {"ok": False, "error": "no xray binary"}
        proc = subprocess.Popen([xbin, "run", "-c", cfg_path],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not source._wait_port(port, timeout=4):
            return {"ok": False, "error": "port timeout"}
        ip = source._http_egress_check(port, timeout=timeout)
        if ip:
            record_probe(ip, "probe")
            return {"ok": True, "egress": ip}
        record_probe("-", "no egress")
        return {"ok": False, "error": "no egress"}
    except OSError as exc:
        return {"ok": False, "error": str(exc)[:120]}
    finally:
        if proc is not None:
            try:
                if proc.poll() is None:
                    proc.terminate()
            except Exception:
                pass
            try:
                proc.wait(timeout=2)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        try:
            os.remove(cfg_path)
        except OSError:
            pass
