"""A-WARP / A-WARP-M: zapasnoy kanal Cloudflare WARP (NABOR konfigov).

Konfig WARP ne generiruetsya na servere: s serverov Cloudflare-API ne dostupen
(TLS-filtratsiya, endpoint warp_reg otvechaet 404, storonnie API generatora -
403). Vlaselets generiruet konfig na PK (stranica warp-generation) i zagruzhaet
ego cherez panel Aurora; modul tolko prinimaet, proverяet i podnimaet gotovyy
outbound.

A-WARP-M: konfigov neskolko, u kazhdogo SVOE IMYA.odin ne khranilsya -
spisok v data/warp_configs.json (shifrovano cherez config, 0600), vybor
aktivnogo. Staryy odinochnyy data/warp.json migruetsya v spisok avtomatichesko
sohraneniem ego imeni iz endpoint - inache zagruzhennyy rezerv propal by.

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
WARP_STORE = os.path.join(config.DATA_DIR, "warp_configs.json")
WARP_TAG = "warp"
NOISE_TAG = "warp-noise"
MODES = ("off", "auto", "on")
MAX_CONFIG_BYTES = 256 * 1024
MAX_CONFIGS = 32
MAX_NAME_LEN = 40
PROBE_PORT = 19960
PROBE_TIMEOUT_S = 12

_LOCK = threading.RLock()
_CACHE = {"mtime": None, "value": None}
_LAST = {"ip": "-", "ts": 0.0, "reason": ""}

_B64_RE = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$")
_HOSTPORT_RE = re.compile(r"^[A-Za-z0-9._-]{1,253}:\d{1,5}$")
_NAME_RE = re.compile(r"^[A-Za-z0-9 _.\-]{1,%d}$" % MAX_NAME_LEN)


def mode():
    """Tekushhiy rezhim iz nastroyek, tolko iz belyh znacheniy."""
    value = str(config.get("warp_mode", "off") or "off").strip().lower()
    return value if value in MODES else "off"


def clean_name(value, fallback=""):
    """Imya konfiga: tolko bezopasnye simvoly, obrezka do MAX_NAME_LEN."""
    name = str(value or "").strip()
    name = re.sub(r"[^A-Za-z0-9 _.\-]+", " ", name).strip()
    name = re.sub(r"\s{2,}", " ", name)[:MAX_NAME_LEN].strip()
    if not name:
        name = str(fallback or "").strip() or "warp"
    return name


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


# --- A-WARP-M: khranilishche namerovannykh konfigov ---

def _crypt_module():
    """A-WARP-M: publichnaya sborka xranit konfigi v shifrovannom vide (crypt).

    Modul vozvrashchaet crypt esli on dostupen, inache None - togda ishem
    obychnyy json. Eto pozvolyaet odnomu i tomu zhe warp.py rabotat i v
    masterskom, i v publichnom dereve bez pravok.
    """
    try:
        import crypt
        return crypt
    except Exception:
        return None


def _store_read(path):
    """A-WARP-M: prochitat fail konfigov. Esli est crypt - cherez nego."""
    cr = _crypt_module()
    if cr is not None and hasattr(cr, "load_json"):
        try:
            value = cr.load_json(path, None)
        except Exception:
            value = None
        if value is not None:
            return value
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError, TypeError):
        return None


def _store_write(path, obj):
    """A-WARP-M: zapisat fail konfigov. Esli est crypt - cherez nego."""
    cr = _crypt_module()
    if cr is not None and hasattr(cr, "save_json"):
        try:
            cr.save_json(path, obj)
        except Exception:
            pass
        else:
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            return True
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f)
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return True


def _blank_store():
    return {"active": "", "items": {}}


def _legacy_entry():
    """A-WARP-M: staryy odinochnyy warp.json -> zapis spiska."""
    raw = _store_read(WARP_FILE)
    if not isinstance(raw, dict) or not isinstance(raw.get("outbounds"), list) \
            or not raw["outbounds"]:
        return None
    return {
        "outbounds": raw["outbounds"],
        "endpoint": str(raw.get("endpoint") or ""),
        "noise": bool(raw.get("noise")),
        "ts": int(raw.get("ts") or 0),
        "egress": str(raw.get("egress") or "-"),
        "egress_ts": int(raw.get("egress_ts") or 0),
    }


def _save_store(store):
    _store_write(WARP_STORE, store)


def _store_mtime():
    """A-WARP-M: mtime fayla - tolko KLYUCH kesha, a ne istina.

    V publichnom dereve konfigi lezhat v shifrovannom crypt-konteynere i fayla
    warp_configs.json mozhet ne byt voobshe. Ranee eto prichinyalo "spisok pust"
    posle uspešnogo install: getmtime = None -> store = blank, a kesh s etim
    zhe None schitalsya "svezhim". Teper mtime eto tolko marker kesha, a istinnoe
    chtenie vsegda idet cherez _store_read (a v shifrovannom rezhime - kazhdyy
    raz, blagodarya crypke pretvorayut miss v pustoy, a ne v lozhnoe kesh).
    """
    try:
        return os.path.getmtime(WARP_STORE)
    except OSError:
        return None


def _read_store():
    """Spisok konfigov s odnoj migratsiey so starogo warp.json. Kesh po mtime."""
    mtime = _store_mtime()
    encrypted = _crypt_module() is not None
    with _LOCK:
        if _CACHE["mtime"] == mtime and _CACHE["value"] is not None and not encrypted:
            return json.loads(json.dumps(_CACHE["value"]))
        store = _blank_store()
        raw = _store_read(WARP_STORE)
        if isinstance(raw, dict) and isinstance(raw.get("items"), dict):
            store["items"] = dict(raw["items"])
            store["active"] = str(raw.get("active") or "")
        else:
            store = _blank_store()
        # A-WARP-M: migritsiya starogo odinochnogo konfiga v spisok
        if not store["items"]:
            legacy = _legacy_entry()
            if legacy:
                name = clean_name(legacy["endpoint"].replace(":", "-"), "warp-1")
                store["items"][name] = legacy
                store["active"] = name
                try:
                    _save_store(store)
                except (OSError, TypeError, ValueError):
                    pass
        _CACHE["mtime"] = _store_mtime()
        _CACHE["value"] = store
    return json.loads(json.dumps(store))


def _unique_name(store, name):
    if name not in store["items"]:
        return name
    base = name
    for i in range(2, MAX_CONFIGS + 2):
        candidate = "%s-%d" % (base[:MAX_NAME_LEN - 3], i)
        if candidate not in store["items"]:
            return candidate
    return base


def install(raw, name=""):
    """A-WARP-M: prinyal konfig pod imenem. Pervyy lyagayet aktivnym."""
    warp_ob, noise_ob, reason = extract(raw)
    if warp_ob is None:
        return {"ok": False, "error": reason or "bad warp config"}
    outbounds = [warp_ob] + ([noise_ob] if noise_ob else [])
    peer = warp_ob["settings"]["peers"][0]
    entry = {
        "outbounds": outbounds,
        "endpoint": peer["endpoint"],
        "noise": bool(noise_ob),
        "ts": int(time.time()),
        "egress": "-",
        "egress_ts": 0,
    }
    try:
        store = _read_store()
        key = clean_name(name or peer["endpoint"].replace(":", "-"), "warp-1")
        if len(store["items"]) >= MAX_CONFIGS and key not in store["items"]:
            return {"ok": False, "error": "too many configs (max %d)" % MAX_CONFIGS}
        key = _unique_name(store, key)
        store["items"][key] = entry
        # Pervyy lyagayet aktivnym, inache rezerv ne podnimetsya sam
        if not store.get("active") or store["active"] not in store["items"]:
            store["active"] = key
        _save_store(store)
    except (OSError, TypeError, ValueError) as exc:
        return {"ok": False, "error": "save failed: %s" % str(exc)[:120]}
    with _LOCK:
        _CACHE["mtime"] = None
        _CACHE["value"] = None
    return {"ok": True, "name": key, "endpoint": peer["endpoint"],
            "noise": bool(noise_ob), "count": len(_read_store()["items"])}


def select(name):
    """A-WARP-M: sdelat konfig aktivnym."""
    key = clean_name(name, "")
    if not key:
        return {"ok": False, "error": "empty name"}
    try:
        store = _read_store()
        if key not in store["items"]:
            return {"ok": False, "error": "no such config"}
        store["active"] = key
        _save_store(store)
    except (OSError, TypeError, ValueError) as exc:
        return {"ok": False, "error": "save failed: %s" % str(exc)[:120]}
    with _LOCK:
        _CACHE["mtime"] = None
        _CACHE["value"] = None
    return {"ok": True, "name": key, "status": status()}


def remove(name):
    """A-WARP-M: udalit odin konfig; pri poslednem rezerv obnarodit storoe."""
    key = clean_name(name, "")
    if not key:
        return {"ok": False, "error": "empty name"}
    try:
        store = _read_store()
        if key not in store["items"]:
            return {"ok": False, "error": "no such config"}
        store["items"].pop(key, None)
        if store.get("active") == key:
            store["active"] = next(iter(store["items"]), "")
        if store["items"]:
            _save_store(store)
        else:
            # spisok pust - chistim oba fayla, inache staryy warp.json
            # podnimetsya zanovo cherez _read_store i pokazhet "zagruzheno"
            for path in (WARP_STORE, WARP_FILE):
                try:
                    os.remove(path)
                except OSError:
                    pass
    except (OSError, TypeError, ValueError) as exc:
        return {"ok": False, "error": "save failed: %s" % str(exc)[:120]}
    with _LOCK:
        _CACHE["mtime"] = None
        _CACHE["value"] = None
    return {"ok": True, "count": len(_read_store()["items"]), "status": status()}


def list_configs():
    """A-WARP-M: spisok konfigov dlya paneli (bez sekretnyh klyuchey)."""
    store = _read_store()
    active = store.get("active") or ""
    out = []
    for name in sorted(store["items"]):
        item = store["items"][name]
        out.append({
            "name": name,
            "endpoint": str(item.get("endpoint") or ""),
            "noise": bool(item.get("noise")),
            "ts": int(item.get("ts") or 0),
            "egress": str(item.get("egress") or "-"),
            "egress_ts": int(item.get("egress_ts") or 0),
            "active": name == active,
        })
    return out


def active_name():
    store = _read_store()
    active = store.get("active") or ""
    if active and active in store["items"]:
        return active
    return ""


def clear():
    """Udalit VSE konfigy rezerva (vydacha rezerva obratno v keys)."""
    for path in (WARP_STORE, WARP_FILE):
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
        except OSError as exc:
            return {"ok": False, "error": str(exc)[:120]}
    with _LOCK:
        _CACHE["mtime"] = None
        _CACHE["value"] = None
    return {"ok": True, "count": 0}


def load(name=""):
    """A-WARP-M: outbound'y aktivnogo (ili ukazannogo) konfiga. Kesh po mtime."""
    store = _read_store()
    key = clean_name(name, "") if name else (store.get("active") or "")
    if not key and store["items"]:
        key = next(iter(store["items"]))
    item = store["items"].get(key)
    if not isinstance(item, dict):
        return None
    try:
        return json.loads(json.dumps(item.get("outbounds") or [])) or None
    except (TypeError, ValueError):
        return None


def copy_outbounds(value):
    try:
        return json.loads(json.dumps(value.get("outbounds") or []))
    except (TypeError, ValueError):
        return None


def endpoint(name=""):
    store = _read_store()
    key = clean_name(name, "") if name else (store.get("active") or "")
    item = store["items"].get(key) or {}
    return str(item.get("endpoint") or "")


def has_noise(name=""):
    data = load(name)
    return bool(data and len(data) > 1)


def active(alive_keys=0):
    """Aktiv li WARP prichyne: ruchnoy rezhim - vsegda, avto - tolko pustoy pul."""
    if mode() == "off":
        return False
    if not _read_store()["items"]:
        return False
    if mode() == "on":
        return True
    return int(alive_keys or 0) <= 0


def status():
    """A-WARP-M: fakt sostoyaniya dlya paneli: spisok, aktivnyy, rezhim, vyhod."""
    store = _read_store()
    with _LOCK:
        last_ip = _LAST["ip"]
        last_ts = _LAST["ts"]
        reason = _LAST["reason"]
    configs = list_configs()
    current = active_name()
    return {
        "loaded": bool(configs),
        "count": len(configs),
        "name": current,
        "configs": configs,
        "mode": mode(),
        "active": active(),
        "endpoint": endpoint(),
        "noise": has_noise(),
        "egress": last_ip,
        "egress_ts": int(last_ts),
        "reason": reason,
    }


def record_probe(ip, reason="", name=""):
    key = clean_name(name, "") if name else active_name()
    with _LOCK:
        _LAST["ip"] = str(ip or "-")
        _LAST["ts"] = time.time()
        _LAST["reason"] = str(reason or "")
        _LAST["name"] = key
    if not key:
        return
    try:
        store = _read_store()
        if key in store["items"]:
            store["items"][key]["egress"] = str(ip or "-")
            store["items"][key]["egress_ts"] = int(time.time())
            _save_store(store)
        with _LOCK:
            _CACHE["mtime"] = None
            _CACHE["value"] = None
    except (OSError, TypeError, ValueError):
        pass


def probe(timeout=PROBE_TIMEOUT_S, port=PROBE_PORT, name=""):
    """Fakticheskiy vyhod WARP cherez vremennyi xray (kak v source.keytest)."""
    data = load(name)
    if not data:
        # A-WARP-M: net konfiga -> net kanala. Sprosat source ne nuzhno,
        # inache module-not-found zamenyaet chestnyy "net konfiga".
        return {"ok": False, "error": "no warp config"}
    import subprocess
    import source

    if not source._port_free(port):
        return {"ok": False, "error": "port-busy"}
    try:
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
        if not source._wait_port(port, timeout=4, proc=proc):
            return {"ok": False, "error": "port timeout"}
        ip = source._http_egress_check(port, timeout=timeout)
        if ip:
            record_probe(ip, "probe", name)
            return {"ok": True, "egress": ip}
        record_probe("-", "no egress", name)
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
