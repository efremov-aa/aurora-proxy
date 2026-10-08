# -*- coding: utf-8 -*-
"""A-434 (Sh1.2): virtualnyy adapter igrovoy L3-podseti gruppy.

TUN dlya Linux (/dev/net/tun) i WinTun dlya Windows. Adapter prinimaet syrye
IPv4-pakety iz lokalnoy stoshenki i otdayet ih v mesh cherez
meshtunnel.raw_send(), a prinimaet cherez meshtunnel.game_sink().

Adapter mozhno otkryt tolko s pravami root/CAP_NET_ADMIN - eto ne defekt,
a trebovanie yadra. Esli prav net - module govorit eto chestno
("no_permission"), a ne prichinaetsya tisho.
"""

import ctypes
import errno
import os
import struct
import subprocess
import sys
import threading
import time

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None

try:
    import config
except Exception:  # pragma: no cover - vozvolnyy rezhim importa
    config = None

# --- konstanty -------------------------------------------------------------

TUN_DEVICE = "/dev/net/tun"
TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

IF_NAME = str(os.environ.get("AURORA_MESH_IF", "aurora") or "aurora")[:15]
GROUP_MASK = 24
READ_MAX = 65535
POLL_S = 0.01
# A-473: skolko paketov chitaem iz TNA za odin prohod petli
TUN_BATCH_MAX = 64
# A-477: prefiks marshruta gruppy (sosedi zhivut v drugikh /24)
GROUP_ROUTE_MASK = 16
WIN_EVENT_TIMEOUT_MS = 100

# --- sostoyanie ------------------------------------------------------------

_LOCK = threading.RLock()
_STATE = {
    "stop": False,
    "fd": 0,
    "session": 0,
    "mode": "",
    "ifname": "",
    "addr": "",
    "mtu": 0,
    "opened": False,
    "error": "",
    # A-467: pi_stripped - snyat 4-baytnyy PI-zagolovok yadra,
    # dropped_v6 - shestverk otbroshen chestno (mesh vedet tolko IPv4).
    "stats": {"read": 0, "sent": 0, "bad_len": 0, "bad_ver": 0,
              "write_error": 0, "no_fd": 0, "loop": 0,
              "pi_stripped": 0, "dropped_v6": 0},
}


def _log(msg):
    try:
        if config is not None:
            config.log("meshtun: %s" % msg)
            return
    except Exception:
        pass
    sys.stderr.write("meshtun: %s\n" % msg)


def _stat(name, delta=1):
    with _LOCK:
        st = _STATE["stats"]
        st[name] = int(st.get(name, 0) or 0) + int(delta)


def _set(**kw):
    with _LOCK:
        _STATE.update(kw)


def _mtu_default():
    try:
        import meshtunnel
        return int(getattr(meshtunnel, "GAME_MTU", 1500) or 1500)
    except Exception:
        return 1500


# --- proverka dostupnosti --------------------------------------------------

def probe():
    """Chto mozhno na etoy mashine - chestno, bez popytok otkryt."""
    out = {"os": "windows" if os.name == "nt" else "posix",
           "mode": "", "reason": "", "device": ""}
    if os.name == "nt":
        try:
            _load_wintun()
            out["mode"] = "wintun"
        except Exception as exc:
            out["reason"] = "wintun_najden_net (%s)" % type(exc).__name__
    else:
        if fcntl is None:
            out["reason"] = "net fcntl"
        elif not os.path.exists(TUN_DEVICE):
            out["reason"] = "net %s" % TUN_DEVICE
        else:
            out["mode"] = "tun"
            out["device"] = TUN_DEVICE
    try:
        out["uid"] = os.geteuid()
    except AttributeError:
        out["uid"] = -1
    out["is_root"] = out.get("uid", -1) == 0
    return out


# --- Linux /dev/net/tun ----------------------------------------------------

def _open_linux(name):
    """Otкрывает TUN i prosit yadro sozdat interfeys. Bez prav - OSError(EPERM)."""
    fd = os.open(TUN_DEVICE, os.O_RDWR)
    try:
        ifr = struct.pack("16sH22x", name.encode("ascii", "ignore")[:15],
                          IFF_TUN | IFF_NO_PI)
        fcntl.ioctl(fd, TUNSETIFF, ifr)
        os.set_blocking(fd, False)
    except Exception:
        os.close(fd)
        raise
    return fd


def _ip(*args):
    try:
        proc = subprocess.run(["ip"] + [str(a) for a in args],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              timeout=10)
    except Exception as exc:
        return 255, str(exc)
    out = proc.stdout.decode("utf-8", "replace").strip()
    return proc.returncode, out


def _group_prefix(addr, mask):
    """A-477: shirokiy prefiks gruppy 10.<g>.0.0/16 iz adresa 10.<g>.<x>.1.

    Game_address() daet kazhdomu uzlu SVOY /24, poetomu Marshrut v /24
    ne pokryvaet sosedey. Obezchayonnyy prefiks gruppy pokryvaet vse.
    """
    try:
        parts = str(addr or "").strip().split(".")
        if len(parts) != 4:
            return ""
        mask = int(mask)
        if mask <= 0 or mask > 32:
            return ""
        octets = [int(p) for p in parts]
        if any(o < 0 or o > 255 for o in octets):
            return ""
        value = (octets[0] << 24) | (octets[1] << 16) | \
                (octets[2] << 8) | octets[3]
        if mask < 32:
            value &= (0xFFFFFFFF << (32 - mask)) & 0xFFFFFFFF
        net = [(value >> 24) & 255, (value >> 16) & 255,
               (value >> 8) & 255, value & 255]
        return ".".join(str(x) for x in net) + "/%d" % mask
    except Exception:
        return ""


def _route_owner(prefix):
    """Кто сейчас владеет маршрутом префикса. Пустая строка — маршрута нет.

    A-757: нужно, чтобы НЕ перетирать маршрут, принадлежащий другому интерфейсу.
    """
    rc, out = _ip("route", "show", prefix)
    if rc != 0 or not out:
        return ""
    for line in out.splitlines():
        parts = line.split()
        if "dev" in parts:
            i = parts.index("dev")
            if i + 1 < len(parts):
                return parts[i + 1]
    return ""


def _configure_linux(ifname, addr, mtu):
    """Nastraivaet adres i MTU. Trebuet root/CAP_NET_ADMIN."""
    rc, out = _ip("addr", "flush", "dev", ifname)
    if rc != 0:
        return False, "flush rc=%d %s" % (rc, out[:120])
    rc, out = _ip("addr", "add", "%s/%d" % (addr, GROUP_MASK), "dev", ifname)
    if rc != 0:
        return False, "addr rc=%d %s" % (rc, out[:120])
    rc, out = _ip("link", "set", "dev", ifname, "mtu", int(mtu))
    if rc != 0:
        return False, "mtu rc=%d %s" % (rc, out[:120])
    rc, out = _ip("link", "set", "dev", ifname, "up")
    if rc != 0:
        return False, "up rc=%d %s" % (rc, out[:120])
    # A-477: marshrut vsej gruppy cherez nash TUN, inache sosed uvidet
    # tolko svoi /24 i paket k nemu ushyol v defoltnyy shlyuz.
    # A-479: tolko POSLE "link up" - do etogo yadro otvechaet
    # "Device for nexthop is not up" (fakt a478e.txt) i marshrut ne sozdaetsya.
    prefix = _group_prefix(addr, GROUP_ROUTE_MASK)
    if prefix:
        # A-757: NAYDENO NA ZHIVOM UZLE. "ip route replace" MOLCHA perepisyval
        # marshrut /16: pri tryoh mostah odnoj gruppy na odnom hoste marshrut
        # prinadlezhit POSLEDNEMU podnyatomu interfeysu, a ne tomu, k komu
        # realno idet paket. Zamer na 10.1.136.56: 10.7.0.0/16 dev aurorac
        # src 10.7.221.1, a mosty a/b/c — 10.7.205.1, 10.7.115.1, 10.7.221.1.
        # To est paket ot 10.7.205.1 k 10.7.115.1 ukhodit v aurorac i v
        # nikuda: eto prichina «vhod est, vykhoda net» v flud-priyemke.
        # CHESTNOE RESHENIE: chuzhoy marshrut NE perepisyvaem. Pervyj podnyatyj
        # most vladayet marshrutom, ostalnye otdayut trafik cherez rely - eto
        # medlennee, no ne «v nikuda». Konflikt pishem v log, a ne zamykchaem.
        owner = _route_owner(prefix)
        if owner and owner != ifname:
            _log("A-757 route %s busy by dev %s, keep it (this is %s): "
                 "pakety gruppy idut cherez %s, ne cherez %s"
                 % (prefix, owner, ifname, owner, ifname))
            return True, "route-busy:%s" % owner
        rrc, rout = _ip("route", "replace", prefix, "dev", ifname,
                        "src", addr)
        # A-478: marshrut gruppy - edinstvennoe mesto, gde sosedey voobshche
        # vidno. Bez nego igrovaya set rabotaet tolko na odnom hoste.
        # Pishem rezultat v log, inache otkaz legko propustit.
        _log("A-477 route %s dev %s rc=%d %s" %
             (prefix, ifname, rrc, (rout or "")[:80]))
    else:
        _log("A-477 route skip: addr=%r mask=%d" % (addr, GROUP_ROUTE_MASK))
    return True, "ok"


# --- Windows WinTun --------------------------------------------------------

_W32 = {"loaded": False, "dll": None, "reason": ""}


def _guid(s):
    return (ctypes.c_ulong, ctypes.c_ushort, ctypes.c_ushort,
            ctypes.c_ubyte * 8, ctypes.c_ubyte * 4, ctypes.c_ubyte * 4,
            ctypes.c_ubyte * 4, ctypes.c_ubyte * 4)


class LUID(ctypes.Structure):
    _fields_ = [("Value", ctypes.c_uint32 * 2)]


def _load_wintun():
    if _W32["loaded"]:
        return _W32["dll"]
    if _W32["reason"]:
        raise OSError(_W32["reason"])
    if os.name != "nt":
        _W32["reason"] = "wintun tolko pod Windows"
        raise OSError(_W32["reason"])
    dll = None
    try:
        dll = ctypes.WinDLL("wintun.dll")
    except Exception:
        base = os.path.dirname(os.path.abspath(__file__))
        for cand in (os.path.join(base, "bin", "wintun.dll"),
                     os.path.join(base, "wintun.dll")):
            if os.path.exists(cand):
                dll = ctypes.WinDLL(cand)
                break
    if dll is None:
        _W32["reason"] = "net wintun.dll"
        raise OSError(_W32["reason"])
    dll.WintunOpenAdapter.argtypes = [ctypes.c_wchar_p]
    dll.WintunOpenAdapter.restype = ctypes.c_void_p
    dll.WintunCloseAdapter.argtypes = [ctypes.c_void_p]
    dll.WintunCloseAdapter.restype = None
    dll.WintunEndSession.argtypes = [ctypes.c_void_p]
    dll.WintunEndSession.restype = None
    dll.WintunSendPacket.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    dll.WintunSendPacket.restype = ctypes.c_ulong
    # A-818 (IZMERENO): postavlyaemaya DLL - WinTun 1.x, ona NE eksportiruet
    # WintunReceiveEvent/WintunReleaseBuffer. Staryj kod blindno bindil ih i
    # pal s AttributeError "function 'WintunReceiveEvent' not found" - to est
    # adapter ne mog podnyat'sya VOOBSHCHE, a ne iz-za prav. Teper API
    # opredelyaetsya po NAЛИЧИYU eksportov, i nedostayushchie - chestnyy otkaz.
    has_new = (hasattr(dll, "WintunReceivePacket")
               and hasattr(dll, "WintunReleaseReceivePacket"))
    has_old = (hasattr(dll, "WintunReceiveEvent")
               and hasattr(dll, "WintunReleaseBuffer"))
    if has_new:
        dll.WintunStartSession.argtypes = [ctypes.c_void_p]
        dll.WintunStartSession.restype = ctypes.c_void_p      # SESSION*
        dll.WintunGetReadWaitEvent.argtypes = [ctypes.c_void_p]
        dll.WintunGetReadWaitEvent.restype = ctypes.c_void_p  # HANDLE sobitiya
        dll.WintunReceivePacket.argtypes = [ctypes.c_void_p,
                                            ctypes.POINTER(ctypes.c_size_t)]
        dll.WintunReceivePacket.restype = ctypes.c_void_p
        dll.WintunReleaseReceivePacket.argtypes = [ctypes.c_void_p,
                                                   ctypes.c_void_p]
        dll.WintunReleaseReceivePacket.restype = None
        if hasattr(dll, "WintunAllocateSendPacket"):
            dll.WintunAllocateSendPacket.argtypes = [ctypes.c_void_p,
                                                     ctypes.c_size_t]
            dll.WintunAllocateSendPacket.restype = ctypes.c_void_p
        _W32["api"] = "1.x"
    elif has_old:
        dll.WintunStartSession.argtypes = [ctypes.c_void_p]
        dll.WintunStartSession.restype = ctypes.c_ulong       # HANDLE sessii
        dll.WintunReceiveEvent.argtypes = [ctypes.c_void_p]
        dll.WintunReceiveEvent.restype = ctypes.c_void_p
        dll.WintunSendPacket.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                         ctypes.c_size_t]
        dll.WintunReleaseBuffer.argtypes = [ctypes.c_void_p]
        dll.WintunReleaseBuffer.restype = None
        _W32["api"] = "0.x"
    else:
        _W32["reason"] = ("wintun.dll bez WintunReceivePacket i "
                          "WintunReceiveEvent - neizvestnaya versiya")
        raise OSError(_W32["reason"])
    # A-820 (IZMERENO): adaptera v sisteme net, a kto-to ego sozdavat dolzhen.
    if hasattr(dll, "WintunCreateAdapter"):
        dll.WintunCreateAdapter.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p,
                                            ctypes.c_wchar_p]
        dll.WintunCreateAdapter.restype = ctypes.c_uint64
    _W32["dll"] = dll
    _W32["loaded"] = True
    return dll


def _open_windows(name):
    """A-819/A-820/A-826: otkryvaet adaptery PO IMENI.

    Izmereno na zhivoy mashine s povyshsheniem (8 progonov, vse fakty):
    - pervyy argument WintunCreateAdapter stanovitsya IMENEM adaptera (peredali
      binarnyy GUID - poluchili krakozyashchiy alias; peredali tekst GUID - alias
      stal raven etomu tekstu; peredali "aurora" - alias stal "aurora");
    - GUID interfeysa generiruet sam draiver, "svoi" GUID ne prinimaetsya;
    - WintunOpenAdapter(ime) vozvrashchaet rabochiy handle;
    - WintunStartSession ne otrabotaly NI ODNOY iz pyati proverennykh
      konvenciy (handle ukazatelem, handle znachением, handle+flag, imya,
      imya+flag) - vsegda ERROR_INVALID_PARAMETER(87). Podnyatie interfeysa
      cherez "netsh interface set interface admin=enabled" ne pomoglo.
      Versiya draivera prilsa: WintunGetRunningDriverVersion = 14 (sovmesto).

    Poetomu sozdat adaptER avtomaticheski MY NEDOLZNY: izmereno, chto sozdanie
    prokhodit, no sessiya vse ravno ne otkryvaetsya, a v sisteme ostanetsya
    neprigodnyy tunnel. Trogat' mashinu clienta bez polzy ne imeem prava -
    luchshe chestnyy otkaz i sozdanie otlozheno na installer (zadacha otdelnaya).
    """
    dll = _load_wintun()
    adapter = dll.WintunOpenAdapter(str(name))
    if not adapter:
        raise OSError("net adaptera %s - sozdat ego ustanovshchik Aurora "
                      "(trebuetsya prava administratora)" % name)
    try:
        session = dll.WintunStartSession(adapter)
        # A-818: 1.x vozvrashchaet SESSION* (0 = oshibka), 0.x - HANDLE,
        # gde 0xFFFFFFFF tozhe oshibka. Odin universalnyy prover ne podhodil.
        if _W32.get("api") == "1.x":
            if not session:
                raise OSError("WintunStartSession vernul 0")
        elif session in (0, 0xFFFFFFFF):
            raise OSError("WintunStartSession rc=%s" % session)
    except Exception:
        dll.WintunCloseAdapter(adapter)
        raise
    _log("adapter %s otkryt" % name)
    return dll, adapter, session


# --- obmen paketami --------------------------------------------------------

def _win_send(pkt):
    """A-818/A-821: zapis v WinTun cherez AllocateSendPacket + SendPacket.

    V API 1.x net "WintunSendPacket(session, buf, size)" - paket peredavaetsya
    cherez bufer, kotoryy vydet sam WinTun. Staraya troika argumentov est
    tolko v 0.x, i s nejey v 1.x lомается.
    """
    dll = _W32.get("dll")
    adapter = _STATE.get("adapter")
    session = _STATE.get("session")
    if not dll or not adapter or not session:
        _stat("no_session")
        return False
    payload = bytes(pkt or b"")
    if not payload:
        _stat("bad_len")
        return False
    try:
        if _W32.get("api") == "1.x":
            alloc = getattr(dll, "WintunAllocateSendPacket", None)
            if not callable(alloc):
                _stat("no_alloc")
                return False
            buf = alloc(session, len(payload))
            if not buf:
                _stat("alloc_failed")
                return False
            ctypes.memmove(buf, payload, len(payload))
            rc = dll.WintunSendPacket(adapter, buf)
            if rc != 0:
                _stat("send_failed")
                _log("WintunSendPacket rc=%d" % int(rc))
                return False
            _stat("sent")
            return True
        rc = dll.WintunSendPacket(session, ctypes.create_string_buffer(payload),
                                  len(payload))
        _stat("sent")
        return int(rc) == 0
    except Exception as exc:
        _stat("write_error")
        _set(error="win_send: %s" % exc)
        _log("zapis v WinTun ne udalas: %s" % exc)
        return False

def on_packet(pkt):
    """Priymnik dlya meshtunnel.game_sink(): pishet syroy paket v adapter.

    A-821: na Windows fd po usloviyu raven 0 (adaptер ne FD), poetu staraya
    proverka `if not fd` otvergala OTKAZ na kazhdyi paket - to est obratnyy
    put' "relay -> uzhel" ne pisal NICHEGO. Teper kazhdaya platforma idet
    svoim putyom, i Windows-real bez prostogo "net fd".
    """
    if _STATE.get("mode") == "wintun":
        return _win_send(pkt)
    fd = _STATE.get("fd")
    if not fd:
        _stat("no_fd")
        return False
    try:
        os.write(int(fd), pkt)
        _stat("sent")
        return True
    except OSError as exc:
        if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
            _stat("write_error")
            return False
        _set(error="write: %s" % exc)
        _log("zapis v adapter ne udalas: %s" % exc)
        _stat("write_error")
        return False


_LAST_HEXDUMP = 0.0


def _hexdiag(pkt):
    """A-467: raz za minutu pokazat pervye bayty neponyatnogo paketa."""
    global _LAST_HEXDUMP
    now = time.time()
    if now - _LAST_HEXDUMP < 60:
        return
    _LAST_HEXDUMP = now
    try:
        _log("neopredelennyy paket len=%d head=%s" %
             (len(pkt), bytes(pkt[:16]).hex()))
    except Exception:
        pass


def _outbound(pkt):
    """Paket iz lokalnoy stoshenki -> v mesh."""
    if not pkt:
        _stat("bad_len")
        return
    if len(pkt) < 20:
        _stat("bad_len")
        return
    ver = pkt[0] >> 4
    if ver != 4:
        # A-467: ranee lyuboy ne-IPv4 paket molcha shel v bad_ver, i uzly
        # videli read=8/bad_ver=8/sent=0. Ishody dva: shestverk (versiya 6)
        # libo 4-baytnyy PI-zagolovok yadra, hotya my prosili IFF_NO_PI.
        # PI snimaem, shestverk schitaem otdelno, ostalnoe - v log.
        if len(pkt) >= 24 and pkt[2:4] == b"\x08\x00":
            pkt = pkt[4:]
            _stat("pi_stripped")
        elif ver == 6:
            _stat("dropped_v6")
            return
        else:
            _stat("bad_ver")
            _hexdiag(pkt)
            return
    mesh, why = _mesh()
    if mesh is None:
        _stat("write_error")
        _set(error=why)
        return
    try:
        mesh.raw_send(pkt)
    except Exception as exc:
        _stat("write_error")
        _set(error="mesh: %s" % exc)


def _pump_posix(fd):
    with _LOCK:
        _STATE["loop"] = 0
    while not _STATE.get("stop"):
        try:
            pkt = os.read(fd, READ_MAX)
        except BlockingIOError:
            time.sleep(POLL_S)
            continue
        except OSError as exc:
            if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                time.sleep(POLL_S)
                continue
            if exc.errno == errno.EBADF:
                break
            _set(error="read: %s" % exc)
            _log("chtenie iz adaptera sboy: %s" % exc)
            break
        if not pkt:
            time.sleep(POLL_S)
            continue
        _stat("read")
        _outbound(pkt)
        # A-473: chitaem ochered TNA paketov podryad, a ne po odnomu za
        # cikl - inache pri vysokoy chastote ochered yadra TUN perepolnyaetsya
        # i pakety otkidayutsya do userspace. Ogranichenie TUN_BATCH_MAX
        # derzhit petlyu otzvyvannoy, kogda ochered pusta.
        batch = 1
        while batch < TUN_BATCH_MAX and not _STATE.get("stop"):
            try:
                nxt = os.read(fd, READ_MAX)
            except OSError:
                break
            if not nxt:
                break
            _stat("read")
            _outbound(nxt)
            batch += 1
        if batch > 1:
            _stat("batch")
    _log("petlya Linux adaptera ostanovlena")


def _pump_windows(dll, adapter, session):
    """A-822: start() peredavat (dll, adapter, session), a staraya funksiya
    prinimala dva - tred umer by s TypeError tiho, kak nichego ne sluchalos.

    A-818: dve raznye petli dlya dvuh versiy WinTun. V 1.x sessiya - ukazatel
    na strukturu, sobitie chiteniya beretsya otdelno, a razmer paketa
    vozvrashchaetsya cherez argument; v 0.x sessiya sama sobytie.
    """
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    k32.WaitForSingleObject.restype = ctypes.c_ulong
    WAIT_OBJECT_0 = 0
    WAIT_TIMEOUT = 258

    if _W32.get("api") == "1.x":
        event = dll.WintunGetReadWaitEvent(session)
        if not event:
            _set(error="net sobytiyachteniya WinTun")
            _log("WintunGetReadWaitEvent vernul 0 - petlya ne zapushchena")
            return
        while not _STATE.get("stop"):
            rc = k32.WaitForSingleObject(event, WIN_EVENT_TIMEOUT_MS)
            if rc == WAIT_TIMEOUT:
                continue
            if rc != WAIT_OBJECT_0:
                break
            size = ctypes.c_size_t(READ_MAX)
            buf = dll.WintunReceivePacket(session, ctypes.byref(size))
            if not buf:
                if ctypes.get_last_error() in (1223, 995):
                    break            # sessiya otmenena - eto normalno
                time.sleep(POLL_S)
                continue
            try:
                pkt = ctypes.string_at(buf, int(size.value))
                if pkt:
                    _stat("read")
                    _outbound(pkt)
            finally:
                dll.WintunReleaseReceivePacket(session, buf)
        _log("petlya WinTun (1.x) ostanovlena")
        return

    while not _STATE.get("stop"):
        rc = k32.WaitForSingleObject(session, WIN_EVENT_TIMEOUT_MS)
        if rc == WAIT_TIMEOUT:
            continue
        if rc != WAIT_OBJECT_0:
            break
        buf = dll.WintunReceiveEvent(session)
        if not buf:
            time.sleep(POLL_S)
            continue
        data = ctypes.cast(buf, ctypes.c_void_p).value
        if not data:
            continue
        size = ctypes.cast(ctypes.c_void_p(buf + 8),
                           ctypes.POINTER(ctypes.c_size_t)).contents.value
        try:
            pkt = ctypes.string_at(data, int(size))
            _stat("read")
            _outbound(pkt)
        finally:
            dll.WintunReleaseBuffer(buf)
    _log("petlya WinTun (0.x) ostanovlena")


# --- start / stop ----------------------------------------------------------

def _mesh():
    """Lazivno otdayot meshtunnel. Staraya versiya bez A-433 - chestnyi otkaz."""
    try:
        import meshtunnel
    except Exception as exc:
        return None, "net meshtunnel: %s" % exc
    for name in ("game_enabled", "raw_send", "game_sink"):
        if not hasattr(meshtunnel, name):
            return None, ("versiya meshtunnel staraya (net %s) - obnovi node"
                          % name)
    return meshtunnel, ""


def start(addr="", mtu=None, use_ip=True):
    """Otkryvaet adapter i zapuskaet petlyu. Vernut (True|False, soobshchenie)."""
    mesh, why = _mesh()
    if mesh is None:
        _set(error=why)
        _log(why)
        return False, why
    if not mesh.game_enabled():
        return False, "igrovoy rezhim vykluchen"
    if not addr:
        addr = mesh.game_address(mesh._node_id())
    if not addr:
        return False, "net adresa igrovogo uzla"
    mtu = int(mtu or _mtu_default())
    with _LOCK:
        if _STATE.get("opened"):
            return True, "uzhe otkryt"
        _STATE["stop"] = False
        try:
            mesh.game_sink(on_packet)
        except Exception as exc:
            return False, "sink: %s" % exc
    try:
        if os.name == "nt":
            dll, adapter, session = _open_windows(IF_NAME)
            # A-821: adapter sohranyaem v sostoyanii - bez nego obratnyy put'
            # "relay -> uzhel" ne imel by chem zapisat paket (on_packet).
            _set(mode="wintun", ifname=IF_NAME, addr=addr, mtu=mtu, opened=True,
                 error="", fd=0, session=session, adapter=adapter,
                 api=_W32.get("api", ""))
            target = (dll, adapter, session)
            runner = _pump_windows
        else:
            if fcntl is None:
                raise OSError("net fcntl")
            fd = _open_linux(IF_NAME)
            _set(mode="tun", ifname=IF_NAME, addr=addr, mtu=mtu, opened=True,
                 error="", fd=fd, session=0)
            target = (fd,)
            runner = _pump_posix
    except PermissionError as exc:
        _set(error="net prav: %s" % exc)
        _log("net prav na sozdanie adaptera (root/CAP_NET_ADMIN): %s" % exc)
        return False, "net prav (root/CAP_NET_ADMIN)"
    except OSError as exc:
        _set(error=("open: %s" % exc))
        _log("adapter ne otkryt: %s" % exc)
        return False, str(exc)
    if use_ip and os.name != "nt":
        ok, why = _configure_linux(IF_NAME, addr, mtu)
        if not ok:
            _log("nastroyka %s ne udalas: %s" % (IF_NAME, why))
            _set(error=why)
    th = threading.Thread(target=runner, args=target, name="mesh-tun",
                          daemon=True)
    th.start()
    _set(loop=0)
    _log("adapter %s otkryt (%s), adres %s/%d, mtu %d" %
         (IF_NAME, _STATE.get("mode"), addr, GROUP_MASK, mtu))
    return True, "otkryt"


def stop():
    with _LOCK:
        _STATE["stop"] = True
        fd = _STATE.get("fd")
        if fd:
            try:
                os.close(int(fd))
            except OSError:
                pass
            _STATE["fd"] = 0
        _STATE["opened"] = False
    _log("adapter %s zakryt" % IF_NAME)
    return True


def info():
    with _LOCK:
        out = dict(_STATE)
    out.pop("stop", None)
    out["stats"] = dict(_STATE.get("stats") or {})
    out["mask"] = GROUP_MASK
    out["probe"] = probe()
    return out