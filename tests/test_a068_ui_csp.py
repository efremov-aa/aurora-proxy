import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

EXPECTED_ACTS = {
    "nav", "toast", "lang", "key-activate", "plan-buy", "policy-open",
    "policy-accept", "update-start", "update-save", "update-check",
    "key-add", "key-clean", "cx-copy", "regions-save", "ru-check",
    "ru-toggle-fail", "tgws-restart", "mesh-join", "mesh-leave",
    "mesh-regen", "mesh-refresh", "mesh-policy-save", "settings-save",
    "invite-copy", "sec-login", "sec-logout", "sec-2fa-on", "sec-2fa-off",
    "sec-rotate", "log-load",
}

HTML_ACTIONS = {
    "nav", "toast", "lang", "plan-buy", "policy-open", "policy-accept",
    "update-start", "update-save", "update-check", "key-add", "key-clean",
    "cx-copy", "regions-save", "ru-check", "ru-toggle-fail", "tgws-restart",
    "mesh-join", "mesh-leave", "mesh-regen", "mesh-refresh",
    "mesh-policy-save", "settings-save", "invite-copy", "sec-login",
    "sec-logout", "sec-2fa-on", "sec-2fa-off", "sec-rotate", "log-load",
}

DYNAMIC_ACTIONS = {"key-activate", "plan-buy", "nav"}

CSP_REQUIRED = (
    "default-src 'self'",
    "base-uri 'none'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "frame-src 'none'",
    "form-action 'self'",
    "script-src 'self'",
    "script-src-attr 'none'",
    "style-src 'self'",
    "style-src-attr 'unsafe-inline'",
    "img-src 'self' data:",
    "connect-src 'self'",
)

SECURITY_HEADER_NAMES = (
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Content-Security-Policy",
)


def region(text, start, end):
    i = text.index(start)
    j = text.index(end, i)
    return text[i:j]


def read(path):
    return path.read_text(encoding="utf-8-sig")


def html_contract(path):
    text = read(path)
    handlers = re.findall(r"\son([a-z]+)\s*=", text)
    assert not handlers, (path, handlers)
    assert not re.search(r"\son[a-z]+\s*=\s*[\"']", text, re.IGNORECASE), path
    assert "javascript:" not in text, path
    scripts = re.findall(r"<script[^>]*>", text, re.IGNORECASE)
    assert len(scripts) == 2, (path, scripts)
    assert all(re.search(r'src\s*=\s*"/(qr|app)\.js"', tag) for tag in scripts), (path, scripts)
    acts = set(re.findall(r'data-act="([^"]+)"', text))
    assert acts == HTML_ACTIONS, (path, sorted(acts ^ HTML_ACTIONS))
    assert EXPECTED_ACTS - HTML_ACTIONS == {"key-activate"}, path
    for tab in ("update", "mesh-topo", "mesh-routes", "shop-plans",
                "shop-features", "keys", "logs", "rusegment"):
        assert 'data-act="nav" data-tab="%s"' % tab in text, (path, tab)
    assert 'data-act="plan-buy"' in text, path
    assert 'data-act="policy-accept"' in text, path
    assert text.count('data-act="toast" data-msg="') == 2, path
    assert text.count('data-act="mesh-policy-save"') == 3, path
    assert 'data-act="lang"' in text, path
    assert 'data-tag=' not in text, path
    assert 'data-plan-id=' not in text, path
    assert 'href="/style.css"' in text, path


def app_contract(path):
    text = read(path)
    assert "onclick=" not in text, path
    assert "onchange=" not in text, path
    assert not re.search(r"\son(click|change|input|error|load|mouse[a-z]+)\s*=", text), path
    assert "function el(" not in text, path
    assert "eval(" not in text, path
    assert "new Function(" not in text, path
    assert not re.search(r"setTimeout\(\s*['\"]", text), path
    assert "javascript:" not in text, path
    table = region(text, "var ACTS = {", "\n  function actTarget")
    keys = set(re.findall(r"^\s{4}'?([a-z0-9-]+)'?:", table, re.MULTILINE))
    assert keys == EXPECTED_ACTS, (path, sorted(keys ^ EXPECTED_ACTS))
    dispatcher = region(text, "function actDispatch(ev) {", "\n  function bindActions")
    assert "node.closest('[data-act]')" in text, path
    assert "ACTS[t.getAttribute('data-act')]" in dispatcher, path
    assert "if (ev.type === 'click') ev.preventDefault();" in dispatcher, path
    assert "fn(t, ev);" in dispatcher, path
    assert "document.addEventListener('click', actDispatch);" in text, path
    assert "document.addEventListener('change', actDispatch);" in text, path
    assert "'key-activate': function (t) { window.setActive(t.getAttribute('data-tag') || ''); }" in table, path
    assert "'plan-buy': function (t) { var id = t.getAttribute('data-plan-id');" in table, path
    assert "nav: function (t) { navTo(t.getAttribute('data-tab')); }" in table, path
    assert "toast: function (t) { toast(t.getAttribute('data-msg') || '', true); }" in table, path
    assert "policy-open': function (t) { window.policyShow(t.getAttribute('data-force') === '1'); }" in table, path
    assert "lang: function (t, ev) { setLang(((ev && ev.target && ev.target.value)" in table, path
    assert "data-act=\"key-activate\" data-tag=\"" in text, path
    assert 'data-act="plan-buy" data-plan-id="' in text, path
    assert "data-act=\"nav\" data-tab=\"mesh-routes\"" in text, path
    assert "setActive('" not in text, path
    assert "buyPlan('" not in text, path
    assert "navTo('mesh-routes')" not in text, path
    dynamic = set(re.findall(r"data-act=\"([a-z0-9-]+)\"", text))
    assert dynamic == DYNAMIC_ACTIONS, (path, sorted(dynamic))
    for fn in ("setActive", "buyPlan", "navTo", "toast", "setLang", "keyAdd",
               "keyClean", "cxCopy", "ruCheck", "ruToggleFail", "policyShow",
               "policyAccept", "regionsSave", "tgRestart", "meshJoin",
               "meshLeave", "meshRegen", "meshRefresh", "inviteCopy",
               "settingsSave", "secLogin", "secTwofaEnable", "secTwofaDisable",
               "secLogout", "secRotate", "loadLog", "checkUpdate",
               "startUpdate", "updSave", "buyPlan", "meshPolicySave"):
        assert ("function %s(" % fn in text or "window.%s = function" % fn in text
                or "%s: function" % fn in text), (path, fn)
    assert "authHdr" in text, path
    upd = region(text, "function loadUpdate() {", "\n  function renderUpdateDash()")
    for needle in ("var s = j.state || '';",
                   "var stateText = _t('upd.cur');",
                   "var stateCls = 'badge on';",
                   "stateText = _t('upd.err'); stateCls = 'badge off';",
                   "stateText = _t('upd.now'); stateCls = 'badge warn';",
                   "stateText = _t('upd.avail'); stateCls = 'badge gold';",
                   "var msgText = j.msg || (s === 'error' ? _t('upd.err-hint')",
                   "$('upd-state-b').textContent = stateText;",
                   "$('upd-state-b').className = stateCls;",
                   "$('du-msg').textContent = msgText;",
                   "var updTag = $('tag-upd');",
                   "updTag.style.display = avail ? '' : 'none';"):
        assert needle in upd, (path, needle)
    assert upd.count("stateText = _t(") == 4, path
    assert text.count("'upd.err':") == 10, path
    assert text.count("'upd.err-hint':") == 10, path


def api_contract(path):
    text = read(path)
    csp = region(text, "_CSP = (", "\n\ndef _security_headers()")
    for directive in CSP_REQUIRED:
        assert directive in csp, (path, directive)
    assert "script-src 'self' 'unsafe-inline'" not in text, path
    assert "script-src 'self' 'unsafe-hashes'" not in text, path
    headers = region(text, "def _security_headers():", "\ndef _sub_publish")
    for name in SECURITY_HEADER_NAMES:
        assert '"%s"' % name in headers, (path, name)
    assert '("X-Content-Type-Options", "nosniff")' in headers, path
    assert '("X-Frame-Options", "DENY")' in headers, path
    assert '("Referrer-Policy", "no-referrer")' in headers, path
    assert '("Content-Security-Policy", _CSP)' in headers, path
    assert text.count("for _name, _value in _security_headers():") == 2, path
    send = region(text, "def _send(self", "def do_GET(self)")
    assert "for _name, _value in _security_headers():" in send, path
    assert "Cache-Control" in send, path
    publish = region(text, "def _sub_publish", "def build_state")
    assert "for _name, _value in _security_headers():" in publish, path
    assert "text/plain; charset=utf-8" in publish, path
    assert "Cache-Control" in publish and "no-store" in publish, path
    assert "Content-Disposition" in publish, path
    assert "send_response(200)" in publish, path
    for status in ("400", "403", "404", "410"):
        assert "send_response(%s)" % status not in publish, (path, status)


def parity():
    linux_html = ROOT / "ui" / "index.html"
    windows_html = ROOT / "windows" / "ui" / "index.html"
    assert hashlib.md5(linux_html.read_bytes()).hexdigest() == hashlib.md5(windows_html.read_bytes()).hexdigest()
    linux_app = read(ROOT / "ui" / "app.js")
    windows_app = read(ROOT / "windows" / "ui" / "app.js")
    for start, end in (("var ACTS = {", "\n  function bindActions"),
                       ("function loadUpdate() {", "\n  function renderUpdateDash()")):
        assert region(linux_app, start, end) == region(windows_app, start, end)
    linux_api = read(ROOT / "api.py")
    windows_api = read(ROOT / "windows" / "api.py")
    start = "_CSP = ("
    end = "\ndef _sub_publish"
    assert region(linux_api, start, end) == region(windows_api, start, end)
    for token in ("data-act=\"key-activate\"", "data-act=\"plan-buy\"", "data-act=\"nav\" data-tab=\"mesh-routes\""):
        assert token in linux_app and token in windows_app, token
    for token in ("X-Frame-Options", "Referrer-Policy", "script-src-attr 'none'"):
        assert token in linux_api and token in windows_api, token


def qr_contract(path):
    text = read(path)
    assert not re.search(r"\son[a-z]+\s*=", text), path
    assert "eval(" not in text, path


if __name__ == "__main__":
    for tree in (ROOT / "windows", ROOT):
        html_contract(tree / "ui" / "index.html")
        app_contract(tree / "ui" / "app.js")
        qr_contract(tree / "ui" / "qr.js")
        api_contract(tree / "api.py")
    parity()
    print("A068_UI_CSP_OK")
