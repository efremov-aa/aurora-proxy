import ipaddress
import socket
import sys
from pathlib import Path

import pool
import source

failures = []
def check(condition, message):
    if not condition:
        failures.append(message)

def run_resolver(answer, expected):
    old = pool.socket.getaddrinfo
    pool.socket.getaddrinfo = lambda *args, **kwargs: answer
    try:
        result = pool.resolve_public_host("public.example", 443)
    finally:
        pool.socket.getaddrinfo = old
    check(result == expected, "resolver result %r != %r" % (result, expected))

check(pool._canonical_host("Example.COM.") == "example.com", "canonical host")
check(pool._canonical_host("localhost") == "", "localhost canonical")
check(pool._canonical_host("foo.local") == "", "local suffix canonical")
check(pool._host_name_allowed("example.com"), "public FQDN syntax")
check(not pool._host_name_allowed("127.0.0.1"), "loopback literal")
check(not pool._host_name_allowed("10.0.0.1"), "private literal")
check(not pool._host_name_allowed("169.254.169.254"), "metadata literal")
check(not pool._host_name_allowed("168.63.129.16"), "azure special literal")
check(pool._host_name_allowed("1.1.1.1"), "public IPv4 literal")
check(pool._host_name_allowed("2606:4700:4700::1111"), "public IPv6 literal")
run_resolver([], None)
run_resolver([(2, 1, 6, "", ("93.184.216.34", 443)), (10, 1, 6, "", ("2606:4700:4700::1111", 443))], "93.184.216.34")
run_resolver([(2, 1, 6, "", ("93.184.216.34", 443)), (2, 1, 6, "", ("10.0.0.1", 443))], None)
run_resolver([(2, 1, 6, "", ("169.254.169.254", 443))], None)

pbk = "A" * 43
uri = "vless://00000000-0000-0000-0000-000000000001@example.com:443?encryption=none&security=reality&pbk=" + pbk + "&sid=01&sni=example.com#test"
private_uri = uri.replace("example.com", "127.0.0.1")
check(pool.validate_vless_key({"uri": private_uri, "pbk": pbk}), "private URI rejected")
check(pool.validate_vless_key({"uri": uri, "pbk": pbk}) is None, "public URI accepted")
try:
    pool._prepare_keys([{"uri": private_uri, "host": "example.com", "port": 443}])
except ValueError:
    pass
else:
    failures.append("URI/record mismatch accepted")
old_resolver = pool.resolve_public_host
pool.resolve_public_host = lambda host, port=443: "93.184.216.34"
try:
    outbound = pool.build_outbound({"uri": uri, "tag": "test"})
finally:
    pool.resolve_public_host = old_resolver
check(outbound is not None, "public outbound built")
if outbound:
    check(outbound["settings"]["vnext"][0]["address"] == "93.184.216.34", "numeric address pin")
    check(outbound["streamSettings"]["realitySettings"]["serverName"] == "example.com", "SNI preserved")

old_resolver = source.pool.resolve_public_host
old_connect = source.socket.create_connection
source.pool.resolve_public_host = lambda host, port=443: None
calls = []
def forbidden_connect(*args, **kwargs):
    calls.append(args)
    raise AssertionError("unsafe connect attempted")
source.socket.create_connection = forbidden_connect
try:
    source._tcp_ping_ms("public.example", 443)
finally:
    source.pool.resolve_public_host = old_resolver
    source.socket.create_connection = old_connect
check(not calls, "unsafe keytest connect")

if failures:
    raise AssertionError("; ".join(failures))
print("A063_CHILD_OK")
