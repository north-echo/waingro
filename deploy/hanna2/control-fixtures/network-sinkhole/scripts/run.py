import json
import socket
import ssl
import urllib.request

try:
    ssl.create_default_context()
except Exception:
    raise SystemExit(11) from None

try:
    socket.getaddrinfo("fixture.invalid", 443, type=socket.SOCK_STREAM)
except OSError:
    raise SystemExit(12) from None

try:
    with urllib.request.urlopen("https://fixture.invalid/control", timeout=5) as response:
        body = json.load(response)
except Exception:
    raise SystemExit(13) from None

if body != {"status": "WAINGRO_SYNTHETIC_OK"}:
    raise SystemExit(14)
print("WAINGRO_SINKHOLE_CONTROL_COMPLETE")
