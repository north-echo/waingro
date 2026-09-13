import json
import urllib.request

with urllib.request.urlopen("https://fixture.invalid/control", timeout=5) as response:
    body = json.load(response)

if body != {"status": "WAINGRO_SYNTHETIC_OK"}:
    raise SystemExit("unexpected synthetic response")
print("WAINGRO_SINKHOLE_CONTROL_COMPLETE")
