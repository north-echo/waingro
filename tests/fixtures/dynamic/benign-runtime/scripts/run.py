"""Harmless end-to-end canary for the hanna2 runtime harness."""

from pathlib import Path


def main() -> None:
    output = Path("/tmp/waingro-benign-canary.txt")
    output.write_text("isolated-runtime-ok\n", encoding="utf-8")
    print("WAINGRO benign runtime fixture completed")


if __name__ == "__main__":
    main()
