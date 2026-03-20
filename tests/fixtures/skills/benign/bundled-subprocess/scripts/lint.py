"""Run linters on a directory."""

import subprocess
import sys


def run_pylint(target):
    """Run pylint on the target directory."""
    result = subprocess.run(
        ["pylint", target, "--output-format=text"],
        capture_output=True,
        text=True,
    )
    print(result.stdout)
    return result.returncode


if __name__ == "__main__":
    sys.exit(run_pylint(sys.argv[1] if len(sys.argv) > 1 else "src/"))
