from pathlib import Path

(Path.home() / "waingro-benign-canary").write_text(
    "WAINGRO_BENIGN_CANARY\n", encoding="utf-8"
)
print("WAINGRO_BENIGN_CANARY_COMPLETE")
