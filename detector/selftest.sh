#!/usr/bin/env bash
# Cold-machine proof + full Docket pipeline for Molato.
# Usage:
#   ./selftest.sh                         # offline fixture pipeline (no device)
#   ./selftest.sh path/to/real.logcat     # scan a captured device log
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
chmod +x detector/run.sh 2>/dev/null || true

INPUT="${1:-detector/fixtures/sample_logcat.txt}"
FIXTURE="detector/fixtures/sample_logcat.txt"

echo "== Molato cold-machine check =="
echo "1) detector pipeline on: $INPUT"
python3 detector/docket.py --input "$INPUT" --output docket.json --md-output DOCKET.md
bash detector/run.sh "$INPUT"

export MOLATO_INPUT="$INPUT"
export MOLATO_FIXTURE="$FIXTURE"
export MOLATO_ROOT="$ROOT"

python3 - <<'PY'
import json
import os
from pathlib import Path

root = Path(os.environ["MOLATO_ROOT"])
input_path = os.environ["MOLATO_INPUT"]
fixture = os.environ["MOLATO_FIXTURE"]

docket = json.loads((root / "docket.json").read_text(encoding="utf-8"))
md = (root / "DOCKET.md").read_text(encoding="utf-8")
readme = (root / "README.md").read_text(encoding="utf-8")
summary = docket["summary"]

print("findings", summary["findings"])
print("rules", summary["by_rule"])
print("conditions", summary["by_condition"])

assert (root / "docket.json").exists()
assert (root / "DOCKET.md").exists()
assert (root / "app/lib/services/insecure_logger.dart").exists()
assert (root / "detector/docket.py").exists()
assert "WTC-SULJLKF2" in readme
assert "Condition 5 — Purpose Specification" not in readme
assert "# The Docket" in md
assert "Condition 7 — Security safeguards" in md
assert "Condition 3 — Purpose specification" in md
assert "s.19(1)" in md
assert "s.13(1)" in md

for f in docket["findings"]:
    conds = {p["condition"] for p in f["popia"]}
    assert any("Condition 7" in c for c in conds), f
    assert any("Condition 3" in c for c in conds), f
    assert f["offense"]["file"] == "app/lib/services/insecure_logger.dart"
    assert isinstance(f["offense"]["line"], int)

using_fixture = Path(input_path).as_posix().endswith(Path(fixture).as_posix())
if using_fixture:
    rules_seen = {f["rule"] for f in docket["findings"]}
    required = {
        "auth_login_pii_in_logs",
        "tx_amount_account_in_logs",
        "session_logout_account_in_logs",
    }
    missing = required - rules_seen
    assert not missing, f"missing planted leak rules: {missing}"
    assert summary["by_rule"].get("auth_login_pii_in_logs", 0) >= 2
    assert summary["by_rule"].get("tx_amount_account_in_logs", 0) >= 2
    assert summary["by_rule"].get("session_logout_account_in_logs", 0) >= 1
    assert summary["findings"] == 5
else:
    print(f"note: non-fixture input ({input_path}) — skipping planted-rule counts")

print("2) artifacts: docket.json + DOCKET.md")
print("3) POPIA: Condition 3 (s.13) + Condition 7 (s.19) cited")
print("4) verification code WTC-SULJLKF2 present in README")
print("COLD-MACHINE CHECK PASSED")
PY
