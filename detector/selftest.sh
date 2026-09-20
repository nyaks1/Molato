#!/usr/bin/env bash
set -euo pipefail
cd /home/nyaks/src/github/Molato
chmod +x detector/run.sh
python3 detector/docket.py --input detector/fixtures/sample_logcat.txt --output docket.json
bash detector/run.sh detector/fixtures/sample_logcat.txt
python3 - <<'PY'
import json
from pathlib import Path

docket = json.loads(Path("docket.json").read_text(encoding="utf-8"))
summary = docket["summary"]
print("findings", summary["findings"])
print("rules", summary["by_rule"])
print("conditions", summary["by_condition"])
rules_seen = set()
ids = []
for f in docket["findings"]:
    rules_seen.add(f["rule"])
    ids.append(f"{f['id']}:{f['rule']}")
    for popia in f["popia"]:
        assert popia["condition"].startswith("Condition"), popia
print("ids", ids)

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

# Every finding must cite Condition 7 (security) — logging PII
for f in docket["findings"]:
    conds = {p["condition"] for p in f["popia"]}
    assert any("Condition 7" in c for c in conds), f
    assert any("Condition 3" in c for c in conds), f
    assert f["offense"]["file"] == "app/lib/services/insecure_logger.dart"
    assert isinstance(f["offense"]["line"], int)

# README must not claim Condition 5 is Purpose specification
readme = Path("README.md").read_text(encoding="utf-8")
assert "Condition 5 — Purpose Specification" not in readme
print("ALL CHECKS PASSED")
PY
