#!/usr/bin/env python3
"""The Docket — scan device logs for Molato PII leaks and cite POPIA."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = REPO_ROOT / "docket.json"
OFFENSE_FILE = "app/lib/services/insecure_logger.dart"

POPIA_CONDITION_7 = {
    "condition": "Condition 7 — Security safeguards",
    "section": "s.19(1)",
    "citation": (
        "A responsible party must secure the integrity and confidentiality of "
        "personal information in its possession or under its control by taking "
        "appropriate, reasonable technical and organisational measures to "
        "prevent— ... (b) unlawful access to or processing of personal information."
    ),
}

POPIA_CONDITION_3 = {
    "condition": "Condition 3 — Purpose specification",
    "section": "s.13(1)",
    "citation": (
        "Personal information must be collected for a specific, explicitly "
        "defined and lawful purpose related to a function or activity of the "
        "responsible party."
    ),
}

RULES = [
    {
        "id": "001",
        "rule": "auth_login_pii_in_logs",
        "severity": "high",
        "regex": re.compile(
            r"\[AUTH\] login success user=(?P<fullName>.+?) "
            r"email=(?P<email>\S+) account=(?P<accountNumber>\d+)"
        ),
        "source_line": 6,
        "offense": (
            "Login success log writes name, email and account number "
            "to device logs"
        ),
        "why_c7": (
            "Raw personal information is persisted in a log buffer with no "
            "access control, redaction, or integrity protection."
        ),
        "why_c3": (
            "Authentication UI only needs a session flag; logging full "
            "identity + account number exceeds that purpose."
        ),
    },
    {
        "id": "002",
        "rule": "tx_amount_account_in_logs",
        "severity": "high",
        "regex": re.compile(
            r"\[TX\] processed for (?P<fullName>.+?) \| "
            r"account=(?P<accountNumber>\d+) \| amount=(?P<amount>\S+)"
        ),
        "source_line": 16,
        "offense": (
            "Transaction log writes account number, full name and amount "
            "to device logs"
        ),
        "why_c7": (
            "Financial personal information is written in plaintext and can "
            "be read by anyone with log access (adb, MDM, bugreports)."
        ),
        "why_c3": (
            "Showing a confirmation snackbar needs an amount, not the "
            "user's account number and legal name in logs."
        ),
    },
    {
        "id": "003",
        "rule": "session_logout_account_in_logs",
        "severity": "medium",
        "regex": re.compile(
            r"\[SESSION\] logout account=(?P<accountNumber>\d+) "
            r"user=(?P<fullName>.+)"
        ),
        "source_line": 21,
        "offense": (
            "Logout log still writes account number and full name "
            "to device logs"
        ),
        "why_c7": (
            "Session teardown re-exposes identifiers that should leave the "
            "device memory path with the session, not land in logs."
        ),
        "why_c3": (
            "Logout needs no PII; the app's purpose at that step is only to "
            "clear local session state."
        ),
    },
]


def scan_lines(text: str) -> list[dict]:
    findings: list[dict] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for rule in RULES:
            match = rule["regex"].search(line)
            if not match:
                continue
            extracted = {k: v for k, v in match.groupdict().items() if v is not None}
            findings.append(
                {
                    "id": rule["id"],
                    "rule": rule["rule"],
                    "severity": rule["severity"],
                    "log_line": line_no,
                    "evidence": line.strip(),
                    "extracted": extracted,
                    "offense": {
                        "file": OFFENSE_FILE,
                        "line": rule["source_line"],
                        "description": rule["offense"],
                    },
                    "owasp": "M6: Inadequate Privacy Controls — sensitive data in logs",
                    "popia": [
                        {
                            **POPIA_CONDITION_7,
                            "why_broken": rule["why_c7"],
                        },
                        {
                            **POPIA_CONDITION_3,
                            "why_broken": rule["why_c3"],
                        },
                    ],
                }
            )
    return findings


def build_docket(text: str, source: str) -> dict:
    findings = scan_lines(text)
    by_condition: dict[str, int] = {}
    by_rule: dict[str, int] = {}
    for finding in findings:
        by_rule[finding["rule"]] = by_rule.get(finding["rule"], 0) + 1
        for popia in finding["popia"]:
            key = popia["condition"]
            by_condition[key] = by_condition.get(key, 0) + 1
    return {
        "case": "Molato — The Docket",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "owasp": "OWASP Mobile Top 10 — M6: Inadequate Privacy Controls",
        "popia_source": "Protection of Personal Information Act 4 of 2013 (South Africa)",
        "findings": findings,
        "summary": {
            "findings": len(findings),
            "by_rule": by_rule,
            "by_condition": by_condition,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Molato POPIA violation detector")
    parser.add_argument(
        "--input",
        "-i",
        default="-",
        help="Log file path, or '-' for stdin (default)",
    )
    parser.add_argument(
        "--output",
        "-o",
        default=str(DEFAULT_OUTPUT),
        help=f"Path to docket.json (default: {DEFAULT_OUTPUT})",
    )
    args = parser.parse_args(argv)

    if args.input == "-":
        text = sys.stdin.read()
        source = "stdin"
    else:
        path = Path(args.input)
        text = path.read_text(encoding="utf-8", errors="replace")
        source = str(path)

    docket = build_docket(text, source)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(docket, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(f"Docket written: {output}")
    print(f"Findings: {docket['summary']['findings']}")
    for rule, count in sorted(docket["summary"]["by_rule"].items()):
        print(f"  - {rule}: {count}")
    for condition, count in sorted(docket["summary"]["by_condition"].items()):
        print(f"  - {condition}: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
