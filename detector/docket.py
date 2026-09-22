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
DEFAULT_MD_OUTPUT = REPO_ROOT / "DOCKET.md"
OFFENSE_FILE = "app/lib/services/insecure_logger.dart"

# How popia.co.za titles and links these parts (navigation, Chapter 3 / 10 / 11).
POPIA_SITE = "https://popia.co.za/"
POPIA_SITE_NAME = "popia.co.za — POPI Act as enacted, reformatted as a website"

URL_CONDITION_3 = (
    "https://popia.co.za/protection-of-personal-information-act-popia/"
    "chapter-3-2/chapter-3/condition-3-purpose-specification/"
)
URL_SECTION_13 = "https://popia.co.za/section-13-collection-for-specific-purpose/"
URL_CONDITION_7 = (
    "https://popia.co.za/protection-of-personal-information-act-popia/"
    "chapter-3-2/chapter-3/condition-7-security-safeguards/"
)
URL_SECTION_19 = (
    "https://popia.co.za/section-19-security-measures-on-integrity-and-confidentiality-of-personal-information/"
)
URL_SECTION_99 = "https://popia.co.za/section-99-civil-remedies/"
URL_SECTION_105 = (
    "https://popia.co.za/section-105-unlawful-acts-by-responsible-party-in-connection-with-account-number/"
)
URL_SECTION_107 = "https://popia.co.za/section-107-penalties/"
URL_SECTION_109 = "https://popia.co.za/section-109-administrative-fines/"

POPIA_CONDITION_7 = {
    "condition": "Condition 7 — Security safeguards",
    "section": "s.19(1)",
    "as_listed_on_popia_co_za": "Condition 7 Security safeguards",
    "url": URL_CONDITION_7,
    "section_as_listed_on_popia_co_za": (
        "Section 19 Security measures on integrity and confidentiality of personal information"
    ),
    "section_url": URL_SECTION_19,
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
    "as_listed_on_popia_co_za": "Condition 3 Purpose specification",
    "url": URL_CONDITION_3,
    "section_as_listed_on_popia_co_za": "Section 13 Collection for specific purpose",
    "section_url": URL_SECTION_13,
    "citation": (
        "Personal information must be collected for a specific, explicitly "
        "defined and lawful purpose related to a function or activity of the "
        "responsible party."
    ),
}

# Act 4 of 2013 penalties — do not invent amounts. s.109 ceiling is statutory.
PENALTY_ADMIN_FINE_CEILING_ZAR = 10_000_000
PENALTY_ADMIN_FINE = {
    "label": "Administrative fine ceiling",
    "section": "s.109(2)(c)",
    "as_listed_on_popia_co_za": "Section 109 Administrative fines",
    "url": URL_SECTION_109,
    "citation": (
        "…the amount of the administrative fine payable, which amount may, "
        "subject to subsection (10), not exceed R10 million…"
    ),
    "max_zar": PENALTY_ADMIN_FINE_CEILING_ZAR,
}
PENALTY_CRIMINAL_ACCOUNT = {
    "label": "Criminal exposure (account number offences)",
    "section": "s.105 + s.107(1)(a)",
    "as_listed_on_popia_co_za": (
        "Section 105 Unlawful acts by responsible party in connection with account number; "
        "Section 107 Penalties"
    ),
    "url": URL_SECTION_105,
    "url_alt": URL_SECTION_107,
    "citation": (
        "Unlawful processing of a data subject's account number may be an "
        "offence (s.105); conviction is liable to a fine or imprisonment not "
        "exceeding 10 years, or both (s.107)."
    ),
}
PENALTY_CIVIL = {
    "label": "Civil damages",
    "section": "s.99(1), (3)",
    "as_listed_on_popia_co_za": "Section 99 Civil remedies",
    "url": URL_SECTION_99,
    "citation": (
        "A data subject may sue for damages for breach of the Act; a court may "
        "award damages, aggravated damages, interest and costs "
        "(just and equitable — uncapped statutory figure)."
    ),
    "max_zar": None,
}

# Teaching tariff only — shapes the "debt clicks" line in demos. NOT a court figure.
# High = account number + identity/money in logs. Medium = identity in logs only.
ILLUSTRATIVE_TARIFF_ZAR = {"high": 2_000_000, "medium": 500_000}

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
                    "exposure": {
                        "illustrative_zar": ILLUSTRATIVE_TARIFF_ZAR[rule["severity"]]
                        if rule["severity"] in ILLUSTRATIVE_TARIFF_ZAR
                        else ILLUSTRATIVE_TARIFF_ZAR["medium"],
                        "illustrative_basis": (
                            "Teaching tariff only — not a court-ordered fine"
                        ),
                        "statutory": [
                            PENALTY_ADMIN_FINE,
                            PENALTY_CRIMINAL_ACCOUNT
                            if "accountNumber" in extracted
                            else PENALTY_CIVIL,
                            PENALTY_CIVIL,
                        ],
                    },
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
    illustrative_total = sum(f["exposure"]["illustrative_zar"] for f in findings)
    return {
        "case": "Molato — The Docket",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "owasp": "OWASP Mobile Top 10 — M6: Inadequate Privacy Controls",
        "popia_source": "Protection of Personal Information Act 4 of 2013 (South Africa)",
        "popia_read_more": {
            "site": POPIA_SITE_NAME,
            "home": POPIA_SITE,
            "note": (
                "popia.co.za lists these under Chapter 3 Conditions for Lawful Processing "
                "(Condition 3 / Condition 7) and Chapter 11 Offences, Penalties and "
                "Administrative Fines (ss. 105, 107, 109). s.99 Civil remedies sits under "
                "Chapter 10 Enforcement."
            ),
        },
        "findings": findings,
        "summary": {
            "findings": len(findings),
            "by_rule": by_rule,
            "by_condition": by_condition,
        },
        "debt_total": {
            "currency": "ZAR",
            "illustrative_session_debt_zar": illustrative_total,
            "illustrative_basis": (
                "Teaching tariff (high=R2m, medium=R0.5m per finding). "
                "NOT a court-ordered or statutory per-finding fine."
            ),
            "statutory_admin_fine_ceiling_zar": PENALTY_ADMIN_FINE_CEILING_ZAR,
            "statutory_admin_fine_note": (
                "s.109(2)(c): administrative fine may not exceed R10 million "
                "per infringement notice — ceiling is NOT multiplied by finding count."
            ),
            "criminal_exposure": PENALTY_CRIMINAL_ACCOUNT["citation"],
            "civil_exposure": PENALTY_CIVIL["citation"],
            "one_liner": (
                f"{len(findings)} leaks booked · "
                f"illustrative session debt R{illustrative_total:,.0f} · "
                f"statutory admin fine ceiling R{PENALTY_ADMIN_FINE_CEILING_ZAR:,.0f} · "
                "civil claims open · account-number offences up to 10 years"
            ),
        },
    }


def render_markdown(docket: dict) -> str:
    lines: list[str] = []
    lines.append("# The Docket")
    lines.append("")
    lines.append(f"**Case:** {docket['case']}")
    lines.append(f"**Generated:** {docket['generated_at']}")
    lines.append(f"**Source:** `{docket['source']}`")
    lines.append(f"**Framework:** {docket['owasp']}")
    lines.append(f"**Law:** {docket['popia_source']}")
    read_more = docket.get("popia_read_more") or {}
    if read_more.get("home"):
        lines.append(
            f"**Read more:** [{read_more.get('site', 'popia.co.za')}]({read_more['home']})"
        )
        if read_more.get("note"):
            lines.append(f"_{read_more['note']}_")
    lines.append("")
    lines.append("## Charge sheet")
    lines.append("")
    summary = docket["summary"]
    lines.append(f"**Findings:** {summary['findings']}")
    lines.append("")
    lines.append("| Rule | Count |")
    lines.append("|---|---|")
    for rule, count in sorted(summary["by_rule"].items()):
        lines.append(f"| `{rule}` | {count} |")
    lines.append("")
    lines.append("| POPIA condition | Findings |")
    lines.append("|---|---|")
    for condition, count in sorted(summary["by_condition"].items()):
        lines.append(f"| {condition} | {count} |")
    lines.append("")
    debt = docket.get("debt_total", {})
    if debt:
        lines.append("## Debt total (what Molato means)")
        lines.append("")
        lines.append(f"**{debt.get('one_liner', '')}**")
        lines.append("")
        lines.append("| Line | ZAR | Basis |")
        lines.append("|---|---|---|")
        lines.append(
            f"| Illustrative session debt | "
            f"R{debt.get('illustrative_session_debt_zar', 0):,.0f} | "
            f"{debt.get('illustrative_basis', '')} |"
        )
        lines.append(
            f"| Statutory admin fine ceiling | "
            f"R{debt.get('statutory_admin_fine_ceiling_zar', 0):,.0f} | "
            f"[s.109 Administrative fines]({URL_SECTION_109}) — not multiplied by finding count |"
        )
        lines.append(
            f"| Civil damages ([s.99 Civil remedies]({URL_SECTION_99})) | uncapped | "
            f"just and equitable + aggravated damages |"
        )
        lines.append(
            f"| Criminal ([s.105]({URL_SECTION_105}) + [s.107 Penalties]({URL_SECTION_107})) | "
            f"fine and/or ≤10 years | serious/persistent account-number offences |"
        )
        lines.append("")
        lines.append(
            "_Illustrative tariff is a teaching price so the debt is felt in Rand. "
            "Statutory ceilings come from Act 4 of 2013. Not legal advice._"
        )
        lines.append("")
        lines.append("### Read the Act online")
        lines.append("")
        lines.append(
            f"Readable site for the enacted POPI Act: **[{POPIA_SITE_NAME}]({POPIA_SITE})** "
            "(not the Information Regulator). How our citations appear there:"
        )
        lines.append("")
        lines.append("| How it appears on popia.co.za | Molato uses | Link |")
        lines.append("|---|---|---|")
        lines.append(
            "| Condition 3 Purpose specification (Ch. 3 → Part A) | purpose breach (s.13) | "
            f"[open]({URL_CONDITION_3}) |"
        )
        lines.append(
            "| Section 13 Collection for specific purpose | s.13(1) citation | "
            f"[open]({URL_SECTION_13}) |"
        )
        lines.append(
            "| Condition 7 Security safeguards (Ch. 3 → Part A) | security breach (s.19) | "
            f"[open]({URL_CONDITION_7}) |"
        )
        lines.append(
            "| Section 19 Security measures on integrity and confidentiality of personal information | "
            f"s.19(1) citation | [open]({URL_SECTION_19}) |"
        )
        lines.append(
            "| Section 99 Civil remedies (Ch. 10 Enforcement) | civil damages | "
            f"[open]({URL_SECTION_99}) |"
        )
        lines.append(
            "| Section 105 Unlawful acts by responsible party in connection with account number (Ch. 11) | "
            f"account-number offence | [open]({URL_SECTION_105}) |"
        )
        lines.append(
            f"| Section 107 Penalties (Ch. 11) | ≤10 years for s.105 offences | "
            f"[open]({URL_SECTION_107}) |"
        )
        lines.append(
            f"| Section 109 Administrative fines (Ch. 11) | R10m ceiling | "
            f"[open]({URL_SECTION_109}) |"
        )
        lines.append("")
        lines.append(
            f"_Site note from [{POPIA_SITE}]({POPIA_SITE}): "
            "“the POPI Act … as enacted by the South African Parliament, "
            "reformatted in the form of a website.” They are not the Information Regulator._"
        )
        lines.append("")
    lines.append("## Findings")
    lines.append("")
    if not docket["findings"]:
        lines.append("_No planted PII leaks matched. Run the app, trigger login/tx/logout, scan again._")
        lines.append("")
        return "\n".join(lines)

    for finding in docket["findings"]:
        offense = finding["offense"]
        lines.append(
            f"### #{finding['id']} `{finding['rule']}` "
            f"({finding['severity']})"
        )
        lines.append("")
        lines.append(f"- **Log line:** {finding['log_line']}")
        lines.append(
            f"- **Offense:** `{offense['file']}:{offense['line']}` — {offense['description']}"
        )
        lines.append(f"- **OWASP:** {finding['owasp']}")
        extracted = ", ".join(f"`{k}={v}`" for k, v in finding["extracted"].items())
        lines.append(f"- **Extracted PII:** {extracted}")
        exposure = finding.get("exposure", {})
        if exposure:
            lines.append(
                f"- **Exposure:** illustrative R{exposure.get('illustrative_zar', 0):,.0f} "
                f"({exposure.get('illustrative_basis', '')})"
            )
            for stat in exposure.get("statutory", []):
                max_zar = stat.get("max_zar")
                ceiling = (
                    f" — ceiling R{max_zar:,.0f}" if max_zar is not None else ""
                )
                listed = stat.get("as_listed_on_popia_co_za")
                listed_bit = f" — on popia.co.za as “{listed}”" if listed else ""
                lines.append(
                    f"  - **[{stat['label']}]({stat.get('url', POPIA_SITE)})** "
                    f"(`{stat['section']}`){ceiling}{listed_bit}"
                )
        lines.append(f"- **Evidence:** `{finding['evidence']}`")
        lines.append("")
        lines.append("**POPIA violations**")
        lines.append("")
        for popia in finding["popia"]:
            lines.append(
                f"- **[{popia['condition']}]({popia.get('url', POPIA_SITE)})** "
                f"(`[{popia['section']}]({popia.get('section_url', POPIA_SITE)})`) — "
                f"{popia['why_broken']}"
            )
            lines.append(f"  - Citation: {popia['citation']}")
            if popia.get("as_listed_on_popia_co_za"):
                sec = popia.get("section_as_listed_on_popia_co_za")
                sec_link = (
                    f" → [{sec}]({popia.get('section_url')})"
                    if sec and popia.get("section_url")
                    else ""
                )
                lines.append(
                    f"  - On [popia.co.za]({POPIA_SITE}): "
                    f"[{popia['as_listed_on_popia_co_za']}]({popia.get('url', POPIA_SITE)})"
                    f"{sec_link}"
                )
        lines.append("")
    return "\n".join(lines)


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
    parser.add_argument(
        "--md-output",
        default=str(DEFAULT_MD_OUTPUT),
        help=f"Path to DOCKET.md (default: {DEFAULT_MD_OUTPUT})",
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

    md_output = Path(args.md_output)
    md_output.write_text(render_markdown(docket), encoding="utf-8")

    print(f"Docket written: {output}")
    print(f"Charge sheet:   {md_output}")
    print(f"Findings: {docket['summary']['findings']}")
    for rule, count in sorted(docket["summary"]["by_rule"].items()):
        print(f"  - {rule}: {count}")
    for condition, count in sorted(docket["summary"]["by_condition"].items()):
        print(f"  - {condition}: {count}")
    debt = docket.get("debt_total", {})
    if debt:
        print(f"Debt: {debt.get('one_liner', '')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
