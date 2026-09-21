# Molato

WTC-SULJLKF2

Molato (Setswana: offense / fault / case) — a deliberately vulnerable Flutter fintech app paired with a detector that turns every privacy leak into The Docket: a charge sheet mapping each violation to the exact POPIA section it breaks.

## What this is

Two parts, one story:

- **The Offense** — `/app` — a small Flutter fintech demo that deliberately leaks PII (name, account number, transaction amount) into device logs. OWASP Mobile Top 10 — **M6: Inadequate Privacy Controls**.
- **The Docket** — `/detector` — Python + Bash that reads device logs, flags every leak, and writes `docket.json` + `DOCKET.md`, each finding mapped to the POPIA condition it breaks.

The point isn't "here's a vulnerable app." The point is: here's proof I can find the offense and write the case against it.

## Why it exists

Solo proof-of-work for the WeThinkCode_ Cybersecurity elective selection — original work, public repo, commit history, demo video.

## OWASP mapping

| OWASP M6 sub-issue | Where it lives in the app |
|---|---|
| Sensitive data in logs | `app/lib/services/insecure_logger.dart:6` (login), `:16` (tx), `:21` (logout) |
| No log redaction layer | `app/lib/services/insecure_logger.dart` — whole `InsecureLogger` class |
| Debug logging left in release build | bare `print()` in `InsecureLogger` (linter: `avoid_print`) |

## POPIA mapping (from the Act, wired into the detector)

Citations from **Protection of Personal Information Act 4 of 2013** (gov.za). Condition 5 is *Information quality* — purpose lives in Condition 3.

| Condition | Section | What's broken | Evidence |
|---|---|---|---|
| Condition 7 — Security safeguards | s.19(1) | PII persisted in plaintext logs | `docket.json` / `DOCKET.md` findings |
| Condition 3 — Purpose specification | s.13(1) | Logged fields exceed what the feature needs | `docket.json` / `DOCKET.md` findings |

Human-readable charge sheet is **generated** by `detector/docket.py` → `DOCKET.md` (do not hand-edit).

## POPIA standing gate

- **Collected:** synthetic demo name, account number, transaction amount — no real user data.
- **Hosted:** nowhere. Local on-device demo; no cloud backend; nothing leaves the machine.
- **Deleted:** `adb logcat -c` / app uninstall clears the log buffer.

## Architecture

```
molato/
├── app/                 # Flutter offense
│   └── lib/
│       ├── models/demo_user.dart
│       ├── screens/login_screen.dart
│       ├── screens/home_screen.dart
│       └── services/insecure_logger.dart
├── detector/            # The Docket
│   ├── docket.py        # regex + POPIA citations → json + md
│   ├── run.sh           # adb logcat or file → detector
│   ├── selftest.sh      # cold-machine check
│   └── fixtures/sample_logcat.txt
├── docket.json          # generated, machine-readable
├── DOCKET.md            # generated, human-readable charge sheet
└── README.md
```

## Running it

### Offline proof (no device required — cold-machine safe)

```bash
bash detector/selftest.sh
# → docket.json + DOCKET.md
# → prints COLD-MACHINE CHECK PASSED
```

### Full pipeline (emulator or physical device)

```bash
# 1. Run the offense
cd app && flutter run

# 2. In the app: Sign in → Send money → Log out
# 3. Pull logs and write the charge sheet
cd ../detector
./run.sh
# → docket.json + DOCKET.md at repo root
```

Expected Logcat offense lines:

```text
[AUTH] login success user=Neo Serame email=neo.serame@demo.molato.local account=10098765432
[TX] processed for Neo Serame | account=10098765432 | amount=ZAR450.0
[SESSION] logout account=10098765432 user=Neo Serame
```

## Demo (90 seconds live path)

1. **Problem (10s):** Mobile fintech apps leak PII into device logs. OWASP M6. POPIA Condition 7.
2. **Villain (10s):** `InsecureLogger` — bare `print()` of name + account + amount.
3. **Crime scene (20s):** Android Studio Logcat shows the three leak lines after login / send / logout.
4. **Hero (30s):** `bash detector/run.sh` → open `DOCKET.md` — each finding cites Condition 7 (s.19) and Condition 3 (s.13) with the exact offense file:line.
5. **Why now / ask (20s):** Same pattern exists in real apps. The Docket is the shovel: turn logs into a legal charge sheet automatically.

📺 Demo video — unlisted YouTube, 5–10 min (link here once recorded)

### Cold-machine checklist (run before you submit)

```bash
git clone git@github.com:nyaks1/Molato.git
cd Molato
bash detector/selftest.sh
```

Must print `COLD-MACHINE CHECK PASSED`. Verify `WTC-SULJLKF2` is in this README.

## Status

Complete for WeThinkCode_ Cohort2025 elective proof-of-work (due 25 Sept 2026):

- [x] Vulnerable Flutter app with intentional PII log leaks
- [x] `docket.py` detector + POPIA citations (Act 4 of 2013)
- [x] Auto-generated `docket.json` + `DOCKET.md`
- [x] Offline cold-machine self-test
- [x] OWASP M6 file:line mapping
- [ ] Demo video link (record on emulator/device, paste above)
