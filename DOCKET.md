# The Docket

**Case:** Molato — The Docket
**Generated:** 2026-09-21T07:13:57.414606+00:00
**Source:** `detector/fixtures/sample_logcat.txt`
**Framework:** OWASP Mobile Top 10 — M6: Inadequate Privacy Controls
**Law:** Protection of Personal Information Act 4 of 2013 (South Africa)

## Charge sheet

**Findings:** 5

| Rule | Count |
|---|---|
| `auth_login_pii_in_logs` | 2 |
| `session_logout_account_in_logs` | 1 |
| `tx_amount_account_in_logs` | 2 |

| POPIA condition | Findings |
|---|---|
| Condition 3 — Purpose specification | 5 |
| Condition 7 — Security safeguards | 5 |

## Findings

### #001 `auth_login_pii_in_logs` (high)

- **Log line:** 4
- **Offense:** `app/lib/services/insecure_logger.dart:6` — Login success log writes name, email and account number to device logs
- **OWASP:** M6: Inadequate Privacy Controls — sensitive data in logs
- **Extracted PII:** `fullName=Neo Serame`, `email=neo.serame@demo.molato.local`, `accountNumber=10098765432`
- **Evidence:** `09-19 08:40:03.440  9999  9999 I flutter : [AUTH] login success user=Neo Serame email=neo.serame@demo.molato.local account=10098765432`

**POPIA violations**

- **Condition 7 — Security safeguards** (`s.19(1)`) — Raw personal information is persisted in a log buffer with no access control, redaction, or integrity protection.
  - Citation: A responsible party must secure the integrity and confidentiality of personal information in its possession or under its control by taking appropriate, reasonable technical and organisational measures to prevent— ... (b) unlawful access to or processing of personal information.
- **Condition 3 — Purpose specification** (`s.13(1)`) — Authentication UI only needs a session flag; logging full identity + account number exceeds that purpose.
  - Citation: Personal information must be collected for a specific, explicitly defined and lawful purpose related to a function or activity of the responsible party.

### #002 `tx_amount_account_in_logs` (high)

- **Log line:** 6
- **Offense:** `app/lib/services/insecure_logger.dart:16` — Transaction log writes account number, full name and amount to device logs
- **OWASP:** M6: Inadequate Privacy Controls — sensitive data in logs
- **Extracted PII:** `fullName=Neo Serame`, `accountNumber=10098765432`, `amount=ZAR450.0`
- **Evidence:** `09-19 08:40:05.880  9999  9999 I flutter : [TX] processed for Neo Serame | account=10098765432 | amount=ZAR450.0`

**POPIA violations**

- **Condition 7 — Security safeguards** (`s.19(1)`) — Financial personal information is written in plaintext and can be read by anyone with log access (adb, MDM, bugreports).
  - Citation: A responsible party must secure the integrity and confidentiality of personal information in its possession or under its control by taking appropriate, reasonable technical and organisational measures to prevent— ... (b) unlawful access to or processing of personal information.
- **Condition 3 — Purpose specification** (`s.13(1)`) — Showing a confirmation snackbar needs an amount, not the user's account number and legal name in logs.
  - Citation: Personal information must be collected for a specific, explicitly defined and lawful purpose related to a function or activity of the responsible party.

### #002 `tx_amount_account_in_logs` (high)

- **Log line:** 7
- **Offense:** `app/lib/services/insecure_logger.dart:16` — Transaction log writes account number, full name and amount to device logs
- **OWASP:** M6: Inadequate Privacy Controls — sensitive data in logs
- **Extracted PII:** `fullName=Neo Serame`, `accountNumber=10098765432`, `amount=ZAR120.5`
- **Evidence:** `09-19 08:40:06.200  9999  9999 I flutter : [TX] processed for Neo Serame | account=10098765432 | amount=ZAR120.5`

**POPIA violations**

- **Condition 7 — Security safeguards** (`s.19(1)`) — Financial personal information is written in plaintext and can be read by anyone with log access (adb, MDM, bugreports).
  - Citation: A responsible party must secure the integrity and confidentiality of personal information in its possession or under its control by taking appropriate, reasonable technical and organisational measures to prevent— ... (b) unlawful access to or processing of personal information.
- **Condition 3 — Purpose specification** (`s.13(1)`) — Showing a confirmation snackbar needs an amount, not the user's account number and legal name in logs.
  - Citation: Personal information must be collected for a specific, explicitly defined and lawful purpose related to a function or activity of the responsible party.

### #003 `session_logout_account_in_logs` (medium)

- **Log line:** 9
- **Offense:** `app/lib/services/insecure_logger.dart:21` — Logout log still writes account number and full name to device logs
- **OWASP:** M6: Inadequate Privacy Controls — sensitive data in logs
- **Extracted PII:** `accountNumber=10098765432`, `fullName=Neo Serame`
- **Evidence:** `09-19 08:40:08.300  9999  9999 I flutter : [SESSION] logout account=10098765432 user=Neo Serame`

**POPIA violations**

- **Condition 7 — Security safeguards** (`s.19(1)`) — Session teardown re-exposes identifiers that should leave the device memory path with the session, not land in logs.
  - Citation: A responsible party must secure the integrity and confidentiality of personal information in its possession or under its control by taking appropriate, reasonable technical and organisational measures to prevent— ... (b) unlawful access to or processing of personal information.
- **Condition 3 — Purpose specification** (`s.13(1)`) — Logout needs no PII; the app's purpose at that step is only to clear local session state.
  - Citation: Personal information must be collected for a specific, explicitly defined and lawful purpose related to a function or activity of the responsible party.

### #001 `auth_login_pii_in_logs` (high)

- **Log line:** 10
- **Offense:** `app/lib/services/insecure_logger.dart:6` — Login success log writes name, email and account number to device logs
- **OWASP:** M6: Inadequate Privacy Controls — sensitive data in logs
- **Extracted PII:** `fullName=Neo Serame`, `email=neo.serame@demo.molato.local`, `accountNumber=10098765432`
- **Evidence:** `09-19 08:40:09.001  9999  9999 I flutter : [AUTH] login success user=Neo Serame email=neo.serame@demo.molato.local account=10098765432`

**POPIA violations**

- **Condition 7 — Security safeguards** (`s.19(1)`) — Raw personal information is persisted in a log buffer with no access control, redaction, or integrity protection.
  - Citation: A responsible party must secure the integrity and confidentiality of personal information in its possession or under its control by taking appropriate, reasonable technical and organisational measures to prevent— ... (b) unlawful access to or processing of personal information.
- **Condition 3 — Purpose specification** (`s.13(1)`) — Authentication UI only needs a session flag; logging full identity + account number exceeds that purpose.
  - Citation: Personal information must be collected for a specific, explicitly defined and lawful purpose related to a function or activity of the responsible party.
