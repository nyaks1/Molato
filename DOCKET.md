# The Docket

**Case:** Molato — The Docket
**Generated:** 2026-09-22T15:38:28.890417+00:00
**Source:** `detector/fixtures/sample_logcat.txt`
**Framework:** OWASP Mobile Top 10 — M6: Inadequate Privacy Controls
**Law:** Protection of Personal Information Act 4 of 2013 (South Africa)
**Read more:** [popia.co.za — POPI Act as enacted, reformat­ted as a website](https://popia.co.za/)
_popia.co.za lists these under Chapter 3 Conditions for Lawful Processing (Condition 3 / Condition 7) and Chapter 11 Offences, Penalties and Administrative Fines (ss. 105, 107, 109). s.99 Civil remedies sits under Chapter 10 Enforcement._

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

## Debt total (what Molato means)

**5 leaks booked · illustrative session debt R8,500,000 · statutory admin fine ceiling R10,000,000 · civil claims open · account-number offences up to 10 years**

| Line | ZAR | Basis |
|---|---|---|
| Illustrative session debt | R8,500,000 | Teaching tariff (high=R2m, medium=R0.5m per finding). NOT a court-ordered or statutory per-finding fine. |
| Statutory admin fine ceiling | R10,000,000 | [s.109 Administrative fines](https://popia.co.za/section-109-administrative-fines/) — not multiplied by finding count |
| Civil damages ([s.99 Civil remedies](https://popia.co.za/section-99-civil-remedies/)) | uncapped | just and equitable + aggravated damages |
| Criminal ([s.105](https://popia.co.za/section-105-unlawful-acts-by-responsible-party-in-connection-with-account-number/) + [s.107 Penalties](https://popia.co.za/section-107-penalties/)) | fine and/or ≤10 years | serious/persistent account-number offences |

_Illustrative tariff is a teaching price so the debt is felt in Rand. Statutory ceilings come from Act 4 of 2013. Not legal advice._

### Read the Act online

Readable site for the enacted POPI Act: **[popia.co.za — POPI Act as enacted, reformat­ted as a website](https://popia.co.za/)** (not the Information Regulator). How our citations appear there:

| How it appears on popia.co.za | Molato uses | Link |
|---|---|---|
| Condition 3 Purpose specification (Ch. 3 → Part A) | purpose breach (s.13) | [open](https://popia.co.za/protection-of-personal-information-act-popia/chapter-3-2/chapter-3/condition-3-purpose-specification/) |
| Section 13 Collection for specific purpose | s.13(1) citation | [open](https://popia.co.za/section-13-collection-for-specific-purpose/) |
| Condition 7 Security safeguards (Ch. 3 → Part A) | security breach (s.19) | [open](https://popia.co.za/protection-of-personal-information-act-popia/chapter-3-2/chapter-3/condition-7-security-safeguards/) |
| Section 19 Security measures on integrity and confidentiality of personal information | s.19(1) citation | [open](https://popia.co.za/section-19-security-measures-on-integrity-and-confidentiality-of-personal-information/) |
| Section 99 Civil remedies (Ch. 10 Enforcement) | civil damages | [open](https://popia.co.za/section-99-civil-remedies/) |
| Section 105 Unlawful acts by responsible party in connection with account number (Ch. 11) | account-number offence | [open](https://popia.co.za/section-105-unlawful-acts-by-responsible-party-in-connection-with-account-number/) |
| Section 107 Penalties (Ch. 11) | ≤10 years for s.105 offences | [open](https://popia.co.za/section-107-penalties/) |
| Section 109 Administrative fines (Ch. 11) | R10m ceiling | [open](https://popia.co.za/section-109-administrative-fines/) |

_Site note from [https://popia.co.za/](https://popia.co.za/): “the POPI Act … as enacted by the South African Parliament, reformatted in the form of a website.” They are not the Information Regulator._

## Findings

### #001 `auth_login_pii_in_logs` (high)

- **Log line:** 4
- **Offense:** `app/lib/services/insecure_logger.dart:6` — Login success log writes name, email and account number to device logs
- **OWASP:** M6: Inadequate Privacy Controls — sensitive data in logs
- **Extracted PII:** `fullName=Neo Serame`, `email=neo.serame@demo.molato.local`, `accountNumber=10098765432`
- **Exposure:** illustrative R2,000,000 (Teaching tariff only — not a court-ordered fine)
  - **[Administrative fine ceiling](https://popia.co.za/section-109-administrative-fines/)** (`s.109(2)(c)`) — ceiling R10,000,000 — on popia.co.za as “Section 109 Administrative fines”
  - **[Criminal exposure (account number offences)](https://popia.co.za/section-105-unlawful-acts-by-responsible-party-in-connection-with-account-number/)** (`s.105 + s.107(1)(a)`) — on popia.co.za as “Section 105 Unlawful acts by responsible party in connection with account number; Section 107 Penalties”
  - **[Civil damages](https://popia.co.za/section-99-civil-remedies/)** (`s.99(1), (3)`) — on popia.co.za as “Section 99 Civil remedies”
- **Evidence:** `09-19 08:40:03.440  9999  9999 I flutter : [AUTH] login success user=Neo Serame email=neo.serame@demo.molato.local account=10098765432`

**POPIA violations**

- **[Condition 7 — Security safeguards](https://popia.co.za/protection-of-personal-information-act-popia/chapter-3-2/chapter-3/condition-7-security-safeguards/)** (`[s.19(1)](https://popia.co.za/section-19-security-measures-on-integrity-and-confidentiality-of-personal-information/)`) — Raw personal information is persisted in a log buffer with no access control, redaction, or integrity protection.
  - Citation: A responsible party must secure the integrity and confidentiality of personal information in its possession or under its control by taking appropriate, reasonable technical and organisational measures to prevent— ... (b) unlawful access to or processing of personal information.
  - On [popia.co.za](https://popia.co.za/): [Condition 7 Security safeguards](https://popia.co.za/protection-of-personal-information-act-popia/chapter-3-2/chapter-3/condition-7-security-safeguards/) → [Section 19 Security measures on integrity and confidentiality of personal information](https://popia.co.za/section-19-security-measures-on-integrity-and-confidentiality-of-personal-information/)
- **[Condition 3 — Purpose specification](https://popia.co.za/protection-of-personal-information-act-popia/chapter-3-2/chapter-3/condition-3-purpose-specification/)** (`[s.13(1)](https://popia.co.za/section-13-collection-for-specific-purpose/)`) — Authentication UI only needs a session flag; logging full identity + account number exceeds that purpose.
  - Citation: Personal information must be collected for a specific, explicitly defined and lawful purpose related to a function or activity of the responsible party.
  - On [popia.co.za](https://popia.co.za/): [Condition 3 Purpose specification](https://popia.co.za/protection-of-personal-information-act-popia/chapter-3-2/chapter-3/condition-3-purpose-specification/) → [Section 13 Collection for specific purpose](https://popia.co.za/section-13-collection-for-specific-purpose/)

### #002 `tx_amount_account_in_logs` (high)

- **Log line:** 6
- **Offense:** `app/lib/services/insecure_logger.dart:16` — Transaction log writes account number, full name and amount to device logs
- **OWASP:** M6: Inadequate Privacy Controls — sensitive data in logs
- **Extracted PII:** `fullName=Neo Serame`, `accountNumber=10098765432`, `amount=ZAR450.0`
- **Exposure:** illustrative R2,000,000 (Teaching tariff only — not a court-ordered fine)
  - **[Administrative fine ceiling](https://popia.co.za/section-109-administrative-fines/)** (`s.109(2)(c)`) — ceiling R10,000,000 — on popia.co.za as “Section 109 Administrative fines”
  - **[Criminal exposure (account number offences)](https://popia.co.za/section-105-unlawful-acts-by-responsible-party-in-connection-with-account-number/)** (`s.105 + s.107(1)(a)`) — on popia.co.za as “Section 105 Unlawful acts by responsible party in connection with account number; Section 107 Penalties”
  - **[Civil damages](https://popia.co.za/section-99-civil-remedies/)** (`s.99(1), (3)`) — on popia.co.za as “Section 99 Civil remedies”
- **Evidence:** `09-19 08:40:05.880  9999  9999 I flutter : [TX] processed for Neo Serame | account=10098765432 | amount=ZAR450.0`

**POPIA violations**

- **[Condition 7 — Security safeguards](https://popia.co.za/protection-of-personal-information-act-popia/chapter-3-2/chapter-3/condition-7-security-safeguards/)** (`[s.19(1)](https://popia.co.za/section-19-security-measures-on-integrity-and-confidentiality-of-personal-information/)`) — Financial personal information is written in plaintext and can be read by anyone with log access (adb, MDM, bugreports).
  - Citation: A responsible party must secure the integrity and confidentiality of personal information in its possession or under its control by taking appropriate, reasonable technical and organisational measures to prevent— ... (b) unlawful access to or processing of personal information.
  - On [popia.co.za](https://popia.co.za/): [Condition 7 Security safeguards](https://popia.co.za/protection-of-personal-information-act-popia/chapter-3-2/chapter-3/condition-7-security-safeguards/) → [Section 19 Security measures on integrity and confidentiality of personal information](https://popia.co.za/section-19-security-measures-on-integrity-and-confidentiality-of-personal-information/)
- **[Condition 3 — Purpose specification](https://popia.co.za/protection-of-personal-information-act-popia/chapter-3-2/chapter-3/condition-3-purpose-specification/)** (`[s.13(1)](https://popia.co.za/section-13-collection-for-specific-purpose/)`) — Showing a confirmation snackbar needs an amount, not the user's account number and legal name in logs.
  - Citation: Personal information must be collected for a specific, explicitly defined and lawful purpose related to a function or activity of the responsible party.
  - On [popia.co.za](https://popia.co.za/): [Condition 3 Purpose specification](https://popia.co.za/protection-of-personal-information-act-popia/chapter-3-2/chapter-3/condition-3-purpose-specification/) → [Section 13 Collection for specific purpose](https://popia.co.za/section-13-collection-for-specific-purpose/)

### #002 `tx_amount_account_in_logs` (high)

- **Log line:** 7
- **Offense:** `app/lib/services/insecure_logger.dart:16` — Transaction log writes account number, full name and amount to device logs
- **OWASP:** M6: Inadequate Privacy Controls — sensitive data in logs
- **Extracted PII:** `fullName=Neo Serame`, `accountNumber=10098765432`, `amount=ZAR120.5`
- **Exposure:** illustrative R2,000,000 (Teaching tariff only — not a court-ordered fine)
  - **[Administrative fine ceiling](https://popia.co.za/section-109-administrative-fines/)** (`s.109(2)(c)`) — ceiling R10,000,000 — on popia.co.za as “Section 109 Administrative fines”
  - **[Criminal exposure (account number offences)](https://popia.co.za/section-105-unlawful-acts-by-responsible-party-in-connection-with-account-number/)** (`s.105 + s.107(1)(a)`) — on popia.co.za as “Section 105 Unlawful acts by responsible party in connection with account number; Section 107 Penalties”
  - **[Civil damages](https://popia.co.za/section-99-civil-remedies/)** (`s.99(1), (3)`) — on popia.co.za as “Section 99 Civil remedies”
- **Evidence:** `09-19 08:40:06.200  9999  9999 I flutter : [TX] processed for Neo Serame | account=10098765432 | amount=ZAR120.5`

**POPIA violations**

- **[Condition 7 — Security safeguards](https://popia.co.za/protection-of-personal-information-act-popia/chapter-3-2/chapter-3/condition-7-security-safeguards/)** (`[s.19(1)](https://popia.co.za/section-19-security-measures-on-integrity-and-confidentiality-of-personal-information/)`) — Financial personal information is written in plaintext and can be read by anyone with log access (adb, MDM, bugreports).
  - Citation: A responsible party must secure the integrity and confidentiality of personal information in its possession or under its control by taking appropriate, reasonable technical and organisational measures to prevent— ... (b) unlawful access to or processing of personal information.
  - On [popia.co.za](https://popia.co.za/): [Condition 7 Security safeguards](https://popia.co.za/protection-of-personal-information-act-popia/chapter-3-2/chapter-3/condition-7-security-safeguards/) → [Section 19 Security measures on integrity and confidentiality of personal information](https://popia.co.za/section-19-security-measures-on-integrity-and-confidentiality-of-personal-information/)
- **[Condition 3 — Purpose specification](https://popia.co.za/protection-of-personal-information-act-popia/chapter-3-2/chapter-3/condition-3-purpose-specification/)** (`[s.13(1)](https://popia.co.za/section-13-collection-for-specific-purpose/)`) — Showing a confirmation snackbar needs an amount, not the user's account number and legal name in logs.
  - Citation: Personal information must be collected for a specific, explicitly defined and lawful purpose related to a function or activity of the responsible party.
  - On [popia.co.za](https://popia.co.za/): [Condition 3 Purpose specification](https://popia.co.za/protection-of-personal-information-act-popia/chapter-3-2/chapter-3/condition-3-purpose-specification/) → [Section 13 Collection for specific purpose](https://popia.co.za/section-13-collection-for-specific-purpose/)

### #003 `session_logout_account_in_logs` (medium)

- **Log line:** 9
- **Offense:** `app/lib/services/insecure_logger.dart:21` — Logout log still writes account number and full name to device logs
- **OWASP:** M6: Inadequate Privacy Controls — sensitive data in logs
- **Extracted PII:** `accountNumber=10098765432`, `fullName=Neo Serame`
- **Exposure:** illustrative R500,000 (Teaching tariff only — not a court-ordered fine)
  - **[Administrative fine ceiling](https://popia.co.za/section-109-administrative-fines/)** (`s.109(2)(c)`) — ceiling R10,000,000 — on popia.co.za as “Section 109 Administrative fines”
  - **[Criminal exposure (account number offences)](https://popia.co.za/section-105-unlawful-acts-by-responsible-party-in-connection-with-account-number/)** (`s.105 + s.107(1)(a)`) — on popia.co.za as “Section 105 Unlawful acts by responsible party in connection with account number; Section 107 Penalties”
  - **[Civil damages](https://popia.co.za/section-99-civil-remedies/)** (`s.99(1), (3)`) — on popia.co.za as “Section 99 Civil remedies”
- **Evidence:** `09-19 08:40:08.300  9999  9999 I flutter : [SESSION] logout account=10098765432 user=Neo Serame`

**POPIA violations**

- **[Condition 7 — Security safeguards](https://popia.co.za/protection-of-personal-information-act-popia/chapter-3-2/chapter-3/condition-7-security-safeguards/)** (`[s.19(1)](https://popia.co.za/section-19-security-measures-on-integrity-and-confidentiality-of-personal-information/)`) — Session teardown re-exposes identifiers that should leave the device memory path with the session, not land in logs.
  - Citation: A responsible party must secure the integrity and confidentiality of personal information in its possession or under its control by taking appropriate, reasonable technical and organisational measures to prevent— ... (b) unlawful access to or processing of personal information.
  - On [popia.co.za](https://popia.co.za/): [Condition 7 Security safeguards](https://popia.co.za/protection-of-personal-information-act-popia/chapter-3-2/chapter-3/condition-7-security-safeguards/) → [Section 19 Security measures on integrity and confidentiality of personal information](https://popia.co.za/section-19-security-measures-on-integrity-and-confidentiality-of-personal-information/)
- **[Condition 3 — Purpose specification](https://popia.co.za/protection-of-personal-information-act-popia/chapter-3-2/chapter-3/condition-3-purpose-specification/)** (`[s.13(1)](https://popia.co.za/section-13-collection-for-specific-purpose/)`) — Logout needs no PII; the app's purpose at that step is only to clear local session state.
  - Citation: Personal information must be collected for a specific, explicitly defined and lawful purpose related to a function or activity of the responsible party.
  - On [popia.co.za](https://popia.co.za/): [Condition 3 Purpose specification](https://popia.co.za/protection-of-personal-information-act-popia/chapter-3-2/chapter-3/condition-3-purpose-specification/) → [Section 13 Collection for specific purpose](https://popia.co.za/section-13-collection-for-specific-purpose/)

### #001 `auth_login_pii_in_logs` (high)

- **Log line:** 10
- **Offense:** `app/lib/services/insecure_logger.dart:6` — Login success log writes name, email and account number to device logs
- **OWASP:** M6: Inadequate Privacy Controls — sensitive data in logs
- **Extracted PII:** `fullName=Neo Serame`, `email=neo.serame@demo.molato.local`, `accountNumber=10098765432`
- **Exposure:** illustrative R2,000,000 (Teaching tariff only — not a court-ordered fine)
  - **[Administrative fine ceiling](https://popia.co.za/section-109-administrative-fines/)** (`s.109(2)(c)`) — ceiling R10,000,000 — on popia.co.za as “Section 109 Administrative fines”
  - **[Criminal exposure (account number offences)](https://popia.co.za/section-105-unlawful-acts-by-responsible-party-in-connection-with-account-number/)** (`s.105 + s.107(1)(a)`) — on popia.co.za as “Section 105 Unlawful acts by responsible party in connection with account number; Section 107 Penalties”
  - **[Civil damages](https://popia.co.za/section-99-civil-remedies/)** (`s.99(1), (3)`) — on popia.co.za as “Section 99 Civil remedies”
- **Evidence:** `09-19 08:40:09.001  9999  9999 I flutter : [AUTH] login success user=Neo Serame email=neo.serame@demo.molato.local account=10098765432`

**POPIA violations**

- **[Condition 7 — Security safeguards](https://popia.co.za/protection-of-personal-information-act-popia/chapter-3-2/chapter-3/condition-7-security-safeguards/)** (`[s.19(1)](https://popia.co.za/section-19-security-measures-on-integrity-and-confidentiality-of-personal-information/)`) — Raw personal information is persisted in a log buffer with no access control, redaction, or integrity protection.
  - Citation: A responsible party must secure the integrity and confidentiality of personal information in its possession or under its control by taking appropriate, reasonable technical and organisational measures to prevent— ... (b) unlawful access to or processing of personal information.
  - On [popia.co.za](https://popia.co.za/): [Condition 7 Security safeguards](https://popia.co.za/protection-of-personal-information-act-popia/chapter-3-2/chapter-3/condition-7-security-safeguards/) → [Section 19 Security measures on integrity and confidentiality of personal information](https://popia.co.za/section-19-security-measures-on-integrity-and-confidentiality-of-personal-information/)
- **[Condition 3 — Purpose specification](https://popia.co.za/protection-of-personal-information-act-popia/chapter-3-2/chapter-3/condition-3-purpose-specification/)** (`[s.13(1)](https://popia.co.za/section-13-collection-for-specific-purpose/)`) — Authentication UI only needs a session flag; logging full identity + account number exceeds that purpose.
  - Citation: Personal information must be collected for a specific, explicitly defined and lawful purpose related to a function or activity of the responsible party.
  - On [popia.co.za](https://popia.co.za/): [Condition 3 Purpose specification](https://popia.co.za/protection-of-personal-information-act-popia/chapter-3-2/chapter-3/condition-3-purpose-specification/) → [Section 13 Collection for specific purpose](https://popia.co.za/section-13-collection-for-specific-purpose/)
