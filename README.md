README.md
# PIM JIT + Anti-Sticky-Admin Bot (Entra + Graph)
Enables PIM for JIT privileged access and runs a bot to detect permanent privileged assignments, stale eligibilities, and long activations. Produces JSON/CSV evidence and optional GitHub Issues. Includes a compliance pack.
*A small, practical project to kill “always-on” admin and prove it with evidence.*

## What this is (in plain English)
We turned off permanent admin access in Entra ID and switched to **just-in-time** (JIT) elevation using PIM.  
This bot checks that policy is actually working: it looks for **permanent privileged admins**, **stale eligibilities** (people who are eligible but never activate), and **over-long activations**. It writes **JSON + CSV** evidence you can hand to an auditor, and it can optionally open **GitHub Issues** so nothing gets ignored.

## Why it matters
- Fewer standing privileges = smaller blast radius.
- Clear evidence = shorter audits.
- Automated tickets = faster cleanup and tighter feedback loop.

---

## What it does (technical summary)
- Uses **MSAL (client credentials)** to call Microsoft Graph with your app registration.
- Reads:
  - `/roleManagement/directory/roleAssignments`
  - `/roleManagement/directory/roleEligibilitySchedules`
  - `/roleManagement/directory/roleAssignmentScheduleInstances` *(no fragile server-side filter; we filter by `startDateTime` locally)*
  - Resolves role names from `/roleManagement/directory/roleDefinitions` *(bulk with per-ID fallback so it never crashes)*
- Flags:
  - **Permanent privileged assignments** (aka “sticky admins”)
  - **Stale eligibilities** (no activation in the last 30 days by default)
  - **Long activations** (> 8 hours by default)
- Writes evidence to `evidence/` and (optionally) opens GitHub Issues.

---

## Quick start
```bash
git clone https://github.com/<you>/iam-pim-jit-anti-sticky-admin.git
cd iam-pim-jit-anti-sticky-admin

# Create venv (Windows)
py -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install deps (type the hyphen in -r yourself)
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r .\requirements.txt

# Run
python .\src\pim_audit.py
```
You should see a summary and new files in `evidence/` and `evidence/csv/`.

---

## Project layout
```
.
├─ src/
│  └─ pim_audit.py          # the bot
├─ evidence/
│  ├─ pim-snapshot-*.json   # full snapshot + metrics
│  ├─ csv/
│  │  ├─ permanent_privileged.csv
│  │  ├─ stale_eligibilities.csv
│  │  └─ long_activations.csv
│  └─ screenshots/          # portal and run screenshots
├─ compliance/              # control mappings & narratives (optional)
├─ .env                     # secrets (ignored by Git)
├─ requirements.txt
├─ .gitignore
└─ README.md
```

---

## Setup (once)
### 1) Configure Entra PIM (preventive control)
- **Where:** Entra ID → *Privileged Identity Management* → *Azure AD roles*
- Pick a safe test role (e.g., *Global Reader* or *Application Administrator*).
- Make your user **Eligible** (not Active).
- Set **Activation** settings: require **MFA**, **Justification**, **Max duration** (e.g., 4 hours), **Approver** (optional).

**Screenshots to save → `evidence/screenshots/`**
- `YYYY-MM-DD_pim-role-eligibility.png`
- `YYYY-MM-DD_pim-role-activation-settings.png`

**Explain to non-technical folks:** “Admin rights are off by default. When someone needs them, they turn them on briefly with MFA and a reason.”  
**Explain to technical folks:** “Standing privilege is removed; PIM enforces time-bound elevation with MFA/justification/approval.”

### 2) App registration for the bot
- **Where:** Entra ID → *App registrations* → *New registration* → **Single tenant**.
- Copy **Directory (tenant) ID** and **Application (client) ID**.
- **Certificates & secrets:** create a **client secret** and copy its **Value** (not the ID).
- **API permissions (Application):** `RoleManagement.Read.Directory`, `Directory.Read.All`, `AuditLog.Read.All` → **Grant admin consent**.

Fill your `.env` (no quotes or extra spaces):
```
TENANT_ID=<tenant-guid>
CLIENT_ID=<app-client-id>
CLIENT_SECRET=<client-secret-VALUE>
GITHUB_REPO_OWNER=<your-github-username>
GITHUB_REPO_NAME=iam-pim-jit-anti-sticky-admin
GITHUB_TOKEN=    # optional; leave blank for DRY RUN
```

**Screenshots:**
- `YYYY-MM-DD_app-overview.png`
- `YYYY-MM-DD_api-permissions.png`
- `YYYY-MM-DD_client-secret-created.png` *(mask the value)*

### 3) Optional: GitHub Issues automation
- Create a **fine-grained PAT** for this repo with **Issues: Read & write** (authorize SSO if required).
- Put it in `.env` as `GITHUB_TOKEN=<token-value>`.
- If you skip this, the bot stays in **DRY RUN** for issues and won’t crash.

---

## Run it
```bash
# from the project root with the venv active
python .\src\pim_audit.py
```
What you’ll see:
- A line showing how many instances were found in the last 30 days.
- “Wrote evidence/pim-snapshot-*.json” and CSV export messages.
- If a GitHub token is set and valid: “Token OK as … / Repo reachable … / Created issue: …”  
  Otherwise: “GitHub token not set → DRY RUN mode for issues.”

**Screenshot:** `YYYY-MM-DD_bot-run-success.png` (the terminal summary).

---

## Evidence and outputs
- **JSON**: a full snapshot with metrics + findings (permanent/stale/long).  
  → `evidence/pim-snapshot-<timestamp>.json`
- **CSVs** for quick review:  
  → `evidence/csv/permanent_privileged.csv`  
  → `evidence/csv/stale_eligibilities.csv`  
  → `evidence/csv/long_activations.csv`
- **Screenshots** for auditors: see checklist below.

**How to talk about this:**
- *Non-technical:* “Here’s proof our policy is active: screenshots, CSVs, and a JSON snapshot from the last run.”  
- *Technical:* “Evidence includes portal configuration screenshots, data snapshots from Graph app-only calls, and repeatable exports.”

---

## Screenshot checklist (put in `evidence/screenshots/`)
- `YYYY-MM-DD_pim-role-eligibility.png`
- `YYYY-MM-DD_pim-role-activation-settings.png`
- `YYYY-MM-DD_app-overview.png`
- `YYYY-MM-DD_api-permissions.png`
- `YYYY-MM-DD_client-secret-created.png` *(mask secret)*
- `YYYY-MM-DD_interpreter-selected.png` *(optional: shows .venv in VS Code status bar)*
- `YYYY-MM-DD_pip-success.png` *(optional: successful dependency install)*
- `YYYY-MM-DD_bot-run-success.png`
- `YYYY-MM-DD_github-issue-created.png` *(if enabled)*

---

## Troubleshooting (things I actually ran into)
- **Token 401 (AADSTS…):** usually a bad/expired secret or extra whitespace. Recreate the secret and paste its **Value** into `.env`.
- **Pandas build error on Windows:** use `pandas==2.2.3` (wheel exists) or a Python 3.12 venv.
- **Pylance “cannot import module”:** VS Code using the wrong interpreter. Select `.venv\\Scripts\\python.exe`.
- **`roleDefinitions` 400:** avoid `$top` and fall back to per-ID lookups (the code already does this).
- **`roleAssignmentScheduleInstances` filter 400:** we don’t filter server-side; we pull and filter locally by `startDateTime`.
- **GitHub 401:** invalid/expired token, SSO not authorized, or missing **Issues: Read & write**. The script now self-checks and falls back to **DRY RUN** with friendly guidance.
- **`pip install -r requirements.txt` tried to install “requirements.txt”:** the dash was an en-dash (–). Type a normal `-` or use `--requirement`.

---

## Numbers you can show
- **Permanent privileged assignments:** aim for **0**  
- **Activations last 30d:** shows healthy JIT usage  
- **Stale eligibilities:** trend to **0** (or justify)  
- **Long activations (>8h):** **0** unless policy requires otherwise  
- **MTTD/MTTR** for risky findings (detected → ticketed → resolved)

---

## Roadmap (nice-to-haves)
- GitHub Actions nightly **DRY RUN** that uploads the JSON as a build artifact.
- Email/Teams webhook on new findings.
- Parameterize windows and thresholds via `.env`.
- Add support for workload-specific roles (Exchange/SharePoint) if needed.

---

## Safety notes
- `.env` and everything under `evidence/` are ignored by Git via `.gitignore`.
- Never commit secrets. If you do by accident, revoke and rotate immediately.

---

## License
MIT – use it, tweak it, make it yours.
