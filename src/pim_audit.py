# src/pim_audit.py
# PIM JIT + Anti-Sticky-Admin bot with:
# - MSAL client-credentials auth (prints AADSTS details on failure)
# - Robust Graph calls (no fragile $orderby/$top on roleDefinitions; local filter for instances)
# - GitHub token self-check (prints actionable messages; DRY RUN if not OK)

import os, json, time
from datetime import datetime, timedelta, timezone
import requests
import pandas as pd
from dotenv import load_dotenv
import msal

load_dotenv()

# ── ENV ───────────────────────────────────────────────────────
def _getenv(name: str) -> str:
    v = os.getenv(name)
    if v is None or not v.strip():
        raise SystemExit(f"Missing/empty {name} in .env")
    return v.strip()

TENANT_ID = _getenv("TENANT_ID")
CLIENT_ID = _getenv("CLIENT_ID")
CLIENT_SECRET = _getenv("CLIENT_SECRET")

GITHUB_REPO_OWNER = (os.getenv("GITHUB_REPO_OWNER") or "").strip()
GITHUB_REPO_NAME  = (os.getenv("GITHUB_REPO_NAME")  or "").strip()
GITHUB_TOKEN      = (os.getenv("GITHUB_TOKEN")      or "").strip() or None

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
GRAPH     = "https://graph.microsoft.com/v1.0"
GITHUB    = "https://api.github.com"

# Policy windows
STALE_ELIGIBILITY_DAYS = 90          # narrative label for README/metrics
MAX_ACTIVATION_HOURS   = 8
WINDOW_DAYS            = 30          # how far back we look for activations

# ── Auth via MSAL (prints AADSTS details on failure) ─────────
def get_token() -> str:
    app = msal.ConfidentialClientApplication(
        CLIENT_ID, authority=AUTHORITY, client_credential=CLIENT_SECRET
    )
    r = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
    if "access_token" in r:
        return r["access_token"]
    print("\n[AUTH ERROR]")
    print("error:", r.get("error"))
    print("error_description:", r.get("error_description"))
    print("correlation_id:", r.get("correlation_id"))
    print("Fixes: paste secret *Value* (not ID), verify TENANT_ID & CLIENT_ID, remove quotes/spaces.")
    raise SystemExit("Token acquisition failed")

# ── Graph helpers (pagination + encoded params) ──────────────
def gget_all(path: str, token: str, params: dict | None = None) -> list:
    url = GRAPH + path
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Prefer": "odata.maxpagesize=999",
    }
    items = []
    while url:
        r = requests.get(url, headers=headers, params=params, timeout=30)
        params = None
        if r.status_code == 429:
            wait_s = int(r.headers.get("Retry-After", "2"))
            print(f"[Graph] 429 throttled, sleeping {wait_s}s…")
            time.sleep(wait_s); continue
        if r.status_code >= 400:
            try: print("\n[Graph ERROR]", r.status_code, r.json())
            except Exception: print("\n[Graph ERROR]", r.status_code, r.text[:800], "…")
            r.raise_for_status()
        data = r.json()
        items.extend(data.get("value", []))
        url = data.get("@odata.nextLink")
    return items

# ── GitHub helpers (with self-check) ─────────────────────────
def gh_headers():
    if not GITHUB_TOKEN:
        return {"Accept":"application/vnd.github+json","User-Agent":"pim-anti-sticky-bot/1.2"}
    return {"Authorization":f"token {GITHUB_TOKEN}","Accept":"application/vnd.github+json","User-Agent":"pim-anti-sticky-bot/1.2"}

def gh_self_check() -> bool:
    """Verify token is usable and repo is reachable; print guidance if not."""
    if not (GITHUB_TOKEN and GITHUB_REPO_OWNER and GITHUB_REPO_NAME):
        print("[INFO] GitHub token not set → DRY RUN mode for issues.")
        return False

    h = gh_headers()

    # Who am I?
    r = requests.get(f"{GITHUB}/user", headers=h, timeout=15)
    if r.status_code == 401:
        print("[GITHUB AUTH] 401 Bad credentials. Fixes:")
        print("  • Paste the *token value* (not an ID) into GITHUB_TOKEN")
        print("  • Ensure the token isn’t expired and (if required) SSO-authorized")
        print("  • Fine-grained: grant Issues: Read & Write and select this repo")
        return False
    login = r.json().get("login")
    print(f"[GITHUB AUTH] Token OK as: {login}")

    # Can we see the repo?
    repo_url = f"{GITHUB}/repos/{GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}"
    r2 = requests.get(repo_url, headers=h, timeout=15)
    if r2.status_code >= 400:
        print(f"[GITHUB AUTH] Cannot access repo {GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME} ({r2.status_code}).")
        print("  • Check owner/name in .env and repo visibility")
        print("  • Fine-grained: ensure this repo is selected; Classic: use repo/public_repo scope")
        return False

    if not r2.json().get("has_issues", True):
        print("[GITHUB AUTH] Repo has Issues disabled. Enable Issues in repo Settings → Features.")
        return False

    print(f"[GITHUB AUTH] Repo reachable: {GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}")
    return True

def create_issue(title, body, labels=None, enabled=True):
    if not enabled:
        print("[DRY RUN] Would create issue:", title); return
    url = f"{GITHUB}/repos/{GITHUB_REPO_OWNER}/{GITHUB_REPO_NAME}/issues"
    payload = {"title": title, "body": body}
    if labels: payload["labels"] = labels
    r = requests.post(url, headers=gh_headers(), json=payload, timeout=30)
    if r.status_code >= 400:
        try: print("\n[GitHub ERROR]", r.status_code, r.json())
        except Exception: print("\n[GitHub ERROR]", r.status_code, r.text[:800], "…")
        r.raise_for_status()
    print("Created issue:", r.json().get("html_url"))

# ── Risk rules ───────────────────────────────────────────────
PRIV_ROLES = {
    "Global Administrator",
    "Privileged Role Administrator",
    "Security Administrator",
    "Conditional Access Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
}

# ── Role definitions cache + resilient lookup ────────────────
_role_name_by_id: dict[str, str] = {}

def load_all_role_definitions(token: str):
    try:
        defs = gget_all("/roleManagement/directory/roleDefinitions", token)  # no $top to avoid 400s
        _role_name_by_id.update({d["id"]: d.get("displayName","") for d in defs})
        print(f"[INFO] Loaded {len(_role_name_by_id)} role definitions.")
    except Exception as ex:
        print("[WARN] Bulk roleDefinitions failed. Will fetch per-role on demand.", ex)

def role_name(role_def_id: str, token: str) -> str:
    if not role_def_id: return ""
    if role_def_id in _role_name_by_id: return _role_name_by_id[role_def_id]
    try:
        url = f"{GRAPH}/roleManagement/directory/roleDefinitions/{role_def_id}"
        r = requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=30)
        if r.status_code < 400:
            name = r.json().get("displayName", role_def_id)
            _role_name_by_id[role_def_id] = name
            return name
    except Exception:
        pass
    return role_def_id

# ── Main ─────────────────────────────────────────────────────
def main():
    os.makedirs("evidence/csv", exist_ok=True)
    token = get_token()
    gh_ok = gh_self_check()  # ← NEW: preflight GitHub token/repo; enables DRY RUN if False

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")

    assignments = gget_all("/roleManagement/directory/roleAssignments", token)
    eligibles   = gget_all("/roleManagement/directory/roleEligibilitySchedules", token)

    # Pull instances without server-side $filter; filter locally by startDateTime
    since_dt = datetime.now(timezone.utc) - timedelta(days=WINDOW_DAYS)
    inst_all = gget_all("/roleManagement/directory/roleAssignmentScheduleInstances", token)

    def _parse_iso(dt: str):
        if not dt: return None
        try: return datetime.fromisoformat(dt.replace("Z","+00:00"))
        except Exception: return None

    inst = [i for i in inst_all if (s:=_parse_iso(i.get("startDateTime"))) and s >= since_dt]
    print(f"[INFO] Got {len(inst_all)} instances; {len(inst)} in the last {WINDOW_DAYS} days.")

    load_all_role_definitions(token)

    def upn(pid: str) -> str:
        if not pid: return ""
        try:
            r = requests.get(f"{GRAPH}/users/{pid}", headers={"Authorization": f"Bearer {token}"}, timeout=30)
            return r.json().get("userPrincipalName", pid) if r.status_code < 400 else pid
        except Exception:
            return pid

    inst_keys = {(i.get("principalId"), i.get("roleDefinitionId")) for i in inst}

    permanent = []
    for a in assignments:
        rname = role_name(a.get("roleDefinitionId"), token)
        if rname in PRIV_ROLES:
            key = (a.get("principalId"), a.get("roleDefinitionId"))
            if key not in inst_keys:  # likely standing assignment in the window
                permanent.append({
                    "principalId": a.get("principalId"),
                    "principalUPN": upn(a.get("principalId")),
                    "role": rname,
                    "assignmentId": a.get("id"),
                    "createdDateTime": a.get("createdDateTime"),
                })

    recent_keys = {(i.get("principalId"), i.get("roleDefinitionId")) for i in inst}
    stale = []
    for e in eligibles:
        rname = role_name(e.get("roleDefinitionId"), token)
        if rname in PRIV_ROLES:
            key = (e.get("principalId"), e.get("roleDefinitionId"))
            if key not in recent_keys:  # no activation in the window → stale
                stale.append({
                    "principalId": e.get("principalId"),
                    "principalUPN": upn(e.get("principalId")),
                    "role": rname,
                    "eligibilityId": e.get("id"),
                    "eligibleSince": e.get("startDateTime"),
                })

    long_acts = []
    for i in inst:
        rname = role_name(i.get("roleDefinitionId"), token)
        if rname in PRIV_ROLES:
            start, end = i.get("startDateTime"), i.get("endDateTime")
            if start and end:
                try:
                    s = datetime.fromisoformat(start.replace("Z","+00:00"))
                    e = datetime.fromisoformat(end.replace("Z","+00:00"))
                    hours = (e - s).total_seconds()/3600.0
                    if hours > MAX_ACTIVATION_HOURS:
                        long_acts.append({
                            "principalId": i.get("principalId"),
                            "principalUPN": upn(i.get("principalId")),
                            "role": rname,
                            "instanceId": i.get("id"),
                            "start": start, "end": end, "hours": round(hours,2),
                        })
                except Exception:
                    pass

    metrics = {
        "timestamp": ts,
        "privileged_roles_tracked": sorted(list(PRIV_ROLES)),
        "active_privileged_assignments": sum(1 for a in assignments if role_name(a.get("roleDefinitionId"), token) in PRIV_ROLES),
        "eligible_privileged_users":   sum(1 for e in eligibles   if role_name(e.get("roleDefinitionId"), token) in PRIV_ROLES),
        f"activations_last_{WINDOW_DAYS}d": len(inst),
        "permanent_privileged_assignments": len(permanent),
        "stale_eligibilities_90d": len(stale),
        "long_activations_over_8h": len(long_acts),
    }

    out_json = f"evidence/pim-snapshot-{ts}.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump({"metrics": metrics, "permanent": permanent,
                   "staleEligibilities": stale, "longActivations": long_acts}, f, indent=2)
    print("Wrote", out_json)

    pd.DataFrame(permanent).to_csv("evidence/csv/permanent_privileged.csv", index=False)
    pd.DataFrame(stale).to_csv("evidence/csv/stale_eligibilities.csv", index=False)
    pd.DataFrame(long_acts).to_csv("evidence/csv/long_activations.csv", index=False)
    print("Wrote CSVs to evidence/csv/")

    # Optional GitHub Issues (guarded by gh_ok)
    for p in permanent:
        title = f"Permanent privileged assignment: {p['principalUPN']} → {p['role']}"
        body  = "Detected permanent privileged assignment:\n\n```json\n" + json.dumps(p, indent=2) + "\n```"
        create_issue(title, body, labels=["pim","sticky-admin"], enabled=gh_ok)

    for s in stale:
        title = f"Stale PIM eligibility: {s['principalUPN']} → {s['role']} (no activation in {WINDOW_DAYS}d)"
        body  = "Detected stale eligibility:\n\n```json\n" + json.dumps(s, indent=2) + "\n```"
        create_issue(title, body, labels=["pim","stale-eligibility"], enabled=gh_ok)

    for la in long_acts:
        title = f"Long activation > {MAX_ACTIVATION_HOURS}h: {la['principalUPN']} → {la['role']}"
        body  = "Detected long PIM activation:\n\n```json\n" + json.dumps(la, indent=2) + "\n```"
        create_issue(title, body, labels=["pim","long-activation"], enabled=gh_ok)

    print("Summary:")
    print(json.dumps(metrics, indent=2))

if __name__ == "__main__":
    main()







