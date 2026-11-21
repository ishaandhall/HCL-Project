"""Digital Footprint Analyzer - scores a person's online footprint 0-100."""
import json
import sys
 
WEIGHTS = {"exposure": 30, "breaches": 25, "hygiene": 20,
           "sensitivity": 15, "sprawl": 10}
SENSITIVE = {"email": 0.2, "phone": 0.5, "location": 0.5,
             "birthdate": 0.6, "home_address": 0.8, "id_number": 1.0}
LEVELS = [(25, "LOW"), (50, "MODERATE"),
          (75, "HIGH"), (101, "CRITICAL")]
RULES = [
    ("hygiene", 0.4, "Enable 2FA and use unique passwords"),
    ("breaches", 0.3, "Change leaked passwords, enable alerts"),
    ("exposure", 0.5, "Make profiles private, delist brokers"),
    ("sensitivity", 0.4, "Hide phone, address and birthdate"),
    ("sprawl", 0.4, "Delete dormant accounts"),
]
 
 
# ---------- small helper functions ----------
def clamp(x, lo=0.0, hi=1.0):
    return max(lo, min(hi, x))
 
 
def num(v):
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else 0.0
 
 
def as_list(v):
    return v if isinstance(v, list) else []
 
 
def as_dict(v):
    return v if isinstance(v, dict) else {}
 
 
def as_set(v):
    return {x for x in v if isinstance(x, str)} if isinstance(v, list) else set()
 
 
# ---------- input cleaning ----------
def clean_accounts(profile, warnings):
    good = []
    for i, acc in enumerate(as_list(profile.get("accounts"))):
        if isinstance(acc, dict) and acc.get("platform"):
            good.append(acc)
        else:
            warnings.append(f"account #{i} skipped: malformed")
    return good
 
 
# ---------- the five scorers ----------
def score_exposure(accounts, hits):
    public = sum(1 for a in accounts if a.get("public"))
    ratio = public / len(accounts) if accounts else 0
    searched = clamp(num(hits.get("name_results")) / 20)
    listed = 1.0 if hits.get("address_listed") else 0.0
    return clamp(0.6 * ratio + 0.25 * searched + 0.15 * listed)
 
 
def score_hygiene(accounts):
    if not accounts:
        return 0.0
    penalty = 0.0
    for a in accounts:
        penalty += (0.5 * (not a.get("two_factor"))
                    + 0.5 * bool(a.get("password_reused")))
    return clamp(penalty / len(accounts))
 
 
def score_breaches(breaches):
    total = 0.0
    for b in breaches:
        if not isinstance(b, dict):
            continue
        data = as_set(b.get("data"))
        if "password" in data:
            total += 1.0
        elif data & {"phone", "home_address", "id_number"}:
            total += 0.6
        else:
            total += 0.3
    return clamp(total / 3)
 
 
def score_sensitivity(accounts):
    exposed = set()
    for a in accounts:
        if a.get("public"):
            exposed |= as_set(a.get("shares")) & SENSITIVE.keys()
    return clamp(sum(SENSITIVE[f] for f in exposed) / 2.5)
 
 
def score_sprawl(accounts):
    dormant = sum(1 for a in accounts
                  if num(a.get("last_active_days")) > 365)
    return clamp(0.6 * dormant / 5 + 0.4 * len(accounts) / 30)
 
 
# ---------- advice ----------
def advise(raw):
    hits = [(raw[k], tip) for k, limit, tip in RULES
            if raw[k] >= limit]
    return [tip for _, tip in sorted(hits, reverse=True)][:3]
 
 
# ---------- main engine ----------
def analyze(profile):
    if not isinstance(profile, dict):
        return {"error": "profile must be a JSON object"}
    warnings = []
    accounts = clean_accounts(profile, warnings)
    hits = as_dict(profile.get("search_hits"))
    raw = {
        "exposure": score_exposure(accounts, hits),
        "breaches": score_breaches(as_list(profile.get("breaches"))),
        "hygiene": score_hygiene(accounts),
        "sensitivity": score_sensitivity(accounts),
        "sprawl": score_sprawl(accounts),
    }
    points = {k: round(raw[k] * WEIGHTS[k], 1) for k in raw}
    total = round(sum(points.values()), 1)
    level = next(n for limit, n in LEVELS if total < limit)
    if not accounts:
        warnings.append("no valid accounts found")
    return {
        "name": str(profile.get("name", "unknown")),
        "points": points, "score": total, "level": level,
        "advice": advise(raw), "warnings": warnings,
    }
 
 
# ---------- command-line interface ----------
def main():
    if len(sys.argv) < 2:
        print("usage: python footprint_analyzer.py profile.json")
        return
    try:
        with open(sys.argv[1], encoding="utf-8") as f:
            profile = json.load(f)
    except FileNotFoundError:
        print("error: file not found:", sys.argv[1])
        return
    except json.JSONDecodeError:
        print("error: file is not valid JSON")
        return
    print(json.dumps(analyze(profile), indent=2, ensure_ascii=False))
 
 
if __name__ == "__main__":
    main()
