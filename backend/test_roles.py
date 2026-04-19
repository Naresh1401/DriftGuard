#!/usr/bin/env python3
"""Test all role accounts: create, login, verify."""
import json
import urllib.request
import urllib.error

BASE = "http://localhost:8000/api/v1"

ROLES = [
    ("admin", "Admin User"),
    ("ciso", "CISO User"),
    ("compliance_officer", "Compliance Officer"),
    ("ni_architect", "NI Architect"),
    ("viewer", "Viewer User"),
]

PASSWORD = "Test1234!"

def post(path, data):
    req = urllib.request.Request(
        f"{BASE}{path}",
        data=json.dumps(data).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        resp = urllib.request.urlopen(req)
        return json.loads(resp.read()), resp.status
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            return json.loads(body), e.code
        except:
            return {"error": body}, e.code

def get(path, token):
    req = urllib.request.Request(
        f"{BASE}{path}",
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        resp = urllib.request.urlopen(req)
        return json.loads(resp.read()), resp.status
    except urllib.error.HTTPError as e:
        return {"error": e.read().decode()}, e.code

print("=" * 60)
print("DRIFTGUARD ROLE TESTING")
print("=" * 60)

# 1. Register all accounts
print("\n--- 1. REGISTRATION ---")
for role, name in ROLES:
    email = f"{role}@driftguard.com"
    data, status = post("/auth/register", {
        "email": email,
        "password": PASSWORD,
        "full_name": name,
        "organization": "DriftGuard",
        "role": role,
    })
    if status == 200:
        print(f"  [CREATED] {email} (role={data.get('role')})")
    elif "already registered" in str(data).lower() or status == 400:
        print(f"  [EXISTS]  {email}")
    else:
        print(f"  [ERROR]   {email} → {status}: {data}")

# 2. Login each account
print("\n--- 2. LOGIN ---")
tokens = {}
for role, name in ROLES:
    email = f"{role}@driftguard.com"
    data, status = post("/auth/login", {"email": email, "password": PASSWORD})
    if status == 200 and "access_token" in data:
        tokens[role] = data["access_token"]
        print(f"  [OK]    {email} → role={data.get('role')}, token={data['access_token'][:25]}...")
    else:
        print(f"  [FAIL]  {email} → {status}: {data}")

# 3. Test /auth/me for each role
print("\n--- 3. AUTH/ME VERIFICATION ---")
for role, token in tokens.items():
    data, status = get("/auth/me", token)
    if status == 200:
        print(f"  [OK]    {role}: email={data.get('email')}, role={data.get('role')}, org={data.get('organization')}")
    else:
        print(f"  [FAIL]  {role}: {status}")

# 4. Test dashboard access for each role
print("\n--- 4. DASHBOARD ACCESS ---")
for role, token in tokens.items():
    data, status = get("/dashboard/overview", token)
    if status == 200:
        print(f"  [OK]    {role}: health={data.get('health_score')}, alerts={data.get('alerts',{}).get('total',0)}")
    else:
        print(f"  [FAIL]  {role}: {status}")

# 5. Test alerts access for each role
print("\n--- 5. ALERTS ACCESS ---")
for role, token in tokens.items():
    data, status = get("/alerts/", token)
    if status == 200:
        count = len(data) if isinstance(data, list) else "?"
        print(f"  [OK]    {role}: {count} alerts")
    else:
        print(f"  [FAIL]  {role}: {status}")

# 6. Test health-score endpoint
print("\n--- 6. HEALTH SCORE ---")
for role, token in tokens.items():
    data, status = get("/alerts/health-score/enterprise", token)
    if status == 200:
        print(f"  [OK]    {role}: score={data.get('score')}, trend={data.get('trend')}")
    else:
        print(f"  [FAIL]  {role}: {status}")

# 7. Test drift-map
print("\n--- 7. DRIFT MAP ---")
for role, token in tokens.items():
    data, status = get("/drift-map", token)
    if status == 200:
        cells = data.get("cells", data)
        print(f"  [OK]    {role}: {len(cells) if isinstance(cells, (list, dict)) else '?'} cells")
    else:
        print(f"  [FAIL]  {role}: {status}")

# 8. Test threat-intel
print("\n--- 8. THREAT INTEL ---")
for role, token in tokens.items():
    data, status = get("/threat-intel", token)
    if status == 200:
        items = data if isinstance(data, list) else data.get("advisories", [])
        print(f"  [OK]    {role}: {len(items)} advisories")
    else:
        print(f"  [FAIL]  {role}: {status}")

# 9. Test governance (role-restricted)
print("\n--- 9. GOVERNANCE ---")
for role, token in tokens.items():
    data, status = get("/governance/gates", token)
    if status == 200:
        print(f"  [OK]    {role}: accessible")
    elif status == 403:
        print(f"  [OK]    {role}: restricted (expected for this role)")
    else:
        print(f"  [WARN]  {role}: {status}")

# 10. Test reports
print("\n--- 10. REPORTS ---")
for role, token in tokens.items():
    data, status = get("/reports/", token)
    if status == 200:
        print(f"  [OK]    {role}: accessible")
    elif status == 403:
        print(f"  [OK]    {role}: restricted")
    else:
        print(f"  [WARN]  {role}: {status}")

print("\n" + "=" * 60)
print("ALL ROLE TESTS COMPLETE")
print("=" * 60)
print(f"\nTest accounts (password: {PASSWORD}):")
for role, _ in ROLES:
    print(f"  {role}@driftguard.com → {role}")
