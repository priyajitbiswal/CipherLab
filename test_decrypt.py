"""Quick test to verify decrypt API endpoint works correctly."""

import json
from app import app

client = app.test_client()

# 1. Test Caesar encrypt
r = client.post("/api/cipher/caesar/encrypt",
                json={"text": "HELLO WORLD", "key": "3"})
data = json.loads(r.data)
print(f"[Caesar encrypt] Status: {r.status_code}")
print(f"  result: {data.get('result')}")
print(f"  steps: {len(data.get('steps', []))} steps")
print(f"  error: {data.get('error')}")
print()

# 2. Test Caesar decrypt
r = client.post("/api/cipher/caesar/decrypt",
                json={"text": "KHOOR ZRUOG", "key": "3"})
data = json.loads(r.data)
print(f"[Caesar decrypt] Status: {r.status_code}")
print(f"  result: {data.get('result')}")
print(f"  steps: {len(data.get('steps', []))} steps")
print(f"  error: {data.get('error')}")
print()

# 3. Test Atbash decrypt (no key)
r = client.post("/api/cipher/atbash/decrypt",
                json={"text": "SVOOL DLIOW", "key": ""})
data = json.loads(r.data)
print(f"[Atbash decrypt] Status: {r.status_code}")
print(f"  result: {data.get('result')}")
print(f"  steps: {len(data.get('steps', []))} steps")
print(f"  error: {data.get('error')}")
print()

# 4. Test Augustus decrypt (no key)
r = client.post("/api/cipher/augustus/decrypt",
                json={"text": "IFMMP XPSME", "key": ""})
data = json.loads(r.data)
print(f"[Augustus decrypt] Status: {r.status_code}")
print(f"  result: {data.get('result')}")
print(f"  steps: {len(data.get('steps', []))} steps")
print(f"  error: {data.get('error')}")
print()

# 5. Check step data types for a decrypt response
r = client.post("/api/cipher/caesar/decrypt",
                json={"text": "KHOOR ZRUOG", "key": "3"})
data = json.loads(r.data)
print(f"[Caesar decrypt step data types]")
for i, step in enumerate(data.get('steps', [])):
    dtype = step.get('data', {}).get('type', 'NONE')
    print(f"  Step {i+1}: title='{step['title']}' data_type='{dtype}'")
