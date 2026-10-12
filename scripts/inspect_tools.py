import json

with open("scripts/parse_osint_framework.py") as f:
    pass

# Read arf.json
import urllib.request
url = "https://raw.githubusercontent.com/lockfale/OSINT-Framework/master/public/arf.json"
req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
data = json.loads(urllib.request.urlopen(req, timeout=12).read().decode("utf-8"))

def print_sub(node, depth=0):
    indent = "  " * depth
    name = node.get("name", "")
    url = node.get("url", "")
    children = node.get("children", [])
    if url:
        print(f"{indent}- {name} ({url})")
    else:
        print(f"{indent}+ {name}")
    for c in children:
        print_sub(c, depth + 1)

interesting_cats = ["Domain Name", "IP & MAC Address", "Email Address", "Cyber Threat Intelligence", "Blockchain & Cryptocurrency", "Business Records", "Search Engines"]

for c in data.get("children", []):
    if c.get("name") in interesting_cats:
        print("\n" + "="*50)
        print(f"CATEGORY: {c.get('name')}")
        print("="*50)
        for sub in c.get("children", [])[:4]:
            print_sub(sub, depth=1)
