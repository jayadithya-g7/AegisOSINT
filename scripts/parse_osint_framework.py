import urllib.request
import json

url = "https://raw.githubusercontent.com/lockfale/OSINT-Framework/master/public/arf.json"
req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})

try:
    with urllib.request.urlopen(req, timeout=12) as response:
        data = json.loads(response.read().decode("utf-8"))
        print(f"Root: {data.get('name')}")
        children = data.get("children", [])
        print(f"Total categories: {len(children)}")
        for idx, cat in enumerate(children, 1):
            sub_count = len(cat.get("children", []))
            print(f"{idx}. {cat.get('name')} ({sub_count} subcategories)")
            for sub in cat.get("children", [])[:5]:
                print(f"     -> {sub.get('name')}")
except Exception as e:
    print("Error fetching:", e)
