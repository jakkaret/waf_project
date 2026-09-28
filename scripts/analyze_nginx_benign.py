import json
from collections import Counter

uris = Counter()
static_assets = 0
total = 0

STATIC_EXT = {".html", ".htm", ".css", ".js", ".png", ".jpg", ".jpeg",
              ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot",
              ".map", ".webp", ".avif", ".mp4", ".webm", ".pdf"}

with open('ml/dataset/nginx_real_benign.jsonl') as f:
    for line in f:
        d = json.loads(line)
        uri = d.get('URI', '')
        uris[uri] += 1
        total += 1
        if any(uri.lower().endswith(ext) for ext in STATIC_EXT):
            static_assets += 1

print(f"Total rows: {total}")
print(f"Static assets: {static_assets}")
print(f"Distinct URIs: {len(uris)}")
print("Top 25 URIs:")
for u, c in uris.most_common(25):
    print(f"  {c:5d}x {u}")
