import json
from collections import Counter

status = Counter()
requests = Counter()

with open('/root/waf_project/logs/nginx/access.json', 'r', encoding='utf-8', errors='replace') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
            st = str(d.get('status', ''))
            req = str(d.get('request', ''))
            host = str(d.get('host', ''))
            status[st] += 1
            if st in ('200', '304'):
                requests[(req, host)] += 1
        except Exception:
            pass

print('STATUS:', dict(status))
print('TOTAL UNIQUE (req, host):', len(requests))
print('\nTOP 30 BENIGN (200/304) REQUESTS:')
for (req, host), count in requests.most_common(30):
    print(f"  [{count:5d}x] ({host:25s}) {req}")
