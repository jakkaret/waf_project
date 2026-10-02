#!/usr/bin/env python3
import subprocess, json

cmd = ["ssh", "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=no", "root@178.104.53.123",
       "python3 -c \"import json, collections; "
       "status = collections.Counter(); "
       "requests = collections.Counter(); "
       "with open('/root/waf_project/logs/nginx/access.json') as f: "
       "    for line in f: "
       "        try: "
       "            d = json.loads(line); "
       "            st = d.get('status', ''); "
       "            req = d.get('request', ''); "
       "            status[st] += 1; "
       "            if st in ('200', '304'): "
       "                requests[req] += 1; "
       "        except: pass; "
       "print('STATUS:', dict(status)); "
       "print('TOTAL 200/304 UNIQUE:', len(requests)); "
       "print('TOP 20 REQS:'); "
       "[print(' ', r, c) for r, c in requests.most_common(20)]"
       "\""
]

res = subprocess.run(cmd, capture_output=True, text=True)
print(res.stdout)
if res.stderr:
    print("STDERR:", res.stderr)
