#!/usr/bin/env bash
echo "=== benign ==="
curl -s -o /dev/null -w "%{http_code}\n" "https://Httpbin.originweb.site/"
echo "=== XSS ==="
curl -s -o /dev/null -w "%{http_code}\n" "https://Httpbin.originweb.site/?a=%3Cscript%3Ealert(1)%3C/script%3E"
