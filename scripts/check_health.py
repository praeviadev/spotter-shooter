#!/usr/bin/env python3
import json,urllib.request
print(json.dumps(json.load(urllib.request.urlopen('http://127.0.0.1:8080/api/health')),indent=2))
