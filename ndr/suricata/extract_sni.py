import json
import sys

filename = 'logs/eve-2026-01-20-01.json'
unique_snis = set()

try:
    with open(filename, 'r') as f:
        for line in f:
            try:
                event = json.loads(line)
                if event.get('event_type') == 'tls':
                    tls_data = event.get('tls', {})
                    sni = tls_data.get('sni')
                    if sni:
                        unique_snis.add(sni)
            except json.JSONDecodeError:
                continue
except FileNotFoundError:
    print(f"Error: File {filename} not found.")
    sys.exit(1)

for sni in sorted(unique_snis):
    print(sni)
