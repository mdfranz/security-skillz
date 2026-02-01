import json
import sys

if len(sys.argv) < 2:
    print("Usage: python3 extract_dns.py <filename>")
    sys.exit(1)

filename = sys.argv[1]
dns_servers = set()

try:
    with open(filename, 'r') as f:
        for line in f:
            try:
                event = json.loads(line)
                # Check for event_type 'dns' or traffic to port 53
                if event.get('event_type') == 'dns' or event.get('dest_port') == 53:
                    dest_ip = event.get('dest_ip')
                    if dest_ip:
                        dns_servers.add(dest_ip)
            except json.JSONDecodeError:
                continue
except FileNotFoundError:
    print(f"Error: File {filename} not found.")
    sys.exit(1)

for ip in sorted(dns_servers):
    print(ip)
