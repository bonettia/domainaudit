import sys, ssl, socket, json, requests, pydig
from rich.table import Table
from rich.console import Console
from datetime import datetime


full_dns = False
helptext = "Usage: python domainaudit.py <domain> [--full-dns]"
try:
    domain = sys.argv[1]
    for arg in sys.argv[2:]:
        if arg=="--full-dns":
            full_dns = True
        elif arg=="--help":
            print(helptext)
            sys.exit(0)
except IndexError:
    print(helptext)
    sys.exit(1)



ctx = ssl.create_default_context()
with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
    s.connect((domain, 443))
    cert = s.getpeercert()
    


headers = requests.get(f"https://{domain}").headers
records = {}
record_types = ["A", "AAAA", "MX", "NS", "CNAME", "TXT", "SRV", "PTR", "SOA", "CAA"] if full_dns else ["A", "AAAA", "MX", "NS", "CNAME"]
for record_type in record_types:
    try:
        records[record_type] = pydig.query(domain, record_type)

    except Exception as e:
        print(f"Error retrieving {record_type} records: {e}")
        records[record_type] = None



days_remaining = (datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z") - datetime.now()).days

table = Table(title=domain, show_lines=True)
table.add_column("Check", style="cyan", no_wrap=True)
table.add_column("Result", style="magenta", no_wrap=True)
table.add_row("SSL Expiry", f"{days_remaining} days")
table.add_row("Issuer", cert["issuer"][2][0][1])
table.add_row("HSTS", "Present" if "Strict-Transport-Security" in headers else "Absent")
table.add_row("X-Frame-Options", "Present" if "X-Frame-Options" in headers else "Absent")
table.add_row("CSP", "Present" if "Content-Security-Policy" in headers else "Absent")
for record_type in record_types:
    table.add_row(f"{record_type} Records", "\n".join(records.get(record_type, [])) if records.get(record_type) else "None")

console = Console()
console.print(table)