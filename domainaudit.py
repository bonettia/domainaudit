import sys, ssl, socket, json, requests
from rich.table import Table
from rich.console import Console

try:
    domain = sys.argv[1]
except IndexError:
    print("Usage: python domainaudit.py <domain>")
    sys.exit(1)


print(f"Running domain audit for {domain}...")


ctx = ssl.create_default_context()
with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
    s.connect((domain, 443))
    cert = s.getpeercert()
    


headers = requests.get(f"https://{domain}").headers



table = Table(title=domain, show_lines=True)
table.add_column("Check", style="cyan", no_wrap=True)
table.add_column("Result", style="magenta", no_wrap=True)
table.add_row("Expire Date", cert["notAfter"])
table.add_row("Issuer", cert["issuer"][2][0][1])
table.add_row("HSTS", "Present" if "Strict-Transport-Security" in headers else "Absent")
table.add_row("X-Frame-Options", "Present" if "X-Frame-Options" in headers else "Absent")
table.add_row("CSP", "Present" if "Content-Security-Policy" in headers else "Absent")
console = Console()
console.print(table)