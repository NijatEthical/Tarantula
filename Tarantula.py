#!/usr/bin/env python3
"""
TARANTULA — Educational Website Reconnaissance Toolkit
Use only on systems you own or have explicit permission to test.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import socket
import ssl
import sys
import time
from collections import deque
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, urlunparse

import requests

try:
    import dns.resolver
except ImportError:
    dns = None

try:
    import whois
except ImportError:
    whois = None

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    console = Console()
    RICH_AVAILABLE = True
except ImportError:
    console = None
    RICH_AVAILABLE = False


TOOL_NAME = "TARANTULA"
USER_AGENT = "Tarantula-Recon/1.0 (educational; authorized testing only)"
HTTP_TIMEOUT = 8
MAX_CRAWL_PAGES = 15
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    587: "SMTP submission", 993: "IMAPS", 995: "POP3S",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    8080: "HTTP alternate", 8443: "HTTPS alternate",
}
ADMIN_PATHS = [
    "/admin", "/administrator", "/login", "/wp-admin",
    "/wp-login.php", "/admin/login", "/user/login",
    "/dashboard", "/cpanel",
]


def say(message: str = "") -> None:
    print(message)


def banner() -> None:
    """Display the TARANTULA red-and-white terminal banner."""
    red = "\033[91m"
    white = "\033[97m"
    gray = "\033[90m"
    bold = "\033[1m"
    reset = "\033[0m"

    spider = r"""
                              .-
        -:.                   +*
        -=*+-.     .-===:    +%.
           -+**=: :%@@@@@+ .*@-
              :#@#*%@@@@@%:*@+ :-=+===-==--.
                -#@#@@@@@@@@#=#%#=:::-:::::.
 .::-====+++***%#*#%@@@@@@@@@@#=:.
.==----:-:::::--+#%@@@@@@%%@@@%@@@%*++:
              .+%@%*#@@@@@@@@@@%@@*=-+**+-
            .#@+=-.:%@+@#*##+-@*.=*#*: .-+++=.
          .*%=.  ..:@% +@-.::.-@-   =#*.   :=**=.
        .+#+   ... -@=  *% ..  :@-    +%=     .-=
      .*#=         *@   :@:     -@:    :*#:
     =#=          .@+    @*      =#      =%#.
    :+            -@.    ==                +%=
                  %#                        :+
                 -@-
                 #%
                 =-
"""

    print("\033[2J\033[H", end="")
    print(red + bold + spider + reset)
    print(red + bold + "  ╔══════════════════════════════════════════════════════╗" + reset)
    print(red + bold + "  ║                    T A R A N T U L A                 ║" + reset)
    print(red + bold + "  ╚══════════════════════════════════════════════════════╝" + reset)
    print(white + bold + "       WEB RECONNAISSANCE  |  OSINT TOOL" + reset)
    print(red + "       Scan  •  Discover  •  Analyze  •  Stay Ahead" + reset)
    print(gray + "  " + "─" * 58 + reset)


def menu() -> None:
    red = "\033[91m"
    white = "\033[97m"
    gray = "\033[90m"
    bold = "\033[1m"
    reset = "\033[0m"
    items = [
        ("1", "DNS Lookup"),
        ("2", "WHOIS Lookup"),
        ("3", "GeoIP Lookup"),
        ("4", "TCP Port Scanner (authorized targets only)"),
        ("5", "HTTP Header Inspector"),
        ("6", "TLS/SSL Certificate Checker"),
        ("7", "Get robots.txt"),
        ("8", "Public Email Gathering (same host, limited crawl)"),
        ("9", "Passive Subdomain Discovery (crt.sh)"),
        ("10", "Admin Login Path Check (authorized targets only)"),
        ("11", "Exit"),
    ]
    print("\n" + red + bold + "  [ TOOL MENU ]" + reset)
    print(gray + "  " + "─" * 58 + reset)
    for number, label in items:
        print(f"  {red}{bold}[{number:>2}]{reset} {white}{label}{reset}")
    print(gray + "  " + "─" * 58 + reset)


def ask_target(prompt: str = "Enter the domain (e.g. example.com): ") -> str | None:
    raw = input(prompt).strip()
    if not raw:
        say("Error: the domain/IP cannot be empty.")
        return None
    candidate = raw if "://" in raw else "https://" + raw
    parsed = urlparse(candidate)
    host = parsed.hostname
    if not host:
        say("Error: invalid domain/IP format.")
        return None
    # Prevent path/query from being treated as part of the host.
    return host.strip().rstrip(".")


def ask_base_url(prompt: str = "Enter the site address (e.g. https://example.com): ") -> str | None:
    raw = input(prompt).strip()
    if not raw:
        say("Error: the address cannot be empty.")
        return None
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        say("Error: please enter a valid HTTP/HTTPS URL.")
        return None
    # Keep host and optional port, discard credentials/fragments.
    netloc = parsed.netloc.rsplit("@", 1)[-1]
    path = parsed.path or "/"
    return urlunparse((parsed.scheme, netloc, path, "", parsed.query, ""))


def confirm_authorization() -> bool:
    say("\nRun these checks only on systems you own or have written permission to test.")
    answer = input("Type YES to continue: ").strip().casefold()
    if answer not in {"yes", "y"}:
        say("Operation cancelled.")
        return False
    return True


def make_session() -> requests.Session:
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    return session


def dns_lookup() -> None:
    host = ask_target()
    if not host:
        return
    if dns is None:
        say("Install dnspython for the DNS module: pip install dnspython")
        return
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 5
    print(f"\nDNS results: {host}")
    for record_type in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
        try:
            answers = resolver.resolve(host, record_type)
            print(f"\n{record_type}:")
            for answer in answers:
                print(f"  {answer.to_text()}")
        except dns.resolver.NoAnswer:
            print(f"\n{record_type}: no record found.")
        except dns.resolver.NXDOMAIN:
            print(f"\nDomain does not exist (NXDOMAIN): {host}")
            return
        except (dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout, dns.exception.DNSException) as exc:
            print(f"\n{record_type}: DNS query failed ({type(exc).__name__}).")


def whois_lookup() -> None:
    host = ask_target()
    if not host:
        return
    if whois is None:
        say("Install python-whois for the WHOIS module: pip install python-whois")
        return
    try:
        result = whois.whois(host)
        print(f"\nWHOIS results: {host}")
        if not result:
            say("The WHOIS service returned no data.")
            return
        for key in ("domain_name", "registrar", "creation_date", "expiration_date",
                    "updated_date", "name_servers", "status", "emails"):
            value = result.get(key) if hasattr(result, "get") else None
            if value:
                print(f"{key}: {value}")
    except Exception as exc:
        say(f"WHOIS query failed: {exc}")


def geoip_lookup() -> None:
    raw = input("Enter an IP address (leave blank to be asked for a domain): ").strip()
    if not raw:
        raw = ask_target("Enter the domain: ")
        if not raw:
            return
        try:
            raw = socket.gethostbyname(raw)
        except OSError as exc:
            say(f"The domain could not be resolved to an IP address: {exc}")
            return
    try:
        ipaddress.ip_address(raw)
    except ValueError:
        say("Error: please enter a valid IPv4 or IPv6 address.")
        return
    try:
        response = make_session().get(
            f"http://ip-api.com/json/{raw}",
            params={"fields": "status,message,query,country,regionName,city,zip,lat,lon,timezone,isp,org,as"},
            timeout=HTTP_TIMEOUT,
        )
        response.raise_for_status()
        data = response.json()
        if data.get("status") != "success":
            say(f"GeoIP query failed: {data.get('message', 'unknown reason')}")
            return
        print("\nGeoIP results (approximate network/hosting location):")
        for key in ("query", "country", "regionName", "city", "zip", "lat", "lon",
                    "timezone", "isp", "org", "as"):
            if data.get(key) not in (None, ""):
                print(f"{key}: {data[key]}")
        say("Note: this does not show the exact location of a user or of a site's visitors.")
    except (requests.RequestException, ValueError) as exc:
        say(f"Could not reach the GeoIP service: {exc}")


def tcp_port_scan() -> None:
    if not confirm_authorization():
        return
    host = ask_target()
    if not host:
        return
    print(f"\nChecking selected TCP ports on {host}...")
    try:
        addresses = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        unique_ips = sorted({item[4][0] for item in addresses})
    except OSError as exc:
        say(f"Could not resolve the domain: {exc}")
        return
    if not unique_ips:
        say("No IP address found.")
        return
    say("Resolved IP addresses: " + ", ".join(unique_ips))
    say("Note: on shared hosting, the IP address may be shared with other customers.")
    for ip in unique_ips[:2]:
        print(f"\nIP: {ip}")
        for port, service in COMMON_PORTS.items():
            sock = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.6)
            try:
                result = sock.connect_ex((ip, port))
                if result == 0:
                    print(f"  OPEN  {port:>5}  {service}")
            except OSError:
                pass
            finally:
                sock.close()
    say("Note: an open port alone does not mean a vulnerability. Follow the provider's rules.")


def http_header_inspector() -> None:
    url = ask_base_url()
    if not url:
        return
    try:
        response = make_session().get(url, timeout=HTTP_TIMEOUT, allow_redirects=True)
        print(f"\nRequested URL: {url}")
        print(f"Final URL: {response.url}")
        print(f"HTTP status: {response.status_code}")
        print("Response headers:")
        for key, value in response.headers.items():
            print(f"  {key}: {value}")
        if response.status_code >= 400:
            say("Note: the server returned an HTTP error status.")
        say("Note: headers alone are not enough to draw firm conclusions about a site's security.")
    except requests.RequestException as exc:
        say(f"HTTP request failed: {exc}")


def tls_ssl_check() -> None:
    host = ask_target("Enter the domain (e.g. example.com): ")
    if not host:
        return
    try:
        # Default context validates the certificate chain and hostname.
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=HTTP_TIMEOUT) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert()
                tls_version = tls_sock.version()
                cipher = tls_sock.cipher()

        def parse_cert_time(value: str) -> datetime:
            return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)
        not_before = parse_cert_time(cert["notBefore"])
        not_after = parse_cert_time(cert["notAfter"])
        print("\n--- TLS/SSL Certificate Check ---")
        print(f"Domain: {host}")
        print(f"TLS version: {tls_version or 'not available'}")
        print(f"Cipher: {cipher[0]} ({cipher[2]} bits)" if cipher else "Cipher: not available")
        print("Certificate chain and hostname: verified successfully")
        print(f"Valid from (UTC): {not_before.isoformat()}")
        print(f"Valid until (UTC): {not_after.isoformat()}")
        if now < not_before:
            print("Status: the certificate is not yet valid.")
        elif now > not_after:
            print("Status: the certificate has expired.")
        else:
            days_left = (not_after - now).days
            print(f"Status: valid; about {days_left} days remaining.")
        issuer = cert.get("issuer", ())
        issuer_text = ", ".join(f"{key}={value}" for group in issuer for key, value in group)
        print(f"Issuer: {issuer_text or 'not available'}")
        sans = [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"]
        if sans:
            print("Domain names in the certificate:")
            for name in sans[:12]:
                print(f"  - {name}")
        say("Note: this check does not audit the full TLS configuration or the overall security of the site.")
    except ssl.SSLCertVerificationError as exc:
        say(f"TLS certificate validation failed: {exc}")
        say("The cause may be a hostname mismatch, an untrusted certificate chain, or a date problem.")
    except (socket.timeout, TimeoutError):
        say("Error: the connection to the server timed out.")
    except ConnectionRefusedError:
        say("Error: the server refused the HTTPS connection on port 443.")
    except (OSError, ssl.SSLError, KeyError, ValueError) as exc:
        say(f"TLS/SSL check failed: {exc}")


def robots_txt() -> None:
    base_url = ask_base_url()
    if not base_url:
        return
    parsed = urlparse(base_url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    try:
        response = make_session().get(robots_url, timeout=HTTP_TIMEOUT, allow_redirects=True)
        print(f"\nURL: {response.url}")
        print(f"HTTP status: {response.status_code}")
        if response.status_code == 200:
            print("\n--- robots.txt ---")
            print(response.text[:20000] or "(file is empty)")
        else:
            say("robots.txt was not found or the server did not return a successful response.")
        say("Note: robots.txt is not access control; it should not be used to protect sensitive information.")
    except requests.RequestException as exc:
        say(f"robots.txt request failed: {exc}")


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.text_parts = []
        self.title_parts = []
        self.in_title = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag.lower() == "a" and attrs.get("href"):
            self.links.append(attrs["href"])
        if tag.lower() == "title":
            self.in_title = True

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data):
        clean = data.strip()
        if clean:
            self.text_parts.append(clean)
            if self.in_title:
                self.title_parts.append(clean)


def public_email_gathering() -> None:
    start_url = ask_base_url()
    if not start_url:
        return
    parsed_start = urlparse(start_url)
    allowed_host = parsed_start.hostname
    if not allowed_host:
        say("Could not determine a valid host.")
        return
    session = make_session()
    queue = deque([start_url])
    visited = set()
    emails = set()
    email_pattern = re.compile(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b")
    while queue and len(visited) < MAX_CRAWL_PAGES:
        url = queue.popleft()
        if url in visited:
            continue
        visited.add(url)
        try:
            response = session.get(url, timeout=HTTP_TIMEOUT, allow_redirects=True)
            if response.status_code >= 400:
                continue
            content_type = response.headers.get("Content-Type", "").lower()
            if "text/html" not in content_type:
                continue
            emails.update(email_pattern.findall(response.text))
            parser = PageParser()
            parser.feed(response.text)
            for link in parser.links:
                absolute = urljoin(response.url, link)
                parsed = urlparse(absolute)
                if parsed.scheme not in ("http", "https") or parsed.hostname != allowed_host:
                    continue
                normalized = urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", "", ""))
                if normalized not in visited and len(visited) + len(queue) < MAX_CRAWL_PAGES:
                    queue.append(normalized)
        except requests.RequestException:
            continue
    print(f"\nPages visited: {len(visited)}")
    print(f"Unique public email addresses found: {len(emails)}")
    for email in sorted(emails):
        print(f"  {email}")
    say("Note: finding nothing does not prove there are no email addresses on the site.")


def passive_subdomain_discovery() -> None:
    host = ask_target("Enter the base domain (e.g. example.com): ")
    if not host:
        return
    # crt.sh query is passive Certificate Transparency lookup.
    url = "https://crt.sh/"
    try:
        response = make_session().get(
            url, params={"q": f"%.{host}", "output": "json"},
            timeout=12,
        )
        if response.status_code in (502, 503, 504):
            say("The external service is currently unavailable, please try again later.")
            return
        response.raise_for_status()
        try:
            data = response.json()
        except (requests.JSONDecodeError, ValueError):
            say("The external service returned an unexpected response, please try again later.")
            return
        found = set()
        for item in data if isinstance(data, list) else []:
            names = item.get("name_value", "")
            for name in names.splitlines():
                name = name.strip().lower().lstrip("*.")
                if name == host.lower() or name.endswith("." + host.lower()):
                    if "*" not in name and " " not in name:
                        found.add(name)
        if found:
            print(f"\nUnique subdomains found ({len(found)}):")
            for name in sorted(found):
                print(f"  {name}")
        else:
            say("No subdomains found for this query. This does not guarantee that none exist.")
    except (requests.ConnectionError, requests.Timeout):
        say("The external service is currently unavailable, please try again later.")
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "unknown"
        if status in (502, 503, 504):
            say("The external service is currently unavailable, please try again later.")
        else:
            say(f"The external service returned an HTTP error ({status}); please try again later.")
    except requests.RequestException:
        say("The external service is currently unavailable, please try again later.")


def normalize_body(text: str) -> str:
    # Normalize whitespace to identify catch-all/soft-404 pages more reliably.
    return re.sub(r"\s+", " ", text).strip()[:100000]


def get_page_title(text: str) -> str:
    match = re.search(r"<title\b[^>]*>(.*?)</title\s*>", text, re.I | re.S)
    if not match:
        return ""
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", match.group(1))).strip().lower()


def admin_path_check() -> None:
    if not confirm_authorization():
        return
    base_url = ask_base_url()
    if not base_url:
        return
    parsed = urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}/"
    session = make_session()
    try:
        home = session.get(root, timeout=HTTP_TIMEOUT, allow_redirects=True)
        home_body = normalize_body(home.text)
        home_hash = hashlib.sha256(home_body.encode("utf-8", errors="ignore")).hexdigest()
        home_title = get_page_title(home.text)
    except requests.RequestException as exc:
        say(f"The request to the home page failed: {exc}")
        return

    print("\nPreliminary check of admin/login paths:")
    print("Note: only GET requests are sent; no login attempts or password tests are made.")
    for path in ADMIN_PATHS:
        target = urljoin(root, path.lstrip("/"))
        try:
            response = session.get(target, timeout=HTTP_TIMEOUT, allow_redirects=True)
            body = normalize_body(response.text)
            body_hash = hashlib.sha256(body.encode("utf-8", errors="ignore")).hexdigest()
            title = get_page_title(response.text)
            final_url = response.url
            same_as_home = body_hash == home_hash or (title and title == home_title and len(body) > 0)
            if same_as_home and response.status_code == 200:
                note = "200, but same/similar response as the home page — may be a soft-404"
            elif response.status_code in (301, 302, 303, 307, 308):
                note = f"redirect → {final_url}"
            elif response.status_code == 200:
                note = "200 — a separate page response; does not confirm it is a login page"
            elif response.status_code == 404:
                note = "404 — not found"
            else:
                note = f"HTTP {response.status_code}"
            print(f"  {path:<20} {note}")
        except requests.RequestException as exc:
            print(f"  {path:<20} request failed ({type(exc).__name__})")
    say("Result: an HTTP status alone does not prove that an admin panel exists or is vulnerable.")


def main() -> None:
    while True:
        banner()
        menu()
        choice = input("Enter your choice (1-11): ").strip()
        actions = {
            "1": dns_lookup,
            "2": whois_lookup,
            "3": geoip_lookup,
            "4": tcp_port_scan,
            "5": http_header_inspector,
            "6": tls_ssl_check,
            "7": robots_txt,
            "8": public_email_gathering,
            "9": passive_subdomain_discovery,
            "10": admin_path_check,
        }
        if choice == "11":
            say("Thank you for using TARANTULA. Goodbye!")
            break
        action = actions.get(choice)
        if action:
            try:
                action()
            except KeyboardInterrupt:
                say("\nOperation interrupted by the user.")
            except Exception as exc:
                # Last-resort guard keeps the CLI alive without hiding the error.
                say(f"Unexpected error: {type(exc).__name__}: {exc}")
        else:
            say("Invalid choice. Please choose a number between 1 and 11.")
        input("\nPress Enter to continue...")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nTARANTULA closed.")
        sys.exit(0)
