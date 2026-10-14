# Nijat Ethical ⚓

**A Python-based Cybersecurity Reconnaissance Toolkit**

GRAY MASK is a command-line tool designed for learning cybersecurity fundamentals and performing basic reconnaissance on authorized targets.

## Features

1. **DNS Lookup** — Retrieve common DNS records.
2. **WHOIS Lookup** — Retrieve domain registration information.
3. **GeoIP Lookup** — View approximate public IP geolocation data.
4. **TCP Port Scanner** — Check a limited list of common TCP ports.
5. **HTTP Header Inspector** — Inspect HTTP response headers.
6. **IP Locator** — Retrieve approximate IP geolocation information.
7. **Robots.txt Viewer** — Retrieve a website's `robots.txt` file.
8. **Email Gathering** — Find publicly visible email addresses on a website.
9. **Subdomain Discovery** — Search public Certificate Transparency records.
10. **Admin Login Path Check** — Check common login paths using ordinary HTTP requests.
11. **Exit** — Close the application.

## Requirements

- Python 3.10 or newer
- Internet connection
- Dependencies listed in `requirements.txt`

## Installation

Clone the repository:

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd YOUR_PROJECT_FOLDER
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

## Usage

Run the application:

```bash
python gray_mask.py
```

Choose an option from the interactive terminal menu.

## Responsible Use

GRAY MASK is intended for educational purposes and authorized security assessments.

- Only test systems you own or have explicit permission to assess.
- Respect hosting-provider policies and applicable laws.
- Do not use this tool for unauthorized scanning or data collection.
- GeoIP results are approximate and do not identify a person's exact location.
- A publicly accessible login page is not automatically a security vulnerability.

## Limitations

This project provides basic reconnaissance features. Results may be incomplete or affected by network restrictions, DNS configuration, rate limits, and hosting-provider policies.

The tool is an educational project, not a replacement for a professional security assessment.

## Technologies

- Python
- Requests
- Rich
- dnspython
- python-whois

## Disclaimer

The author is not responsible for misuse of this software. Users are responsible for ensuring that their activities comply with applicable laws and authorization requirements.

## Author

**Project:** Nijat Ethical 
**Category:** Cybersecurity / Python / Reconnaissance
