# CoreInspect — Web Security Auditor

CoreInspect is a **web security auditing** tool designed for **authorized** security assessments. It combines a dynamic crawler (Playwright) with a set of **passive** and **non-destructive active** checks, then produces **TXT / JSON / HTML** reports and a **Security Score (0–100)** with a grade.

> Important: Use CoreInspect **only** on targets you own or have explicit permission to test.

---

## Features

### Crawling
- Dynamic crawling using **Playwright Chromium** (handles JS-rendered pages)
- In-scope link discovery (same-site)
- HTML-focused crawling (skips common static assets)

### Checks (Safe by default)
CoreInspect focuses on security auditing and misconfiguration detection, including:
- TLS/HTTPS posture (HTTP→HTTPS redirect, HSTS presence)
- Security headers (CSP, HSTS, X-Content-Type-Options, etc.)
- Cookie flags (Secure, HttpOnly, SameSite)
- CORS heuristics
- Information disclosure (Server, X-Powered-By)
- Sensitive path exposure probes (best-effort heuristics)
- Form hygiene heuristics (CSRF token presence hints, HTTPS action for password forms)

### Profiles
- `passive` (default): safe checks and configuration auditing
- `active`: includes **non-destructive reflection checks** using benign markers (no exploit payloads)
- `deep`: expands discovery using `robots.txt` and `sitemap.xml` hints (best-effort) + crawling + checks

### Reporting
- **TXT** report (human readable)
- **JSON** report (machine readable)
- **HTML** report (shareable, executive-friendly)
- Security Score **0–100** with grade (A–F), with capped deductions per category

---

## Installation

### 1) Python environment
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2) Playwright browser
```bash
playwright install chromium
```

---

## Usage

### Passive scan (recommended)
```bash
python3 main.py --target https://example.com --profile passive --format both
```

### Active scan (authorized only)
```bash
python3 main.py --target https://example.com --profile active --authorized --format both
```

### Deep scan (authorized only)
```bash
python3 main.py --target https://example.com --profile deep --authorized --max-pages 80 --timeout 20 --format both
```

### Output formats
- `--format txt`
- `--format json`
- `--format html`
- `--format both` (TXT + JSON + HTML)

Reports are saved under:
- `reports/scan_<domain>_<timestamp>.txt`
- `reports/scan_<domain>_<timestamp>.json`
- `reports/scan_<domain>_<timestamp>.html`

Open the latest HTML report:
```bash
xdg-open "$(ls -t reports/*.html | head -n 1)"
```

---

## What the Security Score means
CoreInspect calculates a score by applying severity-based deductions with category caps (to reduce noise).  
The report includes:
- total score + grade
- deduction breakdown by category
- top issues list

---

## Project structure

```text
CoreInspect/
  main.py
  requirements.txt
  core/          # crawler, requester, config, logging
  checks/        # auditing checks
  scoring/       # scoring engine
  reporting/     # TXT/JSON/HTML report generation
  utils/         # colors, helpers
  docs/          # documentation
  reports/       # generated reports (local)
```

---

## Responsible use
CoreInspect is intended for **defensive security** and auditing.  
Do not run it against systems you do not own or have explicit permission to test.

---

## Documentation
- See: [docs/README.md](docs/README.md)
- Troubleshooting: [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)
- Checks reference: [docs/CHECKS.md](docs/CHECKS.md)

---

## License
Choose a license that matches your needs (MIT / Apache-2.0 / GPL-3.0).  
If you want, tell me what license you prefer and I’ll generate the `LICENSE` file.