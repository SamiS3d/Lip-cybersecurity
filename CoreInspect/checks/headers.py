from checks.base import BaseCheck
from reporting.models import Finding


class HeadersCheck(BaseCheck):
    name = "HeadersCheck"

    REQUIRED = {
        "content-security-policy": ("Medium", "Add a strong Content-Security-Policy to reduce XSS risk."),
        "strict-transport-security": ("Medium", "Enable HSTS to enforce HTTPS."),
        "x-content-type-options": ("Low", "Set X-Content-Type-Options: nosniff."),
        "x-frame-options": ("Low", "Set X-Frame-Options to prevent clickjacking (or use CSP frame-ancestors)."),
        "referrer-policy": ("Low", "Set Referrer-Policy to reduce referrer leakage."),
        "permissions-policy": ("Low", "Set Permissions-Policy to restrict powerful browser features."),
    }

    def run_url(self, url: str):
        r = self.req.get(url)
        if not r:
            return

        headers = {k.lower(): v for k, v in r.headers.items()}

        for h, (sev, rec) in self.REQUIRED.items():
            if h not in headers:
                self.reporter.add(Finding(
                    title=f"Missing security header: {h}",
                    severity=sev,
                    category="Headers",
                    url=url,
                    evidence="Header not present in response.",
                    recommendation=rec,
                ))

        # Basic anti-cache suggestion for sensitive pages (heuristic)
        if any(x in url.lower() for x in ("/login", "/account", "/admin")):
            cc = headers.get("cache-control", "")
            if "no-store" not in cc.lower():
                self.reporter.add(Finding(
                    title="Sensitive page may be cacheable (Cache-Control no-store missing)",
                    severity="Low",
                    category="Headers",
                    url=url,
                    evidence=f"Cache-Control: {cc or '(missing)'}",
                    recommendation="Add Cache-Control: no-store to sensitive pages (logins/accounts).",
                ))