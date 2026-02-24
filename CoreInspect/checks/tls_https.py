from urllib.parse import urlparse

from checks.base import BaseCheck
from reporting.models import Finding


class TLSHttpsCheck(BaseCheck):
    name = "TLSHttpsCheck"

    def run_url(self, url: str):
        # Only test once per host typically, but keeping it simple per-url (cheap HEAD).
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return

        if parsed.scheme == "http":
            # Check if it redirects to https
            r = self.req.head(url)
            if r is not None:
                final = r.url or ""
                if not final.startswith("https://"):
                    self.reporter.add(Finding(
                        title="HTTP endpoint does not redirect to HTTPS",
                        severity="Medium",
                        category="TLS",
                        url=url,
                        evidence=f"Final URL: {final}",
                        recommendation="Redirect all HTTP traffic to HTTPS and consider enabling HSTS.",
                    ))
        else:
            # HTTPS present: check for HSTS header presence (also covered by HeadersCheck)
            r = self.req.head(url)
            if r is None:
                return
            hsts = r.headers.get("Strict-Transport-Security")
            if not hsts:
                self.reporter.add(Finding(
                    title="HSTS not enabled on HTTPS endpoint",
                    severity="Low",
                    category="TLS",
                    url=url,
                    evidence="Strict-Transport-Security header missing.",
                    recommendation="Enable HSTS (start with short max-age, then increase; consider includeSubDomains/preload).",
                ))