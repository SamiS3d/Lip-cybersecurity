from urllib.parse import urlparse

from checks.base import BaseCheck
from reporting.models import Finding


class TLSHttpsCheck(BaseCheck):
    name = "TLSHttpsCheck"

    def __init__(self, requester, reporter):
        super().__init__(requester, reporter)
        self._checked_hosts = set()

    def run_url(self, url: str):
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return

        host_key = (parsed.scheme, parsed.netloc)
        if host_key in self._checked_hosts:
            return
        self._checked_hosts.add(host_key)

        # If HTTP: check redirect to HTTPS
        if parsed.scheme == "http":
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
            return

        # HTTPS: check HSTS once per host
        r = self.req.head(url)
        if r is None:
            return

        hsts = r.headers.get("Strict-Transport-Security")
        if not hsts:
            self.reporter.add(Finding(
                title="HSTS not enabled on HTTPS host",
                severity="Low",
                category="TLS",
                url=f"{parsed.scheme}://{parsed.netloc}/",
                evidence="Strict-Transport-Security header missing.",
                recommendation="Enable HSTS (start with short max-age, then increase; consider includeSubDomains/preload).",
            ))
