from urllib.parse import urljoin, urlparse

from checks.base import BaseCheck
from reporting.models import Finding


class SensitivePathsCheck(BaseCheck):
    name = "SensitivePathsCheck"

    COMMON_PATHS = [
        "/.git/HEAD",
        "/.env",
        "/phpinfo.php",
        "/server-status",
        "/admin",
        "/administrator",
        "/wp-admin",
        "/.DS_Store",
        "/backup.zip",
        "/db.sql",
    ]

    def __init__(self, requester, reporter):
        super().__init__(requester, reporter)
        self._checked_hosts = set()

    def run_url(self, url: str):
        parsed = urlparse(url)
        host = parsed.netloc
        if not host or host in self._checked_hosts:
            return
        self._checked_hosts.add(host)

        base = f"{parsed.scheme}://{host}/"

        for path in self.COMMON_PATHS:
            probe = urljoin(base, path)
            r = self.req.get(probe)
            if not r:
                continue

            if r.status_code == 200 and (r.text and len(r.text) > 20):
                severity = "High" if path in ("/.env", "/.git/HEAD") else "Medium"
                self.reporter.add(Finding(
                    title=f"Potentially exposed sensitive path: {path}",
                    severity=severity,
                    category="Exposure",
                    url=probe,
                    evidence=f"HTTP {r.status_code}, length={len(r.text)}",
                    recommendation="Restrict access to sensitive files/paths and ensure proper server configuration.",
                ))
