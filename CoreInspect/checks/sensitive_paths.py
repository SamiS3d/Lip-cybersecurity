from urllib.parse import urljoin

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

    def run_url(self, url: str):
        # Only probe on root-ish pages to reduce noise
        # Probe only once per base host by using the target provided in URL: join with current
        for path in self.COMMON_PATHS:
            probe = urljoin(url, path)
            r = self.req.get(probe)
            if not r:
                continue

            # Heuristic: if 200 and non-trivial body, flag
            if r.status_code == 200 and (r.text and len(r.text) > 20):
                self.reporter.add(Finding(
                    title=f"Potentially exposed sensitive path: {path}",
                    severity="High" if path in ("/.env", "/.git/HEAD") else "Medium",
                    category="Exposure",
                    url=probe,
                    evidence=f"HTTP {r.status_code}, length={len(r.text)}",
                    recommendation="Restrict access to sensitive files/paths and ensure proper server configuration.",
                ))